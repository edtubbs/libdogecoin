# ZK Proof Carrier — developer reference

This document is the developer/integrator reference for the ZK proof carrier
module (`src/zk_carrier/`).  It covers the public C API, the on-wire ZKP1
payload format, and the carrier transaction shape.

For higher-level material:

* The protocol spec lives in
  [`doc/spec/bip-zk-carrier-commitments.mediawiki`](spec/bip-zk-carrier-commitments.mediawiki)
  (canonical encoding, mode identifiers, deployment, mainnet examples).
* The CLI surface (`such -c zk_*` commands and `spvnode --zk-vkey`) and
  configure flags are documented in [`tools.md`](tools.md) under
  *Zero-Knowledge Proof Carrier (ZK) Commands*.
* End-to-end demo scripts live under
  [`contrib/zk_carrier/scripts/`](../contrib/zk_carrier/scripts/).

## Overview

The module implements the on-chain side of the OP_CHECKZKP proposal: a
canonical wire format for ZK proofs (Groth16 / PLONK / STARK) and a P2SH
carrier transaction shape that lets full nodes and SPV clients consume those
proofs without an `OP_CHECKZKP` interpreter (yet) on the network.

## Public API

See `include/dogecoin/zk_carrier.h` for the full surface.  The public
header is C — the rest of libdogecoin is C, and so is this module despite
the OP_CHECKZKP spec saying "C++".

* `dogecoin_zk_encode_payload` / `dogecoin_zk_decode_payload` — codec for
  the canonical `ZKP1` payload (see *On-wire format* below).
* `dogecoin_zk_get_commitment_hash` — `SHA256d(payload)`, the value
  embedded in the OP_RETURN of TX_C.
* `dogecoin_zk_build_opreturn_scriptpubkey` — produces
  `OP_RETURN <push 37> "DZKC" <mode> <commit32>`.  Total length 39 bytes,
  well below the 83-byte standardness limit.
* `dogecoin_zk_build_carrier_tx_c` — appends the OP_RETURN + P2SH carrier
  outputs to an existing `dogecoin_tx*`.  The carrier outputs reuse
  `dogecoin_pqc_carrier_build_redeemscript` /
  `dogecoin_tx_add_pqc_carrier_outputs` verbatim, so PQ + ZK carriers share
  one shape and one SPV walker.
* `dogecoin_zk_build_carrier_tx_r_scriptsigs` — emits the per-part scriptSigs
  for the spend (TX_R) that reveals the payload.  Reuses
  `dogecoin_pqc_carrier_build_part_scriptsig` and changes only the 8-byte
  ASCII tag (`ZKP1FULL` instead of `FLC1FULL` / `DIL2FULL` / `RCG4FULL`).
* `dogecoin_zk_extract_carrier_payload` — parses a TX_R and reassembles the
  ZKP1 payload by walking `dogecoin_pqc_carrier_parse_part_scriptsig`.
* `dogecoin_zk_verify_proof` — dispatch on mode.  Groth16 calls
  `dogecoin_zk_verify_groth16` (rapidsnark when linked, else
  `DOGECOIN_ZK_ERR_DELEGATED`).  PLONK and STARK return
  `DOGECOIN_ZK_ERR_NOT_IMPLEMENTED`.
* `dogecoin_zk_generate_*_proof` — always return `DOGECOIN_ZK_ERR_DELEGATED`
  (Groth16) or `DOGECOIN_ZK_ERR_NOT_IMPLEMENTED` (others).  Proving never
  runs in libdogecoin; see `contrib/zk_carrier/witness_helper.py` for the
  supported snarkjs-driven flow.

## Mode enum (mirrors OP_CHECKZKP modular selector)

| value | mode                       |
|-------|----------------------------|
| 0     | `DOGECOIN_ZK_MODE_GROTH16` |
| 1     | `DOGECOIN_ZK_MODE_PLONK`   |
| 2     | `DOGECOIN_ZK_MODE_STARK_S2`|

Future modes (e.g. Halo2, Bulletproofs) reserve higher integers; an
unknown mode byte returns `DOGECOIN_ZK_ERR_BAD_MODE` from the codec.

## On-wire payload format (`ZKP1`)

| offset | size | field            | encoding           |
|-------:|-----:|------------------|--------------------|
| 0      | 4    | magic `"ZKP1"`   | ASCII              |
| 4      | 1    | mode             | uint8 (see enum)   |
| 5      | 1    | reserved         | must be `0x00`     |
| 6      | 4    | circuit_id       | uint32 BE          |
| 10     | 2    | public_inputs_len| uint16 BE          |
| 12     | N    | public_inputs    | opaque bytes       |
| 12+N   | 4    | proof_len        | uint32 BE          |
| 16+N   | M    | proof            | opaque bytes       |

`public_inputs` and `proof` are typically the JSON blobs emitted by snarkjs
(`public.json`, `proof.json`); rapidsnark accepts the same JSON when it
verifies on-chain.  Carrying JSON keeps the formats interchangeable across
prover backends and avoids a separate canonicalisation step.

## TX_C / TX_R shape

* **TX_C** ("commit"):
  * vout 0 .. n-1: existing outputs of the base tx (change, payments).
  * vout n: `OP_RETURN <push 37> "DZKC" <mode> <commit32>` — value 0.
  * vout n+1 .. n+parts: P2SH carrier outputs, each
    `value = CARRIER_VALUE_KOINU` (≥ 1 DOGE to clear dust), scriptPubKey
    `OP_HASH160 <h160(redeem)> OP_EQUAL`.  The redeem script is the same
    `OP_DROP×5 OP_1` pattern used by the PQ carrier.

* **TX_R** ("reveal"):
  * One input per carrier output, each with scriptSig produced by
    `dogecoin_zk_build_carrier_tx_r_scriptsigs`.  The scriptSig layout is
    `<tag8> <part_index> <part_total> <pk_len_be16> <full_len_be16>
    <chunk0> <chunk1> ... <redeem>` — identical to the PQ carrier, with
    tag `"ZKP1FULL"`.
  * Outputs are operator-defined (typically a change output back to the
    funding address).

When `OP_CHECKZKP` (proposal opcode 185) ships, an interpreter
implementation will:

1. Recognise the OP_RETURN by leading `"DZKC"` tag and read the mode byte.
2. Walk the inputs of the redeeming TX_R, calling
   `dogecoin_pqc_carrier_parse_part_scriptsig` (its tag-agnostic 8-byte
   prefix) and matching `"ZKP1FULL"` to recover the payload.
3. Look up the verification key for `(mode, circuit_id)` in a
   consensus-anchored registry.
4. Call `dogecoin_zk_verify_proof(payload, payload_len, vk, vk_len)`.

Because the carrier shape is fixed today, that interpreter can be added
without invalidating any historical TX_R.

## Build flags

* `--enable-zk-carrier` (default **on**) — compiles the module.  Disable
  with `--disable-zk-carrier` to drop ~25 KB of code.
* `--with-rapidsnark` — links the rapidsnark Groth16 verifier into
  libdogecoin so verification runs in-process.  Without it, verify returns
  `DOGECOIN_ZK_ERR_DELEGATED` and the demo script falls back to
  `snarkjs groth16 verify`.  This is the recommended mobile-friendly
  default — the C library never runs heavy crypto runtimes.
* `--with-mcl[=DIR]` — links the herumi/mcl BN254 pairing library plus
  the in-process Groth16 verifier in `src/zk_carrier/zk_groth16_mcl.cpp`.
  This is what the published mainnet PASSED runs use for in-process
  verification (`spvnode --zk-vkey verification_key.json`).
* `depends/packages/rapidsnark.mk` plus `ZK_CARRIER=1` on the depends
  invocation vendor a verifier-only rapidsnark for x86_64-linux-gnu and
  x86_64/arm64-apple-darwin.  Mingw / Android / iOS hosts are
  intentionally guarded with a hard `$(error)` — we do not ship cross-
  compilation we cannot validate.

These flags are also summarised in [`tools.md`](tools.md) alongside the CLI
commands they unlock.

## Tests

`test/zk_carrier_tests.c` covers:

* Codec round-trip + tamper-detection on the commitment hash.
* `OP_RETURN DZKC` byte layout.
* TX_C / TX_R round-trip with multi-chunk payloads, ensuring extracted
  bytes match the original.
* Mode dispatch — PLONK and STARK return `NOT_IMPLEMENTED` from
  `dogecoin_zk_verify_proof`, regardless of build flags.
* Prover delegation — all `dogecoin_zk_generate_*_proof` entry points
  return the documented error codes (no silent stubbed proofs).
