# `contrib/zk_carrier/scripts/` — ZK carrier end-to-end drivers

This directory consolidates the operator-facing end-to-end test drivers for
the ZK carrier flow (Phase 7 of the OP_CHECKZKP plan).  They sit next to the
circom circuit (`contrib/zk_carrier/circuits/`) and the snarkjs prover helper
(`contrib/zk_carrier/witness_helper.py`) so all ZK demo assets live under one
tree.

> **Note**: this is a libdogecoin-only end-to-end demo.  It is **not**
> integrated with any "DogeOS" / Dogecoin Core ZK proofs work.  The
> `DOGEOS_CARRIER_*` environment-variable names are kept for back-compat with
> earlier test branches; the demo runs entirely against this repo's own
> `range_proof.circom` + snarkjs proving + libdogecoin's
> rapidsnark/mcl/external-snarkjs verifier paths.

## Scripts

### `run_full_dogeos_carrier_demo.{sh,py}` — single-pair driver

End-to-end demo of the ZK carrier flow.

Steps performed:

1. `snarkjs groth16 fullprove` over the range-proof circuit (or any circuit
   you point at via `--wasm` / `--zkey`), via
   `contrib/zk_carrier/witness_helper.py`.
2. Encode the proof + public inputs into the canonical ZKP1 payload.
3. `such -c zk_commit` → SHA256d commitment + `OP_RETURN DZKC <mode> <commit>`
   scriptPubKey.
4. `such -c zk_add_commit_and_carrier_tx` → adds the OP_RETURN output and
   the chunked P2SH carrier outputs to a base unsigned tx.
5. `such -c sign_raw_tx` → signs the funding input with the WIF.
6. Broadcasts via `RPC_URL`, falls back to the local `sendtx` binary, then
   to `dogechain.info/api/v1/pushtx` when neither is configured.
7. Polls the configured explorer (`EXPLORER_BASE`) until the txid appears
   (timeout: 600 s).
8. Local verify: `such -c zk_extract_carrier` reassembles the payload from
   `TX_R_HEX` and prints the decoded header.

#### Network selection

* **`--testnet`** is the default.
* **`--mainnet`** *also* requires `--i-understand-real-doge`.  Otherwise the
  script refuses to broadcast.

#### WIF / address handling

The script never embeds a private key in source.  Resolution order:

1. `DOGEOS_CARRIER_WIF` env var (operator-supplied).
2. `FUNDED_WIF` env var.
3. The mainnet default reused from `contrib/mainnet_falcon_test.sh` and
   friends:
   * WIF: `QP1tqHYuPiAW73MHETRaARgeEff9PhHyYyQcWXAGskEFmSppDt2w`
   * Address: `DDMpdcTrWnZT38tRMebbYzCSAgLSnVMqvr`

   This is the same key/address used by the existing mainnet PQC scripts in
   this branch family — it is **already public there** and is reused only
   so a single funded UTXO chain can be exercised across PQ + ZK demos.

If you don't want that, export `DOGEOS_CARRIER_WIF` to your own WIF (and
`DOGEOS_CARRIER_ADDR` if it differs from the WIF's natural address) before
running.

#### Logging — commit the run log

The script `tee`s every line of stdout/stderr to
`dogeos_carrier_demo_<UTC>.log` in the working directory.

**You MUST commit that file alongside any mainnet run.**  The script
finishes a mainnet run with a banner that prints the exact `git add -f` /
`git commit` / `git push` commands (the repo's `.gitignore` matches
`*.log`, so `-f` is required); copy-paste them.  Reviewers depend on the log to verify:

* the explorer URL the script polled,
* the broadcast txid,
* the `such -c zk_extract_carrier` output (proves TX_R round-trips),
* the snarkjs verify line (proves the proof actually verifies).

Logs from testnet runs are nice-to-have; logs from mainnet runs are
mandatory and gate review.

#### Mainnet warnings

* This script signs and broadcasts real DOGE.  Do not run on mainnet
  without first running on testnet end-to-end.
* The funded UTXO and fee variables (`FUNDED_UTXO_TXID`,
  `FUNDED_UTXO_VALUE_KOINU`, `TX_FEE_KOINU`, `CARRIER_VALUE_KOINU`,
  `TX_R_FEE_KOINU`) must all be set explicitly — there is no auto-fund.
* The `--skip-broadcast` flag is the safe dry-run path: it stops after
  printing the commitment and OP_RETURN scriptPubKey.

#### Python entry point

`run_full_dogeos_carrier_demo.py` is a thin importable wrapper around the
shell script:

```python
from contrib.zk_carrier.scripts.run_full_dogeos_carrier_demo import run_demo
run_demo(["--testnet", "--skip-broadcast", "--low", "0",
          "--high", "1000000", "--amount", "42000"])
```

#### Out of scope (here)

* Full TX_R assembly via RPC.  The ZK carrier reuses the **identical**
  P2SH carrier shape as `contrib/mainnet_falcon_test.sh` (chunked scriptSig
  with 8-byte tag).  The demo prints the per-part scriptSig hexes; feed
  them into the same TX_R-builder helpers from `mainnet_falcon_test.sh` to
  produce a fully signed reveal transaction.  When you have the assembled
  hex, set `TX_R_HEX=...` and rerun the script — step 8 will verify it.

### `broadcast_set.sh` — multi-pair driver

Multi-pair sibling of `run_full_dogeos_carrier_demo.sh` and the ZK analogue
of `contrib/mainnet_dilithium2_test.sh` / `contrib/mainnet_raccoong_test.sh`.

Loops `N` times.  For each iteration it:

1. Picks the next unspent UTXO from `$FUNDED_ADDR` (or the chained change
   output from the previous iteration) and queries explorer APIs for its
   value + scriptPubKey.
2. Generates a fresh Groth16 proof via
   `contrib/zk_carrier/witness_helper.py` with a per-iteration `--amount`
   so each cycle commits a distinct payload.
3. Builds an unsigned base tx (1 input → 1 P2PKH change to `FUNDED_ADDR`),
   derives sighash, and uses
       `such -c zk_add_commit_and_carrier_tx`
   to append the ZKP1 OP_RETURN + P2SH carrier outputs.
4. Signs the funding input with `such -c sign` and broadcasts TX_C with
   `sendtx`.  Waits for the explorer to see TX_C.
5. Builds TX_R that spends every carrier output (one P2SH input per
   carrier part), pastes in the per-part scriptSigs already emitted by
   step 3, and broadcasts TX_R via `sendtx`.
6. Appends `tx_c.txid<TAB>tx_r.txid<TAB>commit<TAB>height_estimate` to a
   manifest.  Chains the next iteration off TX_C's change vout.

After the loop, optionally launches one `spvnode --zk-vkey` scan over the
whole height range and tees the resulting `[zk-commit] PASSED` lines (one
triple per pair) to `test-logs/`.

See the script's own header comment block for the full prerequisite and
environment-variable reference; the same `DOGEOS_CARRIER_WIF` /
`FUNDED_WIF` resolution rules apply.

## Run history

End-to-end PASSED runs of these drivers are committed under
[`test-logs/`](../../../test-logs/), specifically the
`mainnet_zk_carrier_e2e_*PASSED*.txt` / `mainnet_zk_carrier_spvnode_PASSED_*.txt`
files.  Both Groth16 (in-process via mcl) and PLONK (external snarkjs
verifier) end-to-end mainnet pairs are represented.
