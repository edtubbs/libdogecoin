# ZK carrier — circuits

This directory contains the reference circom circuit used by the ZK carrier
demo (`contrib/zk_carrier/scripts/run_full_zk_carrier_demo.sh`).

## Versions

These circuits are pinned to the following toolchain.  Anything older than
circom 2.1 will not parse `pragma circom 2.1.6`.

* circom: **2.1.6** (https://github.com/iden3/circom)
* snarkjs: **0.7.x** (https://github.com/iden3/snarkjs)
* circomlib: **2.0.5** (https://github.com/iden3/circomlib)
* powers-of-tau: **Hermez phase-1 ptau-12** (`pot12_final.ptau` from
  https://github.com/iden3/snarkjs#7-prepare-phase-2 — supports up to 2^12
  constraints, plenty for the 64-bit range proof which uses ~130 constraints).

> Note: ptau-12 only covers small circuits.  Bump to ptau-14/16 if you grow
> the circuit beyond a few thousand constraints.

## Committed phase-1 artifacts (audit by hash, don't rebuild)

`pot12_final.ptau` is the canonical Hermez phase-1 powers-of-tau output for
power 12; thousands of contributors took part in that ceremony, so the
right thing for any downstream consumer is to verify the committed file
by SHA256 rather than try to reproduce it.  The 0000/0001 files are the
early-chain intermediates from the same ceremony.  Pinned hashes:

| file              | SHA256                                                             |
|-------------------|--------------------------------------------------------------------|
| `pot12_final.ptau`| `c99c3bca64440a654a39483f9aae802473e9603fd5a1baf52f60cb576de40095` |
| `pot12_0000.ptau` | `18dd67751dd0659bcd6f58d961ef478d855f1695325ad9db9cd68e30e411e24a` |
| `pot12_0001.ptau` | `b2f0c006be45736475fbd61dc7f3ee86b4172426ea51937abb2e360cb2ec9b38` |

The `build_circuit.sh` script below verifies these on every run.  Source:
the snarkjs phase-2 prep documentation and the Hermez phase-1 archive
(<https://github.com/iden3/snarkjs#7-prepare-phase-2>).

## Reproducible build

The one-shot reproducible build is `./build_circuit.sh`.  It assumes
`circom` 2.1.6 and `snarkjs` 0.7.x are on `$PATH` and that the
`circ_inc/circomlib` submodule has been initialized.

```bash
# Default: random Groth16 entropy (real single-contributor ceremony,
#          NOT byte-reproducible).  The verification_key.json that comes
#          out is what verifiers actually need to trust.
./build_circuit.sh

# Reproducible Groth16 ceremony: anyone running with the same HEX gets
# bit-identical zkeys + verification keys.  Useful for CI, audits, and
# regression-testing the build pipeline; not a substitute for a real
# multi-party ceremony in production.  HEX must be at least 64 hex chars
# (32 bytes) — generate one once with `head -c 32 /dev/urandom | xxd -p -c 64`,
# commit it alongside the artifacts so the ceremony can be replayed, and do
# NOT reuse the example below in any non-test setting (a publicly-known
# entropy value provides no ceremony security).
./build_circuit.sh --deterministic-entropy 7c1c9d3e0f2a8b6543e9d1c4a07b58f23e96cba140d8e7f269b3a51e8d4c0f72

# CI-safe audit: exports verification keys from the committed zkeys and
# diffs them against build/verification_key*.json.  No new entropy is
# consumed; safe to run on every push.
./build_circuit.sh --verify
```

The script's stages are:

1. Verify SHA256 of the committed `pot12_*.ptau` files (table above).
2. Compile `range_proof.circom` → `.r1cs` / `.wasm` / `.sym` (deterministic
   given pinned circom + circomlib).
3. PLONK universal setup → `range_proof_plonk.zkey` (always deterministic;
   PLONK has no per-circuit phase-2 ceremony).
4. Groth16 phase-2 setup + single-contributor `zkey contribute` →
   `range_proof.zkey`.  Entropy source: `/dev/urandom` by default,
   or the `--deterministic-entropy HEX` value.
5. Export both `verification_key.json` and `verification_key_plonk.json`.

### Determinism summary

| artifact                     | reproducible from source? |
|------------------------------|---------------------------|
| `range_proof.r1cs/.wasm/.sym`| yes (circom + circomlib pinned) |
| `range_proof_plonk.zkey`     | yes (PLONK universal setup) |
| `verification_key_plonk.json`| yes (deterministic from PLONK zkey) |
| `range_proof.zkey`           | only with `--deterministic-entropy HEX` |
| `verification_key.json`      | only with `--deterministic-entropy HEX` |

The verification keys are the consensus-relevant artifacts: any verifier
re-exporting them from the committed zkeys (i.e. `--verify`) will get
bit-identical output regardless of which entropy mode produced the
ceremony.

## Manual / custom invocation

If you'd rather drive snarkjs directly:

```bash
# 1. Compile the circuit.
circom range_proof.circom --r1cs --wasm --sym --output build \
    -l ./build/circ_inc

# 2. Trusted-setup phase 2 (Groth16 needs a per-circuit ceremony — for a
#    demo, a single contributor is acceptable; production deployments
#    should run a multi-party ceremony).
snarkjs groth16 setup build/range_proof.r1cs build/pot12_final.ptau build/range_proof_0000.zkey
snarkjs zkey contribute build/range_proof_0000.zkey build/range_proof.zkey \
    --name="demo contributor" -e="$(head -c 32 /dev/urandom | xxd -p)"
snarkjs zkey export verificationkey build/range_proof.zkey build/verification_key.json

# 3. Generate a proof for a concrete witness.
cat > input.json <<'EOF'
{ "low": "0", "high": "1000000", "amount": "42000" }
EOF
snarkjs groth16 fullprove input.json \
    build/range_proof_js/range_proof.wasm \
    build/range_proof.zkey \
    proof.json public.json

# 4. Verify off-box (libdogecoin will do the same on-chain via reserved-opcode
#    validator when that ships; today verification is delegated unless you build with
#    --with-rapidsnark or --with-mcl).
snarkjs groth16 verify build/verification_key.json public.json proof.json
```

## Driving the carrier flow

The Python helper `../witness_helper.py` runs steps 3-4 above and emits the
canonical ZK carrier payload bytes (`ZKP1` magic + headers + public + proof)
that `such -c zk_add_commit_and_carrier_tx` consumes.
