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

## Reproducible build

Assuming `circom`, `snarkjs`, and a copy of `pot12_final.ptau` are on
`$PATH` / in the working directory:

```bash
# 1. Compile the circuit.
circom range_proof.circom --r1cs --wasm --sym --output build \
    -l "$(npm root -g)" \
    -l ./node_modules

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
