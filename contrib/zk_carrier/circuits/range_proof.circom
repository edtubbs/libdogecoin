pragma circom 2.1.6;

/*
 * Range proof: prove that `low <= amount <= high`, with `low` and `high`
 * public and `amount` private.  Used by the ZK carrier demo to prove that a
 * UTXO's value falls inside a committed-to band, without revealing the
 * exact value.
 *
 * Bound: 64-bit unsigned (sufficient for koinu / 2^64-1).
 *
 * Reproduction (see ./README.md for full instructions):
 *   circom range_proof.circom --r1cs --wasm --sym --output build
 *   snarkjs powersoftau prepare phase2 pot12_final.ptau pot12_phase2.ptau
 *   snarkjs groth16 setup build/range_proof.r1cs pot12_phase2.ptau range_proof.zkey
 *   snarkjs zkey export verificationkey range_proof.zkey verification_key.json
 *   snarkjs groth16 fullprove input.json build/range_proof_js/range_proof.wasm \
 *       range_proof.zkey proof.json public.json
 */

include "circomlib/comparators.circom";

template RangeProof(nBits) {
    signal input low;
    signal input high;
    signal input amount;

    // amount >= low  <=>  low <= amount  <=>  LessEqThan(low, amount) == 1
    component leLow = LessEqThan(nBits);
    leLow.in[0] <== low;
    leLow.in[1] <== amount;
    leLow.out === 1;

    // amount <= high <=>  LessEqThan(amount, high) == 1
    component leHigh = LessEqThan(nBits);
    leHigh.in[0] <== amount;
    leHigh.in[1] <== high;
    leHigh.out === 1;
}

component main { public [low, high] } = RangeProof(64);
