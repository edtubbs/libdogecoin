#!/usr/bin/env bash
# contrib/zk_carrier/circuits/build_circuit.sh
#
# Reproducible (or auditable) build for the ZK carrier range_proof circuit.
#
# Stages
#   1. Verify SHA256 of committed Hermez phase-1 ptau artifacts.
#   2. Compile range_proof.circom -> .r1cs / .wasm / .sym.   (deterministic)
#   3. PLONK setup -> range_proof_plonk.zkey.                 (deterministic)
#   4. Groth16 phase-2 setup + single-contributor ceremony
#      -> range_proof.zkey.                                   (random entropy
#         by default; pass --deterministic-entropy HEX to make the ceremony
#         bit-reproducible.)
#   5. Export both verification keys.
#
# Modes
#   (default)                       run all stages with random Groth16 entropy.
#   --deterministic-entropy HEX     use HEX as the snarkjs `-e=` value, making
#                                   the Groth16 ceremony bit-reproducible by
#                                   anyone who reruns with the same HEX.
#   --verify                        rebuild stages 2/3 + re-export both vkeys
#                                   from the committed zkeys, and diff against
#                                   the committed copies.  No ceremony is run;
#                                   safe to run in CI.  Exits non-zero on any
#                                   mismatch.
#
# Pinned tool versions (see ./README.md):
#   circom    2.1.6
#   snarkjs   0.7.x
#   circomlib 2.0.5  (in ./build/circ_inc/circomlib)

set -euo pipefail
umask 022

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
SRC_CIRCOM="$SCRIPT_DIR/range_proof.circom"
INC_DIR="$BUILD_DIR/circ_inc"

CIRCOM="${CIRCOM:-circom}"
SNARKJS="${SNARKJS:-snarkjs}"

MODE="build"
DETERMINISTIC_ENTROPY=""
OUT_DIR=""

usage() {
    cat <<EOF
Usage: $0 [options]
  --deterministic-entropy HEX   make the Groth16 ceremony bit-reproducible by
                                using HEX as snarkjs's contribute entropy.
                                Without this flag, fresh entropy is read from
                                /dev/urandom (a real single-contributor
                                ceremony, but not byte-reproducible).
  --verify                      do not run any ceremony; rebuild deterministic
                                artifacts and verify both verification_key
                                files match the committed copies.  Exits
                                non-zero on any mismatch.
  --out DIR                     write artifacts to DIR instead of $BUILD_DIR
                                (still verifies ptau hashes from $BUILD_DIR).
  -h, --help                    show this help.

Environment overrides:
  CIRCOM      circom binary (default: circom)
  SNARKJS     snarkjs binary (default: snarkjs)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --deterministic-entropy)
            DETERMINISTIC_ENTROPY="$2"; shift ;;
        --verify)
            MODE="verify" ;;
        --out)
            OUT_DIR="$2"; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "Unknown arg: $1" >&2; usage; exit 1 ;;
    esac
    shift
done

if [[ -n "$DETERMINISTIC_ENTROPY" ]]; then
    if ! [[ "$DETERMINISTIC_ENTROPY" =~ ^[0-9a-fA-F]+$ ]]; then
        echo "ERROR: --deterministic-entropy must be a hex string" >&2
        exit 2
    fi
    # Require at least 32 bytes (64 hex chars) of entropy.  snarkjs hashes
    # the input, but accepting a short string would create a misleading
    # "ceremony" with trivially-low entropy.
    if (( ${#DETERMINISTIC_ENTROPY} < 64 )); then
        echo "ERROR: --deterministic-entropy must be at least 64 hex chars (32 bytes)" >&2
        exit 2
    fi
fi

if [[ -z "$OUT_DIR" ]]; then
    OUT_DIR="$BUILD_DIR"
fi
mkdir -p "$OUT_DIR"

# --------------------------- Pinned ptau SHA256s -----------------------------
# These are the SHA256s of the Hermez phase-1 powers-of-tau artifacts shipped
# under build/.  pot12_final.ptau is the canonical published phase-1 output;
# the 0000/0001 intermediates are the early-chain entries from the same
# ceremony.  Source: https://github.com/iden3/snarkjs#7-prepare-phase-2 and
# the Hermez phase-1 ceremony archive.
PTAU_FINAL_SHA256="c99c3bca64440a654a39483f9aae802473e9603fd5a1baf52f60cb576de40095"
PTAU_0000_SHA256="18dd67751dd0659bcd6f58d961ef478d855f1695325ad9db9cd68e30e411e24a"
PTAU_0001_SHA256="b2f0c006be45736475fbd61dc7f3ee86b4172426ea51937abb2e360cb2ec9b38"

verify_sha256() {
    local file="$1" expected="$2" label="$3"
    if [[ ! -f "$file" ]]; then
        echo "ERROR: missing $label: $file" >&2
        return 1
    fi
    local actual
    actual=$(sha256sum "$file" | awk '{print $1}')
    if [[ "$actual" != "$expected" ]]; then
        echo "ERROR: $label sha256 mismatch" >&2
        echo "  file:     $file" >&2
        echo "  expected: $expected" >&2
        echo "  actual:   $actual" >&2
        return 1
    fi
    echo "  ok  $label  sha256=$actual"
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: required tool not in PATH: $1" >&2
        echo "  install circom 2.1.6 and snarkjs 0.7.x first" >&2
        exit 2
    fi
}

# --------------------------- Stage 1: ptau audit -----------------------------
echo "==> [1/5] verifying committed ptau artifacts"
verify_sha256 "$BUILD_DIR/pot12_final.ptau" "$PTAU_FINAL_SHA256" "pot12_final.ptau"
verify_sha256 "$BUILD_DIR/pot12_0000.ptau"  "$PTAU_0000_SHA256"  "pot12_0000.ptau"
verify_sha256 "$BUILD_DIR/pot12_0001.ptau"  "$PTAU_0001_SHA256"  "pot12_0001.ptau"

# --verify mode just checks the committed verification keys still match what
# you'd export from the committed zkeys.  No new entropy is consumed.  This
# is the safe CI / audit path.
if [[ "$MODE" == "verify" ]]; then
    require_tool "$SNARKJS"

    TMPDIR_VERIFY="$(mktemp -d -t zkc-verify.XXXXXX)"
    trap 'rm -rf "$TMPDIR_VERIFY"' EXIT

    echo "==> [verify] exporting verification keys from committed zkeys"
    "$SNARKJS" zkey export verificationkey \
        "$BUILD_DIR/range_proof.zkey" \
        "$TMPDIR_VERIFY/verification_key.json" >/dev/null
    "$SNARKJS" zkey export verificationkey \
        "$BUILD_DIR/range_proof_plonk.zkey" \
        "$TMPDIR_VERIFY/verification_key_plonk.json" >/dev/null

    rc=0
    for vk in verification_key.json verification_key_plonk.json; do
        if [[ ! -f "$BUILD_DIR/$vk" ]]; then
            echo "  FAIL  $vk missing from $BUILD_DIR" >&2
            rc=1
            continue
        fi
        if diff -q "$BUILD_DIR/$vk" "$TMPDIR_VERIFY/$vk" >/dev/null; then
            echo "  ok  $vk matches committed copy"
        else
            echo "  FAIL  $vk differs from committed copy" >&2
            diff -u "$BUILD_DIR/$vk" "$TMPDIR_VERIFY/$vk" || true
            rc=1
        fi
    done
    exit "$rc"
fi

# --------------------------- Stage 2: compile circuit ------------------------
require_tool "$CIRCOM"
require_tool "$SNARKJS"

if [[ ! -d "$INC_DIR/circomlib" ]]; then
    echo "ERROR: circomlib include not found at $INC_DIR/circomlib" >&2
    echo "  did you initialize the submodule?  (git submodule update --init --recursive)" >&2
    exit 2
fi

echo "==> [2/5] compiling range_proof.circom"
"$CIRCOM" "$SRC_CIRCOM" \
    --r1cs --wasm --sym \
    --output "$OUT_DIR" \
    -l "$INC_DIR"

# --------------------------- Stage 3: PLONK setup (deterministic) ------------
echo "==> [3/5] PLONK setup (deterministic)"
"$SNARKJS" plonk setup \
    "$OUT_DIR/range_proof.r1cs" \
    "$BUILD_DIR/pot12_final.ptau" \
    "$OUT_DIR/range_proof_plonk.zkey"

# --------------------------- Stage 4: Groth16 phase-2 ceremony ---------------
echo "==> [4/5] Groth16 phase-2 setup"
"$SNARKJS" groth16 setup \
    "$OUT_DIR/range_proof.r1cs" \
    "$BUILD_DIR/pot12_final.ptau" \
    "$OUT_DIR/range_proof_0000.zkey"

if [[ -n "$DETERMINISTIC_ENTROPY" ]]; then
    echo "    contribute: deterministic (HEX from --deterministic-entropy)"
    CEREMONY_NAME="reproducible-build"
    "$SNARKJS" zkey contribute \
        "$OUT_DIR/range_proof_0000.zkey" \
        "$OUT_DIR/range_proof.zkey" \
        --name="$CEREMONY_NAME" \
        -e="$DETERMINISTIC_ENTROPY"
else
    echo "    contribute: random entropy from /dev/urandom (default)"
    CEREMONY_NAME="single-contributor-demo"
    RAND_ENTROPY="$(head -c 32 /dev/urandom | xxd -p -c 64)"
    if [[ -z "$RAND_ENTROPY" || ${#RAND_ENTROPY} -lt 64 ]]; then
        echo "ERROR: failed to read 32 bytes of entropy from /dev/urandom" >&2
        exit 3
    fi
    "$SNARKJS" zkey contribute \
        "$OUT_DIR/range_proof_0000.zkey" \
        "$OUT_DIR/range_proof.zkey" \
        --name="$CEREMONY_NAME" \
        -e="$RAND_ENTROPY"
    # Wipe ephemeral entropy from the shell.
    RAND_ENTROPY=""
fi

rm -f "$OUT_DIR/range_proof_0000.zkey"

# --------------------------- Stage 5: export verification keys ---------------
echo "==> [5/5] exporting verification keys"
"$SNARKJS" zkey export verificationkey \
    "$OUT_DIR/range_proof.zkey" \
    "$OUT_DIR/verification_key.json"
"$SNARKJS" zkey export verificationkey \
    "$OUT_DIR/range_proof_plonk.zkey" \
    "$OUT_DIR/verification_key_plonk.json"

echo
echo "==> done.  artifacts written to: $OUT_DIR"
if [[ -z "$DETERMINISTIC_ENTROPY" ]]; then
    echo "    note: range_proof.zkey used random entropy and is NOT byte-reproducible."
    echo "          The verification_key.json is what verifiers need; rerun with"
    echo "          --deterministic-entropy HEX to make the ceremony itself repeatable."
fi
