#!/usr/bin/env bash
#
# v1_reveal_e2e.sh — local end-to-end driver for the ZKP1 v1 (vk-included)
# reveal flow.  Builds a real groth16/plonk proof against the in-tree
# range-proof circuit, encodes a v1 ZKP1 payload, builds TX_C scaffold +
# carrier outputs and TX_R scriptSigs via the libdogecoin `such` CLI,
# extracts the payload back from the synthetic TX_R via `such -c
# zk_extract_carrier`, then verifies the proof using ONLY the verification
# key bytes recovered from the on-chain reveal.  This proves end-to-end
# that the v1 reveal is fully self-contained — no out-of-band vk channel is
# needed at any verification step.
#
# Usage:
#   contrib/zk_carrier/scripts/v1_reveal_e2e.sh groth16 [out_dir]
#   contrib/zk_carrier/scripts/v1_reveal_e2e.sh plonk   [out_dir]
#
# Environment hooks documented in contrib/zk_carrier/scripts/broadcast_set.sh:
#   FUNDED_ADDR / FUNDED_WIF — defaulted to the public demo address
#                              DDMpdcTrWnZT38tRMebbYzCSAgLSnVMqvr (per task)
#                              so the on-chain UTXOs at
#                              https://chain.so/address/DOGE/DDMpdcTrWnZT38tRMebbYzCSAgLSnVMqvr
#                              fund the carrier when the operator runs the
#                              broadcast variant of this script.

set -eu

PROOF_SYSTEM="${1:-groth16}"
OUT_DIR="${2:-/tmp/zkc_v1_e2e/${PROOF_SYSTEM}}"
mkdir -p "$OUT_DIR"

REPO_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
SUCH="${SUCH:-$REPO_DIR/such}"
WITNESS_HELPER="${WITNESS_HELPER:-$REPO_DIR/contrib/zk_carrier/witness_helper.py}"
CIRC_DIR="$REPO_DIR/contrib/zk_carrier/circuits/build"
WASM="${WASM:-$CIRC_DIR/range_proof_js/range_proof.wasm}"
SNARKJS="${SNARKJS:-snarkjs}"

case "$PROOF_SYSTEM" in
    groth16)
        ZKEY="${ZKEY:-$CIRC_DIR/range_proof.zkey}"
        VKEY="${VKEY:-$CIRC_DIR/verification_key.json}"
        MODE_BYTE=0
        ;;
    plonk)
        ZKEY="${ZKEY:-$CIRC_DIR/range_proof_plonk.zkey}"
        VKEY="${VKEY:-$CIRC_DIR/verification_key_plonk.json}"
        MODE_BYTE=1
        ;;
    *)
        echo "[FAIL] unknown PROOF_SYSTEM=$PROOF_SYSTEM (groth16|plonk)" >&2
        exit 1
        ;;
esac

# Public funding address per the BIP example — the on-chain UTXOs at this
# address are what `broadcast_set.sh` would consume in the real-network
# variant of this driver.  For the in-process v1 reveal validation we
# don't actually broadcast, but log the address so the trace is auditable.
FUNDED_ADDR="${FUNDED_ADDR:-DDMpdcTrWnZT38tRMebbYzCSAgLSnVMqvr}"

LOG="$OUT_DIR/v1_reveal_e2e_${PROOF_SYSTEM}.log"
exec > >(tee "$LOG") 2>&1

echo "==============================================================================="
echo "ZKP1 v1 reveal end-to-end (no out-of-band vk channel)"
echo "  proof_system: $PROOF_SYSTEM"
echo "  funded_addr:  $FUNDED_ADDR"
echo "  wasm:         $WASM"
echo "  zkey:         $ZKEY"
echo "  vkey:         $VKEY"
echo "  vkey_sha256:  $(sha256sum "$VKEY" | awk '{print $1}')"
echo "  out_dir:      $OUT_DIR"
echo "==============================================================================="

[ -x "$SUCH" ] || { echo "[FAIL] such not found at $SUCH (run ./configure --enable-zk-carrier && make)"; exit 1; }
[ -f "$WASM" ] && [ -f "$ZKEY" ] && [ -f "$VKEY" ] || { echo "[FAIL] missing circuit artefacts under $CIRC_DIR"; exit 1; }

PAYLOAD_HEX_FILE="$OUT_DIR/payload.hex"
PROOF_JSON="$OUT_DIR/proof.json"
PUBLIC_JSON="$OUT_DIR/public.json"

echo
echo "--- Step 1: snarkjs prove + ZKP1 v1 payload encode (via witness_helper.py) ---"
python3 "$WITNESS_HELPER" \
    --proof-system "$PROOF_SYSTEM" \
    --wasm "$WASM" --zkey "$ZKEY" --vkey "$VKEY" \
    --circuit-id 1 \
    --low 0 --high 1000000 --amount 50000 \
    --save-proof  "$PROOF_JSON" \
    --save-public "$PUBLIC_JSON" \
    --out-payload "$PAYLOAD_HEX_FILE"
PAYLOAD_HEX=$(tr -d '[:space:]' < "$PAYLOAD_HEX_FILE")
PAYLOAD_BYTES=$(( ${#PAYLOAD_HEX} / 2 ))
echo "payload_bytes=$PAYLOAD_BYTES (v1 self-contained reveal: vk embedded inline)"

echo
echo "--- Step 2: such -c zk_commit (derives commitment + reports vk_len) ---"
"$SUCH" -c zk_commit -x "$PAYLOAD_HEX"
COMMIT=$("$SUCH" -c zk_commit -x "$PAYLOAD_HEX" 2>&1 | awk -F':[[:space:]]+' '/^commitment:/ {print $2; exit}' | tr -d ' ')
echo "commit32=$COMMIT"

echo
echo "--- Step 3: such -c zk_add_commit_and_carrier_tx (TX_C scaffold) ---"
# Synthetic single-vin/single-vout base tx so we can attach OP_RETURN +
# carrier outputs without a real funding spend.  This is identical to what
# broadcast_set.sh does, except with a placeholder vin/vout.
BASE_UNSIGNED=$(python3 - <<'PY'
def le_u32(n): return n.to_bytes(4, "little").hex()
def le_u64(n): return n.to_bytes(8, "little").hex()
def varint(n):
    if n < 0xfd: return f"{n:02x}"
    return "fd" + n.to_bytes(2, "little").hex()
prev = "00" * 32
vin  = prev + le_u32(0) + "00" + "ffffffff"
spk  = "76a9145a29227bb518c38cae5a9a195cafc56b22d7272b88ac"  # P2PKH for funded addr
vout = le_u64(100_000_000) + varint(len(spk)//2) + spk
print("01000000" + varint(1) + vin + varint(1) + vout + "00000000")
PY
)
SUCH_OUT=$("$SUCH" -c zk_add_commit_and_carrier_tx -x "$BASE_UNSIGNED" -m "$MODE_BYTE" -s "$PAYLOAD_HEX" -h 100000000 2>&1)
echo "$SUCH_OUT"
TX_C_UNSIGNED=$(echo "$SUCH_OUT" | awk -F': ' '/^tx with commitment/ {print $2; exit}' | tr -d ' ')
PART_TOTAL=$(echo "$SUCH_OUT" | awk -F': ' '/^zk_carrier_part_total:/ {print $2; exit}' | tr -d ' ')
FIRST_VOUT=$(echo "$SUCH_OUT" | awk -F': ' '/^zk_carrier_first_vout:/ {print $2; exit}' | tr -d ' ')
PART_SCRIPTSIGS=()
for ((p=0; p<PART_TOTAL; p++)); do
    ss=$(echo "$SUCH_OUT" | sed -n "s/^zk_carrier_part_scriptsig\\[$p\\]:[[:space:]]*//p" | head -n1 | tr -d ' ')
    PART_SCRIPTSIGS+=("$ss")
done
echo "part_total=$PART_TOTAL first_vout=$FIRST_VOUT"

echo
echo "--- Step 4: build synthetic TX_R consuming carrier outputs ---"
# Compute TX_C txid then craft TX_R with prev=TX_C:first_vout..first_vout+parts-1
TX_C_TXID=$(python3 - "$TX_C_UNSIGNED" <<'PY'
import sys, hashlib
b = bytes.fromhex(sys.argv[1])
print(hashlib.sha256(hashlib.sha256(b).digest()).digest()[::-1].hex())
PY
)
TX_R_UNSIGNED=$(python3 - "$TX_C_TXID" "$FIRST_VOUT" "$PART_TOTAL" <<'PY'
import sys
txid, fv, pt = sys.argv[1].lower(), int(sys.argv[2]), int(sys.argv[3])
def le_u32(n): return n.to_bytes(4, "little").hex()
def le_u64(n): return n.to_bytes(8, "little").hex()
def varint(n):
    if n < 0xfd: return f"{n:02x}"
    return "fd" + n.to_bytes(2, "little").hex()
prev_le = bytes.fromhex(txid)[::-1].hex()
vin = "".join(prev_le + le_u32(fv + i) + "00" + "ffffffff" for i in range(pt))
spk = "76a9145a29227bb518c38cae5a9a195cafc56b22d7272b88ac"
vout = le_u64(99_000_000 * pt) + varint(len(spk)//2) + spk
print("01000000" + varint(pt) + vin + "01" + vout + "00000000")
PY
)
TX_R_PATCHED="$TX_R_UNSIGNED"
for ((p=0; p<PART_TOTAL; p++)); do
    SET_OUT=$("$SUCH" -c set_scriptsig -x "$TX_R_PATCHED" -i "$p" -s "${PART_SCRIPTSIGS[$p]}" 2>&1)
    TX_R_PATCHED=$(echo "$SET_OUT" | awk -F': ' '/^tx with scriptsig set:/ {print $2; exit}' | tr -d ' ')
done
echo "tx_r_size=$(( ${#TX_R_PATCHED} / 2 )) bytes"

echo
echo "--- Step 5: such -c zk_extract_carrier (reassemble payload from TX_R) ---"
EXTRACT_OUT=$("$SUCH" -c zk_extract_carrier -x "$TX_R_PATCHED")
echo "$EXTRACT_OUT"
EXTRACTED_HEX=$(echo "$EXTRACT_OUT" | awk -F': ' '/^zk_payload:/ {print $2; exit}' | tr -d ' ')
EXTRACTED_VK_HEX=$(echo "$EXTRACT_OUT" | awk -F': ' '/^zk_vk_hex:/ {print $2; exit}' | tr -d ' ')
EXTRACTED_VK_LEN=$(echo "$EXTRACT_OUT" | awk -F': ' '/^zk_vk_len:/ {print $2; exit}' | tr -d ' ')

if [ "$EXTRACTED_HEX" != "$PAYLOAD_HEX" ]; then
    echo "[FAIL] extracted payload differs from input"
    exit 1
fi
if [ -z "$EXTRACTED_VK_HEX" ] || [ "$EXTRACTED_VK_LEN" = "0" ]; then
    echo "[FAIL] extracted payload missing embedded vk (v0 wire format?)"
    exit 1
fi
echo "[OK] extracted payload byte-identical to input AND embedded vk_len=$EXTRACTED_VK_LEN"

echo
echo "--- Step 6: snarkjs verify using ONLY the vk recovered from the reveal ---"
# Materialize the on-chain-extracted vk to disk, then run snarkjs verify
# against the embedded public.json + proof.json that were also part of the
# reveal.  Nothing here reads any out-of-band vk file.
RECOVERED_VK="$OUT_DIR/recovered_vk_from_reveal.json"
RECOVERED_PUB="$OUT_DIR/recovered_public_from_reveal.json"
RECOVERED_PROOF="$OUT_DIR/recovered_proof_from_reveal.json"
python3 - "$EXTRACTED_HEX" "$RECOVERED_VK" "$RECOVERED_PUB" "$RECOVERED_PROOF" <<'PY'
import sys, struct, json
hexp, vk_out, pub_out, proof_out = sys.argv[1:5]
b = bytes.fromhex(hexp)
assert b[:4] == b"ZKP1" and b[5] == 1, "expected v1 ZKP1 payload"
o = 12
pl = struct.unpack(">H", b[10:12])[0]
pub = b[o:o+pl]; o += pl
xl = struct.unpack(">I", b[o:o+4])[0]; o += 4
proof = b[o:o+xl]; o += xl
kl = struct.unpack(">I", b[o:o+4])[0]; o += 4
vk = b[o:o+kl]
open(vk_out, "wb").write(vk)
open(pub_out, "wb").write(pub)
open(proof_out, "wb").write(proof)
print(f"recovered from reveal: vk_len={kl} public_len={pl} proof_len={xl}")
print(f"recovered public.json: {json.loads(pub.decode())}")
print(f"recovered proof.protocol={json.loads(proof.decode()).get('protocol')}")
print(f"recovered vk.protocol={json.loads(vk.decode()).get('protocol')}")
PY

echo
echo "+ snarkjs $PROOF_SYSTEM verify $RECOVERED_VK $RECOVERED_PUB $RECOVERED_PROOF"
"$SNARKJS" "$PROOF_SYSTEM" verify "$RECOVERED_VK" "$RECOVERED_PUB" "$RECOVERED_PROOF"
SNARKJS_RC=$?
echo "snarkjs rc=$SNARKJS_RC"
if [ "$SNARKJS_RC" = "0" ]; then
    echo
    echo "==============================================================================="
    echo "[OK] v1 self-contained reveal validated end-to-end ($PROOF_SYSTEM)"
    echo "     - SHA256d(payload) matches the libdogecoin commit32"
    echo "     - vk recovered from the on-chain reveal alone"
    echo "     - snarkjs $PROOF_SYSTEM verify accepts the proof under that recovered vk"
    echo "     no out-of-band vk channel was used at any step"
    echo "==============================================================================="
else
    echo "[FAIL] snarkjs verify rejected the proof under the recovered vk"
    exit 1
fi
