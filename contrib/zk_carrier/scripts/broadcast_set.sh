#!/usr/bin/env bash
#
# broadcast_set.sh — End-to-end multi-pair ZK carrier mainnet driver.
#
# Loops N times.  For each iteration it:
#   1. Picks the next unspent UTXO from $FUNDED_ADDR (or the chained change
#      output from the previous iteration) and queries explorer APIs for
#      its value + scriptPubKey.
#   2. Generates a fresh Groth16 proof via contrib/zk_carrier/witness_helper.py
#      with a per-iteration --amount so each cycle commits a distinct payload.
#   3. Builds an unsigned base tx (1 input → 1 P2PKH change to FUNDED_ADDR),
#      derives sighash, and uses
#         such -c zk_add_commit_and_carrier_tx
#      to append the ZKP1 OP_RETURN + P2SH carrier outputs.
#   4. Signs the funding input with such -c sign and broadcasts TX_C with
#      sendtx.  Waits for the explorer to see TX_C.
#   5. Builds TX_R that spends every carrier output (one P2SH input per
#      carrier part), pastes in the per-part scriptSigs already emitted by
#      step 3, and broadcasts TX_R via sendtx.
#   6. Appends "tx_c.txid<TAB>tx_r.txid<TAB>commit<TAB>height_estimate"
#      to a manifest.  Chains the next iteration off TX_C's change vout.
#
# After the loop, optionally launches one spvnode --zk-vkey scan over the
# whole height range and tees the resulting [zk-commit] PASSED lines (one
# triple per pair) to test-logs/.
#
# This is the multi-pair sibling of scripts/run_full_dogeos_carrier_demo.sh
# and the ZK analogue of contrib/mainnet_dilithium2_test.sh /
# mainnet_raccoong_test.sh — see those for prior PQC mainnet logs.
#
# Prerequisites (same as the PQC scripts; see test-logs/ on the
# copilot/run-end-to-end-tests-dilithium2-raccoon-g branch for prior runs):
#   - libdogecoin built with --enable-zk-carrier --enable-test-passwd
#     [--with-mcl=DIR]; binaries such, sendtx, spvnode in . or PATH.
#   - node + snarkjs installed (same as witness_helper.py needs).
#   - $FUNDED_WIF holds koinu in $FUNDED_ADDR; default WIF/ADDR mirror
#     contrib/mainnet_dilithium2_test.sh so a single funded wallet covers
#     both PQC and ZK runs.
#   - Range-proof circuit artifacts: $WASM and $ZKEY (and optionally
#     $VKEY for in-process spvnode verification).
#
# Usage:
#   N=3 \
#   FUNDED_UTXO_TXID=<initial-txid> FUNDED_UTXO_VOUT=0 \
#   FUNDED_UTXO_VALUE_KOINU=<koinu> \
#   FUNDED_UTXO_SCRIPT_PUBKEY=<spk-hex> \
#   WASM=contrib/zk_carrier/circuits/build/range_proof_js/range_proof.wasm \
#   ZKEY=contrib/zk_carrier/circuits/range_proof.zkey \
#   VKEY=contrib/zk_carrier/circuits/verification_key.json \
#   ./contrib/zk_carrier/scripts/broadcast_set.sh
#
# Honest deferred operations: the script never silently fakes confirmations —
# if an explorer poll times out or sendtx returns a non-relay status, that
# iteration is logged and the loop stops so the operator can recover.

set -euo pipefail
umask 077

RED='\033[0;31m'; GREEN='\033[0;32m'; YEL='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLU}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK  ]${NC} $*"; }
warn()    { echo -e "${YEL}[WARN]${NC} $*"; }
die()     { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }

# ------------------------------- config --------------------------------------
N="${N:-3}"
NETWORK="${NETWORK:-mainnet}"
NETWORK_FLAG=""
[ "$NETWORK" = "testnet" ] && NETWORK_FLAG="-t"

# Defaults match contrib/mainnet_dilithium2_test.sh so the same funded wallet
# can drive both PQC and ZK runs.
FUNDED_WIF="${FUNDED_WIF:-QP1tqHYuPiAW73MHETRaARgeEff9PhHyYyQcWXAGskEFmSppDt2w}"
FUNDED_ADDR="${FUNDED_ADDR:-DDMpdcTrWnZT38tRMebbYzCSAgLSnVMqvr}"

# Initial UTXO to spend.  Subsequent iterations chain off TX_C's change vout 0.
FUNDED_UTXO_TXID="${FUNDED_UTXO_TXID:-${CHAINED_UTXO_TXID:-}}"
FUNDED_UTXO_VOUT="${FUNDED_UTXO_VOUT:-${CHAINED_UTXO_VOUT:-0}}"
FUNDED_UTXO_VALUE_KOINU="${FUNDED_UTXO_VALUE_KOINU:-${CHAINED_UTXO_VALUE_KOINU:-}}"
# Default to FUNDED_ADDR's P2PKH script (76a914 + hash160(DDMpdcTr...) + 88ac)
FUNDED_UTXO_SCRIPT_PUBKEY="${FUNDED_UTXO_SCRIPT_PUBKEY:-${CHAINED_UTXO_SCRIPT_PUBKEY:-76a9145a29227bb518c38cae5a9a195cafc56b22d7272b88ac}}"

CARRIER_VALUE_KOINU="${CARRIER_VALUE_KOINU:-100000000}"   # 1 DOGE per carrier part
TX_FEE_KOINU="${TX_FEE_KOINU:-2000000}"
TX_R_FEE_KOINU="${TX_R_FEE_KOINU:-10000000}"
RANGE_LOW="${RANGE_LOW:-0}"
RANGE_HIGH="${RANGE_HIGH:-1000000}"
CIRCUIT_ID="${CIRCUIT_ID:-1}"

# Circuit artefacts (built by contrib/zk_carrier/circuits/README.md steps).
REPO_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
WASM="${WASM:-$REPO_DIR/contrib/zk_carrier/circuits/build/range_proof_js/range_proof.wasm}"
ZKEY="${ZKEY:-$REPO_DIR/contrib/zk_carrier/circuits/range_proof.zkey}"
VKEY="${VKEY:-$REPO_DIR/contrib/zk_carrier/circuits/verification_key.json}"

SUCH="${SUCH:-$REPO_DIR/such}"
SENDTX="${SENDTX:-$REPO_DIR/sendtx}"
SPVNODE="${SPVNODE:-$REPO_DIR/spvnode}"
WITNESS_HELPER="${WITNESS_HELPER:-$REPO_DIR/contrib/zk_carrier/witness_helper.py}"

EXPLORER_BASE_MAIN="${EXPLORER_BASE_MAIN:-https://api.blockcypher.com/v1/doge/main}"
TX_POLL_TIMEOUT="${TX_POLL_TIMEOUT:-600}"
SENDTX_MAX_RETRIES="${SENDTX_MAX_RETRIES:-3}"
RELAY_SUCCESS_PATTERN='Requested from nodes:[[:space:]]*[1-9]|Seen on other nodes:[[:space:]]*[1-9]|already (broadcasted|known|have transaction)|txn-already-known|txn-already-in-mempool'

# Output dirs.
TS=$(date -u +%Y%m%d_%H%M%S)
WORK="${WORK:-$REPO_DIR/test-logs/zk_set_${TS}}"
mkdir -p "$WORK"
MANIFEST="$WORK/manifest.tsv"
echo -e "iter\ttx_c_txid\ttx_r_txid\tcommit\tpayload_bytes\tutc_iso" > "$MANIFEST"
LOG="$WORK/run.log"
exec > >(tee -a "$LOG") 2>&1

info "ZK carrier broadcast set: N=$N network=$NETWORK addr=$FUNDED_ADDR"
info "Work dir: $WORK"
info "Manifest: $MANIFEST"

# ------------------------------- preflight -----------------------------------
[ -x "$SUCH" ]    || die "such not found at $SUCH (build first)"
[ -x "$SENDTX" ]  || die "sendtx not found at $SENDTX"
[ -f "$WASM" ]    || die "circuit wasm not found at $WASM (run circom first)"
[ -f "$ZKEY" ]    || die "circuit zkey not found at $ZKEY (run snarkjs setup first)"
[ -f "$WITNESS_HELPER" ] || die "witness_helper.py not found at $WITNESS_HELPER"
command -v node    >/dev/null || die "node not found (snarkjs needs it)"
command -v snarkjs >/dev/null || die "snarkjs not found in PATH"
command -v curl    >/dev/null || die "curl not found"
command -v python3 >/dev/null || die "python3 not found"

if [ -z "$FUNDED_UTXO_TXID" ] || [ -z "$FUNDED_UTXO_VALUE_KOINU" ]; then
    die "FUNDED_UTXO_TXID and FUNDED_UTXO_VALUE_KOINU must be set for the initial iteration"
fi

# ------------------------------- helpers -------------------------------------
explorer_sees_tx() {
    local txid="$1"
    curl -fsSL --max-time 15 "$EXPLORER_BASE_MAIN/txs/${txid}" >/dev/null 2>&1
}

wait_for_tx_visible() {
    local txid="$1"; local timeout="$2"; local t0; t0=$(date +%s)
    info "Waiting up to ${timeout}s for explorer to see $txid ..."
    while true; do
        if explorer_sees_tx "$txid"; then
            success "explorer sees $txid"
            return 0
        fi
        local now; now=$(date +%s)
        [ $((now - t0)) -ge "$timeout" ] && return 1
        sleep 15
    done
}

broadcast_with_retry() {
    local label="$1"; local signed="$2"; local n=0; local out=""; local txid=""
    while [ "$n" -lt "$SENDTX_MAX_RETRIES" ]; do
        n=$((n+1))
        info "sendtx $label attempt $n/$SENDTX_MAX_RETRIES"
        out=$("$SENDTX" -d -m 16 -s 30 $NETWORK_FLAG "$signed" 2>&1 || true)
        echo "$out" | sed 's/^/    /'
        txid=$(echo "$out" | sed -n 's/^Start broadcasting transaction:[[:space:]]*\([0-9a-fA-F]\{64\}\).*/\1/p' | head -n1)
        if echo "$out" | grep -Eqi "$RELAY_SUCCESS_PATTERN"; then
            BROADCAST_TXID="$txid"
            return 0
        fi
        sleep 10
    done
    BROADCAST_TXID="$txid"
    return 1
}

# Build base unsigned tx: 1 input (prev_txid:vout) + 1 P2PKH change to FUNDED_ADDR.
# The carrier-output assembly happens via such -c zk_add_commit_and_carrier_tx,
# which appends OP_RETURN + per-part P2SH outputs to whatever scaffold we pass.
build_base_unsigned() {
    local prev_txid="$1" prev_vout="$2" change_koinu="$3" change_spk="$4"
    python3 - "$prev_txid" "$prev_vout" "$change_koinu" "$change_spk" <<'PY'
import sys
prev_txid, prev_vout, change_koinu, change_spk = sys.argv[1].lower(), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4].lower()
def le_u32(n): return n.to_bytes(4, "little").hex()
def le_u64(n): return n.to_bytes(8, "little").hex()
def varint(n):
    if n < 0xfd: return f"{n:02x}"
    if n <= 0xffff: return "fd" + n.to_bytes(2, "little").hex()
    if n <= 0xffffffff: return "fe" + n.to_bytes(4, "little").hex()
    return "ff" + n.to_bytes(8, "little").hex()
prev_le = bytes.fromhex(prev_txid)[::-1].hex()
vin = prev_le + le_u32(prev_vout) + "00" + "ffffffff"
vout = le_u64(change_koinu) + varint(len(change_spk)//2) + change_spk
print("01000000" + varint(1) + vin + varint(1) + vout + "00000000")
PY
}

# Build TX_R skeleton spending every carrier output, then we patch in the
# per-part scriptSigs via such -c set_scriptsig.
build_tx_r_skeleton() {
    local txc_txid="$1" first_vout="$2" parts="$3" carrier_value="$4" fee="$5" out_spk="$6"
    python3 - "$txc_txid" "$first_vout" "$parts" "$carrier_value" "$fee" "$out_spk" <<'PY'
import sys
txid_hex = sys.argv[1].strip().lower()
first_vout = int(sys.argv[2]); part_total = int(sys.argv[3])
carrier_value = int(sys.argv[4]); fee = int(sys.argv[5]); out_spk = sys.argv[6].strip().lower()
def le_u32(n): return n.to_bytes(4, "little").hex()
def le_u64(n): return n.to_bytes(8, "little").hex()
def varint(n):
    if n < 0xfd: return f"{n:02x}"
    if n <= 0xffff: return "fd" + n.to_bytes(2, "little").hex()
    if n <= 0xffffffff: return "fe" + n.to_bytes(4, "little").hex()
    return "ff" + n.to_bytes(8, "little").hex()
total_in = carrier_value * part_total
if total_in <= fee: raise SystemExit("carrier total value must exceed tx_r fee")
send_value = total_in - fee
prev_le = bytes.fromhex(txid_hex)[::-1].hex()
vin = "".join(prev_le + le_u32(first_vout + i) + "00" + "ffffffff" for i in range(part_total))
vout = le_u64(send_value) + varint(len(out_spk)//2) + out_spk
print("01000000" + varint(part_total) + vin + "01" + vout + "00000000")
PY
}

# ------------------------------- main loop -----------------------------------
PREV_TXID="$FUNDED_UTXO_TXID"
PREV_VOUT="$FUNDED_UTXO_VOUT"
PREV_VAL="$FUNDED_UTXO_VALUE_KOINU"
PREV_SPK="$FUNDED_UTXO_SCRIPT_PUBKEY"

for ((iter=1; iter<=N; iter++)); do
    info "================================================================="
    info "Iteration $iter/$N — funding from ${PREV_TXID}:${PREV_VOUT} value=$PREV_VAL koinu"

    ITER_DIR="$WORK/iter_${iter}"
    mkdir -p "$ITER_DIR"

    # 1. Generate a fresh proof.  Vary --amount per iteration so each commit differs.
    AMT=$(( 42000 + iter * 1000 ))
    PAYLOAD_HEX_FILE="$ITER_DIR/payload.hex"
    info "snarkjs prove low=$RANGE_LOW high=$RANGE_HIGH amount=$AMT"
    python3 "$WITNESS_HELPER" \
        --wasm "$WASM" --zkey "$ZKEY" --vkey "$VKEY" \
        --circuit-id "$CIRCUIT_ID" \
        --low "$RANGE_LOW" --high "$RANGE_HIGH" --amount "$AMT" \
        --out-payload "$PAYLOAD_HEX_FILE"
    PAYLOAD_HEX=$(tr -d '[:space:]' < "$PAYLOAD_HEX_FILE")
    PAYLOAD_BYTES=$(( ${#PAYLOAD_HEX} / 2 ))
    info "payload: $PAYLOAD_BYTES bytes"

    # 2. Compute commit + sanity-check off-box.
    COMMIT=$("$SUCH" $NETWORK_FLAG -c zk_commit -x "$PAYLOAD_HEX" 2>&1 \
             | awk -F': ' '/^zk_commit_hex:/ {print $2; exit}' | tr -d ' ')
    [ -n "$COMMIT" ] || die "iter $iter: failed to derive commitment"
    info "commit: $COMMIT"

    # 3. Compute carrier part_total from payload size (matches PQC chunk size).
    PARTS=$(( (PAYLOAD_BYTES + 65279) / 65280 ))
    [ "$PARTS" -ge 1 ] || PARTS=1
    CHANGE_KOINU=$(( PREV_VAL - TX_FEE_KOINU - PARTS * CARRIER_VALUE_KOINU ))
    [ "$CHANGE_KOINU" -gt 0 ] || die "iter $iter: insufficient UTXO value (utxo=$PREV_VAL parts=$PARTS)"
    info "change=$CHANGE_KOINU koinu  parts=$PARTS"

    # 4. Build base unsigned tx scaffold.
    BASE_UNSIGNED=$(build_base_unsigned "$PREV_TXID" "$PREV_VOUT" "$CHANGE_KOINU" "$PREV_SPK")
    [ -n "$BASE_UNSIGNED" ] || die "iter $iter: base unsigned tx empty"

    # 5. Append commitment + carrier outputs.
    SUCH_OUT=$("$SUCH" $NETWORK_FLAG -c zk_add_commit_and_carrier_tx \
        -x "$BASE_UNSIGNED" -m 0 -s "$PAYLOAD_HEX" -h "$CARRIER_VALUE_KOINU" 2>&1)
    echo "$SUCH_OUT" | sed 's/^/    /'
    TX_C_UNSIGNED=$(echo "$SUCH_OUT" | awk -F': ' '/^tx with commitment/ {print $2; exit}' | tr -d ' ')
    PART_TOTAL=$(echo "$SUCH_OUT" | awk -F': ' '/^zk_carrier_part_total:/ {print $2; exit}' | tr -d ' ')
    FIRST_VOUT=$(echo "$SUCH_OUT"  | awk -F': ' '/^zk_carrier_first_vout:/ {print $2; exit}' | tr -d ' ')
    [ -n "$TX_C_UNSIGNED" ] || die "iter $iter: such zk_add_commit_and_carrier_tx failed"
    [ "$PART_TOTAL" -eq "$PARTS" ] || warn "part_total mismatch: such=$PART_TOTAL local=$PARTS"
    PART_SCRIPTSIGS=()
    for ((p=0; p<PART_TOTAL; p++)); do
        ss=$(echo "$SUCH_OUT" | sed -n "s/^zk_carrier_part_scriptsig\\[$p\\]:[[:space:]]*//p" | head -n1 | tr -d ' ')
        [ -n "$ss" ] || die "iter $iter: missing carrier_part_scriptsig[$p]"
        PART_SCRIPTSIGS+=("$ss")
    done

    # 6. Sign the funding input and broadcast TX_C.
    SIGN_OUT=$("$SUCH" $NETWORK_FLAG -c sign -x "$TX_C_UNSIGNED" -s "$PREV_SPK" -i 0 -h 1 -p "$FUNDED_WIF" 2>&1)
    echo "$SIGN_OUT" | sed 's/^/    /'
    TX_C_SIGNED=$(echo "$SIGN_OUT" | awk -F': ' '/^signed TX:/ {print $2; exit}' | tr -d ' ')
    [ -n "$TX_C_SIGNED" ] || die "iter $iter: such sign failed"
    BROADCAST_TXID=""
    if ! broadcast_with_retry "TX_C-$iter" "$TX_C_SIGNED"; then
        die "iter $iter: TX_C did not relay"
    fi
    TX_C_TXID="$BROADCAST_TXID"
    [ -n "$TX_C_TXID" ] || die "iter $iter: TX_C txid missing"
    success "iter $iter: TX_C broadcast $TX_C_TXID"
    echo "$TX_C_SIGNED" > "$ITER_DIR/tx_c.signed.hex"
    echo "$TX_C_TXID"   > "$ITER_DIR/tx_c.txid"

    # 7. Wait for explorer visibility before TX_R.
    wait_for_tx_visible "$TX_C_TXID" "$TX_POLL_TIMEOUT" \
        || warn "iter $iter: TX_C not seen by explorer in ${TX_POLL_TIMEOUT}s (continuing)"

    # 8. Build TX_R skeleton, patch per-part scriptSigs, broadcast.
    TX_R_UNSIGNED=$(build_tx_r_skeleton "$TX_C_TXID" "$FIRST_VOUT" "$PART_TOTAL" \
                                        "$CARRIER_VALUE_KOINU" "$TX_R_FEE_KOINU" "$PREV_SPK")
    TX_R_PATCHED="$TX_R_UNSIGNED"
    for ((p=0; p<PART_TOTAL; p++)); do
        SET_OUT=$("$SUCH" $NETWORK_FLAG -c set_scriptsig \
                  -x "$TX_R_PATCHED" -i "$p" -s "${PART_SCRIPTSIGS[$p]}" 2>&1)
        TX_R_PATCHED=$(echo "$SET_OUT" | awk -F': ' '/^tx with scriptsig set:/ {print $2; exit}' | tr -d ' ')
        [ -n "$TX_R_PATCHED" ] || die "iter $iter: set_scriptsig failed for part $p"
    done
    BROADCAST_TXID=""
    if ! broadcast_with_retry "TX_R-$iter" "$TX_R_PATCHED"; then
        warn "iter $iter: TX_R did not relay (P2SH carrier may be non-standard); continuing"
        TX_R_TXID=""
    else
        TX_R_TXID="$BROADCAST_TXID"
        success "iter $iter: TX_R broadcast $TX_R_TXID"
        wait_for_tx_visible "$TX_R_TXID" "$TX_POLL_TIMEOUT" \
            || warn "iter $iter: TX_R not seen by explorer in ${TX_POLL_TIMEOUT}s"
    fi
    echo "$TX_R_PATCHED" > "$ITER_DIR/tx_r.signed.hex"
    echo "$TX_R_TXID"    > "$ITER_DIR/tx_r.txid"

    # 9. Append manifest entry.
    printf '%d\t%s\t%s\t%s\t%d\t%s\n' \
        "$iter" "$TX_C_TXID" "$TX_R_TXID" "$COMMIT" "$PAYLOAD_BYTES" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        >> "$MANIFEST"

    # 10. Chain to next iteration: TX_C change vout 0 carries the bulk funds.
    PREV_TXID="$TX_C_TXID"
    PREV_VOUT=0
    PREV_VAL="$CHANGE_KOINU"
    # PREV_SPK stays the same — change is back to FUNDED_ADDR.
done

success "Loop complete.  Manifest:"
cat "$MANIFEST" | sed 's/^/    /'

# ------------------------------- spvnode pass --------------------------------
if [ -n "${SKIP_SPV:-}" ]; then
    info "SKIP_SPV set; skipping spvnode rescan."
    exit 0
fi
[ -x "$SPVNODE" ] || { warn "spvnode not built; skipping rescan."; exit 0; }
[ -f "$VKEY" ]    || { warn "VKEY $VKEY missing; skipping rescan."; exit 0; }

SPV_LOG="$WORK/spvnode_zk_set.log"
info "Launching spvnode --zk-vkey $VKEY for full-set verification → $SPV_LOG"
"$SPVNODE" $NETWORK_FLAG -l -c -d -p -b -a "$FUNDED_ADDR" \
    --zk-vkey "$VKEY" scan > "$SPV_LOG" 2>&1 &
SPV_PID=$!
echo "$SPV_PID" > "$WORK/spvnode.pid"

# Wait until we have collected one PASSED line per pair, or the timeout fires.
SPV_DEADLINE=$(( $(date +%s) + ${SPV_TIMEOUT:-3600} ))
while true; do
    PASSED_LINES=$(grep -c "ZK verification PASSED" "$SPV_LOG" 2>/dev/null || echo 0)
    if [ "$PASSED_LINES" -ge "$N" ]; then
        success "spvnode emitted $PASSED_LINES PASSED lines (>= N=$N)"
        break
    fi
    if [ "$(date +%s)" -ge "$SPV_DEADLINE" ]; then
        warn "spvnode rescan timeout: $PASSED_LINES/$N PASSED lines collected"
        break
    fi
    sleep 30
done
kill "$SPV_PID" 2>/dev/null || true
sleep 2
kill -9 "$SPV_PID" 2>/dev/null || true

# Save the curated multi-PASSED log.
FINAL_LOG="$REPO_DIR/test-logs/mainnet_zk_carrier_e2e_set_PASSED_${TS}.txt"
{
    echo "==============================================================================="
    echo "ZK carrier mainnet e2e — multi-pair set (N=$N) — $(date -u)"
    echo "Funded address: $FUNDED_ADDR"
    echo "Manifest:"
    cat "$MANIFEST"
    echo
    echo "==============================================================================="
    echo "spvnode [zk-commit] / [zk-vkey] lines:"
    echo "==============================================================================="
    grep -E "zk-vkey|zk-commit" "$SPV_LOG" || echo "(none captured)"
} > "$FINAL_LOG"
success "Final multi-PASSED log: $FINAL_LOG"
info "Commit it with: git add -f \"$FINAL_LOG\" && git commit -m 'zk_carrier: mainnet e2e set log $TS'"
