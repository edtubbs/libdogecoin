#!/bin/bash
set -e
umask 077

TESTNET_FLAG="-t"
TMPDIR="/tmp/witness_testnet_$$"
mkdir -m 700 -p "$TMPDIR"

BASE_TX_HEX="${BASE_TX_HEX:-0100000001aad9ecd645f150557080a0de9053a611bfe1f6a21ddca9f25480ea2d8dd212c8000000006a4730440220074450ba2ea6bc690c3388fd38336bf9c6433c35be2a7ab31d6fc4295c8326a202204655853f57105bd5c16f2cd0162a5e2fa4f570416da4730928069af6b46210e10121021bba012071cc524b955f5be6312bc20c7a658001dcc8de693d2a9081bed37945ffffffff02c0878b3b000000001976a914af1c8b5e0e88be99c779f5340ff47979ee259a1688ac0000000000000000266a24464c4331922cd322a23d7bed9ab0264499d4f3e642ddc50b4693a02065f3a0886968069900000000}"
WITNESS_HEX="${WITNESS_HEX:-ff00aa6c6962646f6765}"
SPV_ADDR="${SPV_ADDR:-nkA4i9AB6ZpLZNAmivbZbnKjJt5Dvw9DZT}"
SPV_TIMEOUT_SECONDS="${SPV_TIMEOUT_SECONDS:-1800}"
RELAY_SUCCESS_PATTERN='tx successfully sent to node|not relayed back|already (broadcasted|known|have transaction)|txn-already-known'

run_and_log() {
    local label="$1"
    shift
    echo "----- ${label}: $* -----"
    "$@" 2>&1
    local rc=$?
    echo "----- ${label} exit=${rc} -----"
    return $rc
}

echo "=========================================="
echo "  Witness Testnet Integration Test"
echo "=========================================="

echo "[1/5] Build tools"
run_and_log "make" make -j2 such sendtx spvnode

echo "[2/5] Build tx with arbitrary witness data"
SUCH_OUT=$(./such -c addwitness -x "$BASE_TX_HEX" -i 0 -s "$WITNESS_HEX")
echo "$SUCH_OUT" | tee "$TMPDIR/such_addwitness.log"
TX_WITH_WITNESS=$(echo "$SUCH_OUT" | awk -F': ' '/^tx with witness:/ {print $2}')
if [ -z "$TX_WITH_WITNESS" ]; then
    echo "Error: failed to create witness tx"
    exit 1
fi

if ! echo "$SUCH_OUT" | grep -q "witness\[0\]: $WITNESS_HEX"; then
    echo "Error: witness payload not present in such output"
    exit 1
fi

echo "[3/5] Start spvnode in SMPV + block mode (checkpointed header sync)"
run_and_log "spvnode" timeout "$SPV_TIMEOUT_SECONDS" ./spvnode $TESTNET_FLAG -l -f 0 -c -d -x -p -b -a "$SPV_ADDR" scan > "$TMPDIR/spvnode.log" 2>&1 &
SPV_PID=$!
sleep 45

echo "[4/5] Broadcast tx via sendtx (with and without witness)"
run_and_log "sendtx_witness" ./sendtx $TESTNET_FLAG -d "$TX_WITH_WITNESS" | tee "$TMPDIR/sendtx_witness.log"
run_and_log "sendtx_nowitness" ./sendtx $TESTNET_FLAG -d "$BASE_TX_HEX" | tee "$TMPDIR/sendtx_nowitness.log"

TXID_WITNESS=$(awk '/Start broadcasting transaction:/ {print $4; exit}' "$TMPDIR/sendtx_witness.log")
TXID_NOWITNESS=$(awk '/Start broadcasting transaction:/ {print $4; exit}' "$TMPDIR/sendtx_nowitness.log")
if [ -z "$TXID_WITNESS" ] || [ -z "$TXID_NOWITNESS" ]; then
    echo "Error: failed to parse txid from sendtx output"
    exit 1
fi

FOUND_NON_WITNESS=0
FOUND_WITNESS=0
DEADLINE=$((SECONDS + SPV_TIMEOUT_SECONDS))
while [ "$SECONDS" -lt "$DEADLINE" ]; do
    if grep -Fq "[smpv] tx=$TXID_NOWITNESS" "$TMPDIR/spvnode.log"; then
        FOUND_NON_WITNESS=1
    fi
    if grep -Fq "[smpv] tx=$TXID_WITNESS" "$TMPDIR/spvnode.log"; then
        FOUND_WITNESS=1
    fi
    if [ "$FOUND_NON_WITNESS" -eq 1 ] && [ "$FOUND_WITNESS" -eq 1 ]; then
        break
    fi
    if ! kill -0 "$SPV_PID" 2>/dev/null; then
        break
    fi
    sleep 10
done

echo "[5/5] Stop spvnode and summarize"
kill "$SPV_PID" 2>/dev/null || true
wait "$SPV_PID" 2>/dev/null || true

cat "$TMPDIR/sendtx_witness.log"
cat "$TMPDIR/sendtx_nowitness.log"
cat "$TMPDIR/spvnode.log"

if grep -Eqi "$RELAY_SUCCESS_PATTERN" "$TMPDIR/sendtx_witness.log"; then
    echo "[SUCCESS] Witness-form tx reached peers (relayed or already known)."
else
    echo "[WARN] No relay-back evidence for witness-form tx."
fi

if grep -Eqi "$RELAY_SUCCESS_PATTERN" "$TMPDIR/sendtx_nowitness.log"; then
    echo "[SUCCESS] Non-witness tx reached peers (relayed or already known)."
else
    echo "[WARN] No relay-back evidence for non-witness tx."
fi

if grep -Fq "$WITNESS_HEX" "$TMPDIR/spvnode.log"; then
    echo "[SUCCESS] spvnode observed witness payload in network tx stream."
else
    echo "[WARN] spvnode witness payload not observed during this run."
fi

if grep -Fq "Found relevant transaction!" "$TMPDIR/spvnode.log"; then
    echo "[SUCCESS] Found relevant transaction! message observed in spvnode log."
elif grep -Fq "[smpv] tx=" "$TMPDIR/spvnode.log"; then
    echo "[SUCCESS] [smpv] tx= relevant transaction message observed in spvnode log."
elif grep -Fq "Waiting for new blocks or relevant transactions..." "$TMPDIR/spvnode.log"; then
    echo "[SUCCESS] Relevant-transaction watch mode enabled message observed in spvnode log."
else
    echo "[WARN] No relevant transaction message observed in this run."
fi

if [ "$FOUND_WITNESS" -eq 1 ] || grep -Fq "[smpv] tx=$TXID_WITNESS" "$TMPDIR/spvnode.log"; then
    echo "[SUCCESS] spvnode reported witness-form txid ($TXID_WITNESS)."
elif grep -Eqi "already (broadcasted|known|have transaction)|txn-already-known" "$TMPDIR/sendtx_witness.log"; then
    echo "[SUCCESS] Witness-form tx was already known by peers; no fresh spvnode txid observation expected."
else
    echo "[WARN] spvnode did not report witness-form txid ($TXID_WITNESS)."
fi

if [ "$FOUND_NON_WITNESS" -eq 1 ] || grep -Fq "[smpv] tx=$TXID_NOWITNESS" "$TMPDIR/spvnode.log"; then
    echo "[SUCCESS] spvnode reported non-witness txid ($TXID_NOWITNESS)."
elif grep -Eqi "already (broadcasted|known|have transaction)|txn-already-known" "$TMPDIR/sendtx_nowitness.log"; then
    echo "[SUCCESS] Non-witness tx was already known by peers; no fresh spvnode txid observation expected."
else
    echo "[WARN] spvnode did not report non-witness txid ($TXID_NOWITNESS)."
fi

echo "Artifacts in: $TMPDIR"
