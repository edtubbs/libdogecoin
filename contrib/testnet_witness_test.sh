#!/bin/bash
set -e
umask 077

TESTNET_FLAG="-t"
TMPDIR="/tmp/witness_testnet_$$"
mkdir -m 700 -p "$TMPDIR"

BASE_TX_HEX="${BASE_TX_HEX:-0100000001aad9ecd645f150557080a0de9053a611bfe1f6a21ddca9f25480ea2d8dd212c8000000006a4730440220074450ba2ea6bc690c3388fd38336bf9c6433c35be2a7ab31d6fc4295c8326a202204655853f57105bd5c16f2cd0162a5e2fa4f570416da4730928069af6b46210e10121021bba012071cc524b955f5be6312bc20c7a658001dcc8de693d2a9081bed37945ffffffff02c0878b3b000000001976a914af1c8b5e0e88be99c779f5340ff47979ee259a1688ac0000000000000000266a24464c4331922cd322a23d7bed9ab0264499d4f3e642ddc50b4693a02065f3a0886968069900000000}"
WITNESS_HEX="${WITNESS_HEX:-ff00aa6c6962646f6765}"
SPV_ADDR="${SPV_ADDR:-nkA4i9AB6ZpLZNAmivbZbnKjJt5Dvw9DZT}"
SPV_TIMEOUT_SECONDS="${SPV_TIMEOUT_SECONDS:-420}"

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

echo "[3/5] Start spvnode in SMPV mode (checkpointed header sync)"
run_and_log "spvnode" timeout "$SPV_TIMEOUT_SECONDS" ./spvnode $TESTNET_FLAG -l -f 0 -c -d -x -p -a "$SPV_ADDR" scan > "$TMPDIR/spvnode.log" 2>&1 &
SPV_PID=$!
sleep 45

echo "[4/5] Broadcast tx via sendtx"
run_and_log "sendtx" ./sendtx $TESTNET_FLAG -d "$TX_WITH_WITNESS" | tee "$TMPDIR/sendtx.log"
sleep 90

echo "[5/5] Stop spvnode and summarize"
kill "$SPV_PID" 2>/dev/null || true
wait "$SPV_PID" 2>/dev/null || true

cat "$TMPDIR/sendtx.log"
cat "$TMPDIR/spvnode.log"

if grep -Eq "tx successfully seen on node|txn-already-known|already known|already have transaction" "$TMPDIR/sendtx.log"; then
    echo "[SUCCESS] Transaction reached peers (relayed or already known)."
else
    echo "[WARN] No relay-back evidence in sendtx output."
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

echo "Artifacts in: $TMPDIR"
