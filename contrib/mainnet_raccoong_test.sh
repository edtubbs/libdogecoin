#!/bin/bash
#
# Raccoon-G-44 Mainnet Integration Test Script
#
# Prerequisites:
#   - libdogecoin built with --enable-liboqs
#   - such, sendtx, and spvnode binaries in PATH or current directory
#

set -e
umask 077

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

NETWORK="${NETWORK:-mainnet}"
NETWORK_FLAG="-t"
if [ "$NETWORK" = "mainnet" ]; then
    NETWORK_FLAG=""
elif [ "$NETWORK" != "testnet" ]; then
    echo "Unsupported NETWORK value: $NETWORK (expected testnet|mainnet)" >&2
    exit 1
fi
TMPDIR=$(mktemp -d /tmp/raccoong_testnet_XXXXXX)
chmod 700 "$TMPDIR"
BROADCASTED=0
BROADCAST_TXID=""
SPV_TIMEOUT_SECONDS="${SPV_TIMEOUT_SECONDS:-1800}"
SPV_REQUIRE_VALIDATION="${SPV_REQUIRE_VALIDATION:-1}"
SPV_HEADERS_FILE="${SPV_HEADERS_FILE:-$TMPDIR/spv_headers.db}"
SPV_WALLET_FILE="${SPV_WALLET_FILE:-$TMPDIR/spv_wallet.db}"
REST_HOST="${REST_HOST:-127.0.0.1}"
REST_PORT="${REST_PORT:-$((20080 + ($$ % 1000)))}"
REST_SERVER="${REST_SERVER:-${REST_HOST}:${REST_PORT}}"
NON_INTERACTIVE="${NON_INTERACTIVE:-1}"
AUTO_BROADCAST="${AUTO_BROADCAST:-1}"
FUNDED_WIF="${FUNDED_WIF:-QP1tqHYuPiAW73MHETRaARgeEff9PhHyYyQcWXAGskEFmSppDt2w}"
FUNDED_ADDR="${FUNDED_ADDR:-DDMpdcTrWnZT38tRMebbYzCSAgLSnVMqvr}"
FUNDED_UTXO_TXID="${FUNDED_UTXO_TXID:-63d79b47b6d55b5143afb5f7782f9300da5d6a4837b5c9837a1769e3e0c44621}"
FUNDED_UTXO_VOUT="${FUNDED_UTXO_VOUT:-0}"
AUTO_PREPARE_TX_FROM_UTXO="${AUTO_PREPARE_TX_FROM_UTXO:-1}"
TX_FEE_KOINU="${TX_FEE_KOINU:-100000}"
FUNDED_UTXO_VALUE_KOINU="${FUNDED_UTXO_VALUE_KOINU:-4194000000}"
FUNDED_UTXO_SCRIPT_PUBKEY="${FUNDED_UTXO_SCRIPT_PUBKEY:-76a9145a29227bb518c38cae5a9a195cafc56b22d7272b88ac}"
RUN_LOG="$TMPDIR/mainnet_raccoong_run.log"
RELAY_SUCCESS_PATTERN='tx successfully sent to node|already (broadcasted|known|have transaction)|txn-already-known'

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
run_and_log() {
    local label="$1"
    shift
    echo "----- ${label}: $* -----" | tee -a "$RUN_LOG"
    "$@" 2>&1 | tee -a "$RUN_LOG"
    local rc=${PIPESTATUS[0]}
    echo "----- ${label} exit=${rc} -----" | tee -a "$RUN_LOG"
    return $rc
}

wait_for_rest_tx() {
    local txid="$1"
    local timeout="$2"
    local start_ts now_ts
    local txid_le
    local rest_utxos rest_txs
    start_ts=$(date +%s)
    txid_le=$(echo "$txid" | sed 's/../& /g' | awk '{for(i=NF;i>=1;i--) printf $i}' | tr -d '\n')
    while true; do
        rest_utxos=$(curl -fsS "http://${REST_SERVER}/getUTXOs" 2>/dev/null || true)
        rest_txs=$(curl -fsS "http://${REST_SERVER}/getTransactions" 2>/dev/null || true)
        if echo "$rest_utxos$rest_txs" | grep -Eqi "${txid}|${txid_le}"; then
            date +%s
            return 0
        fi
        now_ts=$(date +%s)
        if [ $((now_ts - start_ts)) -ge "$timeout" ]; then
            return 1
        fi
        sleep 1
    done
}

check_tools() {
    info "Checking required tools..."
    for tool in such sendtx spvnode; do
        if [ ! -f "./$tool" ] && ! command -v $tool &> /dev/null; then
            error "$tool not found. Please build libdogecoin first."
        fi
    done
    if ! command -v curl &> /dev/null; then
        error "curl not found. Required for REST tx monitoring."
    fi
    if ! ./such -c help 2>&1 | grep -q raccoong_keygen; then
        error "libdogecoin not built with Raccoon-G support. Rebuild with --enable-liboqs"
    fi
    if [ "$SPV_REQUIRE_VALIDATION" -ne 1 ]; then
        error "SPV_REQUIRE_VALIDATION must be 1 for full-run mode"
    fi
    success "All tools available"
}

load_mainnet_wallet() {
    info "Using provided funded mainnet wallet..."
    PRIVKEY_WIF="$FUNDED_WIF"
    run_and_log "such generate_public_key" ./such -c generate_public_key -p "$PRIVKEY_WIF" $NETWORK_FLAG | tee "$TMPDIR/mainnet_addr.txt"
    TESTNET_ADDR=$(grep "p2pkh address:" "$TMPDIR/mainnet_addr.txt" | cut -d: -f2 | tr -d ' ')
    if [ "$TESTNET_ADDR" != "$FUNDED_ADDR" ]; then
        error "Provided WIF does not map to expected funded address"
    fi
    success "Mainnet funded wallet loaded: $TESTNET_ADDR"
}

prepare_tx_from_funded_utxo() {
    info "Constructing unsigned tx from configured funded UTXO..."
    local selected_txid selected_vout selected_value selected_script send_value
    selected_txid="$FUNDED_UTXO_TXID"
    selected_vout="$FUNDED_UTXO_VOUT"
    selected_value="$FUNDED_UTXO_VALUE_KOINU"
    selected_script="$FUNDED_UTXO_SCRIPT_PUBKEY"

    [ -n "$selected_txid" ] || error "FUNDED_UTXO_TXID is required"
    [ -n "$selected_vout" ] || error "FUNDED_UTXO_VOUT is required"
    [ -n "$selected_value" ] || error "FUNDED_UTXO_VALUE_KOINU is required"
    [ -n "$selected_script" ] || error "FUNDED_UTXO_SCRIPT_PUBKEY is required"
    if [ "$selected_value" -le "$TX_FEE_KOINU" ]; then
        error "FUNDED_UTXO_VALUE_KOINU must be greater than TX_FEE_KOINU"
    fi
    send_value=$((selected_value - TX_FEE_KOINU))

    RAW_UNSIGNED_TX=$(python3 - "$selected_txid" "$selected_vout" "$send_value" "$selected_script" <<'PY'
import sys
txid_hex = sys.argv[1].strip().lower()
vout = int(sys.argv[2])
value = int(sys.argv[3])
script_hex = sys.argv[4].strip().lower()

if len(txid_hex) != 64:
    raise SystemExit("invalid txid length")
if len(script_hex) % 2 != 0:
    raise SystemExit("invalid script hex length")

def le_u32(n): return n.to_bytes(4, "little", signed=False).hex()
def le_u64(n): return n.to_bytes(8, "little", signed=False).hex()
def varint(n):
    if n < 0xfd: return f"{n:02x}"
    if n <= 0xffff: return "fd" + n.to_bytes(2, "little").hex()
    if n <= 0xffffffff: return "fe" + n.to_bytes(4, "little").hex()
    return "ff" + n.to_bytes(8, "little").hex()

raw = (
    "01000000"
    + "01"
    + bytes.fromhex(txid_hex)[::-1].hex()
    + le_u32(vout)
    + "00"
    + "ffffffff"
    + "01"
    + le_u64(value)
    + varint(len(script_hex) // 2)
    + script_hex
    + "00000000"
)
print(raw)
PY
)
    SCRIPT_PUBKEY="$selected_script"
    success "Prepared RAW_UNSIGNED_TX from ${selected_txid}:${selected_vout} (same-address cascade output)"
}

generate_raccoong_keypair() {
    info "Generating Raccoon-G-44 keypair..."
    run_and_log "such raccoong_keygen" ./such -c raccoong_keygen | tee "$TMPDIR/raccoong_keys.txt"
    RACCOONG_PK=$(grep "^public key:" "$TMPDIR/raccoong_keys.txt" | cut -d: -f2 | tr -d ' ')
    RACCOONG_SK=$(grep "^secret key:" "$TMPDIR/raccoong_keys.txt" | cut -d: -f2 | tr -d ' ')
    [ -n "$RACCOONG_PK" ] || error "Failed to generate Raccoon-G keypair"
    [ -n "$RACCOONG_SK" ] || error "Failed to generate Raccoon-G keypair"
    if [ "$RACCOONG_PK" = "$RACCOONG_SK" ]; then
        error "Raccoon-G public and secret keys are identical; expected different key material"
    fi
    success "Raccoon-G-44 keypair generated"
}

derive_hd_child() {
    info "Deriving Raccoon-G child keys (non-hardened + hardened)..."
    CHAINCODE=$(printf '42%.0s' {1..32})
    run_and_log "such raccoong_hd_derive non-hardened" \
        ./such -c raccoong_hd_derive -p "$RACCOONG_SK" -s "$CHAINCODE" -i 7 -g 0 | tee "$TMPDIR/raccoong_hd_nonhardened.txt"
    run_and_log "such raccoong_hd_derive hardened" \
        ./such -c raccoong_hd_derive -p "$RACCOONG_SK" -s "$CHAINCODE" -i 7 -g 1 | tee "$TMPDIR/raccoong_hd_hardened.txt"
    run_and_log "such raccoong_hd_derive_pub" \
        ./such -c raccoong_hd_derive_pub -k "$RACCOONG_PK" -s "$CHAINCODE" -i 7 | tee "$TMPDIR/raccoong_hd_pub.txt"
}

build_transaction() {
    info "Build unsigned mainnet tx with such, then paste hex below:"
    if { [ -z "$RAW_UNSIGNED_TX" ] || [ -z "$SCRIPT_PUBKEY" ]; } && [ "$AUTO_PREPARE_TX_FROM_UTXO" -eq 1 ]; then
        prepare_tx_from_funded_utxo
    fi
    if [ -z "$RAW_UNSIGNED_TX" ] && [ "$NON_INTERACTIVE" -eq 1 ]; then
        error "RAW_UNSIGNED_TX must be set in NON_INTERACTIVE mode"
    fi
    if [ -z "$RAW_UNSIGNED_TX" ]; then
        read -p "Enter unsigned raw tx hex: " RAW_UNSIGNED_TX
    else
        info "Using RAW_UNSIGNED_TX from environment"
    fi
    if [ -z "$SCRIPT_PUBKEY" ] && [ "$NON_INTERACTIVE" -eq 1 ]; then
        error "SCRIPT_PUBKEY must be set in NON_INTERACTIVE mode"
    fi
    if [ -z "$SCRIPT_PUBKEY" ]; then
        read -p "Enter scriptPubKey hex for input 0: " SCRIPT_PUBKEY
    else
        info "Using SCRIPT_PUBKEY from environment"
    fi

    # Reject placeholder prevout (32-byte txid + 4-byte vout = 36 bytes = 72 hex chars).
    if echo "$RAW_UNSIGNED_TX" | grep -Eq '^0100000001(00){36}'; then
        error "Input transaction uses a zero prevout placeholder. Provide a real funded UTXO transaction."
    fi
    if echo "$SCRIPT_PUBKEY" | grep -Eq '^76a914(0){40}88ac$'; then
        error "scriptPubKey is a zero placeholder. Provide the real UTXO scriptPubKey."
    fi

    SIGHASH_OUTPUT=$(run_and_log "such tx_sighash32" ./such -c tx_sighash32 -x "$RAW_UNSIGNED_TX" -s "$SCRIPT_PUBKEY" -i 0 -h 1)
    echo "$SIGHASH_OUTPUT"
    TX_SIGHASH_HEX=$(echo "$SIGHASH_OUTPUT" | grep "^tx_sighash32:" | cut -d: -f2 | tr -d ' ')
    [ -n "$TX_SIGHASH_HEX" ] || error "Failed to derive tx_sighash32"

    run_and_log "such raccoong_sign" ./such -c raccoong_sign -p "$RACCOONG_SK" -x "$TX_SIGHASH_HEX" | tee "$TMPDIR/raccoong_sig.txt"
    RACCOONG_SIG=$(grep "^signature:" "$TMPDIR/raccoong_sig.txt" | cut -d: -f2 | tr -d ' ')
    [ -n "$RACCOONG_SIG" ] || error "Failed to sign tx_sighash32"

    run_and_log "such raccoong_commit" ./such -c raccoong_commit -k "$RACCOONG_PK" -s "$RACCOONG_SIG" | tee "$TMPDIR/raccoong_commit.txt"
    RACCOONG_COMMIT=$(grep "^commitment:" "$TMPDIR/raccoong_commit.txt" | cut -d: -f2 | tr -d ' ')
    [ "${#RACCOONG_COMMIT}" -eq 64 ] || error "Invalid commitment length"

    ADD_COMMIT_OUTPUT=$(run_and_log "such raccoong_add_commit_tx" ./such -c raccoong_add_commit_tx -x "$RAW_UNSIGNED_TX" -s "$RACCOONG_COMMIT")
    echo "$ADD_COMMIT_OUTPUT"
    TX_WITH_COMMIT=$(echo "$ADD_COMMIT_OUTPUT" | grep "^tx with commitment:" | cut -d: -f2- | tr -d ' ')
    [ -n "$TX_WITH_COMMIT" ] || error "Failed to append Raccoon-G commitment"

    info "Embedding Raccoon-G public key/signature in scriptSig for input 0..."
    ADD_SCRIPTSIG_PQC_OUTPUT=$(run_and_log "such addscriptsigpqc" ./such -c addscriptsigpqc -x "$TX_WITH_COMMIT" -i 0 -k "$RACCOONG_PK" -s "$RACCOONG_SIG")
    echo "$ADD_SCRIPTSIG_PQC_OUTPUT"
    TX_FOR_SIGNING=$(echo "$ADD_SCRIPTSIG_PQC_OUTPUT" | grep "^tx with scriptsig pqc:" | cut -d: -f2- | tr -d ' ')
    [ -n "$TX_FOR_SIGNING" ] || error "Failed to append Raccoon-G public key/signature to scriptSig"
    info "Verifying scriptSig carries Raccoon-G public key/signature before signing..."
    PRE_SIGN_SCRIPTSIG_OUTPUT=$(./such -c printscriptsigpqc -x "$TX_FOR_SIGNING")
    echo "$PRE_SIGN_SCRIPTSIG_OUTPUT" > "$TMPDIR/raccoong_scriptsig_pqc_presign.txt"
    PRE_SIGN_RACCOONG_ITEM_A=$(echo "$PRE_SIGN_SCRIPTSIG_OUTPUT" | awk '/scriptsig_pqc_pubkey:/ {print $2; exit}')
    PRE_SIGN_RACCOONG_ITEM_B=$(echo "$PRE_SIGN_SCRIPTSIG_OUTPUT" | awk '/scriptsig_pqc_signature:/ {print $2; exit}')
    [ -n "$PRE_SIGN_RACCOONG_ITEM_A" ] || error "scriptSig pre-sign check missing first Raccoon-G item"
    [ -n "$PRE_SIGN_RACCOONG_ITEM_B" ] || error "scriptSig pre-sign check missing second Raccoon-G item"
    PRE_SIGN_RACCOONG_PK=""
    PRE_SIGN_RACCOONG_SIG=""
    for candidate_pk in "$PRE_SIGN_RACCOONG_ITEM_A" "$PRE_SIGN_RACCOONG_ITEM_B"; do
        for candidate_sig in "$PRE_SIGN_RACCOONG_ITEM_A" "$PRE_SIGN_RACCOONG_ITEM_B"; do
            if [ "$candidate_pk" = "$candidate_sig" ]; then
                continue
            fi
            if ./such -c raccoong_verify -k "$candidate_pk" -x "$TX_SIGHASH_HEX" -s "$candidate_sig" 2>/dev/null | grep -Eq "valid:[[:space:]]*true|VERIFIED: Signature is valid|VALID"; then
                PRE_SIGN_RACCOONG_PK="$candidate_pk"
                PRE_SIGN_RACCOONG_SIG="$candidate_sig"
                break 2
            fi
        done
    done
    [ -n "$PRE_SIGN_RACCOONG_PK" ] || error "scriptSig pre-sign payload could not be validated as Raccoon-G pk/signature pair"
    [ -n "$PRE_SIGN_RACCOONG_SIG" ] || error "scriptSig pre-sign payload could not be validated as Raccoon-G pk/signature pair"
    [ "$PRE_SIGN_RACCOONG_PK" = "$RACCOONG_PK" ] || error "scriptSig pre-sign public key mismatch"
    [ "$PRE_SIGN_RACCOONG_SIG" = "$RACCOONG_SIG" ] || error "scriptSig pre-sign signature mismatch"
    success "scriptSig pre-sign payload check passed"

    SIGN_OUTPUT=$(run_and_log "such sign" ./such -c sign -x "$TX_FOR_SIGNING" -s "$SCRIPT_PUBKEY" -i 0 -h 1 -p "$PRIVKEY_WIF" $NETWORK_FLAG)
    echo "$SIGN_OUTPUT"
    SIGNED_TX=$(echo "$SIGN_OUTPUT" | grep "^signed TX:" | cut -d: -f2- | tr -d ' ')
    [ -n "$SIGNED_TX" ] || error "Failed to sign transaction"

    cat > "$TMPDIR/tx_info.txt" <<EOF
RAW_UNSIGNED_TX=$RAW_UNSIGNED_TX
TX_WITH_COMMIT=$TX_WITH_COMMIT
TX_WITH_SCRIPTSIG_PQC=$TX_FOR_SIGNING
SCRIPT_PUBKEY=$SCRIPT_PUBKEY
TX_SIGHASH_HEX=$TX_SIGHASH_HEX
RACCOONG_SIG=$RACCOONG_SIG
RACCOONG_COMMIT=$RACCOONG_COMMIT
SCRIPTSIG_PQC_PUBKEY=$RACCOONG_PK
SIGNED_TX=$SIGNED_TX
OPRETURN_SCRIPT=6a2452434734${RACCOONG_COMMIT}
EOF

    DO_BROADCAST="n"
    if [ "$AUTO_BROADCAST" -eq 1 ]; then
        DO_BROADCAST="y"
    elif [ "$NON_INTERACTIVE" -eq 0 ]; then
        read -p "Broadcast now with sendtx? [y/N]: " DO_BROADCAST
    fi
    if [[ "$DO_BROADCAST" =~ ^[Yy]$ ]]; then
        SENDTX_OUTPUT=$(run_and_log "sendtx" ./sendtx $NETWORK_FLAG "$SIGNED_TX" || true)
        echo "$SENDTX_OUTPUT" | sed 's/Error:/sendtx-note:/g'
        BROADCAST_TXID=$(echo "$SENDTX_OUTPUT" | sed -n 's/^Start broadcasting transaction:[[:space:]]*\([0-9a-fA-F]\{64\}\).*/\1/p' | head -n1)
        [ -n "$BROADCAST_TXID" ] || error "Failed to parse broadcast txid from sendtx output"
        CHAINED_UTXO_TXID="$BROADCAST_TXID"
        CHAINED_UTXO_VOUT=0
        CHAINED_UTXO_VALUE_KOINU=$((FUNDED_UTXO_VALUE_KOINU - TX_FEE_KOINU))
        CHAINED_UTXO_SCRIPT_PUBKEY="$SCRIPT_PUBKEY"
        {
            echo "CHAINED_UTXO"
            echo "chained_utxo_txid=$CHAINED_UTXO_TXID"
            echo "chained_utxo_vout=$CHAINED_UTXO_VOUT"
            echo "chained_utxo_value_koinu=$CHAINED_UTXO_VALUE_KOINU"
            echo "chained_utxo_script_pubkey=$CHAINED_UTXO_SCRIPT_PUBKEY"
        } | tee -a "$TMPDIR/spvnode.log"
        cat >> "$TMPDIR/tx_info.txt" <<EOF
CHAINED_UTXO_TXID=$CHAINED_UTXO_TXID
CHAINED_UTXO_VOUT=$CHAINED_UTXO_VOUT
CHAINED_UTXO_VALUE_KOINU=$CHAINED_UTXO_VALUE_KOINU
CHAINED_UTXO_SCRIPT_PUBKEY=$CHAINED_UTXO_SCRIPT_PUBKEY
EOF
        if echo "$SENDTX_OUTPUT" | grep -Eqi "$RELAY_SUCCESS_PATTERN"; then
            success "Broadcast accepted or already known by peers"
            BROADCASTED=1
        else
            error "sendtx did not report a known relay/acceptance status"
        fi
    else
        error "Broadcast is required for full-run mode"
    fi
}

monitor_spvnode() {
    info "Step 7: Monitor with spvnode"
    echo "Expected log:"
    echo "  [raccoong-commit] Valid at height=X txpos=Y commit=$RACCOONG_COMMIT"
    if [ "$BROADCASTED" -eq 1 ]; then
        local scan_start_ts
        local found_ts
        local elapsed_seconds
        local spv_pipe_pid
        local spv_exit_code
        local commit_match_line=""
        local expected_commit_source="source=scriptsig"
        local expected_commit_mode="scriptsig"
        rm -f "$SPV_WALLET_FILE"
        info "Running spvnode scan with REST monitoring until txid and ${expected_commit_mode} commitment validation are both confirmed..."
        scan_start_ts=$(date +%s)
        : > "$TMPDIR/spvnode.log"
        stdbuf -oL -eL ./spvnode $NETWORK_FLAG -l -h "$SPV_HEADERS_FILE" -w "$SPV_WALLET_FILE" -u "$REST_SERVER" -c -d -x -p -b -a "$TESTNET_ADDR" scan | tee "$TMPDIR/spvnode.log" | tee -a "$RUN_LOG" &
        spv_pipe_pid=$!
        if ! found_ts=$(wait_for_rest_tx "$BROADCAST_TXID" "$SPV_TIMEOUT_SECONDS"); then
            echo "----- spvnode log tail -----"
            tail -n 120 "$TMPDIR/spvnode.log"
            kill "$spv_pipe_pid" 2>/dev/null || true
            set +e
            wait "$spv_pipe_pid"
            set -e
            error "Timed out waiting for txid $BROADCAST_TXID in /getUTXOs"
        fi
        elapsed_seconds=$((found_ts - scan_start_ts))
        success "Broadcast txid observed via REST after ${elapsed_seconds}s (txid=$BROADCAST_TXID)"
        {
            echo "SPV_TIMING"
            echo "txid_seen_via_rest_at=${found_ts}"
            echo "scan_elapsed_seconds=${elapsed_seconds}"
            echo "broadcast_txid=${BROADCAST_TXID}"
        } | tee -a "$TMPDIR/spvnode.log"
        while true; do
            commit_match_line=$(grep -F "[raccoong-commit] Valid" "$TMPDIR/spvnode.log" | grep -F "commit=$RACCOONG_COMMIT" | grep -F "$expected_commit_source" | tail -n1 || true)
            if [ -n "$commit_match_line" ]; then
                success "spvnode confirmed ${expected_commit_mode} Raccoon-G commitment validation for expected commit"
                echo "$commit_match_line" | tee -a "$TMPDIR/spvnode.log"
                break
            fi
            op_return_only_line=$(grep -F "[raccoong-commit] Valid" "$TMPDIR/spvnode.log" | grep -F "commit=$RACCOONG_COMMIT" | grep -F "source=op_return_only" | tail -n1 || true)
            if [ -n "$op_return_only_line" ]; then
                echo "$op_return_only_line" | tee -a "$TMPDIR/spvnode.log"
                error "spvnode validated commitment as source=op_return_only; expected source=scriptsig"
            fi
            if ! kill -0 "$spv_pipe_pid" 2>/dev/null; then
                set +e
                wait "$spv_pipe_pid"
                spv_exit_code=$?
                set -e
                echo "----- spvnode log tail -----"
                tail -n 80 "$TMPDIR/spvnode.log"
                error "spvnode exited before ${expected_commit_mode} Raccoon-G commitment validation was observed (exit=${spv_exit_code})"
            fi
            if [ $(( $(date +%s) - found_ts )) -ge "$SPV_TIMEOUT_SECONDS" ]; then
                echo "----- spvnode log tail -----"
                tail -n 120 "$TMPDIR/spvnode.log"
                kill "$spv_pipe_pid" 2>/dev/null || true
                set +e
                wait "$spv_pipe_pid"
                set -e
                error "Timed out waiting for ${expected_commit_mode} Raccoon-G commitment validation after txid detection"
            fi
            sleep 1
        done
        if kill -0 "$spv_pipe_pid" 2>/dev/null; then
            info "Stopping spvnode scan after relevant transaction detection..."
            kill "$spv_pipe_pid" 2>/dev/null || true
            set +e
            wait "$spv_pipe_pid"
            set -e
        fi
    else
        error "Transaction was not broadcast; cannot continue full-run validation flow"
    fi
}

verify_commitment() {
    info "Step 8: Off-chain verification"
    local VERIFY_PK="$RACCOONG_PK"
    local VERIFY_SIG="$RACCOONG_SIG"
    SCRIPTSIG_OUTPUT=$(./such -c printscriptsigpqc -x "$SIGNED_TX")
    echo "$SCRIPTSIG_OUTPUT" > "$TMPDIR/raccoong_scriptsig_pqc.txt"
    SCRIPTSIG_RACCOONG_PK=$(echo "$SCRIPTSIG_OUTPUT" | awk '/scriptsig_pqc_pubkey:/ {print $2; exit}')
    SCRIPTSIG_RACCOONG_SIG=$(echo "$SCRIPTSIG_OUTPUT" | awk '/scriptsig_pqc_signature:/ {print $2; exit}')
    if [ -z "$SCRIPTSIG_RACCOONG_PK" ]; then
        error "Failed to extract Raccoon-G public key from scriptSig"
    fi
    if [ -z "$SCRIPTSIG_RACCOONG_SIG" ]; then
        error "Failed to extract Raccoon-G signature from scriptSig"
    fi
    if [ "$SCRIPTSIG_RACCOONG_PK" != "$RACCOONG_PK" ]; then
        error "scriptSig Raccoon-G public key does not match expected public key"
    fi
    if [ "$SCRIPTSIG_RACCOONG_SIG" != "$RACCOONG_SIG" ]; then
        error "scriptSig Raccoon-G signature does not match expected signature"
    fi
    VERIFY_PK="$SCRIPTSIG_RACCOONG_PK"
    VERIFY_SIG="$SCRIPTSIG_RACCOONG_SIG"
    success "scriptSig carries expected Raccoon-G public key/signature"

    VERIFY_OUTPUT=$(./such -c raccoong_verify -k "$VERIFY_PK" -x "$TX_SIGHASH_HEX" -s "$VERIFY_SIG")
    echo "$VERIFY_OUTPUT"
    echo "$VERIFY_OUTPUT" > "$TMPDIR/raccoong_verify.txt"
    if ! echo "$VERIFY_OUTPUT" | grep -Eq "valid:[[:space:]]*true|VERIFIED: Signature is valid|VALID"; then
        error "Off-chain Raccoon-G signature verification failed"
    fi

    COMMIT_OUTPUT=$(./such -c raccoong_commit -k "$VERIFY_PK" -s "$VERIFY_SIG")
    echo "$COMMIT_OUTPUT" > "$TMPDIR/raccoong_commit_verify.txt"
    REGENERATED_COMMIT=$(echo "$COMMIT_OUTPUT" | grep "^commitment:" | cut -d: -f2 | tr -d ' ')
    [ -n "$REGENERATED_COMMIT" ] || error "Failed to parse regenerated Raccoon-G commitment"
    if [ "$REGENERATED_COMMIT" != "$RACCOONG_COMMIT" ]; then
        error "Regenerated commitment does not match expected commitment"
    fi
    success "Off-chain Raccoon-G verification and commitment match passed"
}

main() {
    echo ""
    echo "=========================================="
    echo "  Raccoon-G-44 Mainnet Integration Test"
    echo "=========================================="
    echo ""
    check_tools
    load_mainnet_wallet
    generate_raccoong_keypair
    derive_hd_child
    build_transaction
    monitor_spvnode
    verify_commitment
    success "All test data saved in: $TMPDIR"
}

main
