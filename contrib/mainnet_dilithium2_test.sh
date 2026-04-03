#!/bin/bash
#
# Dilithium2 Mainnet Integration Test Script
#
# Prerequisites:
#   - libdogecoin built with --enable-liboqs
#   - such, sendtx, and spvnode binaries in PATH or current directory
#

set -e
umask 077

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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
TMPDIR=$(mktemp -d /tmp/dilithium2_testnet_XXXXXX)
chmod 700 "$TMPDIR"
BROADCASTED=0
BROADCAST_TXID=""
SPV_TIMEOUT_SECONDS="${SPV_TIMEOUT_SECONDS:-1800}"
SPV_REQUIRE_VALIDATION="${SPV_REQUIRE_VALIDATION:-1}"
SPV_NO_BROADCAST_TIMEOUT="${SPV_NO_BROADCAST_TIMEOUT:-30}"
SPV_HEADERS_FILE="${SPV_HEADERS_FILE:-$TMPDIR/spv_headers.db}"
SPV_WALLET_FILE="${SPV_WALLET_FILE:-$TMPDIR/spv_wallet.db}"
REST_HOST="${REST_HOST:-127.0.0.1}"
REST_PORT="${REST_PORT:-$((19080 + ($$ % 1000)))}"
REST_SERVER="${REST_SERVER:-${REST_HOST}:${REST_PORT}}"
NON_INTERACTIVE="${NON_INTERACTIVE:-1}"
AUTO_BROADCAST="${AUTO_BROADCAST:-1}"
FUNDED_WIF="${FUNDED_WIF:-QP1tqHYuPiAW73MHETRaARgeEff9PhHyYyQcWXAGskEFmSppDt2w}"
FUNDED_ADDR="${FUNDED_ADDR:-DDMpdcTrWnZT38tRMebbYzCSAgLSnVMqvr}"
# sendtx can report success either as immediate relay or as "already known".
RELAY_SUCCESS_PATTERN='tx successfully sent to node|already (broadcasted|known|have transaction)|txn-already-known'

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
run_and_log() {
    local label="$1"
    shift
    echo "----- ${label}: $* -----"
    "$@" 2>&1
    local rc=$?
    echo "----- ${label} exit=${rc} -----"
    return $rc
}

wait_for_rest_tx() {
    local txid="$1"
    local timeout="$2"
    local start_ts now_ts
    start_ts=$(date +%s)
    while true; do
        if curl -fsS "http://${REST_SERVER}/smpvTx?id=${txid}" 2>/dev/null | grep -Fq "\"txid\": \"${txid}\""; then
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
    if ! ./such -c help 2>&1 | grep -q dilithium2_keygen; then
        error "libdogecoin not built with Dilithium2 support. Rebuild with --enable-liboqs"
    fi
    if ! ./such -c help 2>&1 | grep -q tx_sighash32; then
        error "such missing tx_sighash32 command"
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

generate_dilithium2_keypair() {
    info "Generating Dilithium2 keypair..."
    run_and_log "such dilithium2_keygen" ./such -c dilithium2_keygen | tee "$TMPDIR/dilithium2_keys.txt"
    DILITHIUM2_PK=$(grep "^public key:" "$TMPDIR/dilithium2_keys.txt" | cut -d: -f2 | tr -d ' ')
    DILITHIUM2_SK=$(grep "^secret key:" "$TMPDIR/dilithium2_keys.txt" | cut -d: -f2 | tr -d ' ')
    [ -n "$DILITHIUM2_PK" ] || error "Failed to parse Dilithium2 public key"
    [ -n "$DILITHIUM2_SK" ] || error "Failed to parse Dilithium2 secret key"
    if [ "$DILITHIUM2_PK" = "$DILITHIUM2_SK" ]; then
        error "Dilithium2 public and secret keys are identical; expected different key material"
    fi
    echo "DILITHIUM2_KEYPAIR"
    echo "dilithium2_pk_len=${#DILITHIUM2_PK}"
    echo "dilithium2_sk_len=${#DILITHIUM2_SK}"
    echo "dilithium2_pk_prefix=${DILITHIUM2_PK:0:64}"
    echo "dilithium2_pk_suffix=${DILITHIUM2_PK: -64}"
    echo "dilithium2_sk_prefix=${DILITHIUM2_SK:0:64}"
    echo "dilithium2_sk_suffix=${DILITHIUM2_SK: -64}"
    success "Dilithium2 keypair generated"
}

sign_message_dilithium2() {
    info "Signing tx_sighash32 with Dilithium2..."
    run_and_log "such dilithium2_sign" ./such -c dilithium2_sign -p "$DILITHIUM2_SK" -x "$TX_SIGHASH_HEX" | tee "$TMPDIR/dilithium2_sig.txt"
    DILITHIUM2_SIG=$(grep "^signature:" "$TMPDIR/dilithium2_sig.txt" | cut -d: -f2 | tr -d ' ')
    [ -n "$DILITHIUM2_SIG" ] || error "Failed to sign tx_sighash32"
    success "tx_sighash32 signed"
}

generate_commitment() {
    info "Generating Dilithium2 commitment..."
    run_and_log "such dilithium2_commit" ./such -c dilithium2_commit -k "$DILITHIUM2_PK" -s "$DILITHIUM2_SIG" | tee "$TMPDIR/dilithium2_commit.txt"
    DILITHIUM2_COMMIT=$(grep "^commitment:" "$TMPDIR/dilithium2_commit.txt" | cut -d: -f2 | tr -d ' ')
    [ "${#DILITHIUM2_COMMIT}" -eq 64 ] || error "Invalid commitment length"
    success "Commitment generated: $DILITHIUM2_COMMIT"
}

build_transaction() {
    info "Build unsigned mainnet tx with such, then paste hex below:"
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
    # Reject zeroed P2PKH scriptPubKey: 76a914 + 20-byte hash160 (40 hex chars) + 88ac.
    if echo "$SCRIPT_PUBKEY" | grep -Eq '^76a914(0){40}88ac$'; then
        error "scriptPubKey is a zero placeholder. Provide the real UTXO scriptPubKey."
    fi

    SIGHASH_OUTPUT=$(run_and_log "such tx_sighash32" ./such -c tx_sighash32 -x "$RAW_UNSIGNED_TX" -s "$SCRIPT_PUBKEY" -i 0 -h 1)
    echo "$SIGHASH_OUTPUT"
    TX_SIGHASH_HEX=$(echo "$SIGHASH_OUTPUT" | grep "^tx_sighash32:" | cut -d: -f2 | tr -d ' ')
    [ -n "$TX_SIGHASH_HEX" ] || error "Failed to derive tx_sighash32"
    [ "${#TX_SIGHASH_HEX}" -eq 64 ] || error "Invalid tx_sighash32 length"
    info "tx_sighash32: $TX_SIGHASH_HEX"
    sign_message_dilithium2
    generate_commitment

    ADD_COMMIT_OUTPUT=$(run_and_log "such dilithium2_add_commit_tx" ./such -c dilithium2_add_commit_tx -x "$RAW_UNSIGNED_TX" -s "$DILITHIUM2_COMMIT")
    echo "$ADD_COMMIT_OUTPUT"
    TX_WITH_COMMIT=$(echo "$ADD_COMMIT_OUTPUT" | grep "^tx with commitment:" | cut -d: -f2- | tr -d ' ')
    [ -n "$TX_WITH_COMMIT" ] || error "Failed to append Dilithium2 commitment"

    info "Embedding Dilithium2 public key/signature in scriptSig for input 0..."
    ADD_SCRIPTSIG_PQC_OUTPUT=$(run_and_log "such addscriptsigpqc" ./such -c addscriptsigpqc -x "$TX_WITH_COMMIT" -i 0 -k "$DILITHIUM2_PK" -s "$DILITHIUM2_SIG")
    echo "$ADD_SCRIPTSIG_PQC_OUTPUT"
    TX_FOR_SIGNING=$(echo "$ADD_SCRIPTSIG_PQC_OUTPUT" | grep "^tx with scriptsig pqc:" | cut -d: -f2- | tr -d ' ')
    [ -n "$TX_FOR_SIGNING" ] || error "Failed to append Dilithium2 public key/signature to scriptSig"
    info "Verifying scriptSig carries Dilithium2 public key/signature before signing..."
    PRE_SIGN_SCRIPTSIG_OUTPUT=$(./such -c printscriptsigpqc -x "$TX_FOR_SIGNING")
    echo "$PRE_SIGN_SCRIPTSIG_OUTPUT" | tee "$TMPDIR/dilithium2_scriptsig_pqc_presign.txt"
    PRE_SIGN_DILITHIUM2_ITEM_A=$(echo "$PRE_SIGN_SCRIPTSIG_OUTPUT" | awk '/scriptsig_pqc_pubkey:/ {print $2; exit}')
    PRE_SIGN_DILITHIUM2_ITEM_B=$(echo "$PRE_SIGN_SCRIPTSIG_OUTPUT" | awk '/scriptsig_pqc_signature:/ {print $2; exit}')
    [ -n "$PRE_SIGN_DILITHIUM2_ITEM_A" ] || error "scriptSig pre-sign check missing first Dilithium2 item"
    [ -n "$PRE_SIGN_DILITHIUM2_ITEM_B" ] || error "scriptSig pre-sign check missing second Dilithium2 item"
    PRE_SIGN_DILITHIUM2_PK=""
    PRE_SIGN_DILITHIUM2_SIG=""
    for candidate_pk in "$PRE_SIGN_DILITHIUM2_ITEM_A" "$PRE_SIGN_DILITHIUM2_ITEM_B"; do
        for candidate_sig in "$PRE_SIGN_DILITHIUM2_ITEM_A" "$PRE_SIGN_DILITHIUM2_ITEM_B"; do
            if [ "$candidate_pk" = "$candidate_sig" ]; then
                continue
            fi
            if ./such -c dilithium2_verify -k "$candidate_pk" -x "$TX_SIGHASH_HEX" -s "$candidate_sig" 2>/dev/null | grep -Eq "valid:[[:space:]]*true|VERIFIED: Signature is valid|VALID"; then
                PRE_SIGN_DILITHIUM2_PK="$candidate_pk"
                PRE_SIGN_DILITHIUM2_SIG="$candidate_sig"
                break 2
            fi
        done
    done
    [ -n "$PRE_SIGN_DILITHIUM2_PK" ] || error "scriptSig pre-sign payload could not be validated as Dilithium2 pk/signature pair"
    [ -n "$PRE_SIGN_DILITHIUM2_SIG" ] || error "scriptSig pre-sign payload could not be validated as Dilithium2 pk/signature pair"
    [ "$PRE_SIGN_DILITHIUM2_PK" = "$DILITHIUM2_PK" ] || error "scriptSig pre-sign public key mismatch"
    [ "$PRE_SIGN_DILITHIUM2_SIG" = "$DILITHIUM2_SIG" ] || error "scriptSig pre-sign signature mismatch"
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
DILITHIUM2_SIG=$DILITHIUM2_SIG
DILITHIUM2_COMMIT=$DILITHIUM2_COMMIT
SCRIPTSIG_PQC_PUBKEY=$DILITHIUM2_PK
SIGNED_TX=$SIGNED_TX
OPRETURN_SCRIPT=6a2444494c32${DILITHIUM2_COMMIT}
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
    echo "  [dilithium-commit] Valid at height=X txpos=Y commit=$DILITHIUM2_COMMIT"
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
        stdbuf -oL -eL ./spvnode $NETWORK_FLAG -l -h "$SPV_HEADERS_FILE" -w "$SPV_WALLET_FILE" -u "$REST_SERVER" -c -d -x -p -b -a "$TESTNET_ADDR" scan | tee "$TMPDIR/spvnode.log" &
        spv_pipe_pid=$!
        if ! found_ts=$(wait_for_rest_tx "$BROADCAST_TXID" "$SPV_TIMEOUT_SECONDS"); then
            echo "----- spvnode log tail -----"
            tail -n 120 "$TMPDIR/spvnode.log"
            kill "$spv_pipe_pid" 2>/dev/null || true
            set +e
            wait "$spv_pipe_pid"
            set -e
            error "Timed out waiting for txid $BROADCAST_TXID in /smpvTx"
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
            commit_match_line=$(grep -F "[dilithium-commit] Valid" "$TMPDIR/spvnode.log" | grep -F "commit=$DILITHIUM2_COMMIT" | grep -F "$expected_commit_source" | tail -n1 || true)
            if [ -n "$commit_match_line" ]; then
                success "spvnode confirmed ${expected_commit_mode} Dilithium2 commitment validation for expected commit"
                echo "$commit_match_line" | tee -a "$TMPDIR/spvnode.log"
                break
            fi
            op_return_only_line=$(grep -F "[dilithium-commit] Valid" "$TMPDIR/spvnode.log" | grep -F "commit=$DILITHIUM2_COMMIT" | grep -F "source=op_return_only" | tail -n1 || true)
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
                error "spvnode exited before ${expected_commit_mode} Dilithium2 commitment validation was observed (exit=${spv_exit_code})"
            fi
            if [ $(( $(date +%s) - found_ts )) -ge "$SPV_TIMEOUT_SECONDS" ]; then
                echo "----- spvnode log tail -----"
                tail -n 120 "$TMPDIR/spvnode.log"
                kill "$spv_pipe_pid" 2>/dev/null || true
                set +e
                wait "$spv_pipe_pid"
                set -e
                error "Timed out waiting for ${expected_commit_mode} Dilithium2 commitment validation after txid detection"
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
    local VERIFY_PK="$DILITHIUM2_PK"
    local VERIFY_SIG="$DILITHIUM2_SIG"
    SCRIPTSIG_OUTPUT=$(./such -c printscriptsigpqc -x "$SIGNED_TX")
    echo "$SCRIPTSIG_OUTPUT" > "$TMPDIR/dilithium2_scriptsig_pqc.txt"
    SCRIPTSIG_DILITHIUM2_PK=$(echo "$SCRIPTSIG_OUTPUT" | awk '/scriptsig_pqc_pubkey:/ {print $2; exit}')
    SCRIPTSIG_DILITHIUM2_SIG=$(echo "$SCRIPTSIG_OUTPUT" | awk '/scriptsig_pqc_signature:/ {print $2; exit}')
    if [ -z "$SCRIPTSIG_DILITHIUM2_PK" ]; then
        error "Failed to extract Dilithium2 public key from scriptSig"
    fi
    if [ -z "$SCRIPTSIG_DILITHIUM2_SIG" ]; then
        error "Failed to extract Dilithium2 signature from scriptSig"
    fi
    if [ "$SCRIPTSIG_DILITHIUM2_PK" != "$DILITHIUM2_PK" ]; then
        error "scriptSig Dilithium2 public key does not match expected public key"
    fi
    if [ "$SCRIPTSIG_DILITHIUM2_SIG" != "$DILITHIUM2_SIG" ]; then
        error "scriptSig Dilithium2 signature does not match expected signature"
    fi
    VERIFY_PK="$SCRIPTSIG_DILITHIUM2_PK"
    VERIFY_SIG="$SCRIPTSIG_DILITHIUM2_SIG"
    success "scriptSig carries expected Dilithium2 public key/signature"

    VERIFY_OUTPUT=$(./such -c dilithium2_verify -k "$VERIFY_PK" -x "$TX_SIGHASH_HEX" -s "$VERIFY_SIG")
    echo "$VERIFY_OUTPUT"
    echo "$VERIFY_OUTPUT" > "$TMPDIR/dilithium2_verify.txt"
    if ! echo "$VERIFY_OUTPUT" | grep -Eq "valid:[[:space:]]*true|VERIFIED: Signature is valid|VALID"; then
        echo "$VERIFY_OUTPUT"
        error "Off-chain Dilithium2 signature verification failed"
    fi

    COMMIT_OUTPUT=$(./such -c dilithium2_commit -k "$VERIFY_PK" -s "$VERIFY_SIG")
    echo "$COMMIT_OUTPUT" > "$TMPDIR/dilithium2_commit_verify.txt"
    REGENERATED_COMMIT=$(echo "$COMMIT_OUTPUT" | grep "^commitment:" | cut -d: -f2 | tr -d ' ')
    if [ -z "$REGENERATED_COMMIT" ]; then
        error "Failed to parse regenerated Dilithium2 commitment"
    fi
    if [ "$REGENERATED_COMMIT" != "$DILITHIUM2_COMMIT" ]; then
        error "Regenerated Dilithium2 commitment does not match expected commitment"
    fi
    success "Off-chain Dilithium2 verification and commitment match passed"
}

main() {
    echo ""
    echo "=========================================="
    echo "  Dilithium2 Mainnet Integration Test"
    echo "=========================================="
    echo ""
    check_tools
    load_mainnet_wallet
    generate_dilithium2_keypair
    build_transaction
    monitor_spvnode
    verify_commitment
    success "All test data saved in: $TMPDIR"
    echo "Files:"
    echo "  - $TMPDIR/tx_info.txt"
    echo "  - $TMPDIR/spvnode.log"
    echo "  - $TMPDIR/dilithium2_verify.txt"
}

main
