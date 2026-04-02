#!/bin/bash
#
# Falcon-512 Testnet Integration Test Script
# 
# This script demonstrates end-to-end testing of Falcon-512 commitments on Dogecoin testnet
# 
# Prerequisites:
#   - libdogecoin built with --enable-liboqs
#   - Testnet coins (get from faucet)
#   - such, sendtx, and spvnode binaries in PATH or current directory
#

set -e  # Exit on error
umask 077

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NETWORK="${NETWORK:-mainnet}"
NETWORK_FLAG="-t"
if [ "$NETWORK" = "mainnet" ]; then
    NETWORK_FLAG=""
elif [ "$NETWORK" != "testnet" ]; then
    echo "Unsupported NETWORK value: $NETWORK (expected testnet|mainnet)" >&2
    exit 1
fi
TMPDIR="/tmp/falcon_mainnet_$$"
mkdir -m 700 -p "$TMPDIR"
BROADCASTED=0
BROADCAST_TXID=""
SPV_TIMEOUT_SECONDS="${SPV_TIMEOUT_SECONDS:-1800}"
SPV_REQUIRE_VALIDATION="${SPV_REQUIRE_VALIDATION:-1}"
SPV_NO_BROADCAST_TIMEOUT="${SPV_NO_BROADCAST_TIMEOUT:-30}"
SPV_HEADERS_FILE="${SPV_HEADERS_FILE:-$TMPDIR/spv_headers.db}"
SPV_WALLET_FILE="${SPV_WALLET_FILE:-$TMPDIR/spv_wallet.db}"
REST_HOST="${REST_HOST:-127.0.0.1}"
REST_PORT="${REST_PORT:-$((18080 + ($$ % 1000)))}"
REST_SERVER="${REST_SERVER:-${REST_HOST}:${REST_PORT}}"
NON_INTERACTIVE="${NON_INTERACTIVE:-1}"
AUTO_BROADCAST="${AUTO_BROADCAST:-1}"
INCLUDE_WITNESS_ITEMS="${INCLUDE_WITNESS_ITEMS:-1}"
FUNDED_WIF="${FUNDED_WIF:-QP1tqHYuPiAW73MHETRaARgeEff9PhHyYyQcWXAGskEFmSppDt2w}"
FUNDED_ADDR="${FUNDED_ADDR:-DDMpdcTrWnZT38tRMebbYzCSAgLSnVMqvr}"
RAW_UNSIGNED_TX="${RAW_UNSIGNED_TX:-}"
SCRIPT_PUBKEY="${SCRIPT_PUBKEY:-}"
RUN_LOG="$TMPDIR/mainnet_falcon_run.log"
# sendtx can report success either as immediate relay or as "already known".
RELAY_SUCCESS_PATTERN='tx successfully sent to node|not relayed back|already (broadcasted|known|have transaction)|txn-already-known'

# Function to print colored messages
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

run_and_log() {
    local label="$1"
    shift
    echo "----- ${label}: $* -----"
    "$@" 2>&1
    local rc=$?
    echo "----- ${label} exit=${rc} -----"
    return $rc
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check if tools are available
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
    
    # Check if built with liboqs and tx_sighash helper
    if ! ./such -c help 2>&1 | grep -q falcon_keygen; then
        error "libdogecoin not built with liboqs support. Rebuild with --enable-liboqs"
    fi
    if ! ./such -c help 2>&1 | grep -q tx_sighash32; then
        error "such missing tx_sighash32 command"
    fi
    if ! command -v curl &> /dev/null; then
        error "curl not found. Required for REST tx monitoring."
    fi
    if [ "$SPV_REQUIRE_VALIDATION" -ne 1 ]; then
        error "SPV_REQUIRE_VALIDATION must be 1 for full-run mode"
    fi
    
    success "All tools available"
}

load_mainnet_wallet() {
    info "Step 1: Using provided funded mainnet wallet..."
    PRIVKEY_WIF="$FUNDED_WIF"
    run_and_log "such generate_public_key" ./such -c generate_public_key -p "$PRIVKEY_WIF" $NETWORK_FLAG | tee "$TMPDIR/mainnet_addr.txt"
    TESTNET_ADDR=$(awk -F': ' '/p2pkh address:/ {print $2; exit}' "$TMPDIR/mainnet_addr.txt" | tr -d ' \r\n')
    PUBKEY=$(awk -F': ' '/^public key hex:/ {print $2; exit}' "$TMPDIR/mainnet_addr.txt" | tr -d ' \r\n')
    if [ "$TESTNET_ADDR" != "$FUNDED_ADDR" ]; then
        error "Provided WIF does not map to expected funded address"
    fi
    success "Mainnet funded wallet loaded"
    echo "  Address: $TESTNET_ADDR"
    echo "  Private Key (WIF): $PRIVKEY_WIF"
    echo "  Public Key: $PUBKEY"
    cat > "$TMPDIR/wallet.txt" <<EOF
MAINNET_ADDR=$TESTNET_ADDR
PRIVKEY_WIF=$PRIVKEY_WIF
PUBKEY=$PUBKEY
EOF
}

log_run_context() {
    {
        echo "RUN_CONTEXT"
        echo "NETWORK=$NETWORK"
        echo "WIF=$PRIVKEY_WIF"
        echo "ADDRESS=$TESTNET_ADDR"
        echo "SCRIPT_PUBKEY=$SCRIPT_PUBKEY"
        echo "SPV_HEADERS_FILE=$SPV_HEADERS_FILE"
        echo "SPV_WALLET_FILE=$SPV_WALLET_FILE"
        echo "REST_SERVER=$REST_SERVER"
        echo "INCLUDE_WITNESS_ITEMS=$INCLUDE_WITNESS_ITEMS"
    } | tee -a "$RUN_LOG"
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

# Step 3: Generate Falcon-512 keypair
generate_falcon_keypair() {
    info "Step 3: Generating Falcon-512 keypair..."
    
    run_and_log "such falcon_keygen" ./such -c falcon_keygen | tee "$TMPDIR/falcon_keys.txt"
    
    FALCON_PK=$(grep "^public key:" "$TMPDIR/falcon_keys.txt" | cut -d: -f2 | tr -d ' ')
    FALCON_SK=$(grep "^secret key:" "$TMPDIR/falcon_keys.txt" | cut -d: -f2 | tr -d ' ')
    
    if [ -z "$FALCON_PK" ] || [ -z "$FALCON_SK" ]; then
        error "Failed to generate Falcon keypair"
    fi
    
    success "Falcon-512 keypair generated"
    echo "  Public Key (${#FALCON_PK} chars): ${FALCON_PK:0:64}..."
    echo "  Secret Key (${#FALCON_SK} chars): ${FALCON_SK:0:64}..."
    
    # Save to file
    cat > "$TMPDIR/falcon_keys.txt" <<EOF
FALCON_PK=$FALCON_PK
FALCON_SK=$FALCON_SK
EOF
}

# Step 6: Build transaction with OP_RETURN
build_transaction() {
    info "Step 4: Building transaction and deriving tx_sighash32..."
    if [ -z "$RAW_UNSIGNED_TX" ] && [ "$NON_INTERACTIVE" -eq 1 ]; then
        error "RAW_UNSIGNED_TX must be set in NON_INTERACTIVE mode"
    fi
    if [ -z "$RAW_UNSIGNED_TX" ]; then
        echo "Create an unsigned mainnet transaction with such first:"
        echo "  ./such -c transaction"
        echo ""
        echo "Then paste the unsigned raw tx hex below."
        read -p "Enter unsigned raw tx hex: " RAW_UNSIGNED_TX
    else
        info "Using RAW_UNSIGNED_TX from environment"
    fi

    if [ -z "$SCRIPT_PUBKEY" ] && [ "$NON_INTERACTIVE" -eq 1 ]; then
        error "SCRIPT_PUBKEY must be set in NON_INTERACTIVE mode"
    fi
    if [ -z "$SCRIPT_PUBKEY" ]; then
        read -p "Enter scriptPubKey hex for input 0 (UTXO being spent): " SCRIPT_PUBKEY
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
    echo "$SIGHASH_OUTPUT" | tee -a "$RUN_LOG"
    TX_SIGHASH_HEX=$(echo "$SIGHASH_OUTPUT" | grep "^tx_sighash32:" | cut -d: -f2 | tr -d ' ')
    if [ -z "$TX_SIGHASH_HEX" ] || [ ${#TX_SIGHASH_HEX} -ne 64 ]; then
        echo "$SIGHASH_OUTPUT"
        error "Failed to derive tx_sighash32 for PQC signing"
    fi
    success "Derived tx_sighash32: $TX_SIGHASH_HEX"

    info "Step 5: Signing tx_sighash32 with Falcon-512..."
    run_and_log "such falcon_sign" ./such -c falcon_sign -p "$FALCON_SK" -x "$TX_SIGHASH_HEX" | tee "$TMPDIR/falcon_sig.txt"
    FALCON_SIG=$(grep "^signature:" "$TMPDIR/falcon_sig.txt" | cut -d: -f2 | tr -d ' ')
    if [ -z "$FALCON_SIG" ]; then
        error "Failed to sign tx_sighash32 with Falcon-512"
    fi
    success "Falcon signature generated from tx_sighash32"

    info "Step 6: Generating commitment from Falcon signature..."
    run_and_log "such falcon_commit" ./such -c falcon_commit -k "$FALCON_PK" -s "$FALCON_SIG" | tee "$TMPDIR/falcon_commit.txt"
    FALCON_COMMIT=$(grep "^commitment:" "$TMPDIR/falcon_commit.txt" | cut -d: -f2 | tr -d ' ')
    if [ -z "$FALCON_COMMIT" ] || [ ${#FALCON_COMMIT} -ne 64 ]; then
        error "Failed to generate commitment (expected 64 hex chars, got ${#FALCON_COMMIT})"
    fi
    success "Commitment generated from tx-bound Falcon signature"

    ADD_COMMIT_OUTPUT=$(run_and_log "such falcon_add_commit_tx" ./such -c falcon_add_commit_tx -x "$RAW_UNSIGNED_TX" -s "$FALCON_COMMIT")
    echo "$ADD_COMMIT_OUTPUT" | tee -a "$RUN_LOG"
    TX_WITH_COMMIT=$(echo "$ADD_COMMIT_OUTPUT" | grep "^tx with commitment:" | cut -d: -f2- | tr -d ' ')

    if [ -z "$TX_WITH_COMMIT" ]; then
        echo "$ADD_COMMIT_OUTPUT"
        error "Failed to append Falcon commitment to transaction"
    fi

    TX_FOR_SIGNING="$TX_WITH_COMMIT"
    TX_WITH_WITNESS="$TX_WITH_COMMIT"
    TX_WITH_WITNESS_SIG="$TX_WITH_COMMIT"
    if [ "$INCLUDE_WITNESS_ITEMS" -eq 1 ]; then
        info "Step 6b: Embedding Falcon public key in witness[0] for input 0..."
        ADD_WITNESS_OUTPUT=$(run_and_log "such addwitness" ./such -c addwitness -x "$TX_WITH_COMMIT" -i 0 -s "$FALCON_PK")
        echo "$ADD_WITNESS_OUTPUT" | tee -a "$RUN_LOG"
        TX_WITH_WITNESS=$(echo "$ADD_WITNESS_OUTPUT" | grep "^tx with witness:" | cut -d: -f2- | tr -d ' ')
        if [ -z "$TX_WITH_WITNESS" ]; then
            error "Failed to append Falcon public key witness item"
        fi

        info "Step 6c: Embedding Falcon signature in witness[1] for input 0..."
        ADD_WITNESS_SIG_OUTPUT=$(run_and_log "such addwitness" ./such -c addwitness -x "$TX_WITH_WITNESS" -i 0 -s "$FALCON_SIG")
        echo "$ADD_WITNESS_SIG_OUTPUT" | tee -a "$RUN_LOG"
        TX_WITH_WITNESS_SIG=$(echo "$ADD_WITNESS_SIG_OUTPUT" | grep "^tx with witness:" | cut -d: -f2- | tr -d ' ')
        if [ -z "$TX_WITH_WITNESS_SIG" ]; then
            error "Failed to append Falcon signature witness item"
        fi
        TX_FOR_SIGNING="$TX_WITH_WITNESS_SIG"
    else
        info "Step 6b/6c: Non-witness flow enabled (INCLUDE_WITNESS_ITEMS=0); signing tx with commitment only"
    fi

    info "Signing transaction with commitment output..."
    SIGN_OUTPUT=$(run_and_log "such sign" ./such -c sign -x "$TX_FOR_SIGNING" -s "$SCRIPT_PUBKEY" -i 0 -h 1 -p "$PRIVKEY_WIF" $NETWORK_FLAG)
    echo "$SIGN_OUTPUT" | tee -a "$RUN_LOG"
    SIGNED_TX=$(echo "$SIGN_OUTPUT" | grep "^signed TX:" | cut -d: -f2- | tr -d ' ')

    if [ -z "$SIGNED_TX" ]; then
        echo "$SIGN_OUTPUT"
        error "Failed to sign transaction"
    fi

    success "Signed transaction with Falcon commitment ready"
    echo "  Signed TX: ${SIGNED_TX:0:80}..."
    echo ""
    DO_BROADCAST="n"
    if [ "$AUTO_BROADCAST" -eq 1 ]; then
        DO_BROADCAST="y"
    elif [ "$NON_INTERACTIVE" -eq 0 ]; then
        read -p "Broadcast now with sendtx? [y/N]: " DO_BROADCAST
    fi
    if [[ "$DO_BROADCAST" =~ ^[Yy]$ ]]; then
        SENDTX_OUTPUT=$(run_and_log "sendtx" ./sendtx $NETWORK_FLAG "$SIGNED_TX" || true)
        echo "$SENDTX_OUTPUT" | sed 's/Error:/sendtx-note:/g' | tee "$TMPDIR/sendtx.log" | tee -a "$RUN_LOG"
        BROADCAST_TXID=$(echo "$SENDTX_OUTPUT" | sed -n 's/^Start broadcasting transaction:[[:space:]]*\([0-9a-fA-F]\{64\}\).*/\1/p' | head -n1)
        if [ -z "$BROADCAST_TXID" ]; then
            error "Failed to parse broadcast txid from sendtx output"
        fi
        if echo "$SENDTX_OUTPUT" | grep -Eqi "$RELAY_SUCCESS_PATTERN"; then
            success "Broadcast accepted or already known by peers"
            BROADCASTED=1
        else
            error "sendtx did not report a known relay/acceptance status"
        fi
    else
        error "Broadcast is required for full-run mode"
    fi

    cat > "$TMPDIR/tx_info.txt" <<EOF
RAW_UNSIGNED_TX=$RAW_UNSIGNED_TX
TX_WITH_COMMIT=$TX_WITH_COMMIT
TX_WITH_WITNESS=$TX_WITH_WITNESS
TX_WITH_WITNESS_SIG=$TX_WITH_WITNESS_SIG
SCRIPT_PUBKEY=$SCRIPT_PUBKEY
TX_SIGHASH_HEX=$TX_SIGHASH_HEX
FALCON_SIG=$FALCON_SIG
FALCON_COMMIT=$FALCON_COMMIT
WITNESS_PQC_PUBKEY=$FALCON_PK
SIGNED_TX=$SIGNED_TX
TXID=$BROADCAST_TXID
OPRETURN_SCRIPT=6a24464c4331${FALCON_COMMIT}
EOF
}

# Step 7: Monitor with SPV node
monitor_spvnode() {
    info "Step 7: Monitoring with SPV node..."
    
    echo ""
    echo "After broadcasting your transaction, monitor it with block scan mode:"
    echo ""
    echo "  # -l no prompt, -c continuous, -d debug, -x smpv, -p checkpoint, -a address"
    echo "  ./spvnode $NETWORK_FLAG -l -c -d -x -p -a \"$TESTNET_ADDR\" scan"
    echo ""
    echo "Then switch to full block scan mode (or use -b directly):"
    echo ""
    echo "  ./spvnode $NETWORK_FLAG -l -c -d -x -p -b -a \"$TESTNET_ADDR\" scan"
    echo ""
    echo "The SPV node will:"
    echo "  - Sync mainnet blockchain headers"
    echo "  - Track wallet activity for: $TESTNET_ADDR"
    echo "  - Download and scan blocks in full mode"
    echo "  - Detect Falcon commitments"
    echo "  - Log: [falcon-commit] Valid at height=X txpos=Y commit=$FALCON_COMMIT"
    echo ""
    
    info "SPV sync may take time. Be patient!"
    if [ "$BROADCASTED" -eq 1 ]; then
        local spv_cmd=("./spvnode" $NETWORK_FLAG -l -h "$SPV_HEADERS_FILE" -c -d -x -p -b -a "$TESTNET_ADDR" scan)
        local scan_start_ts
        local found_ts
        local elapsed_seconds
        local spv_pipe_pid
        local spv_exit_code
        local commit_match_line=""
        local rest_timeout_remaining
        rm -f "$SPV_WALLET_FILE"
        info "Running spvnode scan with REST monitoring until txid and witness-based commitment validation are both confirmed..."
        scan_start_ts=$(date +%s)
        : > "$TMPDIR/spvnode.log"
        if [ -f "$SPV_HEADERS_FILE" ]; then
            info "Reusing headers file: $SPV_HEADERS_FILE"
        fi
        spv_cmd+=(-w "$SPV_WALLET_FILE" -u "$REST_SERVER")
        set +e
        stdbuf -oL -eL "${spv_cmd[@]}" | tee "$TMPDIR/spvnode.log" | tee -a "$RUN_LOG" &
        spv_pipe_pid=$!
        set -e
        rest_timeout_remaining="$SPV_TIMEOUT_SECONDS"
        if ! found_ts=$(wait_for_rest_tx "$BROADCAST_TXID" "$rest_timeout_remaining"); then
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
        } | tee -a "$RUN_LOG"
        while true; do
            commit_match_line=$(grep -F "[falcon-commit] Valid" "$TMPDIR/spvnode.log" | grep -F "commit=$FALCON_COMMIT" | grep -F "source=witness" | tail -n1 || true)
            if [ -n "$commit_match_line" ]; then
                success "spvnode confirmed witness-based Falcon commitment validation for expected commit"
                echo "$commit_match_line" | tee -a "$RUN_LOG"
                break
            fi
            if ! kill -0 "$spv_pipe_pid" 2>/dev/null; then
                set +e
                wait "$spv_pipe_pid"
                spv_exit_code=$?
                set -e
                echo "----- spvnode log tail -----"
                tail -n 80 "$TMPDIR/spvnode.log"
                error "spvnode exited before 'Found relevant transaction!' was observed (exit=${spv_exit_code})"
            fi
            if [ $(( $(date +%s) - found_ts )) -ge "$SPV_TIMEOUT_SECONDS" ]; then
                echo "----- spvnode log tail -----"
                tail -n 120 "$TMPDIR/spvnode.log"
                kill "$spv_pipe_pid" 2>/dev/null || true
                set +e
                wait "$spv_pipe_pid"
                set -e
                error "Timed out waiting for witness-based Falcon commitment validation after txid detection"
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

# Step 8: Verify commitment off-chain
verify_commitment() {
    info "Step 8: Verifying commitment off-chain..."
    if [ "$INCLUDE_WITNESS_ITEMS" -eq 1 ]; then
        WITNESS_OUTPUT=$(./such -c printwitness -x "$SIGNED_TX")
        echo "$WITNESS_OUTPUT" | tee "$TMPDIR/falcon_witness.txt" | tee -a "$RUN_LOG" >/dev/null
        WITNESS_FALCON_PK=$(echo "$WITNESS_OUTPUT" | awk '/witness\[0\]:/ {print $2; exit}')
        WITNESS_FALCON_SIG=$(echo "$WITNESS_OUTPUT" | awk '/witness\[1\]:/ {print $2; exit}')
        if [ -z "$WITNESS_FALCON_PK" ]; then
            error "Failed to extract Falcon public key from witness"
        fi
        if [ -z "$WITNESS_FALCON_SIG" ]; then
            error "Failed to extract Falcon signature from witness"
        fi
        if [ "$WITNESS_FALCON_PK" != "$FALCON_PK" ]; then
            error "Witness Falcon public key does not match expected public key"
        fi
        if [ "$WITNESS_FALCON_SIG" != "$FALCON_SIG" ]; then
            error "Witness Falcon signature does not match expected signature"
        fi
        success "Witness carries expected Falcon public key"
        {
            echo "WITNESS_VALIDATION"
            echo "witness[0]=$WITNESS_FALCON_PK"
            echo "witness[1]=$WITNESS_FALCON_SIG"
            echo "tx_sighash32=$TX_SIGHASH_HEX"
            echo "expected_commit=$FALCON_COMMIT"
        } | tee -a "$RUN_LOG"
    else
        {
            echo "WITNESS_VALIDATION"
            echo "witness_items=skipped"
            echo "tx_sighash32=$TX_SIGHASH_HEX"
            echo "expected_commit=$FALCON_COMMIT"
        } | tee -a "$RUN_LOG"
    fi

    VERIFY_OUTPUT=$(./such -c falcon_verify -k "$FALCON_PK" -x "$TX_SIGHASH_HEX" -s "$FALCON_SIG")
    echo "$VERIFY_OUTPUT" | tee -a "$RUN_LOG"
    echo "$VERIFY_OUTPUT" > "$TMPDIR/falcon_verify.txt"
    if ! echo "$VERIFY_OUTPUT" | grep -Eq "valid:[[:space:]]*true|VERIFIED: Signature is valid"; then
        echo "$VERIFY_OUTPUT"
        error "Off-chain Falcon signature verification failed"
    fi

    COMMIT_OUTPUT=$(./such -c falcon_commit -k "$FALCON_PK" -s "$FALCON_SIG")
    echo "$COMMIT_OUTPUT" > "$TMPDIR/falcon_commit_verify.txt"
    REGENERATED_COMMIT=$(echo "$COMMIT_OUTPUT" | grep "^commitment:" | cut -d: -f2 | tr -d ' ')
    if [ -z "$REGENERATED_COMMIT" ]; then
        error "Failed to parse regenerated Falcon commitment"
    fi
    if [ "$REGENERATED_COMMIT" != "$FALCON_COMMIT" ]; then
        error "Regenerated Falcon commitment does not match expected commitment"
    fi
    success "Off-chain Falcon verification and commitment match passed"

    echo ""
    echo "Verification details:"
    echo "  valid: true"
    echo "  Expected commitment: $FALCON_COMMIT"
    echo "  Regenerated commitment: $REGENERATED_COMMIT"
    echo ""
    {
        echo "commitment_regenerated=$REGENERATED_COMMIT"
        echo "commitment_match=true"
    } | tee -a "$RUN_LOG"
}

# Main workflow
main() {
    echo ""
    echo "=========================================="
    echo "  Falcon-512 Mainnet Integration Test"
    echo "=========================================="
    echo ""
    
    check_tools
    load_mainnet_wallet
    log_run_context
    generate_falcon_keypair
    build_transaction
    monitor_spvnode
    verify_commitment
    
    echo ""
    echo "=========================================="
    echo "  TEST COMPLETE"
    echo "=========================================="
    echo ""
    success "All test data saved in: $TMPDIR"
    echo ""
    echo "Files:"
    echo "  - $TMPDIR/wallet.txt (mainnet wallet)"
    echo "  - $TMPDIR/falcon_keys.txt (Falcon keypair)"
    echo "  - $TMPDIR/falcon_sig.txt (tx_sighash signature)"
    echo "  - $TMPDIR/falcon_commit.txt (tx-bound commitment)"
    echo "  - $TMPDIR/tx_info.txt (transaction info)"
    echo "  - $TMPDIR/spvnode.log (SPV validation log)"
    echo "  - $TMPDIR/falcon_verify.txt (off-chain verify result)"
    echo "  - $RUN_LOG (full run log with WIF/address + witness validation artifacts)"
    echo ""
}

# Run main workflow
main
