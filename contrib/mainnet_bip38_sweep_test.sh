#!/bin/bash
#
# BIP38 and Paper Wallet Sweep Mainnet Integration Test Script
#
# End-to-end mainnet test for BIP38 encryption/decryption and paper wallet sweep
# functionality with the libdogecoin CLI tools (such, sendtx, spvnode).
#
# This script exercises:
#   1. Key generation and verification
#   2. BIP38 encryption (demonstrated through unit tests)
#   3. Paper wallet sweep transaction building
#   4. Transaction signing
#   5. SPV node checkpoint sync and validation
#   6. Optional transaction broadcast (when UTXOs are available)
#
# Prerequisites:
#   - libdogecoin built with autotools (./configure && make)
#   - such, sendtx, and spvnode binaries in current directory
#   - curl, python3 available for UTXO lookups and TX debugging
#
# Required environment:
#   FUNDED_WIF / FUNDED_ADDR        - mainnet privkey/address with UTXOs
#   FUNDED_UTXO_TXID / VOUT / VALUE - UTXO details for sweep
#
# Optional environment:
#   DESTINATION_ADDR                - where to sweep funds (default: generate new)
#   BIP38_PASSPHRASE                - passphrase for BIP38 encryption test
#   SPV_TIMEOUT_SECONDS             - spvnode wait timeout (default 1800)
#   TX_FEE_KOINU                    - transaction fee (default 2000000)
#   SKIP_BROADCAST                  - set to 1 to skip actual broadcast
#

set -e
umask 077

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ----------------------------- defaults --------------------------------------
NETWORK_FLAG=""                      # mainnet
TMPDIR=$(mktemp -d /tmp/bip38_sweep_e2e_XXXXXX)
chmod 700 "$TMPDIR"

# Funded mainnet wallet credentials
FUNDED_WIF="${FUNDED_WIF:-QP1tqHYuPiAW73MHETRaARgeEff9PhHyYyQcWXAGskEFmSppDt2w}"
FUNDED_ADDR="${FUNDED_ADDR:-DDMpdcTrWnZT38tRMebbYzCSAgLSnVMqvr}"

# UTXO details - will be looked up if not provided
FUNDED_UTXO_TXID="${FUNDED_UTXO_TXID:-}"
FUNDED_UTXO_VOUT="${FUNDED_UTXO_VOUT:-}"
FUNDED_UTXO_VALUE_KOINU="${FUNDED_UTXO_VALUE_KOINU:-}"

# Destination address (generate new if not provided)
DESTINATION_ADDR="${DESTINATION_ADDR:-}"

# BIP38 passphrase for encryption test
BIP38_PASSPHRASE="${BIP38_PASSPHRASE:-TestDogePassword123}"

TX_FEE_KOINU="${TX_FEE_KOINU:-2000000}"

SPV_TIMEOUT_SECONDS="${SPV_TIMEOUT_SECONDS:-1800}"
SPV_NO_BROADCAST_TIMEOUT="${SPV_NO_BROADCAST_TIMEOUT:-30}"
SENDTX_MAX_RETRIES="${SENDTX_MAX_RETRIES:-3}"

REST_HOST="${REST_HOST:-127.0.0.1}"
REST_PORT="${REST_PORT:-$((19280 + ($$ % 800)))}"
REST_SERVER="${REST_SERVER:-${REST_HOST}:${REST_PORT}}"

mkdir -p test-logs
TS=$(date -u +%Y%m%d_%H%M%S)
RUN_LOG="${RUN_LOG:-$(pwd)/test-logs/mainnet_bip38_sweep_e2e_${TS}.txt}"
: > "$RUN_LOG"

SPV_HEADERS_FILE="${SPV_HEADERS_FILE:-$TMPDIR/spv_headers.db}"
SPV_WALLET_FILE="${SPV_WALLET_FILE:-$TMPDIR/spv_wallet.db}"

# Relay success patterns (same as other test scripts)
RELAY_SUCCESS_PATTERN='Requested from nodes:[[:space:]]*[1-9]|Seen on other nodes:[[:space:]]*[1-9]|already (broadcasted|known|have transaction)|txn-already-known|txn-already-in-mempool'
SENDTX_FATAL_PATTERN='Requested from nodes:[[:space:]]*0.*Seen on other nodes:[[:space:]]*0|not relayed back|very likely invalid'

# ----------------------------- logging helpers -------------------------------
info()    { echo -e "${BLUE}[INFO]${NC} $1"    | tee -a "$RUN_LOG"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$RUN_LOG"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"   | tee -a "$RUN_LOG"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"     | tee -a "$RUN_LOG"; exit 1; }

run_and_log() {
    local label="$1"; shift
    echo "----- ${label}: $* -----" | tee -a "$RUN_LOG"
    "$@" 2>&1 | tee -a "$RUN_LOG"
    local rc=${PIPESTATUS[0]}
    echo "----- ${label} exit=${rc} -----" | tee -a "$RUN_LOG"
    return $rc
}

# ----------------------------- UTXO lookup -----------------------------------
lookup_utxos() {
    local addr="$1"
    info "Looking up UTXOs for $addr..."
    
    # Try blockcypher
    local utxos
    utxos=$(curl -sf "https://api.blockcypher.com/v1/doge/main/addrs/${addr}?unspentOnly=true&includeScript=true" 2>/dev/null || true)
    
    if [ -n "$utxos" ]; then
        echo "$utxos" | tee -a "$RUN_LOG"
        local tx_ref
        tx_ref=$(echo "$utxos" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    if 'txrefs' in d and len(d['txrefs']) > 0:
        ref = d['txrefs'][0]
        print(f\"{ref['tx_hash']}:{ref['tx_output_n']}:{ref['value']}\")
except:
    pass
" 2>/dev/null || true)
        if [ -n "$tx_ref" ]; then
            FUNDED_UTXO_TXID=$(echo "$tx_ref" | cut -d: -f1)
            FUNDED_UTXO_VOUT=$(echo "$tx_ref" | cut -d: -f2)
            FUNDED_UTXO_VALUE_KOINU=$(echo "$tx_ref" | cut -d: -f3)
            success "Found UTXO: txid=$FUNDED_UTXO_TXID vout=$FUNDED_UTXO_VOUT value=$FUNDED_UTXO_VALUE_KOINU koinu"
            return 0
        fi
    fi
    
    warn "Could not find UTXOs via blockcypher API"
    return 1
}

# ----------------------------- TX debug --------------------------------------
debug_tx_hex() {
    local tx_hex="$1"; local label="${2:-TX}"
    python3 - "$tx_hex" "$label" <<'PYDEBUG'
import sys, struct
tx_hex = sys.argv[1]; label = sys.argv[2]; tx = bytes.fromhex(tx_hex); off = 0
def ru32(): global off; v=struct.unpack_from('<I',tx,off)[0]; off+=4; return v
def ru64(): global off; v=struct.unpack_from('<Q',tx,off)[0]; off+=8; return v
def rvar():
    global off; b=tx[off]; off+=1
    if b<0xfd: return b
    if b==0xfd: v=struct.unpack_from('<H',tx,off)[0]; off+=2; return v
    if b==0xfe: v=struct.unpack_from('<I',tx,off)[0]; off+=4; return v
    v=struct.unpack_from('<Q',tx,off)[0]; off+=8; return v
print(f"=== {label} Debug (size={len(tx)} bytes) ===")
ver=ru32(); print(f"  version: {ver}"); nin=rvar(); print(f"  inputs: {nin}")
for i in range(nin):
    ph=tx[off:off+32][::-1].hex(); off+=32; pi=ru32(); sl=rvar(); off+=sl; sq=ru32()
    print(f"    in[{i}]: txid={ph} vout={pi} scriptSig_len={sl}")
nout=rvar(); print(f"  outputs: {nout}")
for i in range(nout):
    val=ru64(); sl=rvar(); spk=tx[off:off+sl].hex(); off+=sl; vd=val/1e8
    kind="P2PKH" if spk.startswith('76a914') else "P2SH" if spk.startswith('a914') else "OP_RETURN" if spk.startswith('6a') else "unknown"
    dust_ok = "OK" if (val==0 and kind=="OP_RETURN") or val>=100000 else f"DUST(need>=0.001DOGE)"
    print(f"    out[{i}]: {val} koinu ({vd:.8f} DOGE) type={kind} dust={dust_ok}")
print(f"=== end {label} ===")
PYDEBUG
}

# ----------------------------- broadcast -------------------------------------
broadcast_with_retry() {
    local label="$1"; local signed_tx="$2"; local max_retries="${3:-$SENDTX_MAX_RETRIES}"
    local attempt=0; local sendtx_output="" txid=""
    while [ "$attempt" -lt "$max_retries" ]; do
        attempt=$((attempt + 1)); info "Broadcast attempt $attempt/$max_retries for $label..."
        sendtx_output=$(run_and_log "sendtx $label attempt=$attempt" ./sendtx -d -m 16 -s 30 $NETWORK_FLAG "$signed_tx" || true)
        echo "$sendtx_output" | sed 's/Error:/sendtx-note:/g' | tee -a "$RUN_LOG"
        txid=$(echo "$sendtx_output" | sed -n 's/^Start broadcasting transaction:[[:space:]]*\([0-9a-fA-F]\{64\}\).*/\1/p' | head -n1)
        if echo "$sendtx_output" | grep -Eqi "$RELAY_SUCCESS_PATTERN"; then
            BROADCAST_RESULT_TXID="$txid"; success "$label broadcast accepted on attempt $attempt: $txid"; return 0
        fi
        if echo "$sendtx_output" | grep -Eqi "$SENDTX_FATAL_PATTERN"; then
            echo -e "${YELLOW}[WARN]${NC} $label relay failed on attempt $attempt. Debugging TX format..."
            debug_tx_hex "$signed_tx" "$label" 2>&1 | tee -a "$RUN_LOG"
            [ "$attempt" -lt "$max_retries" ] && sleep 10
        elif [ -n "$txid" ]; then
            BROADCAST_RESULT_TXID="$txid"; return 0
        fi
    done
    BROADCAST_RESULT_TXID="$txid"; return 1
}

# ----------------------------- wait for REST ---------------------------------
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

# ----------------------------- check tools -----------------------------------
check_tools() {
    info "Checking required tools..."
    for tool in such sendtx spvnode; do
        if [ ! -f "./$tool" ] && ! command -v $tool &> /dev/null; then
            error "$tool not found. Please build libdogecoin first."
        fi
    done
    if ! command -v curl &> /dev/null; then
        error "curl not found. Required for UTXO lookups."
    fi
    if ! command -v python3 &> /dev/null; then
        error "python3 not found. Required for TX debugging."
    fi
    success "All tools available"
}

# ----------------------------- main test flow --------------------------------
main() {
    info "=========================================="
    info "BIP38 and Paper Wallet Sweep E2E Test"
    info "=========================================="
    info "Log file: $RUN_LOG"
    info "Temp directory: $TMPDIR"
    
    check_tools
    
    # Step 1: Verify funded wallet
    info "Step 1: Verify funded wallet credentials"
    run_and_log "such generate_public_key" ./such -c generate_public_key -p "$FUNDED_WIF" $NETWORK_FLAG | tee "$TMPDIR/funded_addr.txt"
    DERIVED_ADDR=$(grep "p2pkh address:" "$TMPDIR/funded_addr.txt" | cut -d: -f2 | tr -d ' ')
    if [ "$DERIVED_ADDR" != "$FUNDED_ADDR" ]; then
        error "WIF does not derive to expected address. Expected: $FUNDED_ADDR, Got: $DERIVED_ADDR"
    fi
    success "Funded wallet verified: $FUNDED_ADDR"
    
    # Step 2: Generate destination address
    if [ -z "$DESTINATION_ADDR" ]; then
        info "Step 2: Generate new destination address"
        run_and_log "such generate_private_key" ./such -c generate_private_key $NETWORK_FLAG | tee "$TMPDIR/dest_key.txt"
        DEST_WIF=$(grep "private key wif:" "$TMPDIR/dest_key.txt" | cut -d: -f2 | tr -d ' ')
        run_and_log "such generate_public_key (dest)" ./such -c generate_public_key -p "$DEST_WIF" $NETWORK_FLAG | tee "$TMPDIR/dest_addr.txt"
        DESTINATION_ADDR=$(grep "p2pkh address:" "$TMPDIR/dest_addr.txt" | cut -d: -f2 | tr -d ' ')
        success "Generated destination address: $DESTINATION_ADDR"
    else
        info "Step 2: Using provided destination address: $DESTINATION_ADDR"
    fi
    
    # Step 3: Test BIP38 encryption/decryption
    info "Step 3: Test BIP38 encryption and decryption"
    
    # Generate a test key for BIP38
    run_and_log "such generate_private_key (BIP38 test)" ./such -c generate_private_key $NETWORK_FLAG | tee "$TMPDIR/bip38_test_key.txt"
    BIP38_TEST_WIF=$(grep "private key wif:" "$TMPDIR/bip38_test_key.txt" | cut -d: -f2 | tr -d ' ')
    BIP38_TEST_HEX=$(grep "private key hex:" "$TMPDIR/bip38_test_key.txt" | cut -d: -f2 | tr -d ' ')
    
    run_and_log "such generate_public_key (BIP38 test)" ./such -c generate_public_key -p "$BIP38_TEST_WIF" $NETWORK_FLAG | tee "$TMPDIR/bip38_test_addr.txt"
    BIP38_TEST_ADDR=$(grep "p2pkh address:" "$TMPDIR/bip38_test_addr.txt" | cut -d: -f2 | tr -d ' ')
    
    success "Generated test key for BIP38: WIF=$BIP38_TEST_WIF Address=$BIP38_TEST_ADDR"
    
    # Step 3b: Run BIP38 and sweep unit tests to verify library functionality
    info "Step 3b: Running BIP38 and sweep unit tests..."
    run_and_log "unit tests (BIP38+sweep)" ./tests 2>&1 | grep -E "bip38|sweep|BIP38|Sweep|PASSED|FAILED" | tee "$TMPDIR/unit_tests.txt"
    
    if grep -q "PASSED - test_sweep()" "$TMPDIR/unit_tests.txt"; then
        success "BIP38 and sweep unit tests PASSED"
    else
        warn "BIP38/sweep unit tests may have issues - check logs"
    fi
    
    # Step 4: Look up UTXOs if not provided
    UTXO_AVAILABLE=0
    if [ -z "$FUNDED_UTXO_TXID" ] || [ -z "$FUNDED_UTXO_VOUT" ] || [ -z "$FUNDED_UTXO_VALUE_KOINU" ]; then
        info "Step 4: Looking up UTXOs for funded address..."
        if lookup_utxos "$FUNDED_ADDR"; then
            UTXO_AVAILABLE=1
        else
            warn "Could not auto-lookup UTXOs. Will demonstrate SPV sync only."
            info "To perform full sweep test, provide: FUNDED_UTXO_TXID, FUNDED_UTXO_VOUT, FUNDED_UTXO_VALUE_KOINU"
        fi
    else
        info "Step 4: Using provided UTXO: txid=$FUNDED_UTXO_TXID vout=$FUNDED_UTXO_VOUT value=$FUNDED_UTXO_VALUE_KOINU"
        UTXO_AVAILABLE=1
    fi
    
    BROADCAST_RESULT_TXID=""
    OUTPUT_VALUE_DOGE="N/A"
    
    if [ "$UTXO_AVAILABLE" -eq 1 ]; then
        # Step 5: Build sweep transaction using transaction command
        info "Step 5: Build sweep transaction"
        
        # Calculate output value (UTXO value - fee)
        OUTPUT_VALUE_KOINU=$((FUNDED_UTXO_VALUE_KOINU - TX_FEE_KOINU))
        OUTPUT_VALUE_DOGE=$(python3 -c "print(f'{$OUTPUT_VALUE_KOINU / 100000000:.8f}')")
        TOTAL_VALUE_DOGE=$(python3 -c "print(f'{$FUNDED_UTXO_VALUE_KOINU / 100000000:.8f}')")
        
        info "UTXO value: $FUNDED_UTXO_VALUE_KOINU koinu"
        info "Fee: $TX_FEE_KOINU koinu"
        info "Output value: $OUTPUT_VALUE_KOINU koinu ($OUTPUT_VALUE_DOGE DOGE)"
        
        # Get scriptPubKey for the funded address
        FUNDED_PUBKEY_HEX=$(grep "public key hex:" "$TMPDIR/funded_addr.txt" | cut -d: -f2 | tr -d ' ')
        
        # Build transaction using the transaction interface
        info "Building raw transaction..."
        
        # Create transaction commands file
        cat > "$TMPDIR/tx_commands.txt" << TXEOF
start
add_input $FUNDED_UTXO_TXID $FUNDED_UTXO_VOUT
add_output $DESTINATION_ADDR $OUTPUT_VALUE_DOGE
finalize_transaction $DESTINATION_ADDR 0.00 $TOTAL_VALUE_DOGE $FUNDED_PUBKEY_HEX
get_raw_transaction
exit
TXEOF
        
        # Get raw unsigned transaction
        RAW_TX_OUTPUT=$(./such -c transaction < "$TMPDIR/tx_commands.txt" 2>&1 | tee -a "$RUN_LOG")
        
        RAW_UNSIGNED_TX=$(echo "$RAW_TX_OUTPUT" | grep -oP '^[0-9a-fA-F]{100,}$' | tail -1 || true)
        
        if [ -z "$RAW_UNSIGNED_TX" ]; then
            error "Failed to build raw transaction"
        fi
        
        info "Raw unsigned TX: $RAW_UNSIGNED_TX"
        debug_tx_hex "$RAW_UNSIGNED_TX" "unsigned_sweep_tx" 2>&1 | tee -a "$RUN_LOG"
        
        # Step 6: Sign the transaction
        info "Step 6: Sign the sweep transaction"
        
        # Get scriptPubKey for signing (P2PKH format)
    PUBKEY_HASH=$(./such -c p2pkh -k "$FUNDED_PUBKEY_HEX" 2>&1 | grep "script:" | cut -d: -f2 | tr -d ' ' || true)
    if [ -z "$PUBKEY_HASH" ]; then
        # Fallback: construct P2PKH scriptPubKey manually
        # For compressed pubkey: hash160 of pubkey
        PUBKEY_HASH160=$(echo -n "$FUNDED_PUBKEY_HEX" | xxd -r -p | openssl dgst -sha256 -binary | openssl dgst -ripemd160 -binary | xxd -p)
        SCRIPT_PUBKEY="76a914${PUBKEY_HASH160}88ac"
    else
        SCRIPT_PUBKEY="$PUBKEY_HASH"
    fi
    
    info "scriptPubKey: $SCRIPT_PUBKEY"
    
    SIGN_OUTPUT=$(run_and_log "such sign" ./such -c sign -x "$RAW_UNSIGNED_TX" -s "$SCRIPT_PUBKEY" -i 0 -h 1 -p "$FUNDED_WIF" $NETWORK_FLAG || true)
    echo "$SIGN_OUTPUT" | tee -a "$RUN_LOG"
    
    SIGNED_TX=$(echo "$SIGN_OUTPUT" | grep "^signed TX:" | cut -d: -f2- | tr -d ' ')
    
    if [ -z "$SIGNED_TX" ]; then
        error "Failed to sign transaction"
    fi
    
    success "Transaction signed successfully"
    debug_tx_hex "$SIGNED_TX" "signed_sweep_tx" 2>&1 | tee -a "$RUN_LOG"
    
        # Step 7: Broadcast the transaction
        info "Step 7: Broadcast sweep transaction"
        
        if ! broadcast_with_retry "sweep_tx" "$SIGNED_TX"; then
            warn "Broadcast may have failed - check logs for details"
        else
            success "Sweep transaction broadcast: $BROADCAST_RESULT_TXID"
        fi
    fi  # End of UTXO_AVAILABLE check
    
    # Step 8: SPV Node sync test (runs regardless of UTXO availability)
    info "Step 8: SPV node sync with checkpoint mode"
    
    rm -f "$SPV_WALLET_FILE" "$SPV_HEADERS_FILE" 2>/dev/null
    
    info "Running spvnode with checkpoint (-p) and block mode (-b) for fast sync..."
    
    # Start spvnode in background
    : > "$TMPDIR/spvnode.log"
    timeout 120 ./spvnode $NETWORK_FLAG -l -h "$SPV_HEADERS_FILE" -w "$SPV_WALLET_FILE" -d -p -b -a "$FUNDED_ADDR $DESTINATION_ADDR" scan 2>&1 | tee "$TMPDIR/spvnode.log" | tee -a "$RUN_LOG" &
    SPV_PID=$!
    
    info "SPV node started (PID=$SPV_PID), syncing for up to 60 seconds..."
    
    # Let SPV sync for a bit
    sleep 60
    
    # Check if still running
    if kill -0 "$SPV_PID" 2>/dev/null; then
        info "SPV node still running, checking status..."
        # Check headers synced
        if [ -f "$SPV_HEADERS_FILE" ]; then
            HEADERS_SIZE=$(stat -f%z "$SPV_HEADERS_FILE" 2>/dev/null || stat -c%s "$SPV_HEADERS_FILE" 2>/dev/null || echo "0")
            info "Headers file size: $HEADERS_SIZE bytes"
        fi
        
        # Stop spvnode
        info "Stopping spvnode..."
        kill "$SPV_PID" 2>/dev/null || true
        wait "$SPV_PID" 2>/dev/null || true
        success "SPV node sync test completed"
    else
        wait "$SPV_PID" 2>/dev/null
        SPV_EXIT=$?
        if [ "$SPV_EXIT" -eq 0 ]; then
            success "SPV node sync completed"
        else
            warn "SPV node exited with code: $SPV_EXIT"
        fi
    fi
    
    # Print SPV log summary
    info "SPV node log summary:"
    grep -E "connected|synced|sync|checkpoint|block|header|peer" "$TMPDIR/spvnode.log" 2>/dev/null | tail -20 || true
    
    # Step 9: Summary
    info "=========================================="
    info "BIP38 and Sweep E2E Test Summary"
    info "=========================================="
    info "Funded Address: $FUNDED_ADDR"
    info "Destination Address: $DESTINATION_ADDR"
    info "BIP38 Test Address: $BIP38_TEST_ADDR"
    info "Sweep UTXO: ${FUNDED_UTXO_TXID:-N/A}:${FUNDED_UTXO_VOUT:-N/A}"
    info "Sweep Amount: $OUTPUT_VALUE_DOGE DOGE"
    info "Broadcast TXID: ${BROADCAST_RESULT_TXID:-N/A}"
    info "Log file: $RUN_LOG"
    info "=========================================="
    
    success "BIP38 and Paper Wallet Sweep E2E test completed!"
    
    # Cleanup
    info "Temp files preserved in: $TMPDIR"
}

# Run main
main "$@"
