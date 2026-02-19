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
TESTNET_FLAG="-t"
TMPDIR="/tmp/falcon_testnet_$$"
mkdir -m 700 -p "$TMPDIR"
BROADCASTED=0

# Function to print colored messages
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
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
    
    # Check if built with liboqs
    if ! ./such -c help 2>&1 | grep -q falcon_keygen; then
        error "libdogecoin not built with liboqs support. Rebuild with --enable-liboqs"
    fi
    
    success "All tools available"
}

# Step 1: Generate testnet wallet
generate_testnet_wallet() {
    info "Step 1: Generating testnet wallet..."

    if [ -n "$TESTNET_PRIVKEY_WIF" ]; then
        PRIVKEY_WIF="$TESTNET_PRIVKEY_WIF"
        echo "private key wif: $PRIVKEY_WIF" > "$TMPDIR/testnet_key.txt"
    else
        ./such -c generate_private_key $TESTNET_FLAG > "$TMPDIR/testnet_key.txt"
        PRIVKEY_WIF=$(grep "^private key wif:" "$TMPDIR/testnet_key.txt" | cut -d: -f2 | tr -d ' ')
    fi

    ./such -c generate_public_key -p "$PRIVKEY_WIF" $TESTNET_FLAG > "$TMPDIR/testnet_addr.txt"
    TESTNET_ADDR=$(grep "p2pkh address:" "$TMPDIR/testnet_addr.txt" | cut -d: -f2 | tr -d ' ')
    PUBKEY=$(grep "^public key hex:" "$TMPDIR/testnet_addr.txt" | cut -d: -f2 | tr -d ' ')
    
    success "Testnet wallet generated"
    echo "  Address: $TESTNET_ADDR"
    echo "  Private Key (WIF): $PRIVKEY_WIF"
    echo "  Public Key: $PUBKEY"
    
    # Save to file for later use
    cat > "$TMPDIR/wallet.txt" <<EOF
TESTNET_ADDR=$TESTNET_ADDR
PRIVKEY_WIF=$PRIVKEY_WIF
PUBKEY=$PUBKEY
EOF
}

# Step 2: Get testnet coins
get_testnet_coins() {
    info "Step 2: Getting testnet coins..."
    
    echo ""
    echo "=========================================="
    echo "  REQUEST TESTNET COINS"
    echo "=========================================="
    echo ""
    echo "Send testnet DOGE to: $TESTNET_ADDR"
    echo ""
    echo "Faucets:"
    echo "  1. https://faucet.doge.toys/"
    echo "  2. https://faucet.triangleplatform.com/dogecoin/testnet"
    echo "  3. https://dogecoin-faucet.ruan.dev/"
    echo "  4. Discord: Dogecoin community #testnet channel"
    echo "  5. Reddit: r/dogecoindev"
    echo ""
    echo "Note: some faucets require browser CAPTCHA or may rate-limit by IP."
    echo ""
    warning "Press Enter after you have received coins..."
    read
    
    success "Assuming coins received. Continuing..."
}

# Step 3: Generate Falcon-512 keypair
generate_falcon_keypair() {
    info "Step 3: Generating Falcon-512 keypair..."
    
    ./such -c falcon_keygen > "$TMPDIR/falcon_keys.txt"
    
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

# Step 4: Sign message with Falcon-512
sign_message_falcon() {
    info "Step 4: Signing message with Falcon-512..."
    
    # Create a timestamped message
    MESSAGE="Falcon-512 testnet test: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    MESSAGE_HEX=$(echo -n "$MESSAGE" | xxd -p | tr -d '\n')
    
    info "Message: $MESSAGE"
    info "Message (hex): $MESSAGE_HEX"
    
    # Sign with Falcon
    ./such -c falcon_sign -p "$FALCON_SK" -x "$MESSAGE_HEX" > "$TMPDIR/falcon_sig.txt"
    
    FALCON_SIG=$(grep "^signature:" "$TMPDIR/falcon_sig.txt" | cut -d: -f2 | tr -d ' ')
    
    if [ -z "$FALCON_SIG" ]; then
        error "Failed to sign message"
    fi
    
    success "Message signed"
    echo "  Signature (${#FALCON_SIG} chars): ${FALCON_SIG:0:64}..."
    
    # Save to file
    cat >> "$TMPDIR/falcon_sig.txt" <<EOF
MESSAGE=$MESSAGE
MESSAGE_HEX=$MESSAGE_HEX
FALCON_SIG=$FALCON_SIG
EOF
}

# Step 5: Generate commitment
generate_commitment() {
    info "Step 5: Generating commitment..."
    
    ./such -c falcon_commit -k "$FALCON_PK" -s "$FALCON_SIG" > "$TMPDIR/falcon_commit.txt"
    
    FALCON_COMMIT=$(grep "^commitment:" "$TMPDIR/falcon_commit.txt" | cut -d: -f2 | tr -d ' ')
    
    if [ -z "$FALCON_COMMIT" ] || [ ${#FALCON_COMMIT} -ne 64 ]; then
        error "Failed to generate commitment (expected 64 hex chars, got ${#FALCON_COMMIT})"
    fi
    
    success "Commitment generated"
    echo "  Commitment (32 bytes): $FALCON_COMMIT"
    
    # Save to file
    cat >> "$TMPDIR/falcon_commit.txt" <<EOF
FALCON_COMMIT=$FALCON_COMMIT
EOF
}

# Step 6: Build transaction with OP_RETURN
build_transaction() {
    info "Step 6: Building transaction with OP_RETURN commit..."
    
    echo "Create an unsigned testnet transaction with such first:"
    echo "  ./such -c transaction"
    echo ""
    echo "Then paste the unsigned raw tx hex below."
    read -p "Enter unsigned raw tx hex: " RAW_UNSIGNED_TX
    read -p "Enter scriptPubKey hex for input 0 (UTXO being spent): " SCRIPT_PUBKEY

    ADD_COMMIT_OUTPUT=$(./such -c falcon_add_commit_tx -x "$RAW_UNSIGNED_TX" -s "$FALCON_COMMIT")
    TX_WITH_COMMIT=$(echo "$ADD_COMMIT_OUTPUT" | grep "^tx with commitment:" | cut -d: -f2- | tr -d ' ')

    if [ -z "$TX_WITH_COMMIT" ]; then
        echo "$ADD_COMMIT_OUTPUT"
        error "Failed to append Falcon commitment to transaction"
    fi

    info "Signing transaction with commitment output..."
    SIGN_OUTPUT=$(./such -c sign -x "$TX_WITH_COMMIT" -s "$SCRIPT_PUBKEY" -i 0 -h 1 -p "$PRIVKEY_WIF" $TESTNET_FLAG)
    SIGNED_TX=$(echo "$SIGN_OUTPUT" | grep "^signed TX:" | cut -d: -f2- | tr -d ' ')

    if [ -z "$SIGNED_TX" ]; then
        echo "$SIGN_OUTPUT"
        error "Failed to sign transaction"
    fi

    success "Signed transaction with Falcon commitment ready"
    echo "  Signed TX: ${SIGNED_TX:0:80}..."
    echo ""
    read -p "Broadcast now with sendtx? [y/N]: " DO_BROADCAST
    if [[ "$DO_BROADCAST" =~ ^[Yy]$ ]]; then
        ./sendtx $TESTNET_FLAG "$SIGNED_TX"
        success "Broadcast command submitted"
        BROADCASTED=1
    else
        warning "Skipping broadcast. You can run:"
        echo "  ./sendtx $TESTNET_FLAG $SIGNED_TX"
        BROADCASTED=0
    fi

    cat > "$TMPDIR/tx_info.txt" <<EOF
RAW_UNSIGNED_TX=$RAW_UNSIGNED_TX
TX_WITH_COMMIT=$TX_WITH_COMMIT
SCRIPT_PUBKEY=$SCRIPT_PUBKEY
SIGNED_TX=$SIGNED_TX
OPRETURN_SCRIPT=6a20${FALCON_COMMIT}
EOF
}

# Step 7: Monitor with SPV node
monitor_spvnode() {
    info "Step 7: Monitoring with SPV node..."
    
    echo ""
    echo "After broadcasting your transaction, monitor it with header-first sync:"
    echo ""
    echo "  # -l no prompt, -c continuous, -d debug, -x smpv, -p checkpoint, -a address"
    echo "  ./spvnode $TESTNET_FLAG -l -c -d -x -p -a \"$TESTNET_ADDR\" scan"
    echo ""
    echo "Then switch to full block scan mode (or use -b directly):"
    echo ""
    echo "  ./spvnode $TESTNET_FLAG -l -c -d -x -p -b -a \"$TESTNET_ADDR\" scan"
    echo ""
    echo "The SPV node will:"
    echo "  - Sync testnet blockchain headers"
    echo "  - Track wallet activity for: $TESTNET_ADDR"
    echo "  - Download and scan blocks in full mode"
    echo "  - Detect Falcon commitments"
    echo "  - Log: [falcon-commit] Valid at height=X txpos=Y commit=$FALCON_COMMIT"
    echo ""
    
    warning "SPV sync may take time. Be patient!"
    if [ "$BROADCASTED" -eq 1 ]; then
        read -p "Start header-first spvnode scan now? [y/N]: " RUN_SPV
        if [[ "$RUN_SPV" =~ ^[Yy]$ ]]; then
            ./spvnode $TESTNET_FLAG -l -c -d -x -p -a "$TESTNET_ADDR" scan
        fi
    fi
}

# Step 8: Verify commitment off-chain
verify_commitment() {
    info "Step 8: Verifying commitment off-chain..."
    
    echo ""
    echo "To verify the commitment off-chain:"
    echo ""
    echo "1. Verify the signature:"
    echo "   ./such -c falcon_verify -k $FALCON_PK \\"
    echo "                           -x $MESSAGE_HEX \\"
    echo "                           -s $FALCON_SIG"
    echo ""
    echo "2. Regenerate commitment and compare:"
    echo "   ./such -c falcon_commit -k $FALCON_PK -s $FALCON_SIG"
    echo "   Expected: $FALCON_COMMIT"
    echo ""
    echo "3. If both match, you've proven:"
    echo "   ✓ Message was signed with Falcon-512 private key"
    echo "   ✓ Commitment was published on testnet blockchain"
    echo "   ✓ Commitment can be verified without revealing full signature"
    echo ""
}

# Main workflow
main() {
    echo ""
    echo "=========================================="
    echo "  Falcon-512 Testnet Integration Test"
    echo "=========================================="
    echo ""
    
    check_tools
    generate_testnet_wallet
    get_testnet_coins
    generate_falcon_keypair
    sign_message_falcon
    generate_commitment
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
    echo "  - $TMPDIR/wallet.txt (testnet wallet)"
    echo "  - $TMPDIR/falcon_keys.txt (Falcon keypair)"
    echo "  - $TMPDIR/falcon_sig.txt (signature)"
    echo "  - $TMPDIR/falcon_commit.txt (commitment)"
    echo "  - $TMPDIR/tx_info.txt (transaction info)"
    echo ""
    
    echo "Next steps:"
    echo "1. Broadcast transaction with OP_RETURN containing: $FALCON_COMMIT"
    echo "2. Monitor with SPV node"
    echo "3. Verify commitment off-chain"
    echo ""
}

# Run main workflow
main
