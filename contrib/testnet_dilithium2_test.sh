#!/bin/bash
#
# Dilithium2 Testnet Integration Test Script
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

TESTNET_FLAG="-t"
TMPDIR=$(mktemp -d /tmp/dilithium2_testnet_XXXXXX)
chmod 700 "$TMPDIR"
BROADCASTED=0

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_tools() {
    info "Checking required tools..."
    for tool in such sendtx spvnode; do
        if [ ! -f "./$tool" ] && ! command -v $tool &> /dev/null; then
            error "$tool not found. Please build libdogecoin first."
        fi
    done
    if ! ./such -c help 2>&1 | grep -q dilithium2_keygen; then
        error "libdogecoin not built with Dilithium2 support. Rebuild with --enable-liboqs"
    fi
    if ! ./such -c help 2>&1 | grep -q tx_sighash32; then
        error "such missing tx_sighash32 command"
    fi
    success "All tools available"
}

generate_testnet_wallet() {
    info "Generating testnet wallet..."
    if [ -n "$TESTNET_PRIVKEY_WIF" ]; then
        PRIVKEY_WIF="$TESTNET_PRIVKEY_WIF"
    else
        ./such -c generate_private_key $TESTNET_FLAG > "$TMPDIR/testnet_key.txt"
        PRIVKEY_WIF=$(grep "^private key wif:" "$TMPDIR/testnet_key.txt" | cut -d: -f2 | tr -d ' ')
    fi
    ./such -c generate_public_key -p "$PRIVKEY_WIF" $TESTNET_FLAG > "$TMPDIR/testnet_addr.txt"
    TESTNET_ADDR=$(grep "p2pkh address:" "$TMPDIR/testnet_addr.txt" | cut -d: -f2 | tr -d ' ')
    success "Wallet ready: $TESTNET_ADDR"
}

get_testnet_coins() {
    echo ""
    echo "Send testnet DOGE to: $TESTNET_ADDR"
    echo "Faucet: https://faucet.doge.toys/"
    warning "Press Enter after funding the address..."
    read
}

generate_dilithium2_keypair() {
    info "Generating Dilithium2 keypair..."
    ./such -c dilithium2_keygen > "$TMPDIR/dilithium2_keys.txt"
    DILITHIUM2_PK=$(grep "^public key:" "$TMPDIR/dilithium2_keys.txt" | cut -d: -f2 | tr -d ' ')
    DILITHIUM2_SK=$(grep "^secret key:" "$TMPDIR/dilithium2_keys.txt" | cut -d: -f2 | tr -d ' ')
    [ -n "$DILITHIUM2_PK" ] || error "Failed to generate Dilithium2 keypair"
    success "Dilithium2 keypair generated"
}

sign_message_dilithium2() {
    info "Signing tx_sighash32 with Dilithium2..."
    ./such -c dilithium2_sign -p "$DILITHIUM2_SK" -x "$TX_SIGHASH_HEX" > "$TMPDIR/dilithium2_sig.txt"
    DILITHIUM2_SIG=$(grep "^signature:" "$TMPDIR/dilithium2_sig.txt" | cut -d: -f2 | tr -d ' ')
    [ -n "$DILITHIUM2_SIG" ] || error "Failed to sign tx_sighash32"
    success "tx_sighash32 signed"
}

generate_commitment() {
    info "Generating Dilithium2 commitment..."
    ./such -c dilithium2_commit -k "$DILITHIUM2_PK" -s "$DILITHIUM2_SIG" > "$TMPDIR/dilithium2_commit.txt"
    DILITHIUM2_COMMIT=$(grep "^commitment:" "$TMPDIR/dilithium2_commit.txt" | cut -d: -f2 | tr -d ' ')
    [ "${#DILITHIUM2_COMMIT}" -eq 64 ] || error "Invalid commitment length"
    success "Commitment generated: $DILITHIUM2_COMMIT"
}

build_transaction() {
    info "Build unsigned testnet tx with such, then paste hex below:"
    read -p "Enter unsigned raw tx hex: " RAW_UNSIGNED_TX
    read -p "Enter scriptPubKey hex for input 0: " SCRIPT_PUBKEY

    SIGHASH_OUTPUT=$(./such -c tx_sighash32 -x "$RAW_UNSIGNED_TX" -s "$SCRIPT_PUBKEY" -i 0 -h 1)
    TX_SIGHASH_HEX=$(echo "$SIGHASH_OUTPUT" | grep "^tx_sighash32:" | cut -d: -f2 | tr -d ' ')
    [ -n "$TX_SIGHASH_HEX" ] || error "Failed to derive tx_sighash32"
    [ "${#TX_SIGHASH_HEX}" -eq 64 ] || error "Invalid tx_sighash32 length"
    info "tx_sighash32: $TX_SIGHASH_HEX"
    sign_message_dilithium2
    generate_commitment

    ADD_COMMIT_OUTPUT=$(./such -c dilithium2_add_commit_tx -x "$RAW_UNSIGNED_TX" -s "$DILITHIUM2_COMMIT")
    TX_WITH_COMMIT=$(echo "$ADD_COMMIT_OUTPUT" | grep "^tx with commitment:" | cut -d: -f2- | tr -d ' ')
    [ -n "$TX_WITH_COMMIT" ] || error "Failed to append Dilithium2 commitment"

    SIGN_OUTPUT=$(./such -c sign -x "$TX_WITH_COMMIT" -s "$SCRIPT_PUBKEY" -i 0 -h 1 -p "$PRIVKEY_WIF" $TESTNET_FLAG)
    SIGNED_TX=$(echo "$SIGN_OUTPUT" | grep "^signed TX:" | cut -d: -f2- | tr -d ' ')
    [ -n "$SIGNED_TX" ] || error "Failed to sign transaction"

    read -p "Broadcast now with sendtx? [y/N]: " DO_BROADCAST
    if [[ "$DO_BROADCAST" =~ ^[Yy]$ ]]; then
        ./sendtx $TESTNET_FLAG "$SIGNED_TX"
        BROADCASTED=1
    else
        BROADCASTED=0
    fi
}

monitor_spvnode() {
    info "Monitor with spvnode:"
    echo "  ./spvnode $TESTNET_FLAG -l -c -d -x -p -a \"$TESTNET_ADDR\" scan"
    echo "Then full mode:"
    echo "  ./spvnode $TESTNET_FLAG -l -c -d -x -p -b -a \"$TESTNET_ADDR\" scan"
    echo "Expected log:"
    echo "  [dilithium-commit] Valid at height=X txpos=Y commit=$DILITHIUM2_COMMIT"
}

verify_commitment() {
    info "Off-chain verification commands:"
    echo "  ./such -c dilithium2_verify -k $DILITHIUM2_PK -x $TX_SIGHASH_HEX -s $DILITHIUM2_SIG"
    echo "  ./such -c dilithium2_commit -k $DILITHIUM2_PK -s $DILITHIUM2_SIG"
    echo "  Expected: $DILITHIUM2_COMMIT"
}

main() {
    echo ""
    echo "=========================================="
    echo "  Dilithium2 Testnet Integration Test"
    echo "=========================================="
    echo ""
    check_tools
    generate_testnet_wallet
    get_testnet_coins
    generate_dilithium2_keypair
    build_transaction
    monitor_spvnode
    verify_commitment
    success "All test data saved in: $TMPDIR"
}

main
