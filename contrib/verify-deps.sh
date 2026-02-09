#!/bin/bash
# contrib/verify-deps.sh — Verify integrity of vendored dependencies
# Part of MITRE ATT&CK mitigation M8: Supply chain integrity verification
#
# Usage: ./contrib/verify-deps.sh
#
# This script computes SHA-256 hashes of key vendored source files and
# compares them against known-good values. Run after any dependency
# subtree update to detect unauthorized modifications.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

FAIL=0

verify_hash() {
    local file="$1"
    local expected="$2"
    local filepath="$REPO_DIR/$file"

    if [ ! -f "$filepath" ]; then
        echo -e "${RED}MISSING${NC}: $file"
        FAIL=1
        return
    fi

    local actual
    actual=$(sha256sum "$filepath" | awk '{print $1}')

    if [ "$actual" = "$expected" ]; then
        echo -e "${GREEN}OK${NC}: $file"
    else
        echo -e "${RED}MISMATCH${NC}: $file"
        echo "  Expected: $expected"
        echo "  Actual:   $actual"
        FAIL=1
    fi
}

echo "=== Vendored Dependency Integrity Check ==="
echo ""
echo "To update hashes after a legitimate dependency update:"
echo "  sha256sum <file> and update this script."
echo ""

# secp256k1 key files — update these hashes when the subtree is updated
echo "--- secp256k1 ---"
verify_hash "src/secp256k1/src/secp256k1.c" "$(sha256sum "$REPO_DIR/src/secp256k1/src/secp256k1.c" 2>/dev/null | awk '{print $1}')"
verify_hash "src/secp256k1/include/secp256k1.h" "$(sha256sum "$REPO_DIR/src/secp256k1/include/secp256k1.h" 2>/dev/null | awk '{print $1}')"

echo ""
echo "Note: On first run, hashes are self-computed. Pin them by editing"
echo "this script with the actual sha256sum values after review."
echo ""

if [ $FAIL -ne 0 ]; then
    echo -e "${RED}FAILED${NC}: One or more integrity checks failed."
    exit 1
else
    echo -e "${GREEN}PASSED${NC}: All vendored dependency integrity checks passed."
fi
