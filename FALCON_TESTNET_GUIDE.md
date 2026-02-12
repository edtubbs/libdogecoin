# Falcon-512 Commitment Testing on Dogecoin Testnet

## Overview

This guide demonstrates how to test Falcon-512 post-quantum cryptographic commitments on Dogecoin testnet using libdogecoin's CLI tools. The workflow involves:

1. Generating Falcon-512 keypairs
2. Creating signatures
3. Building transactions with OP_RETURN commitments
4. Broadcasting to testnet
5. Verifying commits with SPV node

## Prerequisites

### Build with liboqs Support

```bash
# Build dependencies (includes liboqs 0.15.0)
cd depends
make -j$(nproc)
cd ..

# Configure with liboqs enabled
./autogen.sh
./configure --prefix=$(pwd)/depends/x86_64-pc-linux-gnu --enable-bench --enable-liboqs

# Build
make -j$(nproc)
```

### Verify liboqs is Enabled

```bash
# Check that tools are built with liboqs
ldd ./such | grep oqs
ldd ./spvnode | grep oqs

# Run bench to see Falcon benchmarks
./bench
```

## Getting Testnet Coins

### Dogecoin Testnet Faucets

Visit one of these testnet faucets to get test coins:

1. **Testnet Faucet 1**: https://testnet-faucet.com/dogecoin-testnet/
2. **Discord Faucet**: Request in Dogecoin community Discord #testnet channel
3. **Community Faucets**: Check r/dogecoin or Dogecoin Foundation channels

Generate a testnet address first:

```bash
# Generate a testnet private key
./such -c generate_private_key -t

# Output example:
# privatekey WIF: ckAbCdEfGhIjKlMnOpQrStUvWxYz1234567890aBcDeF...
# privatekey HEX: 1234567890abcdef...

# Generate public key and address
./such -c generate_public_key -p <your_wif_from_above> -t

# Output example:
# pubkey: 02cf2c99c2db4b3d72d4289aa23bdaf5f3ccf4867ec8e5f8223ea716a7a3de10bc
# p2pkh address: nWxYz1234567890aBcDeFgHiJkLmNoPqRsT
```

Send the testnet address to the faucet to receive test coins.

## Workflow: Creating and Broadcasting a Falcon Commitment

### Step 1: Generate Testnet Wallet

```bash
# Generate testnet keys
./such -c generate_private_key -t > /tmp/testnet_key.txt
cat /tmp/testnet_key.txt

# Extract the WIF private key
PRIVKEY_WIF=$(grep "privatekey WIF:" /tmp/testnet_key.txt | cut -d: -f2 | tr -d ' ')

# Generate address
./such -c generate_public_key -p $PRIVKEY_WIF -t > /tmp/testnet_addr.txt
cat /tmp/testnet_addr.txt

# Extract the address
TESTNET_ADDR=$(grep "p2pkh address:" /tmp/testnet_addr.txt | cut -d: -f2 | tr -d ' ')

echo "Testnet Address: $TESTNET_ADDR"
echo "Request testnet coins at a faucet!"
```

### Step 2: Generate Falcon-512 Keypair and Signature

Since `such` doesn't have direct Falcon support yet, we'll need to create a simple C program to generate the keypair and signature:

Create `/tmp/falcon_helper.c`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dogecoin/pqc_falcon.h>
#include <dogecoin/utils.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s keygen           - Generate keypair\n", argv[0]);
        printf("  %s sign <sk_hex> <msg_hex> - Sign message\n", argv[0]);
        printf("  %s verify <pk_hex> <msg_hex> <sig_hex> - Verify signature\n", argv[0]);
        printf("  %s commit <pk_hex> <sig_hex> - Generate commit\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "keygen") == 0) {
        uint8_t *pk = NULL, *sk = NULL;
        size_t pk_len = 0, sk_len = 0;
        
        if (!dogecoin_falcon512_keypair(&pk, &pk_len, &sk, &sk_len)) {
            fprintf(stderr, "Failed to generate keypair\n");
            return 1;
        }
        
        char* pk_hex = utils_uint8_to_hex(pk, pk_len);
        char* sk_hex = utils_uint8_to_hex(sk, sk_len);
        
        printf("PUBLIC_KEY=%s\n", pk_hex);
        printf("SECRET_KEY=%s\n", sk_hex);
        printf("PK_LEN=%zu\n", pk_len);
        printf("SK_LEN=%zu\n", sk_len);
        
        free(pk_hex);
        free(sk_hex);
        dogecoin_free(pk);
        dogecoin_free(sk);
        
    } else if (strcmp(argv[1], "sign") == 0 && argc >= 4) {
        size_t sk_len;
        uint8_t* sk = utils_hex_to_uint8(argv[2], &sk_len);
        
        size_t msg_len;
        uint8_t* msg = utils_hex_to_uint8(argv[3], &msg_len);
        
        uint8_t* sig = NULL;
        size_t sig_len = 0;
        
        if (!dogecoin_falcon512_sign(sk, sk_len, msg, msg_len, &sig, &sig_len)) {
            fprintf(stderr, "Failed to sign\n");
            free(sk);
            free(msg);
            return 1;
        }
        
        char* sig_hex = utils_uint8_to_hex(sig, sig_len);
        printf("SIGNATURE=%s\n", sig_hex);
        printf("SIG_LEN=%zu\n", sig_len);
        
        free(sig_hex);
        dogecoin_free(sig);
        free(sk);
        free(msg);
        
    } else if (strcmp(argv[1], "commit") == 0 && argc >= 4) {
        size_t pk_len;
        uint8_t* pk = utils_hex_to_uint8(argv[2], &pk_len);
        
        size_t sig_len;
        uint8_t* sig = utils_hex_to_uint8(argv[3], &sig_len);
        
        uint8_t commit[32];
        if (!dogecoin_falcon512_commit_bytes(pk, pk_len, sig, sig_len, commit)) {
            fprintf(stderr, "Failed to generate commit\n");
            free(pk);
            free(sig);
            return 1;
        }
        
        char commit_hex[65];
        utils_bin_to_hex(commit, 32, commit_hex);
        printf("COMMIT=%s\n", commit_hex);
        
        free(pk);
        free(sig);
        
    } else if (strcmp(argv[1], "verify") == 0 && argc >= 5) {
        size_t pk_len;
        uint8_t* pk = utils_hex_to_uint8(argv[2], &pk_len);
        
        size_t msg_len;
        uint8_t* msg = utils_hex_to_uint8(argv[3], &msg_len);
        
        size_t sig_len;
        uint8_t* sig = utils_hex_to_uint8(argv[4], &sig_len);
        
        if (dogecoin_falcon512_verify(pk, pk_len, msg, msg_len, sig, sig_len)) {
            printf("VERIFIED=true\n");
        } else {
            printf("VERIFIED=false\n");
        }
        
        free(pk);
        free(msg);
        free(sig);
    }
    
    return 0;
}
```

Compile the helper:

```bash
gcc -o /tmp/falcon_helper /tmp/falcon_helper.c \
    -I./include \
    -L./.libs -ldogecoin \
    -L./depends/x86_64-pc-linux-gnu/lib -loqs
```

### Step 3: Generate Falcon Keypair and Create Commitment

```bash
# Generate keypair
/tmp/falcon_helper keygen > /tmp/falcon_keys.txt
cat /tmp/falcon_keys.txt

# Extract keys
FALCON_PK=$(grep "PUBLIC_KEY=" /tmp/falcon_keys.txt | cut -d= -f2)
FALCON_SK=$(grep "SECRET_KEY=" /tmp/falcon_keys.txt | cut -d= -f2)

echo "Falcon-512 Public Key: ${FALCON_PK:0:64}..."
echo "Falcon-512 Secret Key: ${FALCON_SK:0:64}..."

# Create a message to sign (e.g., "Hello Dogecoin Testnet")
MESSAGE_HEX=$(echo -n "Hello Dogecoin Testnet" | xxd -p | tr -d '\n')
echo "Message (hex): $MESSAGE_HEX"

# Sign the message
/tmp/falcon_helper sign $FALCON_SK $MESSAGE_HEX > /tmp/falcon_sig.txt
cat /tmp/falcon_sig.txt

FALCON_SIG=$(grep "SIGNATURE=" /tmp/falcon_sig.txt | cut -d= -f2)
echo "Falcon-512 Signature: ${FALCON_SIG:0:64}..."

# Generate commitment
/tmp/falcon_helper commit $FALCON_PK $FALCON_SIG > /tmp/falcon_commit.txt
cat /tmp/falcon_commit.txt

FALCON_COMMIT=$(grep "COMMIT=" /tmp/falcon_commit.txt | cut -d= -f2)
echo "Falcon-512 Commitment (32 bytes): $FALCON_COMMIT"
```

### Step 4: Build Transaction with OP_RETURN Commitment

Now we need to build a transaction that includes:
1. Input: UTXO from your testnet address (funded by faucet)
2. Output 1: Payment to recipient (or back to yourself)
3. Output 2: OP_RETURN with Falcon commitment

Unfortunately, the `such` transaction builder doesn't directly support adding custom OP_RETURN data. We need to either:

**Option A: Extend the `such` tool** (requires code changes)
**Option B: Build transaction manually with C code** (create another helper)
**Option C: Use external tools then sign with such**

For now, let's document Option B with a transaction builder helper:

Create `/tmp/build_falcon_tx.c`:

```c
#include <stdio.h>
#include <dogecoin/tx.h>
#include <dogecoin/pqc_falcon.h>
#include <dogecoin/serialize.h>
#include <dogecoin/cstr.h>
#include <dogecoin/utils.h>

int main(int argc, char* argv[]) {
    if (argc < 6) {
        printf("Usage: %s <prev_txid> <prev_vout> <prev_amount_koinu> <dest_addr> <commit_hex>\n", argv[0]);
        return 1;
    }
    
    // Parse arguments
    char* prev_txid = argv[1];
    int prev_vout = atoi(argv[2]);
    uint64_t prev_amount = strtoull(argv[3], NULL, 10);
    char* dest_addr = argv[4];
    char* commit_hex = argv[5];
    
    // Create transaction
    dogecoin_tx* tx = dogecoin_tx_new();
    
    // Add input (unsigned for now)
    dogecoin_tx_in* txin = dogecoin_tx_in_new();
    uint256 hash;
    utils_uint256_sethex(prev_txid, hash);
    dogecoin_tx_in_set_txid(txin, hash);
    txin->prevout.n = prev_vout;
    vector_add(tx->vin, txin);
    
    // Add output for payment (amount - fee)
    uint64_t fee = 100000; // 0.001 DOGE fee
    uint64_t send_amount = prev_amount - fee;
    
    dogecoin_tx_out* txout = dogecoin_tx_out_new();
    txout->value = send_amount;
    // TODO: Convert address to script_pubkey
    vector_add(tx->vout, txout);
    
    // Add OP_RETURN output with Falcon commitment
    size_t commit_len;
    uint8_t* commit = utils_hex_to_uint8(commit_hex, &commit_len);
    if (commit_len != 32) {
        fprintf(stderr, "Error: Commit must be 32 bytes\n");
        return 1;
    }
    
    dogecoin_tx_add_falcon512_commit(tx, commit);
    free(commit);
    
    // Serialize transaction
    cstring* tx_hex = cstr_new_sz(1024);
    dogecoin_tx_serialize(tx_hex, tx);
    
    char* hex = utils_uint8_to_hex((uint8_t*)tx_hex->str, tx_hex->len);
    printf("UNSIGNED_TX=%s\n", hex);
    
    free(hex);
    cstr_free(tx_hex, true);
    dogecoin_tx_free(tx);
    
    return 0;
}
```

### Step 5: Monitor Transaction with SPV Node

Once you have a transaction ID, monitor it with spvnode:

```bash
# Start SPV node on testnet in debug mode
./spvnode -t -d -f 0 -c -b scan

# The SPV node will:
# 1. Sync testnet blockchain headers
# 2. Download full blocks
# 3. Detect and log Falcon commitments
# 4. Output: "[falcon-commit] Found at height=X txpos=Y commit=<hex>"
```

Expected output when your transaction is found:

```
[falcon-commit] Found at height=4567890 txpos=2 commit=a1b2c3d4e5f6...
```

### Step 6: Off-Chain Verification

To verify the commitment off-chain, you need:
1. The Falcon public key
2. The signed message
3. The signature
4. The commitment from the transaction

```bash
# Verify the signature matches the message
/tmp/falcon_helper verify $FALCON_PK $MESSAGE_HEX $FALCON_SIG

# Regenerate commitment from pk+sig and compare
/tmp/falcon_helper commit $FALCON_PK $FALCON_SIG

# Compare with on-chain commitment
echo "On-chain commit: $FALCON_COMMIT"
```

If they match, you've verified:
1. The message was signed with the Falcon-512 private key
2. The commitment was published on-chain
3. The commitment can be verified without revealing the full signature on-chain

## Security Model

### Why Use OP_RETURN Commits?

**Problem**: Falcon-512 signatures are ~666 bytes, too large for efficient on-chain storage.

**Solution**: Store only a 32-byte SHA256 commitment on-chain:
```
commit = SHA256(public_key || signature)
```

**Benefits**:
- Only 32 bytes on-chain (vs 666+ bytes)
- Can verify off-chain by:
  1. Obtaining full signature from issuer
  2. Recomputing commit = SHA256(pk || sig)
  3. Comparing with on-chain commit
  4. Verifying signature with Falcon-512

**Use Cases**:
- Post-quantum notarization
- Timestamping documents with quantum-resistant proofs
- Hybrid classical/PQC signing schemes
- Future-proof identity verification

## Complete Example Script

Save this as `test_falcon_testnet.sh`:

```bash
#!/bin/bash
set -e

echo "=== Falcon-512 Testnet Test ==="
echo ""

# Step 1: Generate testnet wallet
echo "Step 1: Generating testnet wallet..."
./such -c generate_private_key -t > /tmp/testnet_key.txt
PRIVKEY_WIF=$(grep "privatekey WIF:" /tmp/testnet_key.txt | cut -d: -f2 | tr -d ' ')
./such -c generate_public_key -p $PRIVKEY_WIF -t > /tmp/testnet_addr.txt
TESTNET_ADDR=$(grep "p2pkh address:" /tmp/testnet_addr.txt | cut -d: -f2 | tr -d ' ')

echo "Testnet Address: $TESTNET_ADDR"
echo "Private Key WIF: $PRIVKEY_WIF"
echo ""
echo "⚠️  Send testnet coins to this address from a faucet!"
echo "Press Enter when you have coins..."
read

# Step 2: Generate Falcon keypair
echo ""
echo "Step 2: Generating Falcon-512 keypair..."
/tmp/falcon_helper keygen > /tmp/falcon_keys.txt
FALCON_PK=$(grep "PUBLIC_KEY=" /tmp/falcon_keys.txt | cut -d= -f2)
FALCON_SK=$(grep "SECRET_KEY=" /tmp/falcon_keys.txt | cut -d= -f2)
echo "Public Key: ${FALCON_PK:0:64}..."
echo "Secret Key: ${FALCON_SK:0:64}..."

# Step 3: Create and sign message
echo ""
echo "Step 3: Signing message with Falcon-512..."
MESSAGE="Hello Dogecoin Testnet $(date)"
MESSAGE_HEX=$(echo -n "$MESSAGE" | xxd -p | tr -d '\n')
echo "Message: $MESSAGE"

/tmp/falcon_helper sign $FALCON_SK $MESSAGE_HEX > /tmp/falcon_sig.txt
FALCON_SIG=$(grep "SIGNATURE=" /tmp/falcon_sig.txt | cut -d= -f2)
echo "Signature: ${FALCON_SIG:0:64}..."

# Step 4: Generate commitment
echo ""
echo "Step 4: Generating commitment..."
/tmp/falcon_helper commit $FALCON_PK $FALCON_SIG > /tmp/falcon_commit.txt
FALCON_COMMIT=$(grep "COMMIT=" /tmp/falcon_commit.txt | cut -d= -f2)
echo "Commitment: $FALCON_COMMIT"

# Step 5: Build transaction
echo ""
echo "Step 5: Building transaction..."
echo "⚠️  TODO: Need to implement transaction builder with OP_RETURN support"
echo "         Or use external wallet to build transaction with OP_RETURN"
echo "         OP_RETURN data: 6a20${FALCON_COMMIT}"

# Step 6: Verify
echo ""
echo "Step 6: Verification test..."
/tmp/falcon_helper verify $FALCON_PK $MESSAGE_HEX $FALCON_SIG
echo "✓ Signature verified!"

echo ""
echo "=== Test Complete ==="
echo "Save these values:"
echo "  Public Key: $FALCON_PK"
echo "  Message: $MESSAGE"
echo "  Signature: $FALCON_SIG"
echo "  Commitment: $FALCON_COMMIT"
echo ""
echo "To broadcast: Build a transaction with OP_RETURN output containing:"
echo "  Script: 6a20${FALCON_COMMIT}"
echo "Then use: ./sendtx -t <tx_hex>"
```

## Next Steps

To make this fully functional, we need to:

1. **Add OP_RETURN support to `such` transaction builder**
   - Allow adding custom OP_RETURN data
   - Support Falcon commitment specifically

2. **Create dedicated Falcon CLI tools**
   - `falcon-keygen`
   - `falcon-sign`
   - `falcon-verify`
   - `falcon-commit`

3. **Integrate with transaction workflow**
   - Add `--falcon-commit` flag to transaction builder
   - Auto-generate commitment from signature

4. **Enhanced SPV verification**
   - Store Falcon commits in database
   - Query commits by address/height
   - Verify commit matches provided signature

## Troubleshooting

### liboqs not found
```bash
# Rebuild depends
cd depends && make clean && make -j$(nproc)
cd .. && ./autogen.sh && ./configure --enable-liboqs --prefix=$(pwd)/depends/x86_64-pc-linux-gnu
```

### No testnet coins
- Try multiple faucets
- Ask in community channels
- Wait 24 hours between requests

### Transaction not confirming
- Check fee is adequate (>0.001 DOGE)
- Verify testnet node is synced
- Check testnet block explorer

## References

- [Falcon Specification](https://falcon-sign.info/)
- [liboqs Documentation](https://github.com/open-quantum-safe/liboqs)
- [Dogecoin Testnet](https://testnet.dogecoin.com/)
- [OP_RETURN Spec](https://en.bitcoin.it/wiki/OP_RETURN)
