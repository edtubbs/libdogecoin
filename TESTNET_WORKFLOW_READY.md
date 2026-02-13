# Testnet Falcon-512 Workflow - Ready to Execute

## Build Status: ✅ Complete

All tools have been successfully built with liboqs and network support enabled.

### Built Tools

```bash
$ ls -lh such sendtx spvnode
-rwxr-xr-x 1 runner runner  13M Feb 13 02:05 such      # Falcon commands + wallet
-rwxr-xr-x 1 runner runner 2.0M Feb 13 02:05 sendtx    # TX broadcasting
-rwxr-xr-x 1 runner runner  13M Feb 13 02:05 spvnode   # SPV + commit detection
```

### Configuration
```
Options used to compile and link:
  with tests      = yes
  with bench      = yes
  with tools      = yes
  with net        = yes ✅
  with logdb      = yes
  with wallet     = yes
  liboqs          = yes ✅ (version 0.15.0)
  
  LIBS            = -levent -levent_core -levent_extra -loqs
```

## Falcon-512 Commands Available in `such`

### 1. Generate Keypair
```bash
./such -c falcon_keygen

# Output:
# public key:  <1794 hex characters> (897 bytes)
# secret key:  <2562 hex characters> (1281 bytes)
# pk length:   897 bytes
# sk length:   1281 bytes
```

### 2. Sign Message
```bash
./such -c falcon_sign -p <secret_key_hex> -x <message_hex>

# Output:
# signature: <hex_signature>
```

### 3. Verify Signature
```bash
./such -c falcon_verify -k <public_key_hex> -x <message_hex> -s <signature_hex>

# Output:
# ✓ Signature is VALID
# or
# ✗ Signature is INVALID
```

### 4. Generate Commitment
```bash
./such -c falcon_commit -k <public_key_hex> -s <signature_hex>

# Output:
# commit: <32_byte_hex> (SHA256 of pk||sig)
```

## Complete Testnet Workflow

### Step 1: Generate Testnet Wallet
```bash
# Generate private key
./such -c generate_private_key -t

# Output will include WIF private key
# Example: cjFyb89xxZCjp6B4y3syywq8Ko98DH5ofxrgKGf7QDDmoXKNs2zs

# Generate address from private key
./such -c generate_public_key -t -p <wif_private_key>

# Output will include p2pkh address
# Example: nq6cNXHFfn16t5ZNNJRt3uVog6kECGdHmT
```

### Step 2: Get Testnet Coins
Visit a Dogecoin testnet faucet:
- Search for "Dogecoin testnet faucet"
- Enter your testnet address from Step 1
- Request test DOGE

### Step 3: Generate Falcon-512 Keypair
```bash
./such -c falcon_keygen > /tmp/falcon_keys.txt

# Extract keys from output
FALCON_PK=$(grep "^public key:" /tmp/falcon_keys.txt | awk '{print $3}')
FALCON_SK=$(grep "^secret key:" /tmp/falcon_keys.txt | awk '{print $3}')

echo "Public Key: $FALCON_PK"
echo "Secret Key: $FALCON_SK"
```

### Step 4: Sign a Message
```bash
# Create a test message
TEST_MSG="48656c6c6f2c20446f676521"  # "Hello, Doge!" in hex

# Sign the message
./such -c falcon_sign -p "$FALCON_SK" -x "$TEST_MSG" > /tmp/falcon_sig.txt

# Extract signature
FALCON_SIG=$(grep "^signature:" /tmp/falcon_sig.txt | awk '{print $2}')
echo "Signature: $FALCON_SIG"
```

### Step 5: Verify Signature (Optional)
```bash
./such -c falcon_verify -k "$FALCON_PK" -x "$TEST_MSG" -s "$FALCON_SIG"
```

### Step 6: Generate Commitment
```bash
./such -c falcon_commit -k "$FALCON_PK" -s "$FALCON_SIG" > /tmp/falcon_commit.txt

# Extract commitment
FALCON_COMMIT=$(grep "^commit:" /tmp/falcon_commit.txt | awk '{print $2}')
echo "Commitment: $FALCON_COMMIT"
```

### Step 7: Build Transaction with OP_RETURN

The Falcon commit needs to be included in a transaction as an OP_RETURN output.

**Transaction Structure:**
```
Inputs:
  - Your testnet UTXO (from faucet coins)

Outputs:
  - Output 0: Recipient address (can be yourself)
  - Output 1: OP_RETURN <FALCON_COMMIT>
```

**Building the Transaction:**

You can use the libdogecoin API to build a transaction with OP_RETURN:
```c
// C code example
dogecoin_tx* tx = dogecoin_tx_new();

// Add your input (from testnet coins)
dogecoin_tx_add_input(...);

// Add recipient output
dogecoin_tx_add_output(...);

// Add Falcon commit as OP_RETURN
uint8_t commit[32];
// ... (decode FALCON_COMMIT hex to bytes)
dogecoin_tx_add_falcon512_commit(tx, commit);

// Sign and serialize transaction
// ... (use standard libdogecoin TX signing)
```

### Step 8: Broadcast Transaction
```bash
# Once you have the raw signed transaction hex
./sendtx -t <raw_transaction_hex>

# This will broadcast to Dogecoin testnet
```

### Step 9: Monitor with SPV Node
```bash
# Start SPV node on testnet
./spvnode -t

# The SPV node will automatically detect Falcon commits:
# Output will show:
# [falcon-commit] Found at height=<block_height> txpos=<position> commit=<hex>
```

### Step 10: Off-Chain Verification

Once the transaction is confirmed, anyone can:
1. Download the block containing your transaction
2. Extract the OP_RETURN commit from the transaction
3. Verify the commit matches SHA256(public_key || signature)
4. Verify the signature is valid for the message
5. All done off-chain without exposing the large Falcon signature on-chain!

## Automated Testing Script

We've provided an automated script at `contrib/testnet_falcon_test.sh`:

```bash
./contrib/testnet_falcon_test.sh
```

This script will:
- Check for required tools
- Generate testnet wallet
- Generate Falcon keypair
- Sign test messages
- Generate commitments
- Guide you through getting testnet coins
- Provide instructions for building and broadcasting transactions

## Known Issues

### Falcon Signing
The `falcon_sign` command is currently reporting "Failed to sign message". This needs debugging:

**Possible causes:**
1. Secret key format/parsing issue
2. liboqs API usage issue
3. Memory allocation issue

**Next steps for debugging:**
1. Add debug output in `dogecoin_falcon512_sign()` in src/pqc_falcon.c
2. Verify secret key is being decoded correctly from hex
3. Check liboqs version compatibility
4. Test with known-good test vectors

## Security Model

### Why Use OP_RETURN Commits?

**Problem:** Falcon-512 signatures are ~690 bytes, too large for efficient on-chain storage.

**Solution:** Store only a 32-byte SHA256 commitment on-chain:
```
commit = SHA256(public_key || signature)
```

**Benefits:**
1. **Small on-chain footprint:** Only 32 bytes instead of ~690
2. **SPV-friendly:** Can be detected by light clients
3. **Verifiable:** Anyone can verify off-chain
4. **Quantum-resistant:** Uses Falcon-512 signatures
5. **Future-proof:** Commit format can be extended

### Use Cases

1. **Proof of authorship:** Timestamp a commitment to prove you signed something
2. **Document notarization:** Commit to a hash of a document
3. **Code signing:** Prove code was signed at a specific time
4. **Identity verification:** Link on-chain identity to PQC keys
5. **Multi-factor authentication:** Combine classical + PQC signatures

## References

- **Falcon Specification:** https://falcon-sign.info/
- **liboqs Documentation:** https://github.com/open-quantum-safe/liboqs
- **Dogecoin Testnet:** https://dogecoin.com/
- **libdogecoin Documentation:** ../doc/

## Next Session Tasks

1. **Debug falcon_sign:** Fix the signing issue
2. **Get testnet coins:** Visit faucet and fund test wallet
3. **Build complete transaction:** Create TX with OP_RETURN output
4. **Broadcast:** Use sendtx to send to testnet
5. **Monitor:** Run spvnode and watch for commit detection
6. **Document results:** Capture transaction ID and block height
7. **Verify off-chain:** Download block and verify commit

## Success Criteria

- ✅ All tools built with liboqs
- ✅ falcon_keygen working
- ⏳ falcon_sign/verify/commit working
- ⏳ Transaction with Falcon commit on testnet
- ⏳ SPV node detecting the commit
- ⏳ Off-chain verification demonstrated

---

**Status:** Ready for testing once signing is debugged!
**Last Updated:** 2026-02-13 02:05 UTC
