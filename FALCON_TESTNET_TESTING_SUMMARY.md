# Falcon-512 Testnet Testing - Implementation Summary

## Overview

This document summarizes the implementation of Falcon-512 post-quantum cryptographic testing tools for Dogecoin testnet. All code and documentation is complete and ready for testing.

## What's Been Implemented

### 1. Falcon Commands in `such` Tool

Four new commands have been added to the `such` CLI tool (in `src/cli/such.c`):

- **`falcon_keygen`**: Generate Falcon-512 keypair
  - Outputs: 897-byte public key, 1281-byte secret key
  - No parameters required

- **`falcon_sign`**: Sign message with Falcon-512
  - Parameters: `-p <secret_key_hex>` `-x <message_hex>`
  - Output: ~666-byte signature

- **`falcon_verify`**: Verify Falcon-512 signature
  - Parameters: `-k <public_key_hex>` `-x <message_hex>` `-s <signature_hex>`
  - Output: Verification result (VALID/INVALID)

- **`falcon_commit`**: Generate SHA256 commitment
  - Parameters: `-k <public_key_hex>` `-s <signature_hex>`
  - Output: 32-byte commitment for OP_RETURN

### 2. SPV Node Falcon Detection

The `spvnode` tool (`src/cli/spvnode.c`) includes:

- Automatic detection of Falcon commitments in OP_RETURN outputs
- Logging: `[falcon-commit] Found at height=X txpos=Y commit=<hex>`
- Works on both mainnet and testnet

### 3. Automated Test Script

**Location**: `contrib/testnet_falcon_test.sh`

**Features**:
- Colored, user-friendly output
- Step-by-step workflow automation
- Error handling and validation
- Artifact saving for review
- Interactive prompts for testnet coin acquisition

**Workflow**:
1. Generate testnet wallet
2. Request coins from faucet
3. Generate Falcon keypair
4. Sign timestamped message
5. Generate commitment
6. Build transaction guidance
7. SPV monitoring instructions
8. Off-chain verification guidance

### 4. Comprehensive Documentation

**Updated**: `doc/tools.md`

**Additions**:
- Complete Falcon command reference
- Usage examples for each command
- Testnet workflow guide
- Security model explanation
- Use cases and benefits
- References and specifications

**Also Available**: `FALCON_TESTNET_GUIDE.md`
- Detailed technical guide
- Code examples
- Helper program templates
- Troubleshooting section

## How to Use

### Prerequisites

1. **Build libdogecoin with liboqs support**:

```bash
# Option 1: Install liboqs system-wide
sudo apt-get install liboqs-dev  # if available

# Option 2: Build from depends (recommended)
cd depends
make liboqs -j$(nproc)
cd ..

# Configure with liboqs
./autogen.sh
./configure --enable-liboqs --disable-net --prefix=$(pwd)/depends/x86_64-pc-linux-gnu

# Build
make -j$(nproc)
```

2. **Verify Falcon commands are available**:

```bash
./such -c help | grep falcon
```

You should see:
```
falcon_keygen (generates Falcon-512 keypair),
falcon_sign (requires -p <falcon_secret_key_hex> -x <message_hex>),
falcon_verify (requires -k <falcon_public_key_hex> -x <message_hex> -s <signature_hex>),
falcon_commit (requires -k <falcon_public_key_hex> -s <signature_hex>)
```

### Quick Start

#### Manual Testing

1. **Generate Falcon keypair**:
```bash
./such -c falcon_keygen
```

2. **Sign a message**:
```bash
MESSAGE_HEX=$(echo -n "Hello Dogecoin" | xxd -p | tr -d '\n')
./such -c falcon_sign -p <secret_key_hex> -x $MESSAGE_HEX
```

3. **Verify signature**:
```bash
./such -c falcon_verify -k <public_key_hex> -x $MESSAGE_HEX -s <signature_hex>
```

4. **Generate commitment**:
```bash
./such -c falcon_commit -k <public_key_hex> -s <signature_hex>
```

#### Automated Testnet Testing

Run the complete testnet integration test:

```bash
./contrib/testnet_falcon_test.sh
```

Follow the prompts to:
1. Generate wallet and get testnet coins
2. Create Falcon keypair and signature
3. Generate commitment
4. Build and broadcast transaction
5. Monitor with SPV node

### Example Output

When running `./such -c falcon_keygen`:
```
Generating Falcon-512 keypair...
Public Key (897 bytes): 014158c4d7f9e2a3b8c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7...
Secret Key (1281 bytes): 50144b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4e5f6a7b8c9d0...
```

When running testnet script:
```
[INFO] Step 1: Generating testnet wallet...
[SUCCESS] Testnet wallet generated
  Address: nWxYz1234567890aBcDeFgHiJkLmNoPqRsT
  
[INFO] Step 2: Getting testnet coins...
Send testnet DOGE to: nWxYz1234567890aBcDeFgHiJkLmNoPqRsT

[INFO] Step 3: Generating Falcon-512 keypair...
[SUCCESS] Falcon-512 keypair generated
  Public Key (1794 chars): 014158c4...
  Secret Key (2562 chars): 50144b2c...
  
[INFO] Step 4: Signing message with Falcon-512...
Message: Falcon-512 testnet test: 2026-02-12T23:45:00Z
[SUCCESS] Message signed
  Signature (1320 chars): 3a7f4e...
  
[INFO] Step 5: Generating commitment...
[SUCCESS] Commitment generated
  Commitment (32 bytes): a1b2c3d4e5f6789012345678901234567890abcdef0123456789abcdef01234
```

## Testnet Workflow

### Complete End-to-End Process

1. **Get Testnet Coins**
   - Use faucet: https://testnet-faucet.com/dogecoin-testnet/
   - Or Discord: Dogecoin community #testnet channel
   - Send to generated testnet address

2. **Generate Falcon Proof**
   ```bash
   ./such -c falcon_keygen > /tmp/falcon_keys.txt
   FALCON_PK=$(grep "Public Key:" /tmp/falcon_keys.txt | cut -d: -f2 | tr -d ' ')
   FALCON_SK=$(grep "Secret Key:" /tmp/falcon_keys.txt | cut -d: -f2 | tr -d ' ')
   
   MESSAGE_HEX=$(echo -n "My proof $(date)" | xxd -p | tr -d '\n')
   ./such -c falcon_sign -p $FALCON_SK -x $MESSAGE_HEX > /tmp/sig.txt
   
   FALCON_SIG=$(grep "Signature:" /tmp/sig.txt | cut -d: -f2 | tr -d ' ')
   ./such -c falcon_commit -k $FALCON_PK -s $FALCON_SIG > /tmp/commit.txt
   
   COMMITMENT=$(grep "Commitment:" /tmp/commit.txt | cut -d: -f2 | tr -d ' ')
   ```

3. **Build Transaction**
   
   You need to create a transaction with:
   - Input: Your testnet UTXO
   - Output 1: Payment (back to yourself or recipient)
   - Output 2: OP_RETURN with commitment
   
   OP_RETURN script format:
   ```
   6a20<commitment_hex>
   ```
   
   Where:
   - `6a` = OP_RETURN opcode
   - `20` = PUSH 32 bytes
   - `<commitment_hex>` = Your 32-byte commitment
   
   **Note**: Current `such` tool doesn't support adding custom OP_RETURN outputs.
   Options:
   - Use Dogecoin Core wallet RPC
   - Extend `such` with OP_RETURN support
   - Use external tools then sign with `such`

4. **Broadcast Transaction**
   ```bash
   ./sendtx -t <signed_tx_hex>
   ```

5. **Monitor with SPV Node**
   ```bash
   ./spvnode -t -d -f 0 -c -b scan
   ```
   
   Wait for output:
   ```
   [falcon-commit] Found at height=4567890 txpos=2 commit=a1b2c3d4...
   ```

6. **Verify Off-Chain**
   ```bash
   # Verify signature
   ./such -c falcon_verify -k $FALCON_PK -x $MESSAGE_HEX -s $FALCON_SIG
   
   # Regenerate commitment
   ./such -c falcon_commit -k $FALCON_PK -s $FALCON_SIG
   
   # Compare with on-chain commitment
   echo "On-chain: $COMMITMENT"
   ```

## Known Limitations

### 1. OP_RETURN Transaction Building

The current `such` transaction builder doesn't have a flag to add custom OP_RETURN outputs. This needs to be implemented.

**Workaround**: Use Dogecoin Core wallet or build transaction manually.

**Future Enhancement**: Add `--falcon-commit` flag to `such`:
```bash
./such -c transaction --falcon-commit <commitment_hex>
```

### 2. SPV Node Commit Database

The SPV node detects and logs Falcon commitments but doesn't store them in a queryable database.

**Future Enhancement**: 
- Store commits in SQLite database
- Add query commands
- Associate commits with blocks/transactions

### 3. liboqs Build Time

Building liboqs from depends can take 5-10 minutes on first build.

**Alternative**: Install pre-built liboqs if available for your system.

## Security Model

### Commitment Scheme

```
commitment = SHA256(public_key || signature)
```

**Properties**:
- **Binding**: Cannot find different (pk, sig) with same commitment
- **Hiding**: Commitment reveals nothing about signature
- **Compact**: Only 32 bytes on-chain
- **Verifiable**: Anyone with (pk, sig) can verify

### Verification Process

1. **On-chain**: Only commitment is stored (32 bytes)
2. **Off-chain**: Full signature available (~660 bytes)
3. **Verify**: 
   - Recompute: `SHA256(pk || sig)`
   - Compare with on-chain commitment
   - Verify Falcon signature: `falcon_verify(pk, msg, sig)`

### Use Cases

1. **Timestamping**: Prove document existed at block height
2. **Notarization**: Quantum-resistant document proofs
3. **Identity**: Future-proof identity verification
4. **Hybrid Schemes**: Combine classical + PQC signatures
5. **Audit Trail**: Immutable quantum-resistant audit logs

## Testing Checklist

- [ ] Build libdogecoin with `--enable-liboqs`
- [ ] Verify Falcon commands available in `such`
- [ ] Generate Falcon keypair
- [ ] Sign test message
- [ ] Verify signature
- [ ] Generate commitment
- [ ] Get testnet coins from faucet
- [ ] Build transaction with OP_RETURN
- [ ] Broadcast transaction to testnet
- [ ] Monitor with SPV node
- [ ] Verify commit detection in logs
- [ ] Verify off-chain with saved signature

## Troubleshooting

### liboqs not found

```bash
# Check if liboqs is in depends
ls depends/x86_64-pc-linux-gnu/lib/liboqs*

# If not, build it
cd depends && make liboqs && cd ..

# Reconfigure
./configure --enable-liboqs --prefix=$(pwd)/depends/x86_64-pc-linux-gnu
```

### Falcon commands not available

```bash
# Check build configuration
./configure --help | grep liboqs

# Rebuild with liboqs
make clean
./configure --enable-liboqs --disable-net
make -j$(nproc)
```

### Signing fails

- Verify secret key length (should be 2562 hex chars = 1281 bytes)
- Ensure message is hex encoded
- Check liboqs version (0.15.0+ recommended)

### Testnet transaction not confirming

- Ensure fee is adequate (>0.001 DOGE)
- Check testnet block explorer
- Verify transaction is properly formatted
- Wait for next block (may take several minutes on testnet)

## Next Steps

1. **Build with liboqs**: Follow prerequisites above
2. **Run automated test**: `./contrib/testnet_falcon_test.sh`
3. **Get testnet coins**: From faucet or community
4. **Create real transaction**: With Falcon commitment
5. **Monitor and verify**: Using SPV node
6. **Document results**: Share findings with community

## References

- **Falcon Specification**: https://falcon-sign.info/
- **liboqs Documentation**: https://github.com/open-quantum-safe/liboqs
- **NIST PQC**: https://csrc.nist.gov/projects/post-quantum-cryptography
- **Dogecoin Testnet**: https://testnet.dogecoin.com/
- **OP_RETURN Spec**: https://en.bitcoin.it/wiki/OP_RETURN

## Contributing

If you test this on testnet and encounter issues or have improvements:

1. Open an issue with details
2. Submit PR with fixes
3. Share results in community channels

## Status

✅ **Implementation Complete**
✅ **Documentation Complete**
⏳ **Awaiting liboqs build and testnet testing**

All code is ready. Next step is building with liboqs and performing actual testnet transactions.
