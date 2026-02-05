# Electrum Test Vector Verification Guide

This document explains how to independently verify the Electrum mnemonic test vectors used in libdogecoin.

## Purpose

The test vectors in `test/bip39_tests.c` and `test/key_tests.c` are NOT generated from libdogecoin itself. They are verified against standard cryptographic implementations to ensure libdogecoin's Electrum support is correct.

## Electrum v2 Test Vectors

Electrum v2 uses standard PBKDF2-HMAC-SHA512 (NIST FIPS 800-132, RFC 2898).

### Test Vector 1: Version 0x100 (Segwit) with Passphrase

```bash
python3 -c "import hashlib; print(hashlib.pbkdf2_hmac('sha512', b'wild father tree among universe such mobile favorite target dynamic credit identify', b'electrummypassphrase', 2048).hex())"
```

**Expected Output:**
```
b1e4b6b2adff19b3f21553eac21937493be96732676b804b3784a1b79492dce7157de526a2d7b1b34009ff55201c79ec6fc66e3e96dcdcecf22fa9a8d1eaef16
```

### Test Vector 2: Version 0x100 (Segwit) without Passphrase

```bash
python3 -c "import hashlib; print(hashlib.pbkdf2_hmac('sha512', b'wild father tree among universe such mobile favorite target dynamic credit identify', b'electrum', 2048).hex())"
```

**Expected Output:**
```
aac2a6302e48577ab4b46f23dbae0774e2e62c796f797d0a1b5faeb528301e3064342dafb79069e7c4c6b8c38ae11d7a973bec0d4f70626f8cc5184a8d0b0756
```

### Test Vector 3: Version 0x01 (Standard)

```bash
python3 -c "import hashlib; print(hashlib.pbkdf2_hmac('sha512', b'cycle rocket west magnet parrot shuffle foot correct salt library feed song', b'electrum', 2048).hex())"
```

**Expected Output:**
```
00302d7db162de47e6cd5074221aee6bbcb6be93982af90c04d0e7710dd26013aeb7848850a56a546e7955b360e561139d62805f2d5d3c940880b0dc91b60b29
```

## Electrum v1 Test Vectors

Electrum v1 uses a custom algorithm: SHA-256 with 100,000 iterations for stretching.

### Test Vector 1: "alpha bravo" without Passphrase

```bash
python3 -c "import hashlib; s=hashlib.sha256(b'alpha bravo').digest(); st=s; exec('st=hashlib.sha256(st+s).digest();'*100000); print(st.hex())"
```

**Expected Output:**
```
d11e7e95635e37239d6552824587675e7b0581414191dcc94bcc04c5b0e206ec
```

### Test Vector 2: "alpha bravo" with Passphrase "testpass"

```bash
python3 -c "import hashlib; s=hashlib.sha256(b'alpha bravo testpass').digest(); st=s; exec('st=hashlib.sha256(st+s).digest();'*100000); print(st.hex())"
```

**Expected Output:**
```
d51554cccc286493f510b8c2a4104e4132562518a5db4ec5e8a3325dff8234ee
```

## References

1. **Python hashlib** - NIST FIPS compliant cryptographic hashing
   - https://docs.python.org/3/library/hashlib.html

2. **PBKDF2 Standard** - RFC 2898 / NIST FIPS 800-132
   - https://tools.ietf.org/html/rfc2898

3. **Official Electrum Source** - Reference implementation
   - https://github.com/spesmilo/electrum/blob/master/electrum/mnemonic.py

4. **Electrum Documentation**
   - https://electrum.readthedocs.io/en/latest/seedphrase.html

## Verification Process

To verify libdogecoin's implementation:

1. Run the verification commands above in any Python 3 environment
2. Compare the output with the expected values
3. Compare those values with the test vectors in the libdogecoin test files
4. If they match, libdogecoin's implementation is correct

This verification is independent of libdogecoin and uses only standard Python libraries.

## How to Use

You can verify any of the test vectors by running the commands directly:

```bash
# Example: Verify Electrum v2 without passphrase
python3 -c "import hashlib; print(hashlib.pbkdf2_hmac('sha512', b'wild father tree among universe such mobile favorite target dynamic credit identify', b'electrum', 2048).hex())"

# Example: Verify Electrum v1 with passphrase
python3 -c "import hashlib; s=hashlib.sha256(b'alpha bravo testpass').digest(); st=s; exec('st=hashlib.sha256(st+s).digest();'*100000); print(st.hex())"
```

These commands use only Python's standard library, which implements:
- SHA-256: FIPS 180-4
- PBKDF2: RFC 2898 / NIST FIPS 800-132

This ensures independent verification without relying on libdogecoin's implementation.
