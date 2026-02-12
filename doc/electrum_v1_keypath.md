# Electrum v1 Keypath Format

## Overview

Electrum v1 uses a custom key derivation scheme that differs from BIP32/BIP44. This document explains the keypath notation used in libdogecoin.

## Keypath Format

```
electrum_v1:n/for_change
```

Where:
- `n` = address index (0, 1, 2, 3, ...)
- `for_change` = 0 or 1
  - `0` = receiving addresses (external chain)
  - `1` = change addresses (internal chain)

## Examples

| Keypath | Meaning | Description |
|---------|---------|-------------|
| `electrum_v1:0/0` | index=0, for_change=0 | First receiving address |
| `electrum_v1:0/1` | index=0, for_change=1 | First change address |
| `electrum_v1:5/0` | index=5, for_change=0 | Sixth receiving address |
| `electrum_v1:5/1` | index=5, for_change=1 | Sixth change address |
| `electrum_v1:10/0` | index=10, for_change=0 | Eleventh receiving address |

## Derivation Algorithm

Electrum v1 derives keys using the following formula:

```
mpk = uncompressed_pubkey(master_secret)[1..64] as hex (128 chars)
tweak = SHA256("<n>:<for_change>:" + mpk_hex)
privkey = (master_secret + tweak) mod curve_order
```

This is fundamentally different from BIP32 which uses HMAC-SHA512 and chain codes for hierarchical deterministic key derivation.

## CLI Usage

### Generating Keys

```bash
# First receiving address (index=0, for_change=0)
./such -c mnemonic_to_key -n "your mnemonic here" -l -i 0 -g 0

# First change address (index=0, for_change=1)
./such -c mnemonic_to_key -n "your mnemonic here" -l -i 0 -g 1

# Sixth receiving address (index=5, for_change=0)
./such -c mnemonic_to_key -n "your mnemonic here" -l -i 5 -g 0
```

### CLI Flags

- `-l` = Use Electrum v1 derivation
- `-i <n>` = Address index (default: 0)
- `-g <for_change>` = Chain type: 0 for receiving, 1 for change (default: 0)
- `-o <account>` = Ignored for Electrum v1 (no account level)

## Differences from BIP32/BIP44

| Feature | Electrum v1 | BIP32/BIP44 |
|---------|------------|-------------|
| Derivation | `master + SHA256(n:change:mpk)` | HMAC-SHA512 with chain codes |
| Hierarchy | Flat (2 levels only) | Multiple levels (m/44'/3'/0'/0/x) |
| Account support | No | Yes |
| Hardened keys | No | Yes |
| Chain codes | No | Yes |
| Keypath format | `electrum_v1:n/for_change` | `m/44'/3'/0'/0/x` |

## References

- [Electrum v1 Source Code](https://github.com/spesmilo/electrum/blob/master/electrum/old_mnemonic.py)
- [Electrum Documentation](https://electrum.readthedocs.io/)
- libdogecoin implementation: `src/key.c` - `electrum_v1_derive_privkey32()`

## Security Considerations

Electrum v1 is an older standard and has been superseded by:
- **Electrum v2** (post-2.0) which uses standard PBKDF2-HMAC-SHA512 with BIP32 derivation
- **BIP39 + BIP44** which is the current industry standard

While Electrum v1 is still supported for backwards compatibility, new wallets should use more modern standards.
