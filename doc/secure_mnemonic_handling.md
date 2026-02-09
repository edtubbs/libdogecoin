# Secure Mnemonic Handling Guide

This document provides guidance for developers integrating libdogecoin's BIP-39
mnemonic generation into their applications. Proper handling of mnemonic
phrases is critical — a leaked mnemonic grants full access to all derived keys
and funds.

See also: `doc/mitre_att&ck_tabletop.md` — Scenario 5 and Mitigation M12.

## Mnemonic Lifecycle

```
Generate  →  Display  →  Verify  →  Derive Seed  →  Destroy
```

Each phase has specific security requirements.

## Generation

- Always use `dogecoin_generate_mnemonic` with full entropy (128–256 bits).
- Ensure the system RNG is available — `dogecoin_random_bytes()` returns
  `false` if entropy is insufficient. **Do not proceed** if it fails.
- For high-value wallets, consider generating mnemonics inside a Trusted
  Execution Environment (OP-TEE or Open Enclave).

## Display

- **Never** log or print the mnemonic to stdout/stderr in production.
- If displaying to a user, use a secure UI that prevents screen capture where
  possible.
- Do not allow the mnemonic to be copied to the system clipboard.
- Display only once — prompt the user to write it down physically.

## Verification

- Ask the user to re-enter the mnemonic (or selected words) to confirm they
  have recorded it.
- Do not store the entered text — validate in memory and discard.

## Seed Derivation

- After deriving the seed from the mnemonic, zero the mnemonic buffer
  immediately using `dogecoin_mem_zero()`.
- Example:
  ```c
  char mnemonic[256];
  /* ... generate or receive mnemonic ... */
  uint8_t seed[64];
  dogecoin_generate_mnemonic_seed(mnemonic, passphrase, seed);
  /* Zero the mnemonic immediately after use */
  dogecoin_mem_zero(mnemonic, sizeof(mnemonic));
  ```

## Destruction

- Always zero mnemonic buffers before freeing or leaving scope.
- Use `dogecoin_mem_zero()` (not `memset` which may be optimized away).
- Zero seed buffers after HD key derivation is complete.

## Anti-Patterns (Do NOT Do)

| Anti-Pattern | Risk |
|-------------|------|
| Store mnemonic in a config file | File theft exposes all keys |
| Log mnemonic for debugging | Logs are often world-readable |
| Pass mnemonic as CLI argument | Visible in process listings (`/proc`) |
| Keep mnemonic in memory indefinitely | Memory dump reveals phrase |
| Copy mnemonic to clipboard | Clipboard is shared across apps |

## Platform Considerations

| Platform | Recommendation |
|----------|---------------|
| Linux | Use `mlock()` to prevent mnemonic pages from being swapped |
| Windows | Use `VirtualLock()` for the same purpose |
| Mobile | Use platform secure enclave APIs |
| Embedded/IoT | Use hardware security module or TEE |

## References

- [BIP-39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [NIST SP 800-90A: Random Number Generation](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
- libdogecoin API: `include/dogecoin/bip39.h`
