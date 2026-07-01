# PR #277 — BIP38 Support: Findings Validation (updated branch)

Validated against PR #277 commit `cfc022994591b8ac7225e529581dde2ee065221b`
("Address bluezr final BIP38/sweep review (scope-limited)"), which supersedes the
lineage reviewed in `bip38_pr277_review_findings.md`.

**Verification performed:** built the branch from a clean tree
(`./autogen.sh && ./configure --disable-net --disable-tools --disable-shared &&
make -j2`) and ran the full unit-test suite (`./tests`). Build succeeded and the
entire suite passed (exit 0), including `test_sweep()` and `test_koinu()`.

## Summary table

| # | Finding | Severity | Status on `cfc0229` | Test coverage |
|---|---------|----------|---------------------|---------------|
| 1 | `set_hex` always derives a compressed address | Blocker | **Fixed** | Yes |
| 2 | `koinu_to_coins_str` writes past a 10-byte buffer | Blocker | **Not changed (latent)** | No |
| 3 | `private_key_out` silently ignored in `encrypt_from_intermediate` | Should fix | **Fixed** | n/a |
| 4 | NULL `chain_params` crash via direct struct access | Should fix | **Fixed** | Yes |
| 5 | `set_fee` accepts `min_fee > max_fee` silently | Should fix | **Fixed** | Yes |
| 6 | Key-derived scratch left unzeroed on error paths (`bip38.c`) | Cleanup | **Fixed** | n/a |

**Bottom line:** 5 of 6 findings are implemented and, where behavioural, are
covered by new unit tests. Only Blocker 2 remains unimplemented in code; it is
currently **latent** (no in-tree caller allocates a 10-byte buffer) but the
unsafe function contract is unchanged.

---

## Detail per finding

### Blocker 1 — `set_hex` compressed flag — FIXED (with tests)
`dogecoin_paper_wallet_set_hex` now takes a `dogecoin_bool compressed` parameter
(`src/sweep.c` ~669, headers `include/dogecoin/sweep.h:127` and
`include/dogecoin/libdogecoin.h:1430`). Address derivation goes through the new
`sweep_pubkey_from_privkey(private_key, compressed, &pubkey)` helper
(`src/sweep.c` ~52–61), which honours `compressed` for both the pubkey length and
`pubkey_out->compressed`; `wallet->compressed = compressed` is stored.
`dogecoin_paper_wallet_new()` now defaults `compressed = false` (`src/sweep.c`
~528).

Tests: `test/sweep_tests.c` ~403/411 build both a compressed and an uncompressed
wallet from the same hex key and assert the resulting addresses differ
(`u_assert_str_not_eq`). All `set_hex` call sites/tests updated to the new
signature.

### Blocker 2 — `koinu_to_coins_str` 10-byte overflow — NOT changed (latent)
`src/koinu.c` still executes `str[10] = '\0'` in the `length < 9` branch after
filling `str[0..9]`, with no size parameter. Only the explanatory comment remains
from the prior review; the contract (needs ≥ 11 bytes) is unchanged and silent.

Impact today is **latent, not active**: every in-tree caller passes a buffer of
≥ 21 bytes — `char[21]` in `src/wallet.c`, `src/cli/such.c`; 64-byte buffers in
`src/sweep.c`; `KOINU_STRINGLEN` (= 21, `include/dogecoin/constants.h:38`) for
`utxo->amount`; `char[21]`/larger in `src/rest.c`. So no current call overflows,
but the public helper remains unsafe for a 10-byte allocation.

Recommendation (unchanged): add a size parameter enforcing an 11-byte minimum, or
rework the loop to fit the terminator within 10 bytes.

### Should fix 3 — `private_key_out` in `encrypt_from_intermediate` — FIXED
The parameter was removed entirely from both the implementation
(`src/bip38.c` ~1452) and the public header
(`include/dogecoin/bip38.h` ~285). The intermediate/printer path legitimately
never possesses the private key, so removal (rather than documenting a no-op) is
the cleaner of the two suggested fixes. The function additionally zeroes
`passpoint` and `seedb` before returning.

### Should fix 4 — NULL `chain_params` guard — FIXED (with tests)
`dogecoin_paper_wallet_get_private_key` now returns `false` on
`!wallet->chain_params` before the WIF-decode path (`src/sweep.c` ~826–828),
preventing the `dogecoin_privkey_decode_wif` NULL dereference reachable via
`is_valid`.

Test: `test/sweep_tests.c` ~1021–1032 sets `private_key_wif`/`address` directly,
forces `wallet->chain_params = NULL`, and asserts `is_valid` returns 0 without
crashing.

### Should fix 5 — `set_fee` min/max ordering — FIXED (with tests)
`dogecoin_sweep_options_set_fee` now returns `false` when `min_fee > max_fee`
(`src/sweep.c` ~1277 `if (min_fee > max_fee) return false;`).

Test: `test/sweep_tests.c:511` asserts
`dogecoin_sweep_options_set_fee(options, 1000, 5000, 1000)` returns 0.

### Cleanup 6 — unzeroed key-derived scratch — FIXED
- `bip38_confirmation_encode` (`src/bip38.c` ~398): `pointb`, `pointbx1`,
  `pointbx2` are now zeroed on both the `written == 0` failure path and success.
- `bip38_encrypt_ec_core` (~505–551): `factorb`, `priv`, `passpoint_work`,
  `derived` zeroed across all error/success exits.
- `bip38_decrypt_ec_multiplied_bytes` (~806): `passfactor`, `passpoint`,
  `derived`, `seedb`, `decrypted2`, `encryptedpart1_full`, `factorb` zeroed.
- Additional hygiene from commit `ae2ee3b` ("Zeroize sensitive BIP38 stack
  buffers"): clears the AES decrypt `block[]` and names the reserved EC flag bit.

---

## Conclusion

The updated branch implements Blockers 1 and both should-fix items (3–5) and
completes the cleanup pass (6), each verified by code inspection and a passing
build + full unit-test run. The only outstanding item is Blocker 2
(`koinu_to_coins_str`), which is not fixed but is presently latent because no
in-tree caller uses a 10-byte buffer; it should still be hardened (size parameter
or terminator-within-budget) before relying on the public helper externally.
