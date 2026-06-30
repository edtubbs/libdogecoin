# PR #277 — BIP38 Support: Review-Findings Status Report

Branch audited: `copilot/end-to-end-mainnet-test` (BIP38 + paper-wallet sweep work,
now including the mainnet end-to-end test `contrib/mainnet_bip38_sweep_test.sh`).

This report checks the six items raised in the last review against the current
code on the branch, and states whether the **end-to-end (e2e) test covers** each
item. Line numbers below are the current locations (they differ from the numbers
quoted in the original review).

## Summary table

| # | Finding | Severity | Addressed? | Covered by e2e test? |
|---|---------|----------|------------|----------------------|
| 1 | `set_hex` always derives a compressed address | Blocker | **No** | No |
| 2 | `koinu_to_coins_str` writes past a 10-byte buffer | Blocker | **No** (only documented) | No |
| 3 | `private_key_out` silently ignored in `dogecoin_bip38_encrypt_from_intermediate` | Should fix | **No** | No |
| 4 | NULL `chain_params` crash via direct struct access | Should fix | **No** | No |
| 5 | `set_fee` accepts `min_fee > max_fee` silently | Should fix | **No** | No |
| 6 | Key-derived scratch left unzeroed on some error paths (`bip38.c`) | Cleanup | **Partially** | No |

**Bottom line:** the new e2e test does **not** cover any of the six findings, and
five of the six are still unaddressed in code (the sixth is only partially done).
All still need to be addressed before merge.

---

## Why the e2e test misses all six

The e2e driver (`contrib/mainnet_bip38_sweep_test.sh`) exercises one happy path:

- It feeds a **compressed** mainnet WIF (`--wif …`) and BIP38-encrypts it
  (`--encrypt-bip38`), i.e. it drives `dogecoin_paper_wallet_set_wif` /
  `dogecoin_paper_wallet_set_encrypted` — **never** `set_hex`.
- It always sets `--min-fee 100000` and `--max-fee 100000000` (a valid
  `min < max` ordering).
- It always constructs the wallet through the public setters, so `chain_params`
  is always populated.
- It uses the WIF/passphrase BIP38 round-trip, **not** the intermediate-code
  ("printer") path.

Because of these choices, none of the failing scenarios in the findings are ever
reached. The test passing is **not** evidence that any finding is fixed.

---

## Detail per finding

### Blocker 1 — `set_hex` always derives a compressed address — NOT addressed
`src/sweep.c`, `dogecoin_paper_wallet_set_hex` (≈ lines 685–716):

```c
dogecoin_pubkey pubkey;
dogecoin_pubkey_from_key(&key, &pubkey);   // compressed pubkey only
...
wallet->compressed = true; /* Assume compressed for now */
```

`dogecoin_pubkey_from_key` still produces a compressed pubkey unconditionally,
and `compressed` is hard-coded to `true`. An old paper wallet funded to an
**uncompressed** P2PKH address will get the wrong address, so the sweep tx is
built for a `scriptPubKey` that does not match the chain and is rejected.

**Fix (unchanged from review):** accept a `bool compressed` parameter (or detect
from the raw key length) and derive the address accordingly. Note the sibling
`set_wif`/`set_encrypted` paths already propagate a real `compressed` flag — only
`set_hex` is wrong.

**e2e coverage:** none. The test never calls `set_hex` and only ever uses a
compressed key.

### Blocker 2 — `koinu_to_coins_str` writes past a 10-byte buffer — NOT addressed
`src/koinu.c`, `koinu_to_coins_str` (≈ lines 148–165):

```c
for (; i < 10; i++, j++) str[i] = swap[j];  // fills str[0..9]
...
str[10] = '\0';                              // writes 11th byte
```

The `length < 9` branch fills `str[0..9]` and then writes the terminator to
`str[10]` — one byte past a 10-byte allocation. The only change on the branch is
an explanatory **comment**; the behaviour and signature are unchanged, so any
caller that allocates exactly 10 bytes still overflows. The function has no size
parameter to enforce the now-required 11-byte minimum.

> Note: in-tree callers (`src/sweep.c`, `src/wallet.c`, `src/rest.c`, examples,
> tests) currently use ≥ 32–64 byte buffers, so the overflow is latent rather
> than presently triggered — but the contract changed silently and the public
> helper remains unsafe.

**Fix (unchanged from review):** add a size parameter and enforce an 11-byte
minimum, or rework the loop to leave room for the terminator within 10 bytes.

**e2e coverage:** none for the bug. Small fee koinu do hit this `length < 9`
branch (that is where the bug was originally noticed), but because the sweep
callers pass 64-byte buffers, the out-of-bounds write is never observed by the
test.

### Should fix 3 — `private_key_out` silently ignored — NOT addressed
`src/bip38.c`, `dogecoin_bip38_encrypt_from_intermediate` (≈ lines 1390–1437):

```c
(void)private_key_out;
return bip38_encrypt_ec_core(..., /*private_key_out=*/NULL, NULL, ...);
```

The parameter is still discarded and `NULL` is passed to the core. The public
header (`include/dogecoin/bip38.h` ≈ lines 280–290) still lists
`uint8_t* private_key_out` with no note that it is a no-op, so callers may
reasonably expect it to be filled.

**Fix:** either remove the parameter, or document in the header that the
printer/intermediate side never has the private key and the argument is always a
no-op.

**e2e coverage:** none. The test uses the WIF→BIP38→WIF round-trip, not the
intermediate-code printer flow.

### Should fix 4 — NULL `chain_params` crash via direct struct access — NOT addressed
`include/dogecoin/sweep.h` (lines 51–60) still declares
`dogecoin_paper_wallet` as a **non-opaque** struct, and
`dogecoin_paper_wallet_new()` (`src/sweep.c` ≈ line 528) sets
`chain_params = NULL`. In `dogecoin_paper_wallet_get_private_key`
(`src/sweep.c` ≈ line 829):

```c
if (!dogecoin_privkey_decode_wif(wallet->private_key_wif, wallet->chain_params, &key))
```

A caller who sets `private_key_wif` directly (without going through `set_wif`)
and then calls `is_valid`/`get_private_key` passes `chain_params == NULL` into
`dogecoin_privkey_decode_wif`, which dereferences
`chain->b58prefix_secret_address` → crash. No NULL guard was added.

**Fix:** make the struct opaque, or add a `if (!wallet->chain_params) return false;`
guard before the WIF-decode path.

**e2e coverage:** none. The test always builds wallets through the setters, which
populate `chain_params`.

### Should fix 5 — `set_fee` accepts `min_fee > max_fee` silently — NOT addressed
`src/sweep.c`, `dogecoin_sweep_options_set_fee` (≈ lines 1271–1284):

```c
options->min_fee = min_fee;
options->max_fee = max_fee;
return true;   // no min/max ordering check
```

`sweep_compute_amounts` (≈ lines 198–203) then clamps the fee **up** to
`min_fee` and **down** to `max_fee`, so with `min_fee > max_fee` the result is a
fee below the stated minimum, silently.

**Fix (one line):** `if (min_fee > max_fee) return false;` in
`dogecoin_sweep_options_set_fee`.

**e2e coverage:** none. The test always passes `min_fee (100000) < max_fee
(100000000)`.

### Cleanup 6 — unzeroed key-derived scratch on error paths — PARTIALLY addressed
Progress was made in `bip38_encrypt_ec_core` (`src/bip38.c` ≈ lines 470–551):
`factorb` and `derived` are now zeroed on the error and success paths.

Still outstanding:
- `bip38_confirmation_encode` (≈ lines 398–432): `pointb` (derived from
  `factorb`) and the `pointbx1`/`pointbx2` AES blocks are **not** zeroed on
  either the success or the `written == 0` failure path.
- `bip38_decrypt_ec_multiplied_bytes` (≈ lines 793–806): `decrypted2` and
  `encryptedpart1_full` are not zeroed before return.

**Fix:** add `dogecoin_mem_zero(...)` for `pointb`/`pointbx1`/`pointbx2` and the
remaining decrypt scratch on all exit paths.

**e2e coverage:** none (scratch-zeroing is not observable from an integration
test).

---

## Recommended action before merge

1. Blockers 1 and 2 must be fixed (wrong/inaccessible sweeps; out-of-bounds
   write).
2. Should-fix items 3–5 are small, self-contained fixes; address all three.
3. Finish the cleanup pass in item 6 (`pointb`/AES blocks and remaining decrypt
   scratch).
4. Extend the e2e test (or, better, add unit tests) to cover the gaps:
   an **uncompressed** `set_hex` wallet, a `min_fee > max_fee` rejection, a
   direct-struct `chain_params == NULL` guard, and the intermediate-code encrypt
   path. The current e2e exercises only a single compressed happy path and gives
   no signal on any of these findings.
