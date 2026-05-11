# Raccoon-G-44 — in-tree port

> ⚠ **Experimental.** This directory is the in-tree C port of the
> Raccoon-G-44 post-quantum threshold signature scheme. The byte-exact KAT
> gate against the upstream Python reference now passes for every staged
> component, `raccoong_is_ready()` returns `true`, and the libdogecoin
> Raccoon-G-44 entry points in `src/pqc_raccoon.c` route here when the
> library is configured with `--enable-raccoon-g`. The implementation has
> not been third-party audited and the upstream protocol may still evolve;
> treat as not-for-production until that audit lands.

## Upstream reference

- Repository: `p-11/lattice-hd-wallets`
- Pinned commit: **`461a5ed9b6d57e3bf8c381be3bb79325ab21d906`** (`update name in
  README (#14)`, the current `main` at the time of pinning).

## Parameter set (Raccoon-G-44)

Pinned in `polyr.h` from `src/raccoon/thrc-py/polyr.py`:

| Symbol         | Value                | Source                  |
|----------------|----------------------|-------------------------|
| `RACCOONG_N`   | 256                  | `RACC_N`                |
| `RACCOONG_Q`   | 562949953438721      | `RACC_Q` (50-bit prime) |
| `RACCOONG_NI`  | 560750930183101      | `RACC_NI` (= n⁻¹ mod q) |
| `RACCOONG_LOG_Q` | 50                 | ⌈log₂ q⌉                |
| `RACCOONG_K`   | 9                    | Raccoon-G-44 dim (rows) |
| `RACCOONG_ELL` | 9                    | Raccoon-G-44 dim (cols) |
| `RACCOONG_TAU` | 23                   | Challenge weight        |
| `RACCOONG_Q_W` | 2048                 | q >> 38 (hint modulus)  |
| `RACCOONG_PK_BYTES`  | 16144          | 16-byte A_seed + 9·256·7 |
| `RACCOONG_SK_BYTES`  | 32272          | pk || 9·256·7 (s mod q) |
| `RACCOONG_SIG_BYTES` | 20768          | 32B c_hash + 9·256·7 z + 9·256·2 h |

The negacyclic NTT twiddle table (`RACC_W`, 256 entries) is embedded
verbatim in `src/raccoon_g/ntt.c`. Its SHA-256 over the LE-u64 byte
encoding is:

    007cf593d0147d705768503556f096e25ac65b9837cf99d2bd7a43b251f0df36

`test/raccoong_ntt_tests.c` recomputes this digest against the in-tree
table and additionally checks `ntt_forward(A)` byte-for-byte, the
`intt(ntt(A)) == A` roundtrip, and the
`intt(pw(ntt(A), ntt(B))) == schoolbook(A, B) mod (X^n + 1)` equivalence
against vectors generated from upstream by
`contrib/raccoon_g/gen_ntt_vectors.py`.

## Release-blocking gate

The port ships **only if** every fixture in
`test/data/raccoong_kat.json` (and its per-component sibling fixtures
under `test/data/raccoong_*_vectors.h`) passes byte-exactly. Specifically:

1. `polyr` round-trip (de)serialization equals upstream for every committed
   sample.
2. NTT twiddle table SHA-256 equals upstream; `ntt_forward` and the
   `intt(pw(ntt, ntt))` schoolbook equivalence are byte-exact.
3. Gaussian sampler is byte-exact against the recorded SHAKE256 driver
   prefix at σ² = 2⁴⁰ and σₜ² = 2¹⁴ (MPFR @256-bit; mpmath@256 cross-check
   reported zero mismatches over 1000 samples on identical 256-bit inputs).
4. `SHAKE256` / `SHAKE128` KATs (empty input, `"abc"`, streaming /
   one-shot / multi-piece-absorb equivalence).
5. `xof_sample_q` (uniform 𝔽_q rejection sampler over SHAKE128) is
   byte-exact across four `(A_seed, i, j)` / `(key, i, j, k)` cells.
6. `expand_a` (9×9 ExpandA), `vec_ntt` / `vec_intt` / `vec_add` /
   `vec_rshift`, and `mul_mat_vec_ntt` are byte-exact against upstream
   `mul_mat_vec_ntt(_expand_a(A_seed), [_xof_sample_q(seed_j) for j])`.
7. `keygen_t_unrounded` (A_seed, sample of `s_i` / `e1_i`, and the full
   9·256 u64 unrounded `t = vec_intt(A·s) + e1`) is byte-exact.
8. `thrc_keygen_from_seed` (HKDF-SHA256 → NIST_KAT_DRBG → unrounded keygen
   → 7-byte LE serialization, pk=16144 B, sk=32272 B) is byte-exact
   against upstream `generate_keypair_from_seed`.
9. HD derive (`thrc_hd_derive_priv` / `_pub`) — HMAC-SHA512 tweak seed,
   coefficient-wise additive child keypair sharing the parent `A_seed` —
   is byte-exact against upstream `generate_tweak_keypair_from_seed`
   + `add_public_keys` + `add_signing_keys` for both hardened and
   non-hardened paths.
10. Signature wire format (20768 B: 32B `c_hash` || 9·256·7B z mod q ||
    9·256·2B h mod q_w, h centered to [-q_w/2, q_w/2) on read) is
    byte-exact and round-trip / out-of-range reject covered.
11. `hash_vec`, `chal_poly`, and BUFF `mu`
    (`mu = SHAKE256(SHAKE256(pk).read(crh) || msg)`) are byte-exact.
12. `thrc_sign` / `thrc_verify` (Algorithm 2 / 3 with unrounded `t̂`,
    BUFF `mu`, challenge poly) reproduce upstream byte-exactly for the
    pinned seed, and reject tampered signatures and wrong-pk verifies.

Any single failure of the gate stops the port; we will not ship a Raccoon-G
backend that disagrees with the reference.

## Why GMP / MPFR in `depends/`

The reference uses `mpmath` (Python) for the rounded Gaussian sampler. MPFR is
the C analogue: arbitrary-precision floating-point with IEEE-754 correct
rounding at user-controlled precision. GMP is its transitive dependency. They
are vendored via `depends/packages/gmp.mk` and `depends/packages/mpfr.mk`
behind `RACCOON_G=y` so that this build path is reproducible and pinned to
the same numerics as the reference.

## File layout

| File          | Responsibility                                     | Status      |
|---------------|----------------------------------------------------|-------------|
| `polyr.{c,h}` | `Z_q[X]/(X^n+1)` polynomial arithmetic             | Session 3 ✓ |
| `ntt.{c,h}`   | Forward / inverse NTT, pointwise multiply          | Session 4 ✓ |
| `gaussian.{c,h}` | MPFR-backed rounded Gaussian sampler            | Session 5 ✓ |
| `shake256.{c,h}` | FIPS 202 SHAKE256 + SHAKE128 (Keccak-f[1600])   | Session 6 ✓ / 7a ✓ |
| `keygen_kdf.{c,h}` | HKDF-SHA256 + NIST_KAT_DRBG (AES-256-CTR)     | Session 7d ✓ |
| `thrc.{c,h}` `xof_sample_q` | Uniform Z_q rejection sampler (SHAKE128) | Session 7a ✓ |
| `thrc.{c,h}` `expand_a` + matvec | 9×9 ExpandA + `vec_ntt`/`mul_mat_vec_ntt` | Session 7b ✓ |
| `thrc.{c,h}` `keygen_t_unrounded` | A_seed + s/e1 + (A·s)+e1 (unrounded t) | Session 7c ✓ |
| `thrc.{c,h}` `thrc_keygen_from_seed` | Full seed → 7-byte LE pk/sk pipeline | Session 7d ✓ |
| `thrc.{c,h}` `thrc_hd_derive_*`      | HMAC-SHA512 BIP32-style HD derive    | Session 7e ✓ |
| `thrc.{c,h}` signature serializer    | 20768-byte canonical wire format     | Session 7f.1 ✓ |
| `thrc.{c,h}` `hash_vec` / `chal_poly` | hash_vec / challenge poly oracles   | Session 7f.2 / 7f.3 ✓ |
| `thrc.{c,h}` BUFF `mu`               | `SHAKE256(SHAKE256(pk)||msg)` BUFF mu | Session 7f.4 ✓ |
| `thrc.{c,h}` `thrc_sign` / `thrc_verify` | Algorithm 2 / 3 glue + KATs       | Session 7f.5 ✓ |
| `raccoong.{c,h}` | Public-shape glue called by `src/pqc_raccoon.c` | Wired ✓ |
| `README.md`   | This file.                                         | —           |

## Test fixtures

The Raccoon-G test fixtures are generated from the upstream Python and
checked in alongside the regenerator script:

- `contrib/raccoon_g/gen_polyr_vectors.py` — generator (polyr.c)
- `contrib/raccoon_g/gen_ntt_vectors.py`   — generator (ntt.c)
- `contrib/raccoon_g/gen_gaussian_vectors.py` — generator (gaussian.c)
- `contrib/raccoon_g/gen_xof_sample_q_vectors.py` — generator (xof_sample_q)
- `contrib/raccoon_g/gen_matvec_vectors.py` — generator (ExpandA + mul_mat_vec)
- `contrib/raccoon_g/gen_keygen_t_vectors.py` — generator (unrounded keygen)
- `contrib/raccoon_g/gen_keypair_vectors.py`  — generator (seed → pk/sk)
- `contrib/raccoon_g/gen_hd_derive_vectors.py` — generator (HD derive)
- `contrib/raccoon_g/gen_signature_serialize_vectors.py` — generator
  (signature wire format)
- `contrib/raccoon_g/gen_hash_vec_vectors.py` — generator (hash_vec)
- `contrib/raccoon_g/gen_chal_poly_vectors.py` — generator (chal_poly)
- `contrib/raccoon_g/gen_buff_mu_vectors.py`  — generator (BUFF mu)
- `contrib/raccoon_g/gen_sign_vectors.py`     — generator (sign/verify KAT)
- `test/data/raccoong_*_vectors.h`            — generated C-array fixtures
- `test/data/raccoong_kat.json`               — top-level sign/verify
  KAT bundle consumed by `test/raccoong_sign_tests.c`, including a
  tampered-signature reject case.

To regenerate:

```sh
git clone https://github.com/p-11/lattice-hd-wallets /tmp/lattice-hd-wallets
git -C /tmp/lattice-hd-wallets checkout 461a5ed9b6d57e3bf8c381be3bb79325ab21d906
for g in contrib/raccoon_g/gen_*.py; do
    python3 "$g" --upstream /tmp/lattice-hd-wallets/src/raccoon/thrc-py \
                 --out test/data/$(basename "${g#contrib/raccoon_g/gen_}" .py | sed 's/_vectors$//')_vectors.h
done
```

The committed header SHAs must match a fresh regeneration; if any drifts,
the upstream pin has moved and the rest of this directory needs
re-validation.

## CI

`.github/workflows/ci.yml` includes an `x86_64-linux-raccoon-g` matrix
entry which builds with `--enable-static --disable-shared
--enable-raccoon-g` (installing `libgmp-dev` / `libmpfr-dev` for the
in-tree Gaussian sampler) and runs the full unit test suite, including
every byte-exact Raccoon-G KAT driver.

## Public libdogecoin API wiring

`src/pqc_raccoon.c` is built only when `--enable-raccoon-g` is configured
and contains exactly one Raccoon-G route, which forwards the
`dogecoin_raccoong44_keypair` / `_sign` / `_verify` / `_hd_derive_priv` /
`_hd_derive_pub` entry points into `raccoong_keygen_from_seed` /
`raccoong_sign` / `raccoong_verify` / `raccoong_hd_derive_priv` /
`raccoong_hd_derive_pub` here. The algorithm-agnostic OP_RETURN
commitment helpers (`dogecoin_raccoong44_commit_bytes`,
`dogecoin_tx_add_raccoong44_commit`,
`dogecoin_tx_extract_raccoong44_commit`) remain in
`src/pqc_raccoon.c` and are independent of the chosen backend.

The public `dogecoin_raccoong44_keypair` entry point draws a 32-byte seed
from `dogecoin_random_bytes` and threads it through
`raccoong_keygen_from_seed`; callers that need byte-deterministic
keypairs (e.g. for KAT replay) can call `raccoong_keygen_from_seed`
directly with a caller-supplied seed. HD derivation uses HMAC-SHA512
keyed on the chaincode (BIP-32 style), matching the upstream reference.

## Outstanding work checklist

- [x] (Session 3) `polyr.c`: parameter set, coefficient layout, add/sub/
  mul_pointwise/scale/lshift/rshift/center, fixture-driven byte-exact test.
- [x] (Session 4) `ntt.c`: twiddle table, forward/inverse NTT, pointwise
  multiply, twiddle-SHA matched against upstream.
- [x] (Session 5) `gaussian.c`: MPFR-backed Marsaglia polar method 1:1 from
  upstream `sample_rounded`; byte-exact gate against a recorded SHAKE256
  prefix at σ² = 2⁴⁰ (256 samples).
- [x] (Session 6) `shake256.c`: FIPS 202 SHAKE256 (Keccak-f[1600]); empty-
  input + `"abc"` KATs; streaming/one-shot/multi-piece-absorb agreement;
  flips `gaussian_sample(out, n, seed[32])` from stub-`false` to byte-exact
  agreement with the recorded fixture seed.
- [x] (Session 7a) SHAKE128 added alongside SHAKE256 (rate 168, shared
  Keccak-f[1600]) and `raccoong_xof_sample_q` — 1:1 port of upstream's
  uniform Z_q rejection sampler used by `ExpandA` and threshold-share
  generation.  Byte-exact gate covers four (A_seed, i, j) / (key, i, j, k)
  cells against pinned upstream output (256 Z_q samples each).
- [x] (Session 7b) `raccoong_expand_a` (9×9 matrix loop over
  `xof_sample_q`) plus the vector helpers `raccoong_vec_ntt` /
  `_vec_intt` / `_vec_add` / `_vec_rshift` and `raccoong_mul_mat_vec_ntt`
  (mirrors upstream `polyr.py::mul_mat_vec_ntt`).  Byte-exact gate
  records the upstream `mul_mat_vec_ntt(_expand_a(A_seed),
  [_xof_sample_q(seed_j) for j])` 9-vector (9·256 u64) and reproduces
  it from seeds in C; an additional NTT-domain pointwise gate isolates
  any regression in `polyr_mul_pointwise`.
- [x] (Session 7c) `raccoong_keygen_t_unrounded(key[32], A_seed_out,
  t_out, s_out)` — 1:1 port of upstream `_keygen_unrounded`.
  Composes `SHAKE256(_hdr8('A')+key, 16)` for `A_seed`,
  `gaussian_sample_seed(2^14, _hdr8('s',i)+key, n)` for `s_i`,
  `gaussian_sample_seed(2^14, _hdr8('e',i,1)+key, n)` for `e1_i`,
  then `t = vec_intt(A_ntt * vec_ntt(s)) + e1`  (no rshift; preserves
  HD-wallet additive linearity).  Byte-exact tiered gate covers
  s[0]/e1[0] at sigma_t²=2^14, A_seed (16 bytes) and the full
  9·256 u64 unrounded `t`.
- [x] (Session 7d) `thrc_keygen_from_seed(seed[32], pk, sk)` — full
  seed→keypair pipeline. HKDF-SHA256(seed, 48) → NIST_KAT_DRBG → 32-byte
  drbg key → `raccoong_keygen_t_unrounded` → canonical LE 7-byte/coeff
  serialization. pk = 16144 B, sk = 32272 B. Byte-exact gated against
  upstream `generate_keypair_from_seed`.
- [x] (Session 7e) `thrc_hd_derive_priv / _pub` — non-hardened and
  hardened child derivation. tweak_seed = `HMAC-SHA512(chaincode,
  tag||sha256(parent_key)||index_BE)[:32]`, with `tag = 'p'` and
  `parent_key = parent_pk` for non-hardened, `tag = 'S'` and
  `parent_key = parent_sk` for hardened (index encoded with the BIP-32
  hardened high bit). The tweak keypair reuses the parent `A_seed`
  (`generate_tweak_keypair_from_seed` upstream); child polynomials are
  obtained by coefficient-wise addition mod q:
  `child_t = parent_t + tweak_t`, `child_s = parent_s + tweak_s`.
  Byte-exact gated against upstream
  `generate_tweak_keypair_from_seed` + `add_public_keys` +
  `add_signing_keys`.
- [x] (Session 7f.1) `thrc.c`: canonical 20768-byte signature wire format
  (`raccoong_serialize_signature` / `raccoong_deserialize_signature`).
  z packed as 9·256·7 little-endian bytes mod q; h packed as 9·256·2 LE
  bytes mod q_w (= q >> 38 = 2048), centered to [-q_w/2, q_w/2) on read.
  Byte-exact gated against upstream `serialize_signature`; round-trip
  and out-of-range coefficient reject covered.
- [x] (Session 7f.2 / 7f.3) `thrc.c` `hash_vec` and `chal_poly` oracles —
  `SHAKE256(_hdr24(ds,len(dat),7·v_len) || dat || ⨁ x.to_bytes(7,LE))`
  hash_vec and the τ=23 challenge polynomial sampler over SHAKE256
  (`_hdr8('c',τ) || c_hash`, 2 bytes per attempt, sign-and-index packing).
  Byte-exact gated against pinned upstream fixtures.
- [x] (Session 7f.4) `thrc.c` BUFF `mu` —
  `tr = SHAKE256(pk).read(32); mu = SHAKE256(tr || msg).read(32)`;
  `thrc_sign` / `thrc_verify` operate on `mu`, not the raw message.
  Byte-exact gated against upstream `_buff_mu`.
- [x] (Session 7f.5) `thrc_sign` / `thrc_verify` glue — Algorithm 2 / 3
  with the unrounded-`t̂` round-and-lshift step, BUFF `mu` binding to
  pk, challenge polynomial, hint vector encoding, and `_check_bounds`
  centering. Byte-exact KAT against upstream
  `_sign_with_unrounded_public_key` / `_verify_with_unrounded_public_key`
  including a tampered-signature reject and a wrong-pk reject.
- [x] (Session 7g) `test/data/raccoong_kat.json` + `test/raccoong_sign_tests.c`
  driver wired into the `tests` binary, including the tampered-signature
  reject case.
- [x] (Session 7h) CI matrix entry exercising `--enable-raccoon-g`
  (`x86_64-linux-raccoon-g` in `.github/workflows/ci.yml`).
- [x] `raccoong_is_ready()` flipped to `true`; libdogecoin
  `dogecoin_raccoong44_*` entry points route through the in-tree
  backend whenever the library is built with `--enable-raccoon-g`.

