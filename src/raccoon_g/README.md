# Raccoon-G-44 — in-tree port

> ⚠ **Experimental and incomplete.** Do not enable for production use.
> This directory is the staged C port of the Raccoon-G-44 post-quantum
> threshold signature scheme. Until the upstream KAT gate (below) passes
> byte-for-byte, `raccoong_is_ready()` returns `false` and every
> `dogecoin_raccoong44_*` entry point fails closed.

## Upstream reference

- Repository: `p-11/lattice-hd-wallets`
- Pinned commit: **`461a5ed9b6d57e3bf8c381be3bb79325ab21d906`** (`update name in
  README (#14)`, the current `main` at the time of pinning).
- Reason for replacing the previous liboqs-backed route: the liboqs Raccoon-G
  implementation does not match this reference and so cannot pass its KATs.

## Parameter set (Raccoon-G-44)

Pinned in `polyr.h` from `src/raccoon/thrc-py/polyr.py`:

| Symbol         | Value                | Source                  |
|----------------|----------------------|-------------------------|
| `RACCOONG_N`   | 256                  | `RACC_N`                |
| `RACCOONG_Q`   | 562949953438721      | `RACC_Q` (50-bit prime) |
| `RACCOONG_NI`  | 560750930183101      | `RACC_NI` (= n⁻¹ mod q) |
| `RACCOONG_LOG_Q` | 50                 | ⌈log₂ q⌉                |

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

The remaining algorithm-level parameters (κ, k, ℓ, weight bounds, σ, σₜ,
masking depth d, signature shape) are pinned alongside the threshold core in
Sessions 6–7.

## Release-blocking gate

The port ships **only if** every fixture in
`test/data/raccoong_kat.json` passes byte-exactly. Specifically:

1. `polyr` round-trip (de)serialization equals upstream for every committed
   sample.
2. NTT twiddle table SHA-256 equals upstream.
3. First 2048 Gaussian samples for a fixed seed equal upstream byte-for-byte.
   This is the highest-risk step because it depends on MPFR matching `mpmath`
   rounding at σ = 2⁷/2⁴⁰.
4. Keypair, signature, and BIP-32 child secret keys equal upstream for the
   committed seeds.

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
| `shake256.{c,h}` | FIPS 202 SHAKE256 (Keccak-f[1600])              | Session 6 ✓ |
| `thrc.{c,h}`  | Keygen, sign, verify, BIP-32 HMAC-SHA512 derive    | Sessions 6-7 |
| `raccoong.{c,h}` | Public-shape glue called by `src/pqc_raccoon.c` | Stubs       |
| `README.md`   | This file.                                         | —           |

## Test fixtures

The Raccoon-G test fixtures are generated from the upstream Python and
checked in alongside the regenerator script:

- `contrib/raccoon_g/gen_polyr_vectors.py` — generator (polyr.c)
- `contrib/raccoon_g/gen_ntt_vectors.py`   — generator (ntt.c)
- `contrib/raccoon_g/gen_gaussian_vectors.py` — generator (gaussian.c)
- `test/data/raccoong_polyr_vectors.h`     — generated fixture for polyr.c
- `test/data/raccoong_ntt_vectors.h`       — generated fixture for ntt.c
- `test/data/raccoong_gaussian_vectors.h`  — generated fixture for gaussian.c

To regenerate:

```sh
git clone https://github.com/p-11/lattice-hd-wallets /tmp/lattice-hd-wallets
git -C /tmp/lattice-hd-wallets checkout 461a5ed9b6d57e3bf8c381be3bb79325ab21d906
python3 contrib/raccoon_g/gen_polyr_vectors.py \
    --upstream /tmp/lattice-hd-wallets/src/raccoon/thrc-py \
    --out test/data/raccoong_polyr_vectors.h
python3 contrib/raccoon_g/gen_ntt_vectors.py \
    --upstream /tmp/lattice-hd-wallets/src/raccoon/thrc-py \
    --out test/data/raccoong_ntt_vectors.h
python3 contrib/raccoon_g/gen_gaussian_vectors.py \
    --upstream /tmp/lattice-hd-wallets/src/raccoon/thrc-py \
    --out test/data/raccoong_gaussian_vectors.h
```

The committed header SHA must match a fresh regeneration; if it ever drifts,
the upstream pin has moved and the rest of this directory needs re-validation.

## Deviations from the public Python API

A couple of items from the previous liboqs-backed `pqc_raccoon.c` are *known*
deviations that must close before the gate can pass; they are tracked here so
they aren't silent:

- **HD derivation.** The previous code used a SHA-256 chain over
  `domain || counter || idx_be || parent || chaincode`. The reference uses
  HMAC-SHA512 keyed on the chaincode (BIP-32). Session 6 replaces this.
- **Keygen randomness.** The previous code called `OQS_SIG_keypair` (internal
  RNG). The reference is seed-deterministic from `bytes(range(32))` for KAT
  verification. The new C API takes a seed (`raccoong_keygen_from_seed`) and
  the libdogecoin public surface threads one through. Session 6 wires this.

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
- [ ] (Session 6) `thrc.c`: seed-deterministic keygen, BIP-32 HMAC-SHA512
  derivation, child-SK SHA-256 gate against upstream digest.
- [ ] (Session 7) `thrc.c`: deterministic sign / verify; tampered-signature
  reject; wrong-pk reject; valgrind clean.
- [ ] (Session 7) `test/data/raccoong_kat.json` + `test/raccoong_kat.c`
  driver wired into the `tests` binary.
- [ ] (Session 7) CI matrix entry exercising `--enable-raccoon-g`.
- [ ] Flip `raccoong_is_ready()` to `true` only when all of the above pass.
