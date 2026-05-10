# Raccoon-G-44 — in-tree port

> ⚠ **Experimental and incomplete.** Do not enable for production use.
> This directory is the staged C port of the Raccoon-G-44 post-quantum
> threshold signature scheme. Until the upstream KAT gate (below) passes
> byte-for-byte, `raccoong_is_ready()` returns `false` and every
> `dogecoin_raccoong44_*` entry point fails closed.

## Upstream reference

- Repository: `p-11/lattice-hd-wallets`
- Pinned commit: **TODO (set in Session 3 alongside `polyr.c`)**
- Reason for replacing the previous liboqs-backed route: the liboqs Raccoon-G
  implementation does not match this reference and so cannot pass its KATs.

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

| File          | Responsibility                                     | Lands in   |
|---------------|----------------------------------------------------|------------|
| `polyr.{c,h}` | `Z_q[X]/(X^n+1)` polynomial arithmetic             | Session 3 |
| `ntt.{c,h}`   | Forward / inverse NTT, pointwise multiply          | Session 4 |
| `gaussian.{c,h}` | MPFR-backed rounded Gaussian sampler            | Session 5 |
| `thrc.{c,h}`  | Keygen, sign, verify, BIP-32 HMAC-SHA512 derive    | Sessions 6-7 |
| `raccoong.{c,h}` | Public-shape glue called by `src/pqc_raccoon.c` | (this commit, stubs) |
| `README.md`   | This file.                                         | (this commit) |

## Parameter set (Raccoon-G-44)

The numeric parameters (modulus `q`, ring degree `n`, weight bounds, sampler
σ and precision, public-key / signature sizes) are **intentionally not
encoded in this skeleton commit**. They are pinned in Session 3 against the
upstream reference and will be added to `polyr.h` then. Encoding values here
prematurely would risk creating a header that downstream code starts to
depend on before they are verified.

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

- [ ] (Session 3) `polyr.c`: parameter set, coefficient layout, add/sub/mul,
  byte-exact (de)serialization, fixture-driven unit tests.
- [ ] (Session 4) `ntt.c`: twiddle table, forward/inverse NTT, pointwise
  multiply, twiddle-SHA matched against upstream.
- [ ] (Session 5) `gaussian.c`: MPFR sampler matching `mpmath` at σ = 2⁷/2⁴⁰;
  first-2048-samples gate.
- [ ] (Session 6) `thrc.c`: seed-deterministic keygen, BIP-32 HMAC-SHA512
  derivation, child-SK SHA-256 gate against upstream digest.
- [ ] (Session 7) `thrc.c`: deterministic sign / verify; tampered-signature
  reject; wrong-pk reject; valgrind clean.
- [ ] (Session 7) `test/data/raccoong_kat.json` + `test/raccoong_kat.c`
  driver wired into the `tests` binary.
- [ ] (Session 7) CI matrix entry exercising `--enable-raccoon-g`.
- [ ] Flip `raccoong_is_ready()` to `true` only when all of the above pass.
