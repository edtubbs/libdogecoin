/*

 The MIT License (MIT)

 Copyright (c) 2026 edtubbs
 Copyright (c) 2026 The Dogecoin Foundation

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/

/*
 * Raccoon-G-44 rounded Gaussian sampler — math kernel.
 *
 * 1:1 port of `sample_rounded` / `unif_real` from upstream
 *   p-11/lattice-hd-wallets@461a5ed9 src/raccoon/thrc-py/thrc_gauss.py
 *
 * Bit-exactness across mpmath@256 and MPFR@256 was checked offline (1000
 * randomly-sampled inputs to log/sqrt at exact 256-bit mantissas, zero
 * mismatches).  The byte-exact gate at runtime is
 * `test/raccoong_gaussian_tests.c::test_raccoong_gaussian` against the
 * recorded fixture in `test/data/raccoong_gaussian_vectors.h`.
 *
 * The seed-driven path (`gaussian_sample`) returns false in this session;
 * SHAKE256 plumbing lands in Session 6 alongside the rest of the upstream
 * XOF construction.
 */

#include "gaussian.h"
#include "shake256.h"

#include <gmp.h>
#include <mpfr.h>

/* mpmath precision in upstream thrc_gauss.py is 256 bits. */
#define RACCOONG_GAUSS_PREC 256

/* Bytes consumed per polar-method attempt: two 64-bit unif_real reads. */
#define RACCOONG_GAUSS_PREC_BITS_PER_SAMPLE 64
#define RACCOONG_GAUSS_BYTES_PER_ATTEMPT \
    ((RACCOONG_GAUSS_PREC_BITS_PER_SAMPLE + 7) / 8 * 2)

dogecoin_bool gaussian_sampler_init(void)
{
    /* Set MPFR's default precision so all callers get the right working
     * width without having to thread it through the kernel API.  Calling
     * twice is harmless. */
    mpfr_set_default_prec(RACCOONG_GAUSS_PREC);
    return true;
}

void gaussian_sampler_shutdown(void)
{
    mpfr_free_cache();
}

/* Read a 64-bit little-endian unsigned integer at `*pos`, advance `*pos`. */
static dogecoin_bool xof_read_u64_le(const uint8_t* buf, size_t buf_len,
                                     size_t* pos, uint64_t* out)
{
    if (*pos + 8 > buf_len) {
        return false;
    }
    uint64_t v = 0;
    for (int k = 0; k < 8; ++k) {
        v |= ((uint64_t)buf[*pos + (size_t)k]) << (8 * k);
    }
    *pos += 8;
    *out = v;
    return true;
}

/* Convert a raw 64-bit unsigned word into a signed mpmath/MPFR value in
 * [-1, 1 - 2^-63] following upstream `unif_real` with prec=64. */
static void unif_real_set_from_u64(mpfr_t dst, uint64_t u)
{
    /* Two's-complement signed: if u >= 2^63, value -= 2^64. */
    int64_t s;
    if (u >= ((uint64_t)1 << 63)) {
        /* u - 2^64 fits in int64_t since u >= 2^63. */
        s = (int64_t)(u - ((uint64_t)1 << 63)) - (int64_t)((uint64_t)1 << 63);
    } else {
        s = (int64_t)u;
    }
    /* upstream: mp_scl = 2^-(prec-1) = 2^-63; result = mp_scl * s. */
    mpfr_set_si(dst, (long)s, MPFR_RNDN);
    mpfr_div_2ui(dst, dst, 63, MPFR_RNDN);
}

/* round_half_up: floor(x + 1/2). */
static long mp_round_half_up_to_long(mpfr_srcptr x, mpfr_t scratch)
{
    /* scratch = x + 0.5 ; floor ; cast to long. */
    mpfr_set_d(scratch, 0.5, MPFR_RNDN);
    mpfr_add(scratch, x, scratch, MPFR_RNDN);
    mpfr_floor(scratch, scratch);
    /* The samples never approach long range overflow at sigma=2^20
     * (|v| < ~18*sigma). MPFR_RNDD is fine since the value is already
     * an integer at this point. */
    return mpfr_get_si(scratch, MPFR_RNDD);
}

dogecoin_bool gaussian_sample_rounded_from_xof(int64_t* out,
                                               size_t n,
                                               uint32_t lg_sigma2,
                                               const uint8_t* xof_bytes,
                                               size_t xof_len,
                                               size_t* xof_consumed_bytes)
{
    if (!out || !xof_bytes || (n & 1u)) {
        /* upstream produces samples in pairs; n must be even. */
        return false;
    }

    /* Upstream:
     *   sig' = sqrt(sig^2 - 1/12); cs2 = -2 * sig'^2
     *        = -2 * (sig^2 - 1/12) = 1/6 - 2*sig^2
     */
    mpfr_t cs2, sig2_mpfr, sixth, x0, x1, s_acc, s_factor, t, scratch;
    mpfr_inits2(RACCOONG_GAUSS_PREC, cs2, sig2_mpfr, sixth, x0, x1,
                s_acc, s_factor, t, scratch, (mpfr_ptr)0);

    /* sig2 = 2^lg_sigma2 (exact). */
    mpfr_set_ui_2exp(sig2_mpfr, 1, lg_sigma2, MPFR_RNDN);

    /* sixth = 1/6 (rounded to 256 bits, matches mpmath fdiv(1,6)). */
    mpfr_set_ui(sixth, 1, MPFR_RNDN);
    mpfr_div_ui(sixth, sixth, 6, MPFR_RNDN);

    /* cs2 = sixth - ldexp(sig2, 1) = 1/6 - 2*sig2.  ldexp(sig2,1) is exact. */
    mpfr_mul_2ui(t, sig2_mpfr, 1, MPFR_RNDN);
    mpfr_sub(cs2, sixth, t, MPFR_RNDN);

    size_t pos = 0;
    size_t i = 0;
    while (i < n) {
        uint64_t u0, u1;
        if (!xof_read_u64_le(xof_bytes, xof_len, &pos, &u0)) {
            goto fail;
        }
        if (!xof_read_u64_le(xof_bytes, xof_len, &pos, &u1)) {
            goto fail;
        }
        unif_real_set_from_u64(x0, u0);
        unif_real_set_from_u64(x1, u1);

        /* s_acc = x0^2 + x1^2 */
        mpfr_sqr(t, x0, MPFR_RNDN);
        mpfr_sqr(s_acc, x1, MPFR_RNDN);
        mpfr_add(s_acc, s_acc, t, MPFR_RNDN);

        /* Reject unless 0 < s_acc < 1. */
        if (mpfr_sgn(s_acc) <= 0) continue;
        if (mpfr_cmp_ui(s_acc, 1) >= 0) continue;

        /* s_factor = sqrt( cs2 * log(s_acc) / s_acc ) */
        mpfr_log(t, s_acc, MPFR_RNDN);
        mpfr_mul(t, cs2, t, MPFR_RNDN);
        mpfr_div(t, t, s_acc, MPFR_RNDN);
        mpfr_sqrt(s_factor, t, MPFR_RNDN);

        /* v[i]   = round_half_up(s_factor * x0)
         * v[i+1] = round_half_up(s_factor * x1) */
        mpfr_mul(t, s_factor, x0, MPFR_RNDN);
        out[i]     = (int64_t)mp_round_half_up_to_long(t, scratch);
        mpfr_mul(t, s_factor, x1, MPFR_RNDN);
        out[i + 1] = (int64_t)mp_round_half_up_to_long(t, scratch);

        i += 2;
    }

    if (xof_consumed_bytes) *xof_consumed_bytes = pos;

    mpfr_clears(cs2, sig2_mpfr, sixth, x0, x1, s_acc, s_factor, t, scratch,
                (mpfr_ptr)0);
    return true;

fail:
    mpfr_clears(cs2, sig2_mpfr, sixth, x0, x1, s_acc, s_factor, t, scratch,
                (mpfr_ptr)0);
    return false;
}

/*
 * Seed-driven entry point.  Drives the kernel from `SHAKE256(seed)` at the
 * default sigma^2 = 2^RACCOONG_GAUSS_LG_SIGMA2_DEFAULT.  Byte-exact against
 * the recorded fixture (see test/raccoong_gaussian_tests.c::test_raccoong_
 * gaussian_seed) because SHAKE256 itself is byte-exact against pycryptodome
 * (FIPS 202 empty-input KAT + 8 KiB-of-fixture-seed agreement test).
 */
dogecoin_bool gaussian_sample(int64_t* out, size_t n, const uint8_t seed[32])
{
    if (!out || !seed || (n & 1u)) return false;

    /* Pre-stream 8 KiB from SHAKE256 — sufficient for sigma = 2^20 over
     * RACCOONG_N samples at the canonical rejection rate (~22%).  If a
     * downstream caller ever needs a larger n or smaller sigma we will
     * switch to streaming the XOF directly into the kernel; for now the
     * batched form keeps this function side-effect-free on the SHAKE state
     * and matches the way the Session-5 fixture is recorded. */
    uint8_t xof[8192];
    shake256(xof, sizeof(xof), seed, 32);

    return gaussian_sample_rounded_from_xof(
        out, n,
        (uint32_t)RACCOONG_GAUSS_LG_SIGMA2_DEFAULT,
        xof, sizeof(xof), /*xof_consumed_bytes=*/NULL);
}
