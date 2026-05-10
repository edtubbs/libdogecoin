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
 * Raccoon-G-44 Z_q polynomial arithmetic.
 *
 * Each function corresponds 1:1 to the matching helper in upstream
 * src/raccoon/thrc-py/polyr.py at commit 461a5ed9b6d57e3bf8c381be3bb79325ab21d906.
 * Byte-exactness is verified by test/raccoong_polyr_tests.c against the
 * fixture in test/data/raccoong_polyr_vectors.h, which is generated from
 * upstream by contrib/raccoon_g/gen_polyr_vectors.py.
 */

#include "polyr.h"

#include <stdlib.h>
#include <string.h>

#include <dogecoin/mem.h>

/*
 * Internal: reduce a value < 2*q into [0, q) via conditional subtraction.
 */
static inline uint64_t reduce_lt_2q(uint64_t v)
{
    return (v >= RACCOONG_Q) ? (v - RACCOONG_Q) : v;
}

dogecoin_bool polyr_alloc(polyr** out)
{
    if (!out) {
        return false;
    }
    polyr* p = (polyr*)dogecoin_calloc(1, sizeof(polyr));
    if (!p) {
        *out = NULL;
        return false;
    }
    *out = p;
    return true;
}

void polyr_free(polyr* p)
{
    if (!p) {
        return;
    }
    /* Defensive zeroing. Coefficients at this layer are public (q, ring
     * elements, public-key components); secret-bearing structs in higher
     * layers (signing key, masking shares) wrap polyr instances and are
     * responsible for their own scrubbing. Zeroing here costs ~2 KB per
     * polyr but makes accidental aliasing of freed memory benign. */
    memset(p, 0, sizeof(*p));
    dogecoin_free(p);
}

void polyr_set_zero(polyr* r)
{
    if (!r) {
        return;
    }
    memset(r->coeffs, 0, sizeof(r->coeffs));
}

void polyr_copy(polyr* r, const polyr* a)
{
    if (!r || !a) {
        return;
    }
    if (r == a) {
        return; /* self-copy is a no-op */
    }
    memcpy(r->coeffs, a->coeffs, sizeof(r->coeffs));
}

dogecoin_bool polyr_equal(const polyr* a, const polyr* b)
{
    if (!a || !b) {
        return false;
    }
    return memcmp(a->coeffs, b->coeffs, sizeof(a->coeffs)) == 0;
}

dogecoin_bool polyr_is_normalized(const polyr* a)
{
    if (!a) {
        return false;
    }
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        if (a->coeffs[i] >= RACCOONG_Q) {
            return false;
        }
    }
    return true;
}

dogecoin_bool polyr_add(polyr* r, const polyr* a, const polyr* b)
{
    if (!r || !a || !b) {
        return false;
    }
    /* a[i] + b[i] < 2*q < 2^51, no uint64 overflow. */
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        r->coeffs[i] = reduce_lt_2q(a->coeffs[i] + b->coeffs[i]);
    }
    return true;
}

dogecoin_bool polyr_sub(polyr* r, const polyr* a, const polyr* b)
{
    if (!r || !a || !b) {
        return false;
    }
    /* (a + q - b) is always positive; result < 2*q. */
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        r->coeffs[i] = reduce_lt_2q(a->coeffs[i] + RACCOONG_Q - b->coeffs[i]);
    }
    return true;
}

dogecoin_bool polyr_mul_pointwise(polyr* r, const polyr* a, const polyr* b)
{
    if (!r || !a || !b) {
        return false;
    }
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        __uint128_t prod = (__uint128_t)a->coeffs[i] * (__uint128_t)b->coeffs[i];
        r->coeffs[i] = (uint64_t)(prod % RACCOONG_Q);
    }
    return true;
}

dogecoin_bool polyr_scale(polyr* r, uint64_t c, const polyr* a)
{
    if (!r || !a) {
        return false;
    }
    /* Reduce c first so the inner loop's product stays < q^2 < 2^100. */
    uint64_t cm = c % RACCOONG_Q;
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        __uint128_t prod = (__uint128_t)cm * (__uint128_t)a->coeffs[i];
        r->coeffs[i] = (uint64_t)(prod % RACCOONG_Q);
    }
    return true;
}

dogecoin_bool polyr_lshift(polyr* r, const polyr* a, unsigned shift)
{
    if (!r || !a) {
        return false;
    }
    /* Bound shift so (a[i] << shift) fits in __uint128_t with margin. a[i]
     * is < 2^50; allowing shift < 64 keeps the product strictly below 2^114. */
    if (shift >= 64) {
        return false;
    }
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        __uint128_t v = (__uint128_t)a->coeffs[i] << shift;
        r->coeffs[i] = (uint64_t)(v % RACCOONG_Q);
    }
    return true;
}

dogecoin_bool polyr_rshift(polyr* r, const polyr* a, unsigned shift)
{
    if (!r || !a) {
        return false;
    }
    /* Upstream uses mid = 1 << (shift - 1), undefined for shift == 0. */
    if (shift == 0 || shift >= 64) {
        return false;
    }
    const uint64_t mid = (uint64_t)1 << (shift - 1);
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        /* a[i] < q < 2^50; a[i] + mid < q + 2^62 fits in uint64 for shift < 63. */
        uint64_t v = (a->coeffs[i] + mid) >> shift;
        r->coeffs[i] = v % RACCOONG_Q;
    }
    return true;
}

dogecoin_bool polyr_center(int64_t out[RACCOONG_N], const polyr* a)
{
    if (!out || !a) {
        return false;
    }
    /* q is odd (562949953438721 = 2*mid + 1), so the centered range is
     * [-mid, mid]. Upstream: ((a + mid) % q) - mid, which equals:
     *   a            if a <= mid
     *   a - q        otherwise
     */
    const uint64_t mid = RACCOONG_Q >> 1;
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        uint64_t v = a->coeffs[i];
        out[i] = (v <= mid) ? (int64_t)v : ((int64_t)v - (int64_t)RACCOONG_Q);
    }
    return true;
}
