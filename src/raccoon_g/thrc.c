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
 * Raccoon-G-44 threshold core — skeleton. Keygen/sign/verify/HD-derive land
 * in Sessions 6-7 and must produce byte-identical output to the upstream
 * Python reference (p-11/lattice-hd-wallets) for the committed KAT seeds.
 */

#include "thrc.h"

#include <string.h>

#include "polyr.h"
#include "ntt.h"
#include "shake256.h"

void raccoong_hdr8(uint8_t out[8], char ds,
                   uint8_t b1, uint8_t b2, uint8_t b3,
                   uint8_t b4, uint8_t b5, uint8_t b6, uint8_t b7)
{
    out[0] = (uint8_t)ds;
    out[1] = b1; out[2] = b2; out[3] = b3;
    out[4] = b4; out[5] = b5; out[6] = b6; out[7] = b7;
}

void raccoong_hdr24(uint8_t out[8], char ds,
                    uint32_t i, uint32_t j, uint8_t k)
{
    /* Upstream layout: bytes([ord(ds), k]) + i.to_bytes(3,'little')
     *                                      + j.to_bytes(3,'little').
     * The 3-byte little-endian fields are the low 3 bytes of i / j. */
    out[0] = (uint8_t)ds;
    out[1] = k;
    out[2] = (uint8_t)(i      );
    out[3] = (uint8_t)(i >> 8 );
    out[4] = (uint8_t)(i >> 16);
    out[5] = (uint8_t)(j      );
    out[6] = (uint8_t)(j >> 8 );
    out[7] = (uint8_t)(j >> 16);
}

dogecoin_bool raccoong_xof_sample_q(uint64_t out[/* RACCOONG_N */],
                                    const uint8_t* seed, size_t seed_len)
{
    if (!out || (!seed && seed_len != 0)) return false;

    /* q_bits = RACCOONG_LOG_Q = 50, blen = ceil(50/8) = 7. */
    const unsigned blen = (RACCOONG_LOG_Q + 7u) / 8u;             /* 7 */
    const uint64_t mask = (RACCOONG_LOG_Q >= 64)
        ? (uint64_t)~0ULL
        : (((uint64_t)1 << RACCOONG_LOG_Q) - 1ULL);               /* 2^50 - 1 */

    shake128_ctx ctx;
    shake128_init(&ctx);
    shake128_absorb(&ctx, seed, seed_len);
    shake128_finalize(&ctx);

    size_t i = 0;
    while (i < RACCOONG_N) {
        uint8_t z[8] = {0};   /* read into low `blen` bytes; high zero */
        shake128_squeeze(&ctx, z, blen);
        uint64_t x = ((uint64_t)z[0]      ) |
                     ((uint64_t)z[1] <<  8) |
                     ((uint64_t)z[2] << 16) |
                     ((uint64_t)z[3] << 24) |
                     ((uint64_t)z[4] << 32) |
                     ((uint64_t)z[5] << 40) |
                     ((uint64_t)z[6] << 48);
        x &= mask;
        if (x < RACCOONG_Q) {
            out[i++] = x;
        }
    }
    return true;
}

dogecoin_bool raccoong_expand_a(polyr A[RACCOONG_K][RACCOONG_ELL],
                                const uint8_t A_seed[RACCOONG_A_SEED_BYTES])
{
    if (!A || !A_seed) return false;

    /* Upstream: a[i][j] = _xof_sample_q(_hdr8('A', i, j) + A_seed). */
    uint8_t buf[8 + RACCOONG_A_SEED_BYTES];
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        for (unsigned j = 0; j < RACCOONG_ELL; ++j) {
            raccoong_hdr8(buf, 'A',
                          (uint8_t)i, (uint8_t)j, 0, 0, 0, 0, 0);
            memcpy(buf + 8, A_seed, RACCOONG_A_SEED_BYTES);
            if (!raccoong_xof_sample_q(A[i][j].coeffs, buf, sizeof(buf))) {
                return false;
            }
        }
    }
    return true;
}

dogecoin_bool raccoong_vec_ntt(polyr* v, size_t n)
{
    if (!v) return false;
    for (size_t i = 0; i < n; ++i) {
        if (!ntt_forward(&v[i])) return false;
    }
    return true;
}

dogecoin_bool raccoong_vec_intt(polyr* v, size_t n)
{
    if (!v) return false;
    for (size_t i = 0; i < n; ++i) {
        if (!ntt_inverse(&v[i])) return false;
    }
    return true;
}

dogecoin_bool raccoong_vec_add(polyr* r, const polyr* a, const polyr* b,
                               size_t n)
{
    if (!r || !a || !b) return false;
    for (size_t i = 0; i < n; ++i) {
        if (!polyr_add(&r[i], &a[i], &b[i])) return false;
    }
    return true;
}

dogecoin_bool raccoong_vec_rshift(polyr* r, const polyr* a, unsigned shift,
                                  size_t n)
{
    if (!r || !a) return false;
    for (size_t i = 0; i < n; ++i) {
        if (!polyr_rshift(&r[i], &a[i], shift)) return false;
    }
    return true;
}

dogecoin_bool raccoong_mul_mat_vec_ntt(polyr out[RACCOONG_K],
                                       const polyr A[RACCOONG_K][RACCOONG_ELL],
                                       const polyr v[RACCOONG_ELL])
{
    if (!out || !A || !v) return false;

    /* Upstream:
     *     for i in range(k):
     *         for j in range(ell):
     *             r[i] = poly_add(r[i], mul_ntt(m[i][j], v[j]))
     * `mul_ntt` is coefficient-wise (NTT-domain) multiplication.
     */
    polyr tmp;
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        polyr_set_zero(&out[i]);
        for (unsigned j = 0; j < RACCOONG_ELL; ++j) {
            if (!polyr_mul_pointwise(&tmp, &A[i][j], &v[j])) return false;
            if (!polyr_add(&out[i], &out[i], &tmp)) return false;
        }
    }
    return true;
}

dogecoin_bool thrc_keygen_from_seed(const uint8_t seed[32],
                                    uint8_t* pk_out, size_t pk_len,
                                    uint8_t* sk_out, size_t sk_len)
{
    (void)seed; (void)pk_out; (void)pk_len; (void)sk_out; (void)sk_len;
    return false;
}

dogecoin_bool thrc_sign(const uint8_t* sk, size_t sk_len,
                        const uint8_t* msg, size_t msg_len,
                        uint8_t* sig_out, size_t* sig_len_inout)
{
    (void)sk; (void)sk_len; (void)msg; (void)msg_len;
    (void)sig_out; (void)sig_len_inout;
    return false;
}

dogecoin_bool thrc_verify(const uint8_t* pk, size_t pk_len,
                          const uint8_t* msg, size_t msg_len,
                          const uint8_t* sig, size_t sig_len)
{
    (void)pk; (void)pk_len; (void)msg; (void)msg_len; (void)sig; (void)sig_len;
    return false;
}

dogecoin_bool thrc_hd_derive_priv(const uint8_t* parent_sk, size_t parent_sk_len,
                                  const uint8_t* parent_pk, size_t parent_pk_len,
                                  const uint8_t chaincode[32],
                                  uint32_t index, dogecoin_bool hardened,
                                  uint8_t* child_sk_out, size_t child_sk_len,
                                  uint8_t* child_pk_out, size_t child_pk_len)
{
    (void)parent_sk; (void)parent_sk_len; (void)parent_pk; (void)parent_pk_len;
    (void)chaincode; (void)index; (void)hardened;
    (void)child_sk_out; (void)child_sk_len;
    (void)child_pk_out; (void)child_pk_len;
    return false;
}

dogecoin_bool thrc_hd_derive_pub(const uint8_t* parent_pk, size_t parent_pk_len,
                                 const uint8_t chaincode[32],
                                 uint32_t index,
                                 uint8_t* child_pk_out, size_t child_pk_len)
{
    (void)parent_pk; (void)parent_pk_len; (void)chaincode; (void)index;
    (void)child_pk_out; (void)child_pk_len;
    return false;
}
