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

#ifndef LIBDOGECOIN_RACCOON_G_THRC_H
#define LIBDOGECOIN_RACCOON_G_THRC_H

#include <stddef.h>
#include <stdint.h>

#include <dogecoin/dogecoin.h>

#include "polyr.h"

LIBDOGECOIN_BEGIN_DECL

/*
 * Raccoon-G-44 threshold core dimensions (mirrors upstream `ThRc_Core` defaults
 * for HD-wallet sigs at #sigs 2^60: k = ell = 9).
 */
#define RACCOONG_K   9u
#define RACCOONG_ELL 9u

/*
 * Size of `A_seed` (the public-matrix seed, "as_sz" upstream).
 */
#define RACCOONG_A_SEED_BYTES 16u

/*
 * Threshold core ("thrc") for Raccoon-G-44: keygen, sign, verify, and BIP-32
 * style child derivation. Glue around polyr / ntt / gaussian. All routines
 * are byte-deterministic with respect to their inputs (seed, message, etc.)
 * to allow byte-exact KAT comparison against the upstream Python reference.
 */

dogecoin_bool thrc_keygen_from_seed(const uint8_t seed[32],
                                    uint8_t* pk_out, size_t pk_len,
                                    uint8_t* sk_out, size_t sk_len);

dogecoin_bool thrc_sign(const uint8_t* sk, size_t sk_len,
                        const uint8_t* msg, size_t msg_len,
                        uint8_t* sig_out, size_t* sig_len_inout);

dogecoin_bool thrc_verify(const uint8_t* pk, size_t pk_len,
                          const uint8_t* msg, size_t msg_len,
                          const uint8_t* sig, size_t sig_len);

dogecoin_bool thrc_hd_derive_priv(const uint8_t* parent_sk, size_t parent_sk_len,
                                  const uint8_t* parent_pk, size_t parent_pk_len,
                                  const uint8_t chaincode[32],
                                  uint32_t index, dogecoin_bool hardened,
                                  uint8_t* child_sk_out, size_t child_sk_len,
                                  uint8_t* child_pk_out, size_t child_pk_len);

dogecoin_bool thrc_hd_derive_pub(const uint8_t* parent_pk, size_t parent_pk_len,
                                 const uint8_t chaincode[32],
                                 uint32_t index,
                                 uint8_t* child_pk_out, size_t child_pk_len);

/*
 * `_xof_sample_q` — uniform Z_q rejection sampler.  1:1 port of upstream
 * `ThRc_Core._xof_sample_q` (thrc_core.py) at kappa=128 (SHAKE128).  Reads
 * ceil(q_bits/8) = 7 bytes per attempt, masks to q_bits=50 bits, accepts
 * if the masked value is in [0, q).  Deterministic given `seed`.
 *
 * `out` receives RACCOONG_N values, each in [0, RACCOONG_Q).  Returns
 * false on null inputs.  Used by ExpandA and threshold-share generation.
 */
dogecoin_bool raccoong_xof_sample_q(uint64_t out[/* RACCOONG_N */],
                                    const uint8_t* seed, size_t seed_len);

/*
 * Upstream domain-separation header constructors.  Verbatim ports of
 * `_hdr8` / `_hdr24` from thrc_core.py.  Output buffer must be >= 8 / 16
 * bytes respectively.
 */
void raccoong_hdr8(uint8_t out[8], char ds,
                   uint8_t b1, uint8_t b2, uint8_t b3,
                   uint8_t b4, uint8_t b5, uint8_t b6, uint8_t b7);
void raccoong_hdr24(uint8_t out[8], char ds,
                    uint32_t i, uint32_t j, uint8_t k);

/*
 * `_expand_a` — fill the public k×ell matrix A from `A_seed`.
 *
 * 1:1 port of upstream `ThRc_Core._expand_a`: for each (i, j) the entry is
 * `_xof_sample_q(_hdr8('A', i, j) + A_seed)`.  Upstream treats this matrix
 * as already living in NTT domain (uniform random in either basis), so the
 * output is consumable directly by `raccoong_mul_mat_vec_ntt`.
 *
 * Returns false on null inputs.
 */
dogecoin_bool raccoong_expand_a(polyr A[RACCOONG_K][RACCOONG_ELL],
                                const uint8_t A_seed[RACCOONG_A_SEED_BYTES]);

/*
 * Vector / matrix-vector helpers over the ring R_q = Z_q[X]/(X^n+1).
 * Mirrors upstream polyr.py functions of the same shape.  All routines
 * return false on null inputs.  Aliasing rules match the underlying
 * `polyr_*` and `ntt_*` calls.
 */
dogecoin_bool raccoong_vec_ntt(polyr* v, size_t n);    /* in-place forward */
dogecoin_bool raccoong_vec_intt(polyr* v, size_t n);   /* in-place inverse */

dogecoin_bool raccoong_vec_add(polyr* r, const polyr* a, const polyr* b,
                               size_t n);
dogecoin_bool raccoong_vec_rshift(polyr* r, const polyr* a, unsigned shift,
                                  size_t n);

/*
 * out[i] = sum_j A[i][j] *_ntt v[j]   for i in [0, k), j in [0, ell).
 * Inputs must already be in NTT domain.  Output is in NTT domain.
 */
dogecoin_bool raccoong_mul_mat_vec_ntt(polyr out[RACCOONG_K],
                                       const polyr A[RACCOONG_K][RACCOONG_ELL],
                                       const polyr v[RACCOONG_ELL]);

LIBDOGECOIN_END_DECL

#endif /* LIBDOGECOIN_RACCOON_G_THRC_H */
