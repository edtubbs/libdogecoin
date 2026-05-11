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

#include <dogecoin/sha2.h>

#include "gaussian.h"
#include "keygen_kdf.h"
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

dogecoin_bool raccoong_chal_poly(int8_t out[256],
                                 const uint8_t c_hash[RACCOONG_C_HASH_BYTES])
{
    if (!out || !c_hash) return false;

    /* Upstream:
     *     mask_n  = n - 1                              # = 0xff for n=256
     *     blen    = (mask_n.bit_length() + 1 + 7) // 8  # = (8+1+7)//8 = 2
     *     xof     = SHAKE256(_hdr8('c', tau) + c_hash)
     *     while wt < tau:
     *         z    = xof.read(blen)
     *         x    = int.from_bytes(z, 'little')
     *         sign = x & 1
     *         idx  = (x >> 1) & mask_n
     *         if c[idx] == 0:
     *             c[idx] = 2*sign - 1
     *             wt    += 1
     */
    memset(out, 0, 256);

    uint8_t hdr[8];
    raccoong_hdr8(hdr, 'c', (uint8_t)RACCOONG_TAU, 0, 0, 0, 0, 0, 0);

    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, hdr, sizeof(hdr));
    shake256_absorb(&ctx, c_hash, RACCOONG_C_HASH_BYTES);
    shake256_finalize(&ctx);

    unsigned wt = 0;
    while (wt < RACCOONG_TAU) {
        uint8_t z[2];
        shake256_squeeze(&ctx, z, sizeof(z));
        unsigned x   = (unsigned)z[0] | ((unsigned)z[1] << 8);
        unsigned sgn = x & 1u;
        unsigned idx = (x >> 1) & 0xffu;       /* mask_n = 255 for n=256 */
        if (out[idx] == 0) {
            out[idx] = (int8_t)((int)(2u * sgn) - 1);   /* sgn=1 -> +1, sgn=0 -> -1 */
            wt++;
        }
    }
    return true;
}

dogecoin_bool raccoong_hash_vec(uint8_t out[RACCOONG_C_HASH_BYTES],
                                char ds,
                                const uint8_t* dat, size_t dat_len,
                                const uint64_t* v, size_t v_len)
{
    if (!out) return false;
    if (dat_len != 0 && !dat) return false;
    if (v_len != 0 && !v) return false;

    /* Upstream:
     *   q_byt = (q_bits + 7) // 8                      # = 7 for Raccoon-G
     *   xof   = SHAKE256(_hdr24(ds, len(dat), q_byt * len(v)) + dat)
     *   for x in v: xof.update((x % q).to_bytes(q_byt, 'little'))
     *   return xof.read(crh)                            # 32 bytes
     *
     * The `_hdr24` "i" and "j" fields are 3-byte little-endian, so the
     * primitive only supports dat_len < 2^24 and v_len < 2^24 / 7 ≈ 2.4M
     * — well above any Raccoon-G-44 call site (largest is k*n = 2304).
     */
    const unsigned q_byt = (RACCOONG_LOG_Q + 7u) / 8u;     /* 7 */
    if (dat_len > 0xFFFFFFu) return false;
    if (v_len   > 0xFFFFFFu / q_byt) return false;

    uint8_t hdr[8];
    raccoong_hdr24(hdr, ds,
                   (uint32_t)dat_len,
                   (uint32_t)(q_byt * v_len),
                   0);

    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, hdr, sizeof(hdr));
    if (dat_len > 0) {
        shake256_absorb(&ctx, dat, dat_len);
    }
    for (size_t i = 0; i < v_len; ++i) {
        /* `x % q` (Python semantics): for unsigned uint64 < 2^63 we can
         * use a plain C `%`, which matches because both operands are
         * non-negative.  Callers feeding centered representatives must
         * reduce them to [0,q) beforehand. */
        uint64_t x = v[i] % RACCOONG_Q;
        uint8_t le[8] = {0};                              /* q_byt <= 7 */
        le[0] = (uint8_t)(x      );
        le[1] = (uint8_t)(x >>  8);
        le[2] = (uint8_t)(x >> 16);
        le[3] = (uint8_t)(x >> 24);
        le[4] = (uint8_t)(x >> 32);
        le[5] = (uint8_t)(x >> 40);
        le[6] = (uint8_t)(x >> 48);
        shake256_absorb(&ctx, le, q_byt);
    }
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, out, RACCOONG_C_HASH_BYTES);
    return true;
}

dogecoin_bool raccoong_pk_hash(uint8_t out[RACCOONG_C_HASH_BYTES],
                               const uint8_t* pk, size_t pk_len)
{
    if (!out) return false;
    if (pk_len != 0 && !pk) return false;

    /* Upstream: tr = SHAKE256(vk_bytes).read(crh). */
    shake256_ctx ctx;
    shake256_init(&ctx);
    if (pk_len > 0) {
        shake256_absorb(&ctx, pk, pk_len);
    }
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, out, RACCOONG_C_HASH_BYTES);
    return true;
}

dogecoin_bool raccoong_buff_mu(uint8_t out[RACCOONG_C_HASH_BYTES],
                               const uint8_t tr[RACCOONG_C_HASH_BYTES],
                               const uint8_t* msg, size_t msg_len)
{
    if (!out || !tr) return false;
    if (msg_len != 0 && !msg) return false;

    /* Upstream: mu = SHAKE256(tr || msg).read(mu_sz = crh). */
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, tr, RACCOONG_C_HASH_BYTES);
    if (msg_len > 0) {
        shake256_absorb(&ctx, msg, msg_len);
    }
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, out, RACCOONG_C_HASH_BYTES);
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

/* Reduce a signed int64_t array to a polyr in [0, RACCOONG_Q). */
static void polyr_load_signed(polyr* dst, const int64_t* src)
{
    const int64_t Q = (int64_t)RACCOONG_Q;
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        int64_t v = src[i] % Q;
        if (v < 0) v += Q;
        dst->coeffs[i] = (uint64_t)v;
    }
}

static dogecoin_bool keygen_t_unrounded_inner(const uint8_t key[32],
                                              const uint8_t A_seed_in[RACCOONG_A_SEED_BYTES],
                                              polyr t_out[RACCOONG_K],
                                              polyr s_out[RACCOONG_ELL])
{
    /* --- 1b. A = ExpandA(A_seed)  (already in NTT domain). --- */
    static polyr A[RACCOONG_K][RACCOONG_ELL];
    if (!raccoong_expand_a(A, A_seed_in)) return false;

    /* --- 2. s ~ D_t^ell, e1 ~ D_t^k via sample_rounded(2^14, hdr8 + key). */
    static polyr s_poly[RACCOONG_ELL];
    static polyr e1_poly[RACCOONG_K];
    int64_t sample_buf[RACCOONG_N];

    uint8_t seed_buf[8 + 32];
    memcpy(seed_buf + 8, key, 32);

    for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
        raccoong_hdr8(seed_buf, 's', (uint8_t)i, 0, 0, 0, 0, 0, 0);
        if (!gaussian_sample_seed(sample_buf, RACCOONG_N,
                                  RACCOONG_LG_SIGMA_T2,
                                  seed_buf, sizeof(seed_buf))) {
            return false;
        }
        polyr_load_signed(&s_poly[i], sample_buf);
    }
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        raccoong_hdr8(seed_buf, 'e', (uint8_t)i, 1, 0, 0, 0, 0, 0);
        if (!gaussian_sample_seed(sample_buf, RACCOONG_N,
                                  RACCOONG_LG_SIGMA_T2,
                                  seed_buf, sizeof(seed_buf))) {
            return false;
        }
        polyr_load_signed(&e1_poly[i], sample_buf);
    }

    /* Capture s in caller's signed-secret slot before we forward-NTT it. */
    if (s_out) {
        for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
            polyr_copy(&s_out[i], &s_poly[i]);
        }
    }

    /* --- 3. t := A * s + e1   (no rshift). --- */
    static polyr s_ntt[RACCOONG_ELL];
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
        polyr_copy(&s_ntt[i], &s_poly[i]);
    }
    if (!raccoong_vec_ntt(s_ntt, RACCOONG_ELL)) return false;

    static polyr t_ntt[RACCOONG_K];
    if (!raccoong_mul_mat_vec_ntt(t_ntt, A, s_ntt)) return false;

    if (!raccoong_vec_intt(t_ntt, RACCOONG_K)) return false;

    return raccoong_vec_add(t_out, t_ntt, e1_poly, RACCOONG_K);
}

dogecoin_bool raccoong_keygen_t_unrounded(const uint8_t key[32],
                                          uint8_t A_seed_out[RACCOONG_A_SEED_BYTES],
                                          polyr t_out[RACCOONG_K],
                                          polyr s_out[RACCOONG_ELL])
{
    if (!key || !A_seed_out || !t_out) return false;

    /* --- 1. A_seed = SHAKE256(_hdr8('A') + key, 16) --- */
    uint8_t hdr_in[8 + 32];
    raccoong_hdr8(hdr_in, 'A', 0, 0, 0, 0, 0, 0, 0);
    memcpy(hdr_in + 8, key, 32);
    shake256(A_seed_out, RACCOONG_A_SEED_BYTES, hdr_in, sizeof(hdr_in));

    return keygen_t_unrounded_inner(key, A_seed_out, t_out, s_out);
}

/*
 * Tweak variant of the unrounded keygen — reuses the parent's `A_seed`
 * instead of deriving it from `key`.  Mirrors upstream
 * `generate_tweak_keypair_from_seed`'s middle section (after the DRBG key
 * is drawn): A_ntt = expand(parent_A_seed); s/e1 ~ sample_rounded(...+key);
 * t = A*s + e1 (unrounded).
 */
static dogecoin_bool raccoong_keygen_t_with_aseed(const uint8_t key[32],
                                                  const uint8_t A_seed_in[RACCOONG_A_SEED_BYTES],
                                                  polyr t_out[RACCOONG_K],
                                                  polyr s_out[RACCOONG_ELL])
{
    if (!key || !A_seed_in || !t_out) return false;
    return keygen_t_unrounded_inner(key, A_seed_in, t_out, s_out);
}

dogecoin_bool thrc_keygen_from_seed(const uint8_t seed[32],
                                    uint8_t* pk_out, size_t pk_len,
                                    uint8_t* sk_out, size_t sk_len);

/* Forward decls for HD-derive helpers. */
static dogecoin_bool deserialize_poly_le7(polyr* dst, const uint8_t* src);
static dogecoin_bool deserialize_pk_into(const uint8_t* pk, size_t pk_len,
                                         uint8_t A_seed_out[RACCOONG_A_SEED_BYTES],
                                         polyr t_out[RACCOONG_K]);
static dogecoin_bool deserialize_sk_into(const uint8_t* sk, size_t sk_len,
                                         uint8_t A_seed_out[RACCOONG_A_SEED_BYTES],
                                         polyr t_out[RACCOONG_K],
                                         polyr s_out[RACCOONG_ELL]);
static dogecoin_bool hd_derive_tweak_seed(uint8_t tweak_seed_out[32],
                                          const uint8_t* parent_pk, size_t parent_pk_len,
                                          const uint8_t* parent_sk, size_t parent_sk_len,
                                          const uint8_t chaincode[32],
                                          uint32_t index, dogecoin_bool hardened);

/* Pack one polyr (already in [0, q)) as 256 little-endian 7-byte coeffs. */
static void serialize_poly_le7(uint8_t* dst, const polyr* p)
{
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        uint64_t c = p->coeffs[i]; /* normalized [0, q), q < 2^50 */
        dst[0] = (uint8_t)(c);
        dst[1] = (uint8_t)(c >> 8);
        dst[2] = (uint8_t)(c >> 16);
        dst[3] = (uint8_t)(c >> 24);
        dst[4] = (uint8_t)(c >> 32);
        dst[5] = (uint8_t)(c >> 40);
        dst[6] = (uint8_t)(c >> 48);
        dst += RACCOONG_COEFF_BYTES;
    }
}

void raccoong_serialize_pk(uint8_t pk_out[/*RACCOONG_PK_BYTES*/],
                           const uint8_t A_seed[RACCOONG_A_SEED_BYTES],
                           const polyr t[RACCOONG_K])
{
    memcpy(pk_out, A_seed, RACCOONG_A_SEED_BYTES);
    uint8_t* p = pk_out + RACCOONG_A_SEED_BYTES;
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        serialize_poly_le7(p, &t[i]);
        p += (size_t)RACCOONG_N * RACCOONG_COEFF_BYTES;
    }
}

void raccoong_serialize_sk(uint8_t sk_out[/*RACCOONG_SK_BYTES*/],
                           const uint8_t A_seed[RACCOONG_A_SEED_BYTES],
                           const polyr t[RACCOONG_K],
                           const polyr s[RACCOONG_ELL])
{
    raccoong_serialize_pk(sk_out, A_seed, t);
    uint8_t* p = sk_out + RACCOONG_PK_BYTES;
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
        serialize_poly_le7(p, &s[i]);
        p += (size_t)RACCOONG_N * RACCOONG_COEFF_BYTES;
    }
}

dogecoin_bool thrc_keygen_from_seed(const uint8_t seed[32],
                                    uint8_t* pk_out, size_t pk_len,
                                    uint8_t* sk_out, size_t sk_len)
{
    if (!seed || !pk_out || !sk_out) return false;
    if (pk_len != RACCOONG_PK_BYTES) return false;
    if (sk_len != RACCOONG_SK_BYTES) return false;

    /* Upstream `generate_keypair_from_seed`:
     *     drbg_seed = HKDF(seed, 48, salt=None, hashmod=SHA256)
     *     drbg = NIST_KAT_DRBG(drbg_seed)
     *     key  = drbg.random_bytes(32)
     *     (vk, s) = _keygen_unrounded(raccoon, key)
     *     return serialize_public_key(vk), serialize_signing_key((vk, s))
     */
    uint8_t drbg_seed[48];
    if (!raccoong_hkdf_sha256(drbg_seed, sizeof(drbg_seed),
                              seed, 32,
                              /*salt=*/NULL, 0,
                              /*info=*/NULL, 0)) {
        return false;
    }

    raccoong_nist_kat_drbg drbg;
    raccoong_nist_kat_drbg_init(&drbg, drbg_seed);
    memset(drbg_seed, 0, sizeof(drbg_seed));

    uint8_t key[32];
    raccoong_nist_kat_drbg_random_bytes(&drbg, key, sizeof(key));
    memset(&drbg, 0, sizeof(drbg));

    uint8_t A_seed[RACCOONG_A_SEED_BYTES];
    static polyr t_vec[RACCOONG_K];
    static polyr s_vec[RACCOONG_ELL];

    if (!raccoong_keygen_t_unrounded(key, A_seed, t_vec, s_vec)) {
        memset(key, 0, sizeof(key));
        return false;
    }
    memset(key, 0, sizeof(key));

    raccoong_serialize_pk(pk_out, A_seed, t_vec);
    raccoong_serialize_sk(sk_out, A_seed, t_vec, s_vec);

    /* Wipe the secret share; the caller now owns sk_out. */
    memset(s_vec, 0, sizeof(s_vec));
    return true;
}

dogecoin_bool raccoong_serialize_signature(
    uint8_t* sig_out, size_t* sig_len_inout,
    const uint8_t c_hash[RACCOONG_C_HASH_BYTES],
    const polyr z[RACCOONG_ELL],
    const int16_t h_signed[RACCOONG_K][256])
{
    if (!sig_out || !sig_len_inout || !c_hash || !z || !h_signed) {
        return false;
    }
    if (*sig_len_inout < RACCOONG_SIG_BYTES) {
        return false;
    }

    /* Reject malformed z up front so we never write a partial signature. */
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
        for (size_t j = 0; j < RACCOONG_N; ++j) {
            if (z[i].coeffs[j] >= RACCOONG_Q) {
                return false;
            }
        }
    }

    memcpy(sig_out, c_hash, RACCOONG_C_HASH_BYTES);
    uint8_t* p = sig_out + RACCOONG_C_HASH_BYTES;

    /* z block: ell * n * 7 bytes, little-endian, value already in [0, q). */
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
        serialize_poly_le7(p, &z[i]);
        p += (size_t)RACCOONG_N * RACCOONG_COEFF_BYTES;
    }

    /* h block: k * n * 2 bytes. Upstream encodes (coeff % q_w) so a signed
     * coefficient and its (coeff + q_w) representative produce the same
     * wire bytes; we just reduce into [0, q_w) here. q_w == 2048 fits in
     * a 16-bit int with room to spare so the modular add never overflows. */
    const uint64_t qw = RACCOONG_Q_W;
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        for (size_t j = 0; j < RACCOONG_N; ++j) {
            int32_t v = (int32_t)h_signed[i][j];
            uint64_t u = (uint64_t)((int64_t)v % (int64_t)qw);
            /* C99 % can return negative for negative v; normalize. */
            if ((int64_t)u < 0) {
                u = (uint64_t)((int64_t)u + (int64_t)qw);
            }
            p[0] = (uint8_t)(u & 0xffu);
            p[1] = (uint8_t)((u >> 8) & 0xffu);
            p += RACCOONG_H_COEFF_BYTES;
        }
    }

    *sig_len_inout = RACCOONG_SIG_BYTES;
    return true;
}

dogecoin_bool raccoong_deserialize_signature(
    uint8_t c_hash_out[RACCOONG_C_HASH_BYTES],
    polyr z_out[RACCOONG_ELL],
    int16_t h_signed_out[RACCOONG_K][256],
    const uint8_t* sig, size_t sig_len)
{
    if (!c_hash_out || !z_out || !h_signed_out || !sig) {
        return false;
    }
    if (sig_len != RACCOONG_SIG_BYTES) {
        return false;
    }

    memcpy(c_hash_out, sig, RACCOONG_C_HASH_BYTES);
    const uint8_t* p = sig + RACCOONG_C_HASH_BYTES;

    /* z block: 7-byte LE, must be < q. */
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
        if (!deserialize_poly_le7(&z_out[i], p)) {
            return false;
        }
        p += (size_t)RACCOONG_N * RACCOONG_COEFF_BYTES;
    }

    /* h block: 2-byte LE in [0, q_w), centered to [-q_w/2, q_w/2). */
    const uint64_t qw = RACCOONG_Q_W;
    const int32_t half_qw = (int32_t)(qw >> 1);
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        for (size_t j = 0; j < RACCOONG_N; ++j) {
            uint32_t u = (uint32_t)p[0] | ((uint32_t)p[1] << 8);
            if ((uint64_t)u >= qw) {
                return false;
            }
            int32_t centered = (int32_t)u;
            if (centered > half_qw) {
                centered -= (int32_t)qw;
            }
            h_signed_out[i][j] = (int16_t)centered;
            p += RACCOONG_H_COEFF_BYTES;
        }
    }
    return true;
}

dogecoin_bool thrc_sign(const uint8_t* sk, size_t sk_len,
                        const uint8_t* msg, size_t msg_len,
                        uint8_t* sig_out, size_t* sig_len_inout)
{
    (void)sk; (void)sk_len; (void)msg; (void)msg_len;
    (void)sig_out; (void)sig_len_inout;
    return false;
}dogecoin_bool thrc_verify(const uint8_t* pk, size_t pk_len,
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
    if (!parent_sk || !parent_pk || !chaincode ||
        !child_sk_out || !child_pk_out) {
        return false;
    }
    if (child_sk_len != RACCOONG_SK_BYTES) return false;
    if (child_pk_len != RACCOONG_PK_BYTES) return false;

    /* 1. Deserialize parent sk = (A_seed, t, s); cross-check A_seed against pk. */
    uint8_t parent_A_seed[RACCOONG_A_SEED_BYTES];
    uint8_t parent_pk_A_seed[RACCOONG_A_SEED_BYTES];
    static polyr parent_t[RACCOONG_K];
    static polyr parent_s[RACCOONG_ELL];
    if (!deserialize_sk_into(parent_sk, parent_sk_len, parent_A_seed,
                             parent_t, parent_s)) {
        return false;
    }
    if (!deserialize_pk_into(parent_pk, parent_pk_len, parent_pk_A_seed,
                             /*t_out=*/NULL)) {
        memset(parent_s, 0, sizeof(parent_s));
        return false;
    }
    if (memcmp(parent_A_seed, parent_pk_A_seed, RACCOONG_A_SEED_BYTES) != 0) {
        memset(parent_s, 0, sizeof(parent_s));
        return false;
    }

    /* 2. tweak_seed = HMAC-SHA512(chaincode, tag || sha256(parent_key) || idx_BE)[:32]
     *    tag is 'p' for non-hardened (uses parent_pk hash) or 'S' for hardened
     *    (uses parent_sk hash). This mirrors the liboqs-side derive_hd_bytes
     *    domain separator tags. */
    uint8_t tweak_seed[32];
    if (!hd_derive_tweak_seed(tweak_seed, parent_pk, parent_pk_len,
                              parent_sk, parent_sk_len, chaincode,
                              index, hardened)) {
        memset(parent_s, 0, sizeof(parent_s));
        return false;
    }

    /* 3. drbg_seed = HKDF-SHA256(tweak_seed, 48); drbg.random_bytes(32) = key. */
    uint8_t drbg_seed[48];
    if (!raccoong_hkdf_sha256(drbg_seed, sizeof(drbg_seed),
                              tweak_seed, sizeof(tweak_seed),
                              NULL, 0, NULL, 0)) {
        memset(tweak_seed, 0, sizeof(tweak_seed));
        memset(parent_s, 0, sizeof(parent_s));
        return false;
    }
    memset(tweak_seed, 0, sizeof(tweak_seed));

    raccoong_nist_kat_drbg drbg;
    raccoong_nist_kat_drbg_init(&drbg, drbg_seed);
    memset(drbg_seed, 0, sizeof(drbg_seed));

    uint8_t key[32];
    raccoong_nist_kat_drbg_random_bytes(&drbg, key, sizeof(key));
    memset(&drbg, 0, sizeof(drbg));

    /* 4. tweak keygen reusing parent A_seed. */
    static polyr tweak_t[RACCOONG_K];
    static polyr tweak_s[RACCOONG_ELL];
    if (!raccoong_keygen_t_with_aseed(key, parent_A_seed, tweak_t, tweak_s)) {
        memset(key, 0, sizeof(key));
        memset(parent_s, 0, sizeof(parent_s));
        return false;
    }
    memset(key, 0, sizeof(key));

    /* 5. child_t = parent_t + tweak_t (mod q); child_s = parent_s + tweak_s (mod q). */
    static polyr child_t[RACCOONG_K];
    static polyr child_s[RACCOONG_ELL];
    if (!raccoong_vec_add(child_t, parent_t, tweak_t, RACCOONG_K)) {
        memset(parent_s, 0, sizeof(parent_s));
        memset(tweak_s, 0, sizeof(tweak_s));
        return false;
    }
    if (!raccoong_vec_add(child_s, parent_s, tweak_s, RACCOONG_ELL)) {
        memset(parent_s, 0, sizeof(parent_s));
        memset(tweak_s, 0, sizeof(tweak_s));
        memset(child_s, 0, sizeof(child_s));
        return false;
    }

    raccoong_serialize_pk(child_pk_out, parent_A_seed, child_t);
    raccoong_serialize_sk(child_sk_out, parent_A_seed, child_t, child_s);

    /* Wipe transient secrets. */
    memset(parent_s, 0, sizeof(parent_s));
    memset(tweak_s, 0, sizeof(tweak_s));
    memset(child_s, 0, sizeof(child_s));
    return true;
}

dogecoin_bool thrc_hd_derive_pub(const uint8_t* parent_pk, size_t parent_pk_len,
                                 const uint8_t chaincode[32],
                                 uint32_t index,
                                 uint8_t* child_pk_out, size_t child_pk_len)
{
    if (!parent_pk || !chaincode || !child_pk_out) return false;
    if (child_pk_len != RACCOONG_PK_BYTES) return false;
    /* Hardened derivation needs the secret key. */
    if (index & 0x80000000U) return false;

    uint8_t parent_A_seed[RACCOONG_A_SEED_BYTES];
    static polyr parent_t[RACCOONG_K];
    if (!deserialize_pk_into(parent_pk, parent_pk_len, parent_A_seed, parent_t)) {
        return false;
    }

    uint8_t tweak_seed[32];
    if (!hd_derive_tweak_seed(tweak_seed, parent_pk, parent_pk_len,
                              /*parent_sk=*/NULL, 0, chaincode,
                              index, /*hardened=*/false)) {
        return false;
    }

    uint8_t drbg_seed[48];
    if (!raccoong_hkdf_sha256(drbg_seed, sizeof(drbg_seed),
                              tweak_seed, sizeof(tweak_seed),
                              NULL, 0, NULL, 0)) {
        memset(tweak_seed, 0, sizeof(tweak_seed));
        return false;
    }
    memset(tweak_seed, 0, sizeof(tweak_seed));

    raccoong_nist_kat_drbg drbg;
    raccoong_nist_kat_drbg_init(&drbg, drbg_seed);
    memset(drbg_seed, 0, sizeof(drbg_seed));

    uint8_t key[32];
    raccoong_nist_kat_drbg_random_bytes(&drbg, key, sizeof(key));
    memset(&drbg, 0, sizeof(drbg));

    static polyr tweak_t[RACCOONG_K];
    if (!raccoong_keygen_t_with_aseed(key, parent_A_seed, tweak_t, NULL)) {
        memset(key, 0, sizeof(key));
        return false;
    }
    memset(key, 0, sizeof(key));

    static polyr child_t[RACCOONG_K];
    if (!raccoong_vec_add(child_t, parent_t, tweak_t, RACCOONG_K)) {
        return false;
    }

    raccoong_serialize_pk(child_pk_out, parent_A_seed, child_t);
    return true;
}

/* ============================================================
 * Deserialization helpers + chain-code-driven tweak derivation.
 * ============================================================ */

static dogecoin_bool deserialize_poly_le7(polyr* dst, const uint8_t* src)
{
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        uint64_t c =
              ((uint64_t)src[0])
            | ((uint64_t)src[1] << 8)
            | ((uint64_t)src[2] << 16)
            | ((uint64_t)src[3] << 24)
            | ((uint64_t)src[4] << 32)
            | ((uint64_t)src[5] << 40)
            | ((uint64_t)src[6] << 48);
        if (c >= RACCOONG_Q) return false;
        dst->coeffs[i] = c;
        src += RACCOONG_COEFF_BYTES;
    }
    return true;
}

static dogecoin_bool deserialize_pk_into(const uint8_t* pk, size_t pk_len,
                                         uint8_t A_seed_out[RACCOONG_A_SEED_BYTES],
                                         polyr t_out[RACCOONG_K])
{
    if (!pk || pk_len != RACCOONG_PK_BYTES) return false;
    memcpy(A_seed_out, pk, RACCOONG_A_SEED_BYTES);
    if (!t_out) return true;
    const uint8_t* p = pk + RACCOONG_A_SEED_BYTES;
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        if (!deserialize_poly_le7(&t_out[i], p)) return false;
        p += (size_t)RACCOONG_N * RACCOONG_COEFF_BYTES;
    }
    return true;
}

static dogecoin_bool deserialize_sk_into(const uint8_t* sk, size_t sk_len,
                                         uint8_t A_seed_out[RACCOONG_A_SEED_BYTES],
                                         polyr t_out[RACCOONG_K],
                                         polyr s_out[RACCOONG_ELL])
{
    if (!sk || sk_len != RACCOONG_SK_BYTES) return false;
    if (!deserialize_pk_into(sk, RACCOONG_PK_BYTES, A_seed_out, t_out)) {
        return false;
    }
    if (!s_out) return true;
    const uint8_t* p = sk + RACCOONG_PK_BYTES;
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
        if (!deserialize_poly_le7(&s_out[i], p)) return false;
        p += (size_t)RACCOONG_N * RACCOONG_COEFF_BYTES;
    }
    return true;
}

/*
 * tweak_seed derivation:
 *
 *   data = tag || sha256(parent_key) || index_BE
 *   tweak_seed = HMAC-SHA512(chaincode, data)[:32]
 *
 *  - non-hardened: tag = 'p' (0x70), parent_key = parent_pk
 *  - hardened:     tag = 'S' (0x53), parent_key = parent_sk
 *
 * sha256() of the parent serialized key keeps the HMAC input small while
 * preserving uniqueness; using parent_pk for non-hardened keeps the pub-only
 * path consistent (no secret-key dependence).
 */
static dogecoin_bool hd_derive_tweak_seed(uint8_t tweak_seed_out[32],
                                          const uint8_t* parent_pk, size_t parent_pk_len,
                                          const uint8_t* parent_sk, size_t parent_sk_len,
                                          const uint8_t chaincode[32],
                                          uint32_t index, dogecoin_bool hardened)
{
    uint8_t data[1 + 32 + 4];
    uint8_t digest[32];

    uint32_t encoded_index = hardened ? (index | 0x80000000u) : index;
    if (hardened) {
        if (!parent_sk || parent_sk_len != RACCOONG_SK_BYTES) return false;
        data[0] = 'S';
        sha256_raw(parent_sk, parent_sk_len, digest);
    } else {
        if (!parent_pk || parent_pk_len != RACCOONG_PK_BYTES) return false;
        data[0] = 'p';
        sha256_raw(parent_pk, parent_pk_len, digest);
    }
    memcpy(data + 1, digest, 32);
    data[33] = (uint8_t)(encoded_index >> 24);
    data[34] = (uint8_t)(encoded_index >> 16);
    data[35] = (uint8_t)(encoded_index >> 8);
    data[36] = (uint8_t)(encoded_index);

    uint8_t I[64];
    hmac_sha512(chaincode, 32, data, sizeof(data), I);
    memcpy(tweak_seed_out, I, 32);
    memset(I, 0, sizeof(I));
    memset(data, 0, sizeof(data));
    return true;
}
