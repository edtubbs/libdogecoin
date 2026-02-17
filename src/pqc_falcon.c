// src/pqc_falcon.c
/**********************************************************************
 * Copyright (c) 2022-2026
 * Distributed under the MIT software license.
 **********************************************************************/

#include <string.h>
#include <stdint.h>

#include <dogecoin/sha2.h>
#include <dogecoin/mem.h>
#include <dogecoin/utils.h>
#include <dogecoin/pqc_falcon.h>

#ifdef USE_LIBOQS
#include <oqs/oqs.h>
#endif

/* ---------- Helpers (compile even without liboqs) ---------- */

static inline void sha256_pk_msg(uint8_t out32[32],
                                 const uint8_t* pk, size_t pk_len,
                                 const uint8_t* msg, size_t msg_len)
{
    sha256_context ctx;
    sha256_init(&ctx);
    if (pk && pk_len) sha256_write(&ctx, pk, pk_len);
    if (msg && msg_len) sha256_write(&ctx, msg, msg_len);
    sha256_finalize(&ctx, out32);
}

/* ---------- Public API ---------- */

dogecoin_bool dogecoin_falcon512_commit_bytes(const uint8_t* pk, size_t pk_len,
                                              const uint8_t* msg, size_t msg_len,
                                              uint8_t out32[32])
{
    if (!pk || !msg || !out32) return false;
    sha256_pk_msg(out32, pk, pk_len, msg, msg_len);
    return true;
}

/* Append OP_RETURN output with Falcon-512 commit */
dogecoin_bool dogecoin_tx_add_falcon512_commit(dogecoin_tx* tx, const uint8_t* commit32) {
    if (!tx || !commit32) return false;

    // script: OP_RETURN (0x6a) PUSHDATA(32) <32 bytes>
    cstring* spk = cstr_new_sz(1 + 1 + 32);
    uint8_t opret = 0x6a;
    uint8_t push  = 32;

    cstr_append_buf(spk, &opret, 1);
    cstr_append_buf(spk, &push, 1);
    cstr_append_buf(spk, commit32, 32);

    dogecoin_tx_out* out = dogecoin_tx_out_new();
    if (!out) { cstr_free(spk, true); return false; }

    out->value = 0;               // OP_RETURN outputs are zero-value
    if (out->script_pubkey) cstr_free(out->script_pubkey, true);
    out->script_pubkey = spk;

    vector_add(tx->vout, out);
    return true;
}

/* Extract Falcon-512 commit from tx */
dogecoin_bool dogecoin_tx_extract_falcon512_commit(const dogecoin_tx* tx, uint8_t* out32) {
    if (!tx || !out32) return false;

    // Look for the first vout whose script matches: 6a 20 <32 bytes>
    for (unsigned i = 0; i < tx->vout->len; ++i) {
        const dogecoin_tx_out* o = vector_idx(tx->vout, i);
        if (!o || !o->script_pubkey || o->script_pubkey->len < (1 + 1 + 32))
            continue;

        const unsigned char* p = (const unsigned char*)o->script_pubkey->str;
        size_t n = o->script_pubkey->len;

        if (n == 34 && p[0] == 0x6a && p[1] == 32) {
            memcpy(out32, p + 2, 32);
            return true;
        }
    }
    return false;
}

#ifdef USE_LIBOQS

/* Allocate and produce a Falcon-512 keypair */
dogecoin_bool dogecoin_falcon512_keypair(uint8_t** pk, size_t* pk_len,
                                         uint8_t** sk, size_t* sk_len)
{
    if (!pk || !pk_len || !sk || !sk_len) return false;

    OQS_SIG* alg = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (!alg) return false;

    uint8_t* pk_buf = (uint8_t*)dogecoin_malloc(alg->length_public_key);
    uint8_t* sk_buf = (uint8_t*)dogecoin_malloc(alg->length_secret_key);
    if (!pk_buf || !sk_buf) {
        if (pk_buf) dogecoin_free(pk_buf);
        if (sk_buf) dogecoin_free(sk_buf);
        OQS_SIG_free(alg);
        return false;
    }

    OQS_STATUS st = OQS_SIG_keypair(alg, pk_buf, sk_buf);
    if (st != OQS_SUCCESS) {
        dogecoin_free(pk_buf);
        dogecoin_free(sk_buf);
        OQS_SIG_free(alg);
        return false;
    }

    *pk      = pk_buf;
    *pk_len  = alg->length_public_key;
    *sk      = sk_buf;
    *sk_len  = alg->length_secret_key;

    OQS_SIG_free(alg);
    return true;
}

/* Sign: allocates *sig_out */
dogecoin_bool dogecoin_falcon512_sign(const uint8_t* sk, size_t sk_len,
                                      const uint8_t* msg, size_t msg_len,
                                      uint8_t** sig_out, size_t* sig_len)
{
    if (!sk || !msg || !sig_out || !sig_len) return false;

    OQS_SIG* alg = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (!alg) return false;

    /* Optional length check */
    if (sk_len && sk_len != alg->length_secret_key) {
        OQS_SIG_free(alg);
        return false;
    }

    uint8_t* sig_buf = (uint8_t*)dogecoin_malloc(alg->length_signature);
    if (!sig_buf) { OQS_SIG_free(alg); return false; }

    size_t outlen = 0;
    OQS_STATUS st = OQS_SIG_sign(alg, sig_buf, &outlen, msg, msg_len, sk);
    if (st != OQS_SUCCESS) {
        dogecoin_free(sig_buf);
        OQS_SIG_free(alg);
        return false;
    }

    *sig_out = sig_buf;
    *sig_len = outlen;
    OQS_SIG_free(alg);
    return true;
}

/* Verify */
dogecoin_bool dogecoin_falcon512_verify(const uint8_t* pk, size_t pk_len,
                                        const uint8_t* msg, size_t msg_len,
                                        const uint8_t* sig, size_t sig_len)
{
    if (!pk || !msg || !sig) return false;

    OQS_SIG* alg = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (!alg) return false;

    /* Optional length check */
    if (pk_len && pk_len != alg->length_public_key) {
        OQS_SIG_free(alg);
        return false;
    }

    OQS_STATUS st = OQS_SIG_verify(alg, msg, msg_len, sig, sig_len, pk);
    OQS_SIG_free(alg);
    return st == OQS_SUCCESS;
}

#else /* !USE_LIBOQS */

/* Stubs when liboqs is not compiled in */
dogecoin_bool dogecoin_falcon512_keypair(uint8_t** pk, size_t* pk_len,
                                         uint8_t** sk, size_t* sk_len)
{
    (void)pk; (void)pk_len; (void)sk; (void)sk_len;
    return false;
}

dogecoin_bool dogecoin_falcon512_sign(const uint8_t* sk, size_t sk_len,
                                      const uint8_t* msg, size_t msg_len,
                                      uint8_t** sig_out, size_t* sig_len)
{
    (void)sk; (void)sk_len; (void)msg; (void)msg_len; (void)sig_out; (void)sig_len;
    return false;
}

dogecoin_bool dogecoin_falcon512_verify(const uint8_t* pk, size_t pk_len,
                                        const uint8_t* msg, size_t msg_len,
                                        const uint8_t* sig, size_t sig_len)
{
    (void)pk; (void)pk_len; (void)msg; (void)msg_len; (void)sig; (void)sig_len;
    return false;
}

#endif /* USE_LIBOQS */
