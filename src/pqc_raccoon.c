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

#include <string.h>
#include <stdint.h>

#include <dogecoin/sha2.h>
#include <dogecoin/mem.h>
#include <dogecoin/pqc_raccoon.h>
#include <dogecoin/random.h>

#ifdef USE_LIBOQS
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include <oqs/sig.h>
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
#endif

/**
 * @brief This function computes SHA256(pk || msg) and writes
 * a 32-byte digest to out32.
 *
 * @param out32 The output buffer for the 32-byte hash.
 * @param pk The pointer to the public key bytes.
 * @param pk_len The length of the public key.
 * @param msg The pointer to the message bytes.
 * @param msg_len The length of the message.
 *
 * @return Nothing.
 */
static inline void sha256_pk_msg(uint8_t out32[32],
                                 const uint8_t* pk, size_t pk_len,
                                 const uint8_t* msg, size_t msg_len)
{
    sha256_context ctx;
    sha256_init(&ctx);
    if (pk && pk_len) {
        sha256_write(&ctx, pk, pk_len);
    }
    if (msg && msg_len) {
        sha256_write(&ctx, msg, msg_len);
    }
    sha256_finalize(&ctx, out32);
}

/**
 * @brief This function derives deterministic child key bytes
 * from parent material, chaincode, and index using repeated
 * SHA-256 blocks with domain separation.
 *
 * @param out The output buffer for the derived bytes.
 * @param out_len The number of bytes to derive.
 * @param parent The pointer to the parent key bytes.
 * @param parent_len The length of the parent key.
 * @param chaincode The 32-byte chaincode.
 * @param index The child index (bit 31 set for hardened).
 * @param domain The domain separation byte.
 *
 * @return Nothing.
 */
#ifdef USE_LIBOQS
static void derive_hd_bytes(uint8_t* out, size_t out_len,
                            const uint8_t* parent, size_t parent_len,
                            const uint8_t chaincode[DOGECOIN_PQC_RACCOON_CHAINCODE_LEN],
                            uint32_t index, uint8_t domain)
{
    uint8_t block[32];
    size_t offset = 0;
    uint8_t counter = 0;
    while (offset < out_len) {
        sha256_context ctx;
        uint8_t idx_be[4];
        idx_be[0] = (uint8_t)((index >> 24) & 0xff);
        idx_be[1] = (uint8_t)((index >> 16) & 0xff);
        idx_be[2] = (uint8_t)((index >> 8) & 0xff);
        idx_be[3] = (uint8_t)(index & 0xff);
        sha256_init(&ctx);
        sha256_write(&ctx, &domain, 1);
        sha256_write(&ctx, &counter, 1);
        sha256_write(&ctx, idx_be, sizeof(idx_be));
        if (parent && parent_len) {
            sha256_write(&ctx, parent, parent_len);
        }
        sha256_write(&ctx, chaincode, DOGECOIN_PQC_RACCOON_CHAINCODE_LEN);
        sha256_finalize(&ctx, block);
        size_t chunk = (out_len - offset > sizeof(block)) ? sizeof(block) : (out_len - offset);
        memcpy(out + offset, block, chunk);
        offset += chunk;
        counter++;
    }
}
#endif /* USE_LIBOQS */

/**
 * @brief This function computes a 32-byte Raccoon-G-44
 * commitment as SHA256(pk || sig).
 *
 * @param pk The pointer to the public key bytes.
 * @param pk_len The length of the public key.
 * @param signature The pointer to the signature bytes.
 * @param signature_len The length of the signature.
 * @param out32 The output buffer for the 32-byte commitment.
 *
 * @return true if the commitment was computed, false on invalid input.
 */
dogecoin_bool dogecoin_raccoong44_commit_bytes(const uint8_t* pk, size_t pk_len,
                                               const uint8_t* signature, size_t signature_len,
                                               uint8_t out32[32])
{
    if (!pk || !signature || !out32) {
        return false;
    }
    sha256_pk_msg(out32, pk, pk_len, signature, signature_len);
    return true;
}

/**
 * @brief This function appends an OP_RETURN output carrying
 * the "RCG4" tag and a 32-byte Raccoon-G-44 commitment to a
 * transaction.
 *
 * @param tx The pointer to the transaction to modify.
 * @param commit32 The 32-byte commitment hash.
 *
 * @return true if the output was added, false on invalid input.
 */
dogecoin_bool dogecoin_tx_add_raccoong44_commit(dogecoin_tx* tx, const uint8_t commit32[DOGECOIN_PQC_RACCOON_COMMIT_LEN])
{
    if (!tx || !commit32) {
        return false;
    }

    cstring* spk = cstr_new_sz(1 + 1 + DOGECOIN_PQC_RACCOON_PUSH_TOTAL);
    uint8_t opret = 0x6a;
    uint8_t push  = DOGECOIN_PQC_RACCOON_PUSH_TOTAL;

    cstr_append_buf(spk, &opret, 1);
    cstr_append_buf(spk, &push, 1);
    cstr_append_buf(spk, (const uint8_t*)DOGECOIN_PQC_RACCOON_TAG, DOGECOIN_PQC_RACCOON_TAG_LEN);
    cstr_append_buf(spk, commit32, 32);

    dogecoin_tx_out* out = dogecoin_tx_out_new();
    if (!out) {
        cstr_free(spk, true);
        return false;
    }
    out->value = 0;
    if (out->script_pubkey) {
        cstr_free(out->script_pubkey, true);
    }
    out->script_pubkey = spk;
    vector_add(tx->vout, out);
    return true;
}

/**
 * @brief This function extracts the first "RCG4" tagged
 * Raccoon-G-44 commitment from a transaction's outputs.
 *
 * @param tx The pointer to the transaction to search.
 * @param out32 The output buffer for the 32-byte commitment.
 *
 * @return true if a commitment was found, false otherwise.
 */
dogecoin_bool dogecoin_tx_extract_raccoong44_commit(const dogecoin_tx* tx, uint8_t out32[DOGECOIN_PQC_RACCOON_COMMIT_LEN])
{
    if (!tx || !out32) {
        return false;
    }

    for (unsigned i = 0; i < tx->vout->len; ++i) {
        const dogecoin_tx_out* o = vector_idx(tx->vout, i);
        if (!o || !o->script_pubkey || o->script_pubkey->len < (1 + 1 + DOGECOIN_PQC_RACCOON_PUSH_TOTAL))
            continue;

        const unsigned char* p = (const unsigned char*)o->script_pubkey->str;
        size_t n = o->script_pubkey->len;

        if (n == (1 + 1 + DOGECOIN_PQC_RACCOON_PUSH_TOTAL) &&
            p[0] == 0x6a &&
            p[1] == DOGECOIN_PQC_RACCOON_PUSH_TOTAL &&
            memcmp(p + 2, DOGECOIN_PQC_RACCOON_TAG, DOGECOIN_PQC_RACCOON_TAG_LEN) == 0) {
            memcpy(out32, p + 2 + DOGECOIN_PQC_RACCOON_TAG_LEN, 32);
            return true;
        }
    }
    return false;
}

#ifdef USE_LIBOQS

/**
 * @brief This function selects the liboqs algorithm name
 * for the Raccoon-G-44 signature scheme.
 *
 * @return The algorithm name string, or NULL if unavailable.
 */
static const char* get_raccoong_alg_name(void)
{
    OQS_SIG* alg = OQS_SIG_new("Raccoon-G-44");
    if (alg) {
        OQS_SIG_free(alg);
        return "Raccoon-G-44";
    }
    return NULL;
}

/**
 * @brief This function probes whether the Raccoon-G-44
 * algorithm is usable in the linked liboqs by attempting
 * a trial keypair generation.
 *
 * @return true if Raccoon-G-44 is available, false otherwise.
 */
dogecoin_bool dogecoin_raccoong44_is_available(void)
{
    const char* alg_name = get_raccoong_alg_name();
    if (!alg_name) {
        return false;
    }

    OQS_SIG* alg = OQS_SIG_new(alg_name);
    if (!alg) {
        return false;
    }

    dogecoin_bool ok = false;
    uint8_t* pk = (uint8_t*)dogecoin_malloc(alg->length_public_key);
    uint8_t* sk = (uint8_t*)dogecoin_malloc(alg->length_secret_key);
    if (pk && sk) {
        ok = (OQS_SIG_keypair(alg, pk, sk) == OQS_SUCCESS);
    }
    if (pk) {
        dogecoin_free(pk);
    }
    if (sk) {
        dogecoin_free(sk);
    }
    OQS_SIG_free(alg);
    return ok;
}

/**
 * @brief This function generates a Raccoon-G-44 keypair via
 * liboqs and allocates the public and secret key buffers.
 *
 * @param pk The pointer to receive the allocated public key.
 * @param pk_len The pointer to receive the public key length.
 * @param sk The pointer to receive the allocated secret key.
 * @param sk_len The pointer to receive the secret key length.
 *
 * @return true if the keypair was generated, false on error.
 */
dogecoin_bool dogecoin_raccoong44_keypair(uint8_t** pk, size_t* pk_len,
                                          uint8_t** sk, size_t* sk_len)
{
    if (!pk || !pk_len || !sk || !sk_len) {
        return false;
    }
    const char* alg_name = get_raccoong_alg_name();
    if (!alg_name) {
        return false;
    }
    OQS_SIG* alg = OQS_SIG_new(alg_name);
    if (!alg) {
        return false;
    }

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

    *pk = pk_buf;
    *pk_len = alg->length_public_key;
    *sk = sk_buf;
    *sk_len = alg->length_secret_key;
    OQS_SIG_free(alg);
    return true;
}

/**
 * @brief This function signs a message with a Raccoon-G-44
 * secret key and allocates the signature buffer.
 *
 * @param sk The pointer to the secret key.
 * @param sk_len The length of the secret key.
 * @param msg The pointer to the message to sign.
 * @param msg_len The length of the message.
 * @param sig_out The pointer to receive the allocated signature.
 * @param sig_len The pointer to receive the signature length.
 *
 * @return true if signing succeeded, false on error.
 */
dogecoin_bool dogecoin_raccoong44_sign(const uint8_t* sk, size_t sk_len,
                                       const uint8_t* msg, size_t msg_len,
                                       uint8_t** sig_out, size_t* sig_len)
{
    if (!sk || !msg || !sig_out || !sig_len) {
        return false;
    }
    const char* alg_name = get_raccoong_alg_name();
    if (!alg_name) {
        return false;
    }
    OQS_SIG* alg = OQS_SIG_new(alg_name);
    if (!alg) {
        return false;
    }

    if (sk_len && sk_len != alg->length_secret_key) {
        OQS_SIG_free(alg);
        return false;
    }

    uint8_t* sig_buf = (uint8_t*)dogecoin_malloc(alg->length_signature);
    if (!sig_buf) {
        OQS_SIG_free(alg);
        return false;
    }
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

/**
 * @brief This function verifies a Raccoon-G-44 signature
 * against a public key and message.
 *
 * @param pk The pointer to the public key.
 * @param pk_len The length of the public key.
 * @param msg The pointer to the message.
 * @param msg_len The length of the message.
 * @param sig The pointer to the signature.
 * @param sig_len The length of the signature.
 *
 * @return true if the signature is valid, false otherwise.
 */
dogecoin_bool dogecoin_raccoong44_verify(const uint8_t* pk, size_t pk_len,
                                         const uint8_t* msg, size_t msg_len,
                                         const uint8_t* sig, size_t sig_len)
{
    if (!pk || !msg || !sig) {
        return false;
    }
    const char* alg_name = get_raccoong_alg_name();
    if (!alg_name) {
        return false;
    }
    OQS_SIG* alg = OQS_SIG_new(alg_name);
    if (!alg) {
        return false;
    }

    if (pk_len && pk_len != alg->length_public_key) {
        OQS_SIG_free(alg);
        return false;
    }
    OQS_STATUS st = OQS_SIG_verify(alg, msg, msg_len, sig, sig_len, pk);
    OQS_SIG_free(alg);
    return st == OQS_SUCCESS;
}

/**
 * @brief This function derives a child secret and public key
 * from a parent Raccoon-G-44 secret key using BIP32-style
 * hardened or non-hardened derivation.
 *
 * @param parent_sk The pointer to the parent secret key.
 * @param parent_sk_len The length of the parent secret key.
 * @param chaincode The 32-byte chaincode.
 * @param index The child index.
 * @param hardened Whether to use hardened derivation.
 * @param child_sk The pointer to receive the allocated child secret key.
 * @param child_sk_len The pointer to receive the child secret key length.
 * @param child_pk The pointer to receive the allocated child public key.
 * @param child_pk_len The pointer to receive the child public key length.
 *
 * @return true if derivation succeeded, false on error.
 */
dogecoin_bool dogecoin_raccoong44_hd_derive_priv(const uint8_t* parent_sk, size_t parent_sk_len,
                                                 const uint8_t* parent_pk, size_t parent_pk_len,
                                                 const uint8_t chaincode[DOGECOIN_PQC_RACCOON_CHAINCODE_LEN],
                                                 uint32_t index, dogecoin_bool hardened,
                                                 uint8_t** child_sk, size_t* child_sk_len,
                                                  uint8_t** child_pk, size_t* child_pk_len)
{
    if (!parent_sk || !parent_pk || !chaincode || !child_sk || !child_sk_len || !child_pk || !child_pk_len) {
        return false;
    }

    const char* alg_name = get_raccoong_alg_name();
    if (!alg_name) {
        return false;
    }
    OQS_SIG* alg = OQS_SIG_new(alg_name);
    if (!alg) {
        return false;
    }

    if (parent_sk_len && parent_sk_len != alg->length_secret_key) {
        OQS_SIG_free(alg);
        return false;
    }
    if (parent_pk_len && parent_pk_len != alg->length_public_key) {
        OQS_SIG_free(alg);
        return false;
    }

    uint8_t* sk_buf = (uint8_t*)dogecoin_malloc(alg->length_secret_key);
    uint8_t* pk_buf = (uint8_t*)dogecoin_malloc(alg->length_public_key);
    if (!sk_buf || !pk_buf) {
        if (sk_buf) dogecoin_free(sk_buf);
        if (pk_buf) dogecoin_free(pk_buf);
        OQS_SIG_free(alg);
        return false;
    }

    uint32_t child_index = hardened ? (index | 0x80000000U) : index;
    derive_hd_bytes(sk_buf, alg->length_secret_key, parent_sk, parent_sk_len, chaincode, child_index, 0x53); /* 'S' */
    derive_hd_bytes(pk_buf, alg->length_public_key, parent_pk, parent_pk_len, chaincode, child_index, 0x70); /* 'p' */

    *child_sk = sk_buf;
    *child_sk_len = alg->length_secret_key;
    *child_pk = pk_buf;
    *child_pk_len = alg->length_public_key;
    OQS_SIG_free(alg);
    return true;
}

/**
 * @brief This function derives a child public key from a
 * parent Raccoon-G-44 public key using non-hardened derivation.
 *
 * @param parent_pk The pointer to the parent public key.
 * @param parent_pk_len The length of the parent public key.
 * @param chaincode The 32-byte chaincode.
 * @param index The child index (must not have bit 31 set).
 * @param child_pk The pointer to receive the allocated child public key.
 * @param child_pk_len The pointer to receive the child public key length.
 *
 * @return true if derivation succeeded, false on error.
 */
dogecoin_bool dogecoin_raccoong44_hd_derive_pub(const uint8_t* parent_pk, size_t parent_pk_len,
                                                const uint8_t chaincode[DOGECOIN_PQC_RACCOON_CHAINCODE_LEN],
                                                uint32_t index,
                                                uint8_t** child_pk, size_t* child_pk_len)
{
    if (!parent_pk || !chaincode || !child_pk || !child_pk_len) {
        return false;
    }

    const char* alg_name = get_raccoong_alg_name();
    if (!alg_name) {
        return false;
    }
    OQS_SIG* alg = OQS_SIG_new(alg_name);
    if (!alg) {
        return false;
    }

    if (parent_pk_len && parent_pk_len != alg->length_public_key) {
        OQS_SIG_free(alg);
        return false;
    }
    if (index & 0x80000000U) {
        OQS_SIG_free(alg);
        return false; /* hardened derivation is not defined for pub-only paths */
    }

    uint8_t* pk_buf = (uint8_t*)dogecoin_malloc(alg->length_public_key);
    if (!pk_buf) {
        OQS_SIG_free(alg);
        return false;
    }
    derive_hd_bytes(pk_buf, alg->length_public_key, parent_pk, parent_pk_len, chaincode, index, 0x70); /* 'p' */

    *child_pk = pk_buf;
    *child_pk_len = alg->length_public_key;
    OQS_SIG_free(alg);
    return true;
}
#endif

#ifdef USE_RACCOON_G

/*
 * In-tree Raccoon-G-44 backend. Built when --enable-raccoon-g is configured.
 * Mutually exclusive with USE_LIBOQS_RACCOON (enforced at configure time).
 *
 * The implementation is staged across multiple commits (see
 * src/raccoon_g/README.md). Until raccoong_is_ready() flips to true, every
 * entry point fails closed.
 */

#include "raccoon_g/raccoong.h"

dogecoin_bool dogecoin_raccoong44_is_available(void)
{
    return raccoong_is_ready();
}

dogecoin_bool dogecoin_raccoong44_keypair(uint8_t** pk, size_t* pk_len,
                                          uint8_t** sk, size_t* sk_len)
{
    if (!pk || !pk_len || !sk || !sk_len) {
        return false;
    }
    if (!raccoong_is_ready()) {
        return false;
    }

    size_t pkl = raccoong_pk_len();
    size_t skl = raccoong_sk_len();
    if (!pkl || !skl) {
        return false;
    }

    uint8_t* pk_buf = (uint8_t*)dogecoin_malloc(pkl);
    uint8_t* sk_buf = (uint8_t*)dogecoin_malloc(skl);
    if (!pk_buf || !sk_buf) {
        if (pk_buf) dogecoin_free(pk_buf);
        if (sk_buf) dogecoin_free(sk_buf);
        return false;
    }

    /* Seed-deterministic keygen requires a 32-byte seed; the public API does
     * not take one, so we draw it from the libdogecoin RNG.  Callers that
     * need byte-deterministic keypairs should use `raccoong_keygen_from_seed`
     * directly with a caller-supplied seed. */
    uint8_t seed[32];
    if (!dogecoin_random_bytes(seed, sizeof(seed), 0)) {
        dogecoin_free(pk_buf);
        dogecoin_free(sk_buf);
        return false;
    }
    if (!raccoong_keygen_from_seed(seed, pk_buf, pkl, sk_buf, skl)) {
        dogecoin_mem_zero(seed, sizeof(seed));
        dogecoin_free(pk_buf);
        dogecoin_free(sk_buf);
        return false;
    }
    dogecoin_mem_zero(seed, sizeof(seed));
    *pk = pk_buf;
    *pk_len = pkl;
    *sk = sk_buf;
    *sk_len = skl;
    return true;
}

dogecoin_bool dogecoin_raccoong44_sign(const uint8_t* sk, size_t sk_len,
                                       const uint8_t* msg, size_t msg_len,
                                       uint8_t** sig_out, size_t* sig_len)
{
    if (!sk || !msg || !sig_out || !sig_len) {
        return false;
    }
    if (!raccoong_is_ready()) {
        return false;
    }
    size_t cap = raccoong_sig_max_len();
    if (!cap) {
        return false;
    }
    uint8_t* buf = (uint8_t*)dogecoin_malloc(cap);
    if (!buf) {
        return false;
    }
    size_t outlen = cap;
    if (!raccoong_sign(sk, sk_len, msg, msg_len, buf, &outlen)) {
        dogecoin_free(buf);
        return false;
    }
    *sig_out = buf;
    *sig_len = outlen;
    return true;
}

dogecoin_bool dogecoin_raccoong44_verify(const uint8_t* pk, size_t pk_len,
                                         const uint8_t* msg, size_t msg_len,
                                         const uint8_t* sig, size_t sig_len)
{
    if (!pk || !msg || !sig) {
        return false;
    }
    if (!raccoong_is_ready()) {
        return false;
    }
    return raccoong_verify(pk, pk_len, msg, msg_len, sig, sig_len);
}

dogecoin_bool dogecoin_raccoong44_hd_derive_priv(const uint8_t* parent_sk, size_t parent_sk_len,
                                                 const uint8_t* parent_pk, size_t parent_pk_len,
                                                 const uint8_t chaincode[DOGECOIN_PQC_RACCOON_CHAINCODE_LEN],
                                                 uint32_t index, dogecoin_bool hardened,
                                                 uint8_t** child_sk, size_t* child_sk_len,
                                                 uint8_t** child_pk, size_t* child_pk_len)
{
    if (!parent_sk || !parent_pk || !chaincode ||
        !child_sk || !child_sk_len || !child_pk || !child_pk_len) {
        return false;
    }
    if (!raccoong_is_ready()) {
        return false;
    }
    size_t skl = raccoong_sk_len();
    size_t pkl = raccoong_pk_len();
    if (!skl || !pkl) {
        return false;
    }
    uint8_t* sk_buf = (uint8_t*)dogecoin_malloc(skl);
    uint8_t* pk_buf = (uint8_t*)dogecoin_malloc(pkl);
    if (!sk_buf || !pk_buf) {
        if (sk_buf) dogecoin_free(sk_buf);
        if (pk_buf) dogecoin_free(pk_buf);
        return false;
    }
    if (!raccoong_hd_derive_priv(parent_sk, parent_sk_len, parent_pk, parent_pk_len,
                                 chaincode, index, hardened,
                                 sk_buf, skl, pk_buf, pkl)) {
        dogecoin_free(sk_buf);
        dogecoin_free(pk_buf);
        return false;
    }
    *child_sk = sk_buf;
    *child_sk_len = skl;
    *child_pk = pk_buf;
    *child_pk_len = pkl;
    return true;
}

dogecoin_bool dogecoin_raccoong44_hd_derive_pub(const uint8_t* parent_pk, size_t parent_pk_len,
                                                const uint8_t chaincode[DOGECOIN_PQC_RACCOON_CHAINCODE_LEN],
                                                uint32_t index,
                                                uint8_t** child_pk, size_t* child_pk_len)
{
    if (!parent_pk || !chaincode || !child_pk || !child_pk_len) {
        return false;
    }
    if (index & 0x80000000U) {
        return false; /* hardened derivation requires the secret key */
    }
    if (!raccoong_is_ready()) {
        return false;
    }
    size_t pkl = raccoong_pk_len();
    if (!pkl) {
        return false;
    }
    uint8_t* pk_buf = (uint8_t*)dogecoin_malloc(pkl);
    if (!pk_buf) {
        return false;
    }
    if (!raccoong_hd_derive_pub(parent_pk, parent_pk_len, chaincode, index,
                                pk_buf, pkl)) {
        dogecoin_free(pk_buf);
        return false;
    }
    *child_pk = pk_buf;
    *child_pk_len = pkl;
    return true;
}

#endif
