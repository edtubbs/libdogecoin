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
 * Groth16 entry points.
 *
 * Policy:
 *
 *   * Proving NEVER runs inside libdogecoin.  The prover lives in a higher
 *     layer (snarkjs in MyDoge / DogeOS, or the rapidsnark CLI on a host).
 *     `dogecoin_zk_generate_groth16_proof` therefore always returns
 *     DOGECOIN_ZK_ERR_DELEGATED — see contrib/zk_carrier/witness_helper.py
 *     for the supported way to drive snarkjs end-to-end.
 *
 *   * Verification CAN run inside libdogecoin when built with rapidsnark
 *     (HAVE_RAPIDSNARK).  Otherwise verification is also DELEGATED, which
 *     lets the demo script fall back to `snarkjs groth16 verify`.
 *
 * The "delegated" status is not a stub: it's the documented behaviour of the
 * mobile-friendly build, and callers (the demo script, MyDoge) handle it.
 *
 * Tying into the OP_CHECKZKP proposal (Opcode 185): when that opcode lands,
 * an interpreter implementation will pull the verification key from a
 * consensus-anchored registry, reuse `dogecoin_zk_extract_carrier_payload`
 * to get the public inputs and proof, and call `dogecoin_zk_verify_groth16`
 * (or PLONK / STARK equivalents) for the matching mode byte.
 */

#if defined(HAVE_CONFIG_H)
#include "libdogecoin-config.h"
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <dogecoin/mem.h>
#include <dogecoin/zk_carrier.h>

#ifdef HAVE_RAPIDSNARK
/* Forward declarations of the rapidsnark verifier C entry point.  The
 * verifier-only build of rapidsnark exposes a small C ABI; if the upstream
 * binding name changes, only this block needs to follow.  See
 * depends/packages/rapidsnark.mk. */
extern int groth16_verify(const char* vk_json,
                          const char* public_json,
                          const char* proof_json,
                          char* error_msg,
                          unsigned long error_msg_maxsize);
#endif

#ifdef HAVE_MCL
/* Forward declaration of the herumi/mcl-backed verifier implemented in
 * src/zk_carrier/zk_groth16_mcl.cpp.  Returns 0 on successful verification,
 * non-zero on any error (with a short non-sensitive diagnostic in err_buf).
 * Linked in via depends/packages/mcl.mk + ./configure --with-mcl. */
extern int groth16_verify_mcl(const char* vk_json,
                              const char* public_json,
                              const char* proof_json,
                              char* err_buf,
                              unsigned long err_buf_max);
#endif

dogecoin_zk_err_t dogecoin_zk_generate_groth16_proof(
    const uint8_t* witness_json,
    size_t witness_json_len,
    const char* circuit_path,
    uint8_t** out_proof,
    size_t* out_proof_len,
    uint8_t** out_public,
    size_t* out_public_len)
{
    (void)witness_json;
    (void)witness_json_len;
    (void)circuit_path;
    if (out_proof) *out_proof = NULL;
    if (out_proof_len) *out_proof_len = 0;
    if (out_public) *out_public = NULL;
    if (out_public_len) *out_public_len = 0;
    /* Intentional: see file header.  Use contrib/zk_carrier/witness_helper.py. */
    return DOGECOIN_ZK_ERR_DELEGATED;
}

dogecoin_zk_err_t dogecoin_zk_verify_groth16(
    const uint8_t* vk_json,
    size_t vk_json_len,
    const uint8_t* public_json,
    size_t public_json_len,
    const uint8_t* proof_json,
    size_t proof_json_len)
{
    /* No verification key configured (e.g. spvnode invoked without
     * --zk-vkey) — the caller cannot do an in-process check.  Return
     * DELEGATED so the SPV reveal still emits "Reveal validated" on
     * commit-match alone, mirroring the documented mobile-friendly
     * behaviour described at the top of this file. */
    if (!vk_json || vk_json_len == 0) {
        return DOGECOIN_ZK_ERR_DELEGATED;
    }
    if (!public_json || public_json_len == 0 ||
        !proof_json  || proof_json_len  == 0) {
        return DOGECOIN_ZK_ERR_INVALID_ARG;
    }
#ifdef HAVE_RAPIDSNARK
    /* rapidsnark wants NUL-terminated JSON strings.  Copy into NUL-terminated
     * buffers; the caller's blobs are bytes that may not be terminated. */
    char* vk = (char*)dogecoin_malloc(vk_json_len + 1);
    char* pubj = (char*)dogecoin_malloc(public_json_len + 1);
    char* prf = (char*)dogecoin_malloc(proof_json_len + 1);
    if (!vk || !pubj || !prf) {
        if (vk) dogecoin_free(vk);
        if (pubj) dogecoin_free(pubj);
        if (prf) dogecoin_free(prf);
        return DOGECOIN_ZK_ERR_OOM;
    }
    memcpy(vk, vk_json, vk_json_len);
    vk[vk_json_len] = '\0';
    memcpy(pubj, public_json, public_json_len);
    pubj[public_json_len] = '\0';
    memcpy(prf, proof_json, proof_json_len);
    prf[proof_json_len] = '\0';

    char err[256];
    err[0] = '\0';
    int rc = groth16_verify(vk, pubj, prf, err, sizeof(err));
    dogecoin_free(vk);
    dogecoin_free(pubj);
    dogecoin_free(prf);
    if (rc != 0) {
        return DOGECOIN_ZK_ERR_VERIFY_FAIL;
    }
    return DOGECOIN_ZK_OK;
#elif defined(HAVE_MCL)
    /* mcl-backed verifier (depends/packages/mcl.mk + --with-mcl).  Like the
     * rapidsnark path it expects NUL-terminated JSON, so copy into freshly
     * allocated NUL-terminated buffers. */
    char* vk = (char*)dogecoin_malloc(vk_json_len + 1);
    char* pubj = (char*)dogecoin_malloc(public_json_len + 1);
    char* prf = (char*)dogecoin_malloc(proof_json_len + 1);
    if (!vk || !pubj || !prf) {
        if (vk) dogecoin_free(vk);
        if (pubj) dogecoin_free(pubj);
        if (prf) dogecoin_free(prf);
        return DOGECOIN_ZK_ERR_OOM;
    }
    memcpy(vk, vk_json, vk_json_len);     vk[vk_json_len] = '\0';
    memcpy(pubj, public_json, public_json_len); pubj[public_json_len] = '\0';
    memcpy(prf, proof_json, proof_json_len);    prf[proof_json_len] = '\0';

    char err[256];
    err[0] = '\0';
    int rc = groth16_verify_mcl(vk, pubj, prf, err, sizeof(err));
    dogecoin_free(vk);
    dogecoin_free(pubj);
    dogecoin_free(prf);
    if (rc != 0) {
        return DOGECOIN_ZK_ERR_VERIFY_FAIL;
    }
    return DOGECOIN_ZK_OK;
#else
    /* No rapidsnark linked: caller falls back to off-box verification.
     * The demo script handles this with `snarkjs groth16 verify`. */
    return DOGECOIN_ZK_ERR_DELEGATED;
#endif
}

dogecoin_zk_err_t dogecoin_zk_verify_proof(
    const uint8_t* payload,
    size_t payload_len,
    const uint8_t* vk_blob,
    size_t vk_blob_len)
{
    dogecoin_zk_mode_t mode;
    uint32_t circuit_id;
    const uint8_t* public_inputs;
    size_t public_inputs_len;
    const uint8_t* proof;
    size_t proof_len;

    dogecoin_zk_err_t e = dogecoin_zk_decode_payload(
        payload, payload_len, &mode, &circuit_id,
        &public_inputs, &public_inputs_len, &proof, &proof_len);
    if (e != DOGECOIN_ZK_OK) return e;
    (void)circuit_id;

    switch (mode) {
    case DOGECOIN_ZK_MODE_GROTH16:
        return dogecoin_zk_verify_groth16(vk_blob, vk_blob_len,
                                          public_inputs, public_inputs_len,
                                          proof, proof_len);
    case DOGECOIN_ZK_MODE_PLONK:
    case DOGECOIN_ZK_MODE_STARK_S2:
        return DOGECOIN_ZK_ERR_NOT_IMPLEMENTED;
    }
    return DOGECOIN_ZK_ERR_BAD_MODE;
}
