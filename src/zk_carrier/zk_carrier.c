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
 * ZK carrier — payload codec, error strings, and OP_RETURN scriptPubKey
 * helper.  TX_C/TX_R construction lives in zk_commit.c, which thinly wraps
 * the existing PQ carrier helpers (src/pqc_carrier.c) so both carriers
 * share one on-chain shape.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <dogecoin/cstr.h>
#include <dogecoin/mem.h>
#include <dogecoin/script.h>
#include <dogecoin/sha2.h>
#include <dogecoin/zk_carrier.h>

const char* dogecoin_zk_strerror(dogecoin_zk_err_t err)
{
    switch (err) {
    case DOGECOIN_ZK_OK:                  return "ok";
    case DOGECOIN_ZK_ERR_INVALID_ARG:     return "invalid argument";
    case DOGECOIN_ZK_ERR_BAD_MAGIC:       return "bad payload magic (expected ZKP1)";
    case DOGECOIN_ZK_ERR_BAD_MODE:        return "unknown ZK mode";
    case DOGECOIN_ZK_ERR_TRUNCATED:       return "payload truncated";
    case DOGECOIN_ZK_ERR_OOM:             return "out of memory";
    case DOGECOIN_ZK_ERR_NOT_IMPLEMENTED: return "not implemented in this build";
    case DOGECOIN_ZK_ERR_DELEGATED:       return "operation delegated to host (use snarkjs/rapidsnark)";
    case DOGECOIN_ZK_ERR_VERIFY_FAIL:     return "proof verification failed";
    }
    return "unknown ZK carrier error";
}

static dogecoin_bool zk_mode_is_known(dogecoin_zk_mode_t mode)
{
    switch (mode) {
    case DOGECOIN_ZK_MODE_GROTH16:
    case DOGECOIN_ZK_MODE_PLONK:
    case DOGECOIN_ZK_MODE_STARK_S2:
    case DOGECOIN_ZK_MODE_GROTH16_BLS12_381:
    case DOGECOIN_ZK_MODE_PLONK_HALO2_KZG_BN256:
        return true;
    }
    return false;
}

dogecoin_zk_err_t dogecoin_zk_encode_payload(
    dogecoin_zk_mode_t mode,
    uint32_t circuit_id,
    const uint8_t* public_inputs,
    size_t public_inputs_len,
    const uint8_t* proof,
    size_t proof_len,
    uint8_t** out_payload,
    size_t* out_payload_len)
{
    if (!out_payload || !out_payload_len) return DOGECOIN_ZK_ERR_INVALID_ARG;
    if (public_inputs_len > 0 && !public_inputs) return DOGECOIN_ZK_ERR_INVALID_ARG;
    if (proof_len > 0 && !proof) return DOGECOIN_ZK_ERR_INVALID_ARG;
    if (!zk_mode_is_known(mode)) return DOGECOIN_ZK_ERR_BAD_MODE;
    if (public_inputs_len > 0xFFFFu) return DOGECOIN_ZK_ERR_INVALID_ARG;
    /* Cap proof bytes at 32 MiB to keep size fields sane and chunking bounded. */
    if (proof_len > 0x02000000u) return DOGECOIN_ZK_ERR_INVALID_ARG;

    size_t total = (size_t)DOGECOIN_ZK_CARRIER_HDR_FIXED + public_inputs_len + 4 + proof_len;
    uint8_t* buf = (uint8_t*)dogecoin_malloc(total);
    if (!buf) return DOGECOIN_ZK_ERR_OOM;

    size_t off = 0;
    memcpy(buf + off, DOGECOIN_ZK_CARRIER_MAGIC, DOGECOIN_ZK_CARRIER_MAGIC_LEN);
    off += DOGECOIN_ZK_CARRIER_MAGIC_LEN;
    buf[off++] = (uint8_t)mode;
    buf[off++] = 0x00; /* reserved */
    buf[off++] = (uint8_t)((circuit_id >> 24) & 0xff);
    buf[off++] = (uint8_t)((circuit_id >> 16) & 0xff);
    buf[off++] = (uint8_t)((circuit_id >> 8) & 0xff);
    buf[off++] = (uint8_t)((circuit_id) & 0xff);
    buf[off++] = (uint8_t)((public_inputs_len >> 8) & 0xff);
    buf[off++] = (uint8_t)((public_inputs_len) & 0xff);
    if (public_inputs_len > 0) {
        memcpy(buf + off, public_inputs, public_inputs_len);
        off += public_inputs_len;
    }
    buf[off++] = (uint8_t)((proof_len >> 24) & 0xff);
    buf[off++] = (uint8_t)((proof_len >> 16) & 0xff);
    buf[off++] = (uint8_t)((proof_len >> 8) & 0xff);
    buf[off++] = (uint8_t)((proof_len) & 0xff);
    if (proof_len > 0) {
        memcpy(buf + off, proof, proof_len);
        off += proof_len;
    }

    *out_payload = buf;
    *out_payload_len = off;
    return DOGECOIN_ZK_OK;
}

dogecoin_zk_err_t dogecoin_zk_decode_payload(
    const uint8_t* payload,
    size_t payload_len,
    dogecoin_zk_mode_t* out_mode,
    uint32_t* out_circuit_id,
    const uint8_t** out_public_inputs,
    size_t* out_public_inputs_len,
    const uint8_t** out_proof,
    size_t* out_proof_len)
{
    if (!payload || !out_mode || !out_circuit_id ||
        !out_public_inputs || !out_public_inputs_len ||
        !out_proof || !out_proof_len) {
        return DOGECOIN_ZK_ERR_INVALID_ARG;
    }
    if (payload_len < DOGECOIN_ZK_CARRIER_HDR_FIXED) return DOGECOIN_ZK_ERR_TRUNCATED;
    if (memcmp(payload, DOGECOIN_ZK_CARRIER_MAGIC, DOGECOIN_ZK_CARRIER_MAGIC_LEN) != 0) {
        return DOGECOIN_ZK_ERR_BAD_MAGIC;
    }

    size_t off = DOGECOIN_ZK_CARRIER_MAGIC_LEN;
    uint8_t mode_byte = payload[off++];
    uint8_t reserved = payload[off++];
    if (reserved != 0x00) return DOGECOIN_ZK_ERR_TRUNCATED;
    dogecoin_zk_mode_t mode = (dogecoin_zk_mode_t)mode_byte;
    if (!zk_mode_is_known(mode)) return DOGECOIN_ZK_ERR_BAD_MODE;

    uint32_t circuit_id = ((uint32_t)payload[off] << 24) |
                          ((uint32_t)payload[off + 1] << 16) |
                          ((uint32_t)payload[off + 2] << 8) |
                          ((uint32_t)payload[off + 3]);
    off += 4;
    uint16_t pl = (uint16_t)(((uint16_t)payload[off] << 8) | payload[off + 1]);
    off += 2;

    if (pl > payload_len - off) return DOGECOIN_ZK_ERR_TRUNCATED;
    const uint8_t* public_ptr = payload + off;
    off += pl;

    if (4 > payload_len - off) return DOGECOIN_ZK_ERR_TRUNCATED;
    uint32_t xl = ((uint32_t)payload[off] << 24) |
                  ((uint32_t)payload[off + 1] << 16) |
                  ((uint32_t)payload[off + 2] << 8) |
                  ((uint32_t)payload[off + 3]);
    off += 4;
    if (xl > payload_len - off) return DOGECOIN_ZK_ERR_TRUNCATED;
    const uint8_t* proof_ptr = payload + off;
    off += xl;

    if (off != payload_len) return DOGECOIN_ZK_ERR_TRUNCATED; /* trailing bytes */

    *out_mode = mode;
    *out_circuit_id = circuit_id;
    *out_public_inputs = pl > 0 ? public_ptr : NULL;
    *out_public_inputs_len = pl;
    *out_proof = xl > 0 ? proof_ptr : NULL;
    *out_proof_len = xl;
    return DOGECOIN_ZK_OK;
}

dogecoin_zk_err_t dogecoin_zk_get_commitment_hash(
    const uint8_t* payload,
    size_t payload_len,
    uint8_t out_commitment[32])
{
    if (!payload || payload_len == 0 || !out_commitment) return DOGECOIN_ZK_ERR_INVALID_ARG;
    /* SHA256d (double-SHA256), the standard Bitcoin/Dogecoin commitment hash. */
    sha256_raw(payload, payload_len, out_commitment);
    sha256_raw(out_commitment, 32, out_commitment);
    return DOGECOIN_ZK_OK;
}

dogecoin_zk_err_t dogecoin_zk_build_opreturn_scriptpubkey(
    dogecoin_zk_mode_t mode,
    const uint8_t commitment[32],
    cstring** out_spk)
{
    if (!out_spk || !commitment) return DOGECOIN_ZK_ERR_INVALID_ARG;
    if (!zk_mode_is_known(mode)) return DOGECOIN_ZK_ERR_BAD_MODE;

    /* Layout: OP_RETURN <push 37> "DZKC" <mode> <commitment32>
       Total scriptPubKey length: 1 (OP_RETURN) + 1 (push len) + 37 = 39 bytes. */
    cstring* s = cstr_new_sz(40);
    if (!s) return DOGECOIN_ZK_ERR_OOM;

    uint8_t op_return = OP_RETURN;
    cstr_append_buf(s, &op_return, 1);

    uint8_t data[DOGECOIN_ZK_OPRETURN_DATA_LEN];
    memcpy(data, DOGECOIN_ZK_OPRETURN_TAG, DOGECOIN_ZK_OPRETURN_TAG_LEN);
    data[DOGECOIN_ZK_OPRETURN_TAG_LEN] = (uint8_t)mode;
    memcpy(data + DOGECOIN_ZK_OPRETURN_TAG_LEN + 1, commitment, 32);

    /* DOGECOIN_ZK_OPRETURN_DATA_LEN is 37 — fits in a direct push (<= 75). */
    uint8_t push_len = (uint8_t)DOGECOIN_ZK_OPRETURN_DATA_LEN;
    cstr_append_buf(s, &push_len, 1);
    cstr_append_buf(s, data, DOGECOIN_ZK_OPRETURN_DATA_LEN);

    *out_spk = s;
    return DOGECOIN_ZK_OK;
}

/* ------------------------------------------------------------------------- *
 * Canonical wire layouts for BLS12-381 Groth16 and BN256 PLONK/Halo2/KZG.
 *
 * These helpers package the inputs into the same byte order an opcode
 * (e.g. the DogeOS `OP_CHECKZKP` DIP at dogecoin/dogecoin#3869, or any
 * libdogecoin successor) would expect on the script stack — so a TX_R
 * reveal published today can be sliced verbatim onto the stack the day
 * such an opcode (if any) ships, without re-encoding.
 * ------------------------------------------------------------------------- */

dogecoin_zk_err_t dogecoin_zk_encode_groth16_bls12_381_payload(
    uint32_t circuit_id,
    const uint8_t pi_a[DOGECOIN_ZK_BLS12_381_PI_A_LEN],
    const uint8_t pi_b[DOGECOIN_ZK_BLS12_381_PI_B_LEN],
    const uint8_t pi_c[DOGECOIN_ZK_BLS12_381_PI_C_LEN],
    const uint8_t public_inputs[DOGECOIN_ZK_BLS12_381_PUB_LEN],
    const uint8_t vk[DOGECOIN_ZK_BLS12_381_VK_LEN],
    uint8_t** out_payload,
    size_t* out_payload_len)
{
    if (!pi_a || !pi_b || !pi_c || !public_inputs || !vk ||
        !out_payload || !out_payload_len) {
        return DOGECOIN_ZK_ERR_INVALID_ARG;
    }

    uint8_t proof_buf[DOGECOIN_ZK_BLS12_381_PAYLOAD_PROOF_LEN];
    size_t off = 0;
    memcpy(proof_buf + off, pi_a, DOGECOIN_ZK_BLS12_381_PI_A_LEN);
    off += DOGECOIN_ZK_BLS12_381_PI_A_LEN;
    memcpy(proof_buf + off, pi_b, DOGECOIN_ZK_BLS12_381_PI_B_LEN);
    off += DOGECOIN_ZK_BLS12_381_PI_B_LEN;
    memcpy(proof_buf + off, pi_c, DOGECOIN_ZK_BLS12_381_PI_C_LEN);
    off += DOGECOIN_ZK_BLS12_381_PI_C_LEN;
    memcpy(proof_buf + off, vk, DOGECOIN_ZK_BLS12_381_VK_LEN);
    off += DOGECOIN_ZK_BLS12_381_VK_LEN;
    /* off == DOGECOIN_ZK_BLS12_381_PAYLOAD_PROOF_LEN by construction. */

    return dogecoin_zk_encode_payload(
        DOGECOIN_ZK_MODE_GROTH16_BLS12_381, circuit_id,
        public_inputs, DOGECOIN_ZK_BLS12_381_PUB_LEN,
        proof_buf, off,
        out_payload, out_payload_len);
}

dogecoin_zk_err_t dogecoin_zk_decode_groth16_bls12_381_payload(
    const uint8_t* payload,
    size_t payload_len,
    uint32_t* out_circuit_id,
    const uint8_t** out_pi_a,
    const uint8_t** out_pi_b,
    const uint8_t** out_pi_c,
    const uint8_t** out_public_inputs,
    const uint8_t** out_vk)
{
    dogecoin_zk_mode_t mode;
    uint32_t cid;
    const uint8_t* pub;
    size_t pub_len;
    const uint8_t* proof;
    size_t proof_len;

    dogecoin_zk_err_t e = dogecoin_zk_decode_payload(
        payload, payload_len, &mode, &cid,
        &pub, &pub_len, &proof, &proof_len);
    if (e != DOGECOIN_ZK_OK) return e;
    if (mode != DOGECOIN_ZK_MODE_GROTH16_BLS12_381) return DOGECOIN_ZK_ERR_BAD_MODE;
    if (pub_len != DOGECOIN_ZK_BLS12_381_PUB_LEN) return DOGECOIN_ZK_ERR_TRUNCATED;
    if (proof_len != DOGECOIN_ZK_BLS12_381_PAYLOAD_PROOF_LEN) return DOGECOIN_ZK_ERR_TRUNCATED;

    if (out_circuit_id)     *out_circuit_id = cid;
    if (out_pi_a)           *out_pi_a = proof;
    if (out_pi_b)           *out_pi_b = proof + DOGECOIN_ZK_BLS12_381_PI_A_LEN;
    if (out_pi_c)           *out_pi_c = proof + DOGECOIN_ZK_BLS12_381_PI_A_LEN
                                              + DOGECOIN_ZK_BLS12_381_PI_B_LEN;
    if (out_vk)             *out_vk   = proof + DOGECOIN_ZK_BLS12_381_PROOF_BYTES;
    if (out_public_inputs)  *out_public_inputs = pub;
    return DOGECOIN_ZK_OK;
}

dogecoin_zk_err_t dogecoin_zk_encode_plonk_halo2_kzg_bn256_payload(
    uint32_t circuit_id,
    const uint8_t* proof,
    size_t proof_len,
    const uint8_t* vk,
    size_t vk_len,
    const uint8_t* public_inputs,
    size_t n_public_inputs,
    uint8_t** out_payload,
    size_t* out_payload_len)
{
    if (!out_payload || !out_payload_len) return DOGECOIN_ZK_ERR_INVALID_ARG;
    if (proof_len > 0 && !proof) return DOGECOIN_ZK_ERR_INVALID_ARG;
    if (vk_len    > 0 && !vk)    return DOGECOIN_ZK_ERR_INVALID_ARG;
    if (n_public_inputs > 0 && !public_inputs) return DOGECOIN_ZK_ERR_INVALID_ARG;
    if (proof_len > DOGECOIN_ZK_HALO2_BN256_MAX_PROOF) return DOGECOIN_ZK_ERR_INVALID_ARG;
    if (vk_len    > DOGECOIN_ZK_HALO2_BN256_MAX_VK)    return DOGECOIN_ZK_ERR_INVALID_ARG;
    if (n_public_inputs > DOGECOIN_ZK_HALO2_BN256_MAX_INPUTS) return DOGECOIN_ZK_ERR_INVALID_ARG;

    /* public_inputs payload field: <n:2 BE> || (32 B × n) */
    size_t pub_field_len = (size_t)2 + n_public_inputs * DOGECOIN_ZK_HALO2_BN256_FR_LEN;
    /* proof payload field: <proof_len:4 LE> || proof || <vk_len:4 LE> || vk */
    size_t proof_field_len = (size_t)4 + proof_len + (size_t)4 + vk_len;

    uint8_t* pub_field = (uint8_t*)dogecoin_malloc(pub_field_len);
    if (!pub_field) return DOGECOIN_ZK_ERR_OOM;
    pub_field[0] = (uint8_t)((n_public_inputs >> 8) & 0xff);
    pub_field[1] = (uint8_t)(n_public_inputs & 0xff);
    if (n_public_inputs > 0) {
        memcpy(pub_field + 2, public_inputs,
               n_public_inputs * DOGECOIN_ZK_HALO2_BN256_FR_LEN);
    }

    uint8_t* proof_field = (uint8_t*)dogecoin_malloc(proof_field_len);
    if (!proof_field) {
        dogecoin_free(pub_field);
        return DOGECOIN_ZK_ERR_OOM;
    }
    size_t off = 0;
    proof_field[off++] = (uint8_t)(proof_len & 0xff);
    proof_field[off++] = (uint8_t)((proof_len >> 8) & 0xff);
    proof_field[off++] = (uint8_t)((proof_len >> 16) & 0xff);
    proof_field[off++] = (uint8_t)((proof_len >> 24) & 0xff);
    if (proof_len > 0) {
        memcpy(proof_field + off, proof, proof_len);
        off += proof_len;
    }
    proof_field[off++] = (uint8_t)(vk_len & 0xff);
    proof_field[off++] = (uint8_t)((vk_len >> 8) & 0xff);
    proof_field[off++] = (uint8_t)((vk_len >> 16) & 0xff);
    proof_field[off++] = (uint8_t)((vk_len >> 24) & 0xff);
    if (vk_len > 0) {
        memcpy(proof_field + off, vk, vk_len);
        off += vk_len;
    }

    dogecoin_zk_err_t e = dogecoin_zk_encode_payload(
        DOGECOIN_ZK_MODE_PLONK_HALO2_KZG_BN256, circuit_id,
        pub_field, pub_field_len,
        proof_field, proof_field_len,
        out_payload, out_payload_len);

    dogecoin_free(pub_field);
    dogecoin_free(proof_field);
    return e;
}

dogecoin_zk_err_t dogecoin_zk_decode_plonk_halo2_kzg_bn256_payload(
    const uint8_t* payload,
    size_t payload_len,
    uint32_t* out_circuit_id,
    const uint8_t** out_proof,
    size_t* out_proof_len,
    const uint8_t** out_vk,
    size_t* out_vk_len,
    const uint8_t** out_public_inputs,
    size_t* out_n_public_inputs)
{
    dogecoin_zk_mode_t mode;
    uint32_t cid;
    const uint8_t* pub;
    size_t pub_len;
    const uint8_t* proof;
    size_t proof_len;

    dogecoin_zk_err_t e = dogecoin_zk_decode_payload(
        payload, payload_len, &mode, &cid,
        &pub, &pub_len, &proof, &proof_len);
    if (e != DOGECOIN_ZK_OK) return e;
    if (mode != DOGECOIN_ZK_MODE_PLONK_HALO2_KZG_BN256) return DOGECOIN_ZK_ERR_BAD_MODE;

    /* Public inputs: <n:2 BE> || 32 B × n */
    if (pub_len < 2) return DOGECOIN_ZK_ERR_TRUNCATED;
    size_t n = ((size_t)pub[0] << 8) | (size_t)pub[1];
    if (n > DOGECOIN_ZK_HALO2_BN256_MAX_INPUTS) return DOGECOIN_ZK_ERR_TRUNCATED;
    if (pub_len != 2 + n * DOGECOIN_ZK_HALO2_BN256_FR_LEN) return DOGECOIN_ZK_ERR_TRUNCATED;

    /* Proof field: <proof_len:4 LE> || proof || <vk_len:4 LE> || vk */
    if (proof_len < 4) return DOGECOIN_ZK_ERR_TRUNCATED;
    size_t off = 0;
    uint32_t pl = ((uint32_t)proof[off]) |
                  ((uint32_t)proof[off + 1] << 8) |
                  ((uint32_t)proof[off + 2] << 16) |
                  ((uint32_t)proof[off + 3] << 24);
    off += 4;
    if (pl > DOGECOIN_ZK_HALO2_BN256_MAX_PROOF) return DOGECOIN_ZK_ERR_TRUNCATED;
    if (pl > proof_len - off) return DOGECOIN_ZK_ERR_TRUNCATED;
    const uint8_t* proof_ptr = proof + off;
    off += pl;

    if (4 > proof_len - off) return DOGECOIN_ZK_ERR_TRUNCATED;
    uint32_t vl = ((uint32_t)proof[off]) |
                  ((uint32_t)proof[off + 1] << 8) |
                  ((uint32_t)proof[off + 2] << 16) |
                  ((uint32_t)proof[off + 3] << 24);
    off += 4;
    if (vl > DOGECOIN_ZK_HALO2_BN256_MAX_VK) return DOGECOIN_ZK_ERR_TRUNCATED;
    if (vl > proof_len - off) return DOGECOIN_ZK_ERR_TRUNCATED;
    const uint8_t* vk_ptr = proof + off;
    off += vl;
    if (off != proof_len) return DOGECOIN_ZK_ERR_TRUNCATED;

    if (out_circuit_id)         *out_circuit_id = cid;
    if (out_proof)              *out_proof = pl > 0 ? proof_ptr : NULL;
    if (out_proof_len)          *out_proof_len = pl;
    if (out_vk)                 *out_vk = vl > 0 ? vk_ptr : NULL;
    if (out_vk_len)             *out_vk_len = vl;
    if (out_public_inputs)      *out_public_inputs = n > 0 ? pub + 2 : NULL;
    if (out_n_public_inputs)    *out_n_public_inputs = n;
    return DOGECOIN_ZK_OK;
}
