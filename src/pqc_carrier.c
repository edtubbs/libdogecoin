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
 * PQC P2SH carrier transaction construction and parsing.
 *
 * Implements the P2SH carrier mode for post-quantum signature commitment
 * transactions.  TX_C creates P2SH outputs whose redeem script is simply
 * OP_DROP*5 OP_1.  TX_R spends those outputs, embedding the full PQ
 * public key and signature in the scriptSig as tagged, chunked data
 * pushes that miners accept (non-standard but consensus-valid).
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <dogecoin/mem.h>
#include <dogecoin/pqc_carrier.h>
#include <dogecoin/rmd160.h>
#include <dogecoin/script.h>
#include <dogecoin/sha2.h>

/**
 * @brief This function pushes a single opcode byte onto a
 * script buffer.
 *
 * @param s The script buffer to append to.
 * @param op The opcode byte.
 *
 * @return Nothing.
 */
static void script_push_op(cstring* s, uint8_t op)
{
    cstr_append_buf(s, &op, 1);
}

/**
 * @brief This function pushes arbitrary data onto a script
 * buffer using the smallest canonical push encoding
 * (direct / OP_PUSHDATA1 / OP_PUSHDATA2).
 *
 * @param s The script buffer to append to.
 * @param data The pointer to the data bytes.
 * @param len The length of the data.
 *
 * @return Nothing.
 */
static void script_push_data(cstring* s, const uint8_t* data, size_t len)
{
    if (len == 0) {
        script_push_op(s, 0x00); /* OP_0 */
        return;
    }
    if (len <= 75) {
        uint8_t l = (uint8_t)len;
        cstr_append_buf(s, &l, 1);
        cstr_append_buf(s, data, len);
        return;
    }
    if (len <= 255) {
        uint8_t op = 0x4c; /* OP_PUSHDATA1 */
        uint8_t l = (uint8_t)len;
        cstr_append_buf(s, &op, 1);
        cstr_append_buf(s, &l, 1);
        cstr_append_buf(s, data, len);
        return;
    }
    uint8_t op = 0x4d; /* OP_PUSHDATA2 */
    uint16_t l = (uint16_t)len;
    uint8_t le[2] = { (uint8_t)(l & 0xff), (uint8_t)((l >> 8) & 0xff) };
    cstr_append_buf(s, &op, 1);
    cstr_append_buf(s, le, 2);
    cstr_append_buf(s, data, len);
}

/**
 * @brief This function reads one push-data element from raw
 * script bytes starting at *off.  On success, *out points
 * into the original buffer and *outlen is set.
 *
 * @param s The pointer to the raw script bytes.
 * @param slen The length of the script.
 * @param off The pointer to the current offset (updated on success).
 * @param out The pointer to receive the data pointer.
 * @param outlen The pointer to receive the data length.
 *
 * @return true on success, false on truncation or unexpected opcodes.
 */
static dogecoin_bool read_push(const uint8_t* s, size_t slen, size_t* off, const uint8_t** out, size_t* outlen)
{
    if (!s || !off || !out || !outlen || *off >= slen) return false;

    uint8_t op = s[*off];
    (*off)++;
    if (op == 0x00) {
        *out = NULL;
        *outlen = 0;
        return true;
    }
    if (op <= 75) {
        size_t n = op;
        if (*off + n > slen) return false;
        *out = s + *off;
        *outlen = n;
        *off += n;
        return true;
    }
    if (op == 0x4c) { /* OP_PUSHDATA1 */
        if (*off + 1 > slen) return false;
        size_t n = s[*off];
        *off += 1;
        if (*off + n > slen) return false;
        *out = s + *off;
        *outlen = n;
        *off += n;
        return true;
    }
    if (op == 0x4d) { /* OP_PUSHDATA2 */
        if (*off + 2 > slen) return false;
        size_t n = (size_t)s[*off] | ((size_t)s[*off + 1] << 8);
        *off += 2;
        if (*off + n > slen) return false;
        *out = s + *off;
        *outlen = n;
        *off += n;
        return true;
    }
    return false;
}

/**
 * @brief This function computes HASH160 (SHA-256 then
 * RIPEMD-160) of the given data.
 *
 * @param data The pointer to the input data.
 * @param len The length of the input data.
 * @param out20 The output buffer for the 20-byte hash.
 *
 * @return Nothing.
 */
static void hash160(const uint8_t* data, size_t len, uint8_t out20[20])
{
    uint8_t h32[32];
    sha256_raw(data, len, h32);
    rmd160(h32, sizeof(h32), out20);
}

/**
 * @brief This function builds the carrier redeem script:
 * OP_DROP OP_DROP OP_DROP OP_DROP OP_DROP OP_1.  This script
 * always succeeds after consuming the five data pushes in the
 * scriptSig, allowing miners to accept the TX_R spend.
 *
 * @param out_redeem The pointer to receive the allocated redeem script.
 *
 * @return true if the script was built, false on error.
 */
dogecoin_bool dogecoin_pqc_carrier_build_redeemscript(cstring** out_redeem)
{
    if (!out_redeem) return false;
    cstring* r = cstr_new_sz(8);
    if (!r) return false;
    for (int i = 0; i < 5; i++) {
        uint8_t op_drop = OP_DROP;
        cstr_append_buf(r, &op_drop, 1);
    }
    uint8_t op_true = OP_1;
    cstr_append_buf(r, &op_true, 1);
    *out_redeem = r;
    return true;
}

/**
 * @brief This function builds the P2SH scriptPubKey
 * (OP_HASH160 <hash160(redeem)> OP_EQUAL) from the carrier
 * redeem script.  Used to create the carrier outputs in TX_C.
 *
 * @param redeem The pointer to the redeem script.
 * @param out_spk The pointer to receive the allocated scriptPubKey.
 *
 * @return true if the scriptPubKey was built, false on error.
 */
dogecoin_bool dogecoin_pqc_carrier_build_p2sh_scriptpubkey(const cstring* redeem, cstring** out_spk)
{
    if (!redeem || !out_spk) return false;
    uint8_t h160[20];
    hash160((const uint8_t*)redeem->str, redeem->len, h160);
    cstring* spk = cstr_new_sz(23);
    if (!spk) return false;

    uint8_t op_hash160 = OP_HASH160;
    uint8_t push20 = 0x14;
    uint8_t op_equal = OP_EQUAL;
    cstr_append_buf(spk, &op_hash160, 1);
    cstr_append_buf(spk, &push20, 1);
    cstr_append_buf(spk, h160, sizeof(h160));
    cstr_append_buf(spk, &op_equal, 1);
    *out_spk = spk;
    return true;
}

/**
 * @brief This function builds a single carrier-part scriptSig
 * for TX_R.  Layout: <tag8> <8-byte-hdr> <chunk0..chunk4>
 * <redeemscript>.  The header encodes version, part index/total,
 * and the public-key and full-payload lengths so the SPV parser
 * can reassemble across parts.
 *
 * @param tag8 The 8-byte algorithm tag.
 * @param part_index The zero-based index of this part.
 * @param part_total The total number of parts.
 * @param pk_len The public key length encoded in the header.
 * @param full_len The full payload length encoded in the header.
 * @param part_data The pointer to this part's data payload.
 * @param part_data_len The length of the part data.
 * @param redeem The pointer to the redeem script.
 * @param out_scriptsig The pointer to receive the allocated scriptSig.
 *
 * @return true if the scriptSig was built, false on error.
 */
dogecoin_bool dogecoin_pqc_carrier_build_part_scriptsig(
    const char tag8[DOGECOIN_PQC_CARRIER_TAG_LEN],
    uint8_t part_index,
    uint8_t part_total,
    uint16_t pk_len,
    uint16_t full_len,
    const uint8_t* part_data,
    size_t part_data_len,
    const cstring* redeem,
    cstring** out_scriptsig)
{
    if (!tag8 || !redeem || !out_scriptsig) return false;
    if (part_total == 0) return false;
    if (part_data_len > DOGECOIN_PQC_CARRIER_MAX_CHUNKS * DOGECOIN_PQC_CARRIER_CHUNK_MAX) return false;

    uint8_t hdr[DOGECOIN_PQC_CARRIER_HDR_LEN];
    hdr[0] = 0x01;
    hdr[1] = part_index;
    hdr[2] = part_total;
    hdr[3] = 0x00;
    hdr[4] = (uint8_t)((pk_len >> 8) & 0xff);
    hdr[5] = (uint8_t)(pk_len & 0xff);
    hdr[6] = (uint8_t)((full_len >> 8) & 0xff);
    hdr[7] = (uint8_t)(full_len & 0xff);

    cstring* ss = cstr_new_sz(2048);
    if (!ss) return false;

    script_push_data(ss, (const uint8_t*)tag8, DOGECOIN_PQC_CARRIER_TAG_LEN);
    script_push_data(ss, hdr, sizeof(hdr));

    size_t off = 0;
    for (size_t i = 0; i < DOGECOIN_PQC_CARRIER_MAX_CHUNKS; i++) {
        size_t n = 0;
        if (off < part_data_len) {
            n = part_data_len - off;
            if (n > DOGECOIN_PQC_CARRIER_CHUNK_MAX) n = DOGECOIN_PQC_CARRIER_CHUNK_MAX;
            script_push_data(ss, part_data + off, n);
            off += n;
        } else {
            script_push_data(ss, NULL, 0);
        }
    }

    script_push_data(ss, (const uint8_t*)redeem->str, redeem->len);
    *out_scriptsig = ss;
    return true;
}

/**
 * @brief This function parses a carrier-part scriptSig produced
 * by dogecoin_pqc_carrier_build_part_scriptsig().  Extracts the
 * 8-byte tag, part index/total, pk/full lengths, the concatenated
 * data payload, and the redeem script.  Caller must free
 * *out_part_data with dogecoin_free() and *out_redeem with
 * cstr_free().
 *
 * @param scriptsig The pointer to the scriptSig to parse.
 * @param out_tag8 The output buffer for the 8-byte tag (null-terminated).
 * @param out_part_index The pointer to receive the part index.
 * @param out_part_total The pointer to receive the part total.
 * @param out_pk_len The pointer to receive the public key length.
 * @param out_full_len The pointer to receive the full payload length.
 * @param out_part_data The pointer to receive the allocated data payload.
 * @param out_part_data_len The pointer to receive the data payload length.
 * @param out_redeem The pointer to receive the allocated redeem script.
 *
 * @return true if parsing succeeded, false on error.
 */
dogecoin_bool dogecoin_pqc_carrier_parse_part_scriptsig(
    const cstring* scriptsig,
    char out_tag8[DOGECOIN_PQC_CARRIER_TAG_LEN + 1],
    uint8_t* out_part_index,
    uint8_t* out_part_total,
    uint16_t* out_pk_len,
    uint16_t* out_full_len,
    uint8_t** out_part_data,
    size_t* out_part_data_len,
    cstring** out_redeem)
{
    if (!scriptsig || !out_tag8 || !out_part_index || !out_part_total || !out_pk_len || !out_full_len ||
        !out_part_data || !out_part_data_len || !out_redeem) {
        return false;
    }

    const uint8_t* s = (const uint8_t*)scriptsig->str;
    size_t slen = scriptsig->len;
    size_t o = 0;
    const uint8_t* p = NULL;
    size_t n = 0;

    if (!read_push(s, slen, &o, &p, &n) || n != DOGECOIN_PQC_CARRIER_TAG_LEN) return false;
    memcpy(out_tag8, p, DOGECOIN_PQC_CARRIER_TAG_LEN);
    out_tag8[DOGECOIN_PQC_CARRIER_TAG_LEN] = '\0';

    if (!read_push(s, slen, &o, &p, &n) || n != DOGECOIN_PQC_CARRIER_HDR_LEN) return false;
    if (p[0] != 0x01) return false;
    *out_part_index = p[1];
    *out_part_total = p[2];
    *out_pk_len = (uint16_t)((p[4] << 8) | p[5]);
    *out_full_len = (uint16_t)((p[6] << 8) | p[7]);

    uint8_t* buf = (uint8_t*)dogecoin_malloc(DOGECOIN_PQC_CARRIER_MAX_CHUNKS * DOGECOIN_PQC_CARRIER_CHUNK_MAX);
    if (!buf) return false;
    size_t w = 0;
    for (size_t i = 0; i < DOGECOIN_PQC_CARRIER_MAX_CHUNKS; i++) {
        if (!read_push(s, slen, &o, &p, &n)) {
            dogecoin_free(buf);
            return false;
        }
        if (n > DOGECOIN_PQC_CARRIER_CHUNK_MAX) {
            dogecoin_free(buf);
            return false;
        }
        if (n && p) {
            memcpy(buf + w, p, n);
            w += n;
        }
    }

    if (!read_push(s, slen, &o, &p, &n)) {
        dogecoin_free(buf);
        return false;
    }
    cstring* r = cstr_new_buf(p, n);
    if (!r) {
        dogecoin_free(buf);
        return false;
    }

    *out_part_data = buf;
    *out_part_data_len = w;
    *out_redeem = r;
    return true;
}

/**
 * @brief This function appends P2SH carrier outputs to a
 * transaction (TX_C).  Creates part_total outputs, each paying
 * value koinu to carrier_spk.  TX_R will later spend each
 * output with its carrier scriptSig.
 *
 * @param tx The pointer to the transaction to modify.
 * @param carrier_spk The P2SH scriptPubKey for carrier outputs.
 * @param value The value in koinu for each carrier output.
 * @param part_total The number of carrier outputs to add.
 *
 * @return true if outputs were added, false on error.
 */
dogecoin_bool dogecoin_tx_add_pqc_carrier_outputs(
    dogecoin_tx* tx,
    const cstring* carrier_spk,
    uint64_t value,
    uint8_t part_total)
{
    if (!tx || !carrier_spk || part_total == 0) return false;
    for (uint8_t i = 0; i < part_total; i++) {
        dogecoin_tx_out* out = dogecoin_tx_out_new();
        if (!out) return false;
        out->value = value;
        if (out->script_pubkey) cstr_free(out->script_pubkey, true);
        out->script_pubkey = cstr_new_buf((const uint8_t*)carrier_spk->str, carrier_spk->len);
        vector_add(tx->vout, out);
    }
    return true;
}
