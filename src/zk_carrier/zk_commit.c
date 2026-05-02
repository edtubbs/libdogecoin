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
 * ZK carrier — TX_C / TX_R construction.
 *
 * This is the integration glue requested by the OP_CHECKZKP proposal:
 * we deliberately reuse the PQ carrier pattern (src/pqc_carrier.c) — same
 * P2SH redeem script, same chunked scriptSig layout, same 8-byte tag slot —
 * so a single SPV path can recognise both PQ-signature and ZK-proof carrier
 * transactions.  Only the ASCII tag changes (PQC uses "FLC1FULL", "DIL2FULL",
 * "RCG4FULL"; ZK uses "ZKP1FULL").
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <dogecoin/cstr.h>
#include <dogecoin/mem.h>
#include <dogecoin/pqc_carrier.h>
#include <dogecoin/script.h>
#include <dogecoin/tx.h>
#include <dogecoin/zk_carrier.h>

/* Per-part chunked payload capacity (mirrors PQC carrier). */
#define ZK_PART_PAYLOAD_MAX (DOGECOIN_PQC_CARRIER_MAX_CHUNKS * DOGECOIN_PQC_CARRIER_CHUNK_MAX)

static dogecoin_bool zk_compute_part_total(size_t payload_len, uint8_t* out_part_total)
{
    if (payload_len == 0) {
        /* Always at least one carrier output so SPV has something to walk. */
        *out_part_total = 1;
        return true;
    }
    size_t parts = (payload_len + ZK_PART_PAYLOAD_MAX - 1) / ZK_PART_PAYLOAD_MAX;
    if (parts == 0 || parts > 0xFF) return false;
    *out_part_total = (uint8_t)parts;
    return true;
}

dogecoin_zk_err_t dogecoin_zk_build_carrier_tx_c(
    dogecoin_tx* tx,
    const uint8_t* payload,
    size_t payload_len,
    dogecoin_zk_mode_t mode,
    uint64_t carrier_value,
    cstring** out_carrier_spk,
    uint8_t* out_part_total)
{
    if (!tx || !payload || payload_len == 0 || !out_carrier_spk || !out_part_total) {
        return DOGECOIN_ZK_ERR_INVALID_ARG;
    }
    *out_carrier_spk = NULL;
    *out_part_total = 0;

    uint8_t commit[32];
    dogecoin_zk_err_t e = dogecoin_zk_get_commitment_hash(payload, payload_len, commit);
    if (e != DOGECOIN_ZK_OK) return e;

    /* 1. OP_RETURN commit output (vout 0 by convention). */
    cstring* opret = NULL;
    e = dogecoin_zk_build_opreturn_scriptpubkey(mode, commit, &opret);
    if (e != DOGECOIN_ZK_OK) return e;
    {
        dogecoin_tx_out* out = dogecoin_tx_out_new();
        if (!out) { cstr_free(opret, true); return DOGECOIN_ZK_ERR_OOM; }
        out->value = 0;
        if (out->script_pubkey) cstr_free(out->script_pubkey, true);
        out->script_pubkey = cstr_new_buf((const uint8_t*)opret->str, opret->len);
        if (!out->script_pubkey) {
            dogecoin_tx_out_free(out);
            cstr_free(opret, true);
            return DOGECOIN_ZK_ERR_OOM;
        }
        vector_add(tx->vout, out);
        cstr_free(opret, true);
    }

    /* 2. Carrier P2SH outputs.  Reuse the PQC redeem + scriptPubKey helpers
     *    verbatim — same `OP_DROP*5 OP_1` redeem script, same hash160 P2SH. */
    cstring* redeem = NULL;
    if (!dogecoin_pqc_carrier_build_redeemscript(&redeem) || !redeem) {
        return DOGECOIN_ZK_ERR_OOM;
    }
    cstring* carrier_spk = NULL;
    if (!dogecoin_pqc_carrier_build_p2sh_scriptpubkey(redeem, &carrier_spk) || !carrier_spk) {
        cstr_free(redeem, true);
        return DOGECOIN_ZK_ERR_OOM;
    }
    cstr_free(redeem, true);

    uint8_t part_total = 0;
    if (!zk_compute_part_total(payload_len, &part_total)) {
        cstr_free(carrier_spk, true);
        return DOGECOIN_ZK_ERR_INVALID_ARG;
    }
    if (!dogecoin_tx_add_pqc_carrier_outputs(tx, carrier_spk, carrier_value, part_total)) {
        cstr_free(carrier_spk, true);
        return DOGECOIN_ZK_ERR_OOM;
    }

    *out_carrier_spk = carrier_spk;
    *out_part_total = part_total;
    return DOGECOIN_ZK_OK;
}

dogecoin_zk_err_t dogecoin_zk_build_carrier_tx_r_scriptsigs(
    const uint8_t* payload,
    size_t payload_len,
    cstring*** out_scriptsigs,
    uint8_t* out_part_total)
{
    if (!payload || payload_len == 0 || !out_scriptsigs || !out_part_total) {
        return DOGECOIN_ZK_ERR_INVALID_ARG;
    }
    *out_scriptsigs = NULL;
    *out_part_total = 0;

    uint8_t part_total = 0;
    if (!zk_compute_part_total(payload_len, &part_total)) {
        return DOGECOIN_ZK_ERR_INVALID_ARG;
    }

    cstring* redeem = NULL;
    if (!dogecoin_pqc_carrier_build_redeemscript(&redeem) || !redeem) {
        return DOGECOIN_ZK_ERR_OOM;
    }

    cstring** sigs = (cstring**)dogecoin_calloc(part_total, sizeof(cstring*));
    if (!sigs) {
        cstr_free(redeem, true);
        return DOGECOIN_ZK_ERR_OOM;
    }

    /* For ZK carriers we don't carry a separate "public key" the way PQC
     * does; we reuse the pk_len/full_len fields of the PQC header to mean
     * (public_inputs_len, payload_len) so an SPV parser can find the public
     * inputs slice without re-decoding the embedded ZKP1 magic.  Decoding
     * the payload is the canonical way; the header values are advisory. */
    dogecoin_zk_mode_t hdr_mode;
    uint32_t hdr_circ;
    const uint8_t* hdr_pi = NULL;
    size_t hdr_pi_len = 0;
    const uint8_t* hdr_proof = NULL;
    size_t hdr_proof_len = 0;
    uint16_t advisory_pl = 0;
    if (dogecoin_zk_decode_payload(payload, payload_len, &hdr_mode, &hdr_circ,
                                   &hdr_pi, &hdr_pi_len, &hdr_proof, &hdr_proof_len) == DOGECOIN_ZK_OK) {
        advisory_pl = (uint16_t)(hdr_pi_len > 0xFFFFu ? 0xFFFFu : hdr_pi_len);
    }
    /* If full payload exceeds 16-bit "full_len" advisory field, fall back to
     * the truncated value 0xFFFF — SPV consumers must rely on the embedded
     * ZKP1 length fields, which are 32-bit. */
    uint16_t advisory_full = (uint16_t)(payload_len > 0xFFFFu ? 0xFFFFu : payload_len);

    for (uint8_t i = 0; i < part_total; i++) {
        size_t off = (size_t)i * ZK_PART_PAYLOAD_MAX;
        size_t len = payload_len - off;
        if (len > ZK_PART_PAYLOAD_MAX) len = ZK_PART_PAYLOAD_MAX;
        cstring* ss = NULL;
        if (!dogecoin_pqc_carrier_build_part_scriptsig(
                DOGECOIN_ZK_CARRIER_TAG8, i, part_total,
                advisory_pl, advisory_full,
                payload + off, len, redeem, &ss) || !ss) {
            for (uint8_t k = 0; k < i; k++) {
                if (sigs[k]) cstr_free(sigs[k], true);
            }
            dogecoin_free(sigs);
            cstr_free(redeem, true);
            return DOGECOIN_ZK_ERR_OOM;
        }
        sigs[i] = ss;
    }

    cstr_free(redeem, true);
    *out_scriptsigs = sigs;
    *out_part_total = part_total;
    return DOGECOIN_ZK_OK;
}

dogecoin_zk_err_t dogecoin_zk_extract_carrier_payload(
    const dogecoin_tx* tx_r,
    uint8_t** out_payload,
    size_t* out_payload_len)
{
    if (!tx_r || !out_payload || !out_payload_len) return DOGECOIN_ZK_ERR_INVALID_ARG;
    *out_payload = NULL;
    *out_payload_len = 0;

    /* Walk every input, find the ZK-tagged carrier parts, reassemble. */
    if (!tx_r->vin) return DOGECOIN_ZK_ERR_INVALID_ARG;

    uint8_t expected_total = 0;
    uint16_t advisory_full = 0;
    uint8_t** part_bufs = NULL;
    size_t* part_lens = NULL;
    int seen_any = 0;

    for (size_t vin = 0; vin < tx_r->vin->len; vin++) {
        dogecoin_tx_in* in = (dogecoin_tx_in*)vector_idx(tx_r->vin, vin);
        if (!in || !in->script_sig || in->script_sig->len < 20) continue;

        char tag8[DOGECOIN_PQC_CARRIER_TAG_LEN + 1];
        uint8_t pi = 0, pt = 0;
        uint16_t pk_len = 0, full_len = 0;
        uint8_t* part_data = NULL;
        size_t part_data_len = 0;
        cstring* redeem = NULL;
        if (!dogecoin_pqc_carrier_parse_part_scriptsig(in->script_sig, tag8, &pi, &pt,
                                                       &pk_len, &full_len,
                                                       &part_data, &part_data_len, &redeem)) {
            continue;
        }
        if (memcmp(tag8, DOGECOIN_ZK_CARRIER_TAG8, DOGECOIN_PQC_CARRIER_TAG_LEN) != 0 ||
            pt == 0 || pi >= pt) {
            if (part_data) dogecoin_free(part_data);
            if (redeem) cstr_free(redeem, true);
            continue;
        }

        if (!seen_any) {
            expected_total = pt;
            advisory_full = full_len;
            part_bufs = (uint8_t**)dogecoin_calloc(expected_total, sizeof(uint8_t*));
            part_lens = (size_t*)dogecoin_calloc(expected_total, sizeof(size_t));
            if (!part_bufs || !part_lens) {
                if (part_bufs) dogecoin_free(part_bufs);
                if (part_lens) dogecoin_free(part_lens);
                if (redeem) cstr_free(redeem, true);
                dogecoin_free(part_data);
                return DOGECOIN_ZK_ERR_OOM;
            }
            seen_any = 1;
        }

        if (pt != expected_total) {
            if (redeem) cstr_free(redeem, true);
            dogecoin_free(part_data);
            continue;
        }
        if (part_bufs[pi]) {
            /* Duplicate part — keep the first. */
            if (redeem) cstr_free(redeem, true);
            dogecoin_free(part_data);
            continue;
        }
        part_bufs[pi] = part_data;
        part_lens[pi] = part_data_len;
        if (redeem) cstr_free(redeem, true);
    }

    if (!seen_any) return DOGECOIN_ZK_ERR_TRUNCATED;

    /* Verify all parts present, sum lengths. */
    size_t total = 0;
    for (uint8_t i = 0; i < expected_total; i++) {
        if (!part_bufs[i]) {
            for (uint8_t k = 0; k < expected_total; k++) {
                if (part_bufs[k]) dogecoin_free(part_bufs[k]);
            }
            dogecoin_free(part_bufs);
            dogecoin_free(part_lens);
            return DOGECOIN_ZK_ERR_TRUNCATED;
        }
        total += part_lens[i];
    }

    /* Cross-check advisory_full when it isn't the saturated sentinel. */
    if (advisory_full != 0xFFFFu && advisory_full != (uint16_t)total) {
        for (uint8_t k = 0; k < expected_total; k++) {
            if (part_bufs[k]) dogecoin_free(part_bufs[k]);
        }
        dogecoin_free(part_bufs);
        dogecoin_free(part_lens);
        return DOGECOIN_ZK_ERR_TRUNCATED;
    }

    uint8_t* out = (uint8_t*)dogecoin_malloc(total);
    if (!out) {
        for (uint8_t k = 0; k < expected_total; k++) {
            if (part_bufs[k]) dogecoin_free(part_bufs[k]);
        }
        dogecoin_free(part_bufs);
        dogecoin_free(part_lens);
        return DOGECOIN_ZK_ERR_OOM;
    }
    size_t off = 0;
    for (uint8_t i = 0; i < expected_total; i++) {
        memcpy(out + off, part_bufs[i], part_lens[i]);
        off += part_lens[i];
        dogecoin_free(part_bufs[i]);
    }
    dogecoin_free(part_bufs);
    dogecoin_free(part_lens);

    /* Sanity-check magic so an obvious non-ZK carrier doesn't pass through. */
    if (off < DOGECOIN_ZK_CARRIER_MAGIC_LEN ||
        memcmp(out, DOGECOIN_ZK_CARRIER_MAGIC, DOGECOIN_ZK_CARRIER_MAGIC_LEN) != 0) {
        dogecoin_free(out);
        return DOGECOIN_ZK_ERR_BAD_MAGIC;
    }

    *out_payload = out;
    *out_payload_len = off;
    return DOGECOIN_ZK_OK;
}

/*
 * Walk a tx's vouts looking for the canonical TX_C OP_RETURN commitment:
 *      0x6a 0x25 "DZKC" <mode-byte> <commitment32>
 * (39-byte scriptPubKey total).  Returns true on the first match and writes
 * the mode + 32-byte commit; false otherwise.  No allocation.
 */
dogecoin_bool dogecoin_tx_extract_zk_commit(
    const dogecoin_tx* tx,
    dogecoin_zk_mode_t* out_mode,
    uint8_t out_commit32[32])
{
    if (!tx || !out_mode || !out_commit32 || !tx->vout) {
        return false;
    }

    /* Total scriptPubKey length is 1 (OP_RETURN) + 1 (push len) + 4 (tag) +
       1 (mode) + 32 (commit) = 39 bytes.  The push length byte equals
       DOGECOIN_ZK_OPRETURN_DATA_LEN (37). */
    const size_t expected_len = 1 + 1 + (size_t)DOGECOIN_ZK_OPRETURN_DATA_LEN;

    for (unsigned i = 0; i < tx->vout->len; ++i) {
        const dogecoin_tx_out* o = (const dogecoin_tx_out*)vector_idx(tx->vout, i);
        if (!o || !o->script_pubkey || o->script_pubkey->len != expected_len) {
            continue;
        }

        const unsigned char* p = (const unsigned char*)o->script_pubkey->str;
        if (p[0] != 0x6a /* OP_RETURN */ ||
            p[1] != (uint8_t)DOGECOIN_ZK_OPRETURN_DATA_LEN ||
            memcmp(p + 2, DOGECOIN_ZK_OPRETURN_TAG, DOGECOIN_ZK_OPRETURN_TAG_LEN) != 0) {
            continue;
        }

        /* Reject unknown modes so a tampered/garbage byte cannot pose as a
         * valid ZK commitment.  Match the same allow-list used by the
         * encoder/decoder (zk_mode_is_known in zk_carrier.c). */
        uint8_t mode_byte = p[2 + DOGECOIN_ZK_OPRETURN_TAG_LEN];
        switch (mode_byte) {
        case DOGECOIN_ZK_MODE_GROTH16:
        case DOGECOIN_ZK_MODE_PLONK:
        case DOGECOIN_ZK_MODE_STARK_S2:
            break;
        default:
            continue;
        }
        *out_mode = (dogecoin_zk_mode_t)mode_byte;
        memcpy(out_commit32, p + 2 + DOGECOIN_ZK_OPRETURN_TAG_LEN + 1, 32);
        return true;
    }
    return false;
}
