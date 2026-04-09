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

#ifndef __LIBDOGECOIN_PQC_CARRIER_H__
#define __LIBDOGECOIN_PQC_CARRIER_H__

#include <stddef.h>
#include <stdint.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/cstr.h>
#include <dogecoin/tx.h>

LIBDOGECOIN_BEGIN_DECL

#define DOGECOIN_PQC_CARRIER_MAX_CHUNKS 3
#define DOGECOIN_PQC_CARRIER_CHUNK_MAX 520
#define DOGECOIN_PQC_CARRIER_HDR_LEN 8
#define DOGECOIN_PQC_CARRIER_TAG_LEN 8

/**
 * @brief This function builds the OP_DROP-based redeem script
 * used for PQC carrier P2SH outputs.
 *
 * @param out_redeem The pointer to receive the allocated redeem script.
 *
 * @return true if the script was built, false on error.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_pqc_carrier_build_redeemscript(cstring** out_redeem);

/**
 * @brief This function builds a P2SH scriptPubKey
 * (OP_HASH160 <hash160(redeem)> OP_EQUAL) from a redeem script.
 *
 * @param redeem The pointer to the redeem script.
 * @param out_spk The pointer to receive the allocated scriptPubKey.
 *
 * @return true if the scriptPubKey was built, false on error.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_pqc_carrier_build_p2sh_scriptpubkey(const cstring* redeem, cstring** out_spk);

/**
 * @brief This function builds a carrier scriptSig for one
 * part of a multi-part PQC payload.
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
LIBDOGECOIN_API dogecoin_bool dogecoin_pqc_carrier_build_part_scriptsig(
    const char tag8[DOGECOIN_PQC_CARRIER_TAG_LEN],
    uint8_t part_index,
    uint8_t part_total,
    uint16_t pk_len,
    uint16_t full_len,
    const uint8_t* part_data,
    size_t part_data_len,
    const cstring* redeem,
    cstring** out_scriptsig);

/**
 * @brief This function parses a carrier scriptSig to extract
 * the tag, part metadata, and payload.
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
LIBDOGECOIN_API dogecoin_bool dogecoin_pqc_carrier_parse_part_scriptsig(
    const cstring* scriptsig,
    char out_tag8[DOGECOIN_PQC_CARRIER_TAG_LEN + 1],
    uint8_t* out_part_index,
    uint8_t* out_part_total,
    uint16_t* out_pk_len,
    uint16_t* out_full_len,
    uint8_t** out_part_data,
    size_t* out_part_data_len,
    cstring** out_redeem);

/**
 * @brief This function adds carrier P2SH outputs to a
 * transaction for the given number of parts.
 *
 * @param tx The pointer to the transaction to modify.
 * @param carrier_spk The P2SH scriptPubKey for carrier outputs.
 * @param value The value in koinu for each carrier output.
 * @param part_total The number of carrier outputs to add.
 *
 * @return true if outputs were added, false on error.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_tx_add_pqc_carrier_outputs(
    dogecoin_tx* tx,
    const cstring* carrier_spk,
    uint64_t value,
    uint8_t part_total);

LIBDOGECOIN_END_DECL

#endif /* __LIBDOGECOIN_PQC_CARRIER_H__ */
