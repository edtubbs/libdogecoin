/*
 The MIT License (MIT)

 Copyright (c) 2026 edtubbs
 Copyright (c) 2026 The Dogecoin Foundation
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

LIBDOGECOIN_API dogecoin_bool dogecoin_pqc_carrier_build_redeemscript(cstring** out_redeem);
LIBDOGECOIN_API dogecoin_bool dogecoin_pqc_carrier_build_p2sh_scriptpubkey(const cstring* redeem, cstring** out_spk);
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

LIBDOGECOIN_API dogecoin_bool dogecoin_tx_add_pqc_carrier_outputs(
    dogecoin_tx* tx,
    const cstring* carrier_spk,
    uint64_t value,
    uint8_t part_total);

LIBDOGECOIN_END_DECL

#endif
