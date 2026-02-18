/*

 The MIT License (MIT)

 Copyright (c) 2023-2024 The Dogecoin Foundation

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

#ifndef __LIBDOGECOIN_BIP37_H__
#define __LIBDOGECOIN_BIP37_H__

#include <dogecoin/dogecoin.h>
#include <dogecoin/serialize.h>

struct dogecoin_node_;
typedef dogecoin_bool (*dogecoin_bip37_match_cb)(const uint8_t txid[32], uint32_t pos, void* ctx);

LIBDOGECOIN_BEGIN_DECL

dogecoin_bool dogecoin_bip37_send_filterload(struct dogecoin_node_* node,
                                             const uint8_t* filter,
                                             uint32_t filter_len,
                                             uint32_t nHashFuncs,
                                             uint32_t nTweak,
                                             uint8_t flags);

dogecoin_bool dogecoin_bip37_build_filtered_getdata_payload(const struct const_buffer* inv_payload,
                                                            uint8_t** out_payload,
                                                            uint32_t* out_len,
                                                            uint32_t* item_count);

dogecoin_bool dogecoin_bip37_traverse_merkle_matches(uint32_t nTx,
                                                     const uint8_t* hashes,
                                                     uint32_t hashCount,
                                                     const uint8_t* flags,
                                                     uint32_t flags_len,
                                                     const uint8_t header_merkle[32],
                                                     dogecoin_bip37_match_cb on_match,
                                                     void* match_ctx);

LIBDOGECOIN_END_DECL

#endif /* __LIBDOGECOIN_BIP37_H__ */
