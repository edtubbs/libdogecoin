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
 * Raccoon-G-44 in-tree backend — public-shape glue.
 *
 * This file routes the libdogecoin Raccoon-G-44 API (defined in
 * include/dogecoin/pqc_raccoon.h) into the staged in-tree implementation
 * (polyr -> ntt -> gaussian -> thrc). It is built only when --enable-raccoon-g
 * is passed.
 *
 * The public libdogecoin API is unchanged: pqc_raccoon.c continues to expose
 * dogecoin_raccoong44_keypair / _sign / _verify / _hd_derive_*. This file
 * supplies the backend those entry points call into.
 *
 * raccoong_is_ready() returns false in this skeleton commit; the libdogecoin
 * API surface honours that and returns false on every call. The flag flips to
 * true only when Sessions 3-7 land and the committed KATs pass.
 */

#include "raccoong.h"

#include "thrc.h"

dogecoin_bool raccoong_is_ready(void)
{
    /* The implementation is staged. Until Sessions 3-7 land and the upstream
     * KATs pass byte-exactly, this function returns false and every public
     * Raccoon-G-44 entry point routed through it must short-circuit. */
    return false;
}

size_t raccoong_pk_len(void)      { return 0; }
size_t raccoong_sk_len(void)      { return 0; }
size_t raccoong_sig_max_len(void) { return 0; }

dogecoin_bool raccoong_keygen_from_seed(const uint8_t seed[32],
                                        uint8_t* pk_out, size_t pk_len,
                                        uint8_t* sk_out, size_t sk_len)
{
    return thrc_keygen_from_seed(seed, pk_out, pk_len, sk_out, sk_len);
}

dogecoin_bool raccoong_sign(const uint8_t* sk, size_t sk_len,
                            const uint8_t* msg, size_t msg_len,
                            uint8_t* sig_out, size_t* sig_len_inout)
{
    return thrc_sign(sk, sk_len, msg, msg_len, sig_out, sig_len_inout);
}

dogecoin_bool raccoong_verify(const uint8_t* pk, size_t pk_len,
                              const uint8_t* msg, size_t msg_len,
                              const uint8_t* sig, size_t sig_len)
{
    return thrc_verify(pk, pk_len, msg, msg_len, sig, sig_len);
}

dogecoin_bool raccoong_hd_derive_priv(const uint8_t* parent_sk, size_t parent_sk_len,
                                      const uint8_t* parent_pk, size_t parent_pk_len,
                                      const uint8_t chaincode[32],
                                      uint32_t index, dogecoin_bool hardened,
                                      uint8_t* child_sk_out, size_t child_sk_len,
                                      uint8_t* child_pk_out, size_t child_pk_len)
{
    return thrc_hd_derive_priv(parent_sk, parent_sk_len, parent_pk, parent_pk_len,
                               chaincode, index, hardened,
                               child_sk_out, child_sk_len,
                               child_pk_out, child_pk_len);
}

dogecoin_bool raccoong_hd_derive_pub(const uint8_t* parent_pk, size_t parent_pk_len,
                                     const uint8_t chaincode[32],
                                     uint32_t index,
                                     uint8_t* child_pk_out, size_t child_pk_len)
{
    return thrc_hd_derive_pub(parent_pk, parent_pk_len, chaincode, index,
                              child_pk_out, child_pk_len);
}
