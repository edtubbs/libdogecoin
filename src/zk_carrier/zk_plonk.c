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
 * PLONK proof system stub.
 *
 * Not implemented in this revision.  When implemented, the recommended
 * path is libsnark's PLONK gadget or a thin C wrapper around an external
 * PLONK verifier (e.g., halo2-style).  The mode byte (DOGECOIN_ZK_MODE_PLONK
 * = 1) is reserved here so on-chain artifacts can be produced today and
 * verified once the verifier ships, mirroring the OP_CHECKZKP modular mode
 * selector.
 */

#include <stddef.h>
#include <stdint.h>

#include <dogecoin/zk_carrier.h>

dogecoin_zk_err_t dogecoin_zk_generate_plonk_proof(
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
    return DOGECOIN_ZK_ERR_NOT_IMPLEMENTED;
}
