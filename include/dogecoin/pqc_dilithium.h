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

#ifndef __LIBDOGECOIN_PQC_DILITHIUM_H__
#define __LIBDOGECOIN_PQC_DILITHIUM_H__

#include <stddef.h>
#include <stdint.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/cstr.h>
#include <dogecoin/tx.h>

LIBDOGECOIN_BEGIN_DECL

#define DOGECOIN_PQC_DILITHIUM_TAG        "DIL2"
#define DOGECOIN_PQC_DILITHIUM_TAG_LEN    4
#define DOGECOIN_PQC_DILITHIUM_COMMIT_LEN 32
#define DOGECOIN_PQC_DILITHIUM_PUSH_TOTAL (DOGECOIN_PQC_DILITHIUM_TAG_LEN + DOGECOIN_PQC_DILITHIUM_COMMIT_LEN)

/**
 * @brief This function generates a Dilithium2 (ML-DSA-44
 * compatible) keypair via liboqs.
 *
 * @param pk The pointer to receive the allocated public key.
 * @param pk_len The pointer to receive the public key length.
 * @param sk The pointer to receive the allocated secret key.
 * @param sk_len The pointer to receive the secret key length.
 *
 * @return true if the keypair was generated, false on error.
 */
#ifdef USE_LIBOQS
LIBDOGECOIN_API dogecoin_bool dogecoin_dilithium2_keypair(uint8_t** pk, size_t* pk_len,
                                                           uint8_t** sk, size_t* sk_len);

/**
 * @brief This function signs a message with a Dilithium2
 * secret key.
 *
 * @param sk The pointer to the secret key.
 * @param sk_len The length of the secret key.
 * @param msg The pointer to the message to sign.
 * @param msg_len The length of the message.
 * @param sig The pointer to receive the allocated signature.
 * @param sig_len The pointer to receive the signature length.
 *
 * @return true if signing succeeded, false on error.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_dilithium2_sign(const uint8_t* sk, size_t sk_len,
                                                        const uint8_t* msg, size_t msg_len,
                                                        uint8_t** sig, size_t* sig_len);

/**
 * @brief This function verifies a Dilithium2 signature
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
LIBDOGECOIN_API dogecoin_bool dogecoin_dilithium2_verify(const uint8_t* pk, size_t pk_len,
                                                          const uint8_t* msg, size_t msg_len,
                                                          const uint8_t* sig, size_t sig_len);

/**
 * @brief This function computes a 32-byte Dilithium2
 * commitment as SHA256(pk || sig).
 *
 * @param pk The pointer to the public key bytes.
 * @param pk_len The length of the public key.
 * @param signature The pointer to the signature bytes.
 * @param signature_len The length of the signature.
 * @param commit32 The output buffer for the 32-byte commitment.
 *
 * @return true if the commitment was computed, false on invalid input.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_dilithium2_commit_bytes(const uint8_t* pk, size_t pk_len,
                                                                const uint8_t* signature, size_t signature_len,
                                                                uint8_t commit32[DOGECOIN_PQC_DILITHIUM_COMMIT_LEN]);

/**
 * @brief This function appends an OP_RETURN output carrying
 * the "DIL2" tag and a 32-byte Dilithium2 commitment to a
 * transaction.
 *
 * @param tx The pointer to the transaction to modify.
 * @param commit32 The 32-byte commitment hash.
 *
 * @return true if the output was added, false on invalid input.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_tx_add_dilithium2_commit(dogecoin_tx* tx,
                                                                 const uint8_t commit32[DOGECOIN_PQC_DILITHIUM_COMMIT_LEN]);

/**
 * @brief This function extracts the first "DIL2" tagged
 * Dilithium2 commitment from a transaction's outputs.
 *
 * @param tx The pointer to the transaction to search.
 * @param out_commit32 The output buffer for the 32-byte commitment.
 *
 * @return true if a commitment was found, false otherwise.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_tx_extract_dilithium2_commit(const dogecoin_tx* tx,
                                                                     uint8_t out_commit32[DOGECOIN_PQC_DILITHIUM_COMMIT_LEN]);
#endif

LIBDOGECOIN_END_DECL

#endif /* __LIBDOGECOIN_PQC_DILITHIUM_H__ */
