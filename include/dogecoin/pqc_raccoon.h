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

#ifndef __LIBDOGECOIN_PQC_RACCOON_H__
#define __LIBDOGECOIN_PQC_RACCOON_H__

#include <stddef.h>
#include <stdint.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/tx.h>

LIBDOGECOIN_BEGIN_DECL

#define DOGECOIN_PQC_RACCOON_TAG        "RCG4"
#define DOGECOIN_PQC_RACCOON_TAG_LEN    4
#define DOGECOIN_PQC_RACCOON_COMMIT_LEN 32
#define DOGECOIN_PQC_RACCOON_PUSH_TOTAL (DOGECOIN_PQC_RACCOON_TAG_LEN + DOGECOIN_PQC_RACCOON_COMMIT_LEN)
#define DOGECOIN_PQC_RACCOON_CHAINCODE_LEN 32

/**
 * @brief This function checks if the Raccoon-G-44 algorithm
 * is available at runtime by probing liboqs.
 *
 * @return true if Raccoon-G-44 is available, false otherwise.
 */
#ifdef USE_LIBOQS_RACCOON
LIBDOGECOIN_API dogecoin_bool dogecoin_raccoong44_is_available(void);

/**
 * @brief This function generates a Raccoon-G-44 keypair
 * via liboqs.
 *
 * @param pk The pointer to receive the allocated public key.
 * @param pk_len The pointer to receive the public key length.
 * @param sk The pointer to receive the allocated secret key.
 * @param sk_len The pointer to receive the secret key length.
 *
 * @return true if the keypair was generated, false on error.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_raccoong44_keypair(uint8_t** pk, size_t* pk_len,
                                                            uint8_t** sk, size_t* sk_len);

/**
 * @brief This function signs a message with a Raccoon-G-44
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
LIBDOGECOIN_API dogecoin_bool dogecoin_raccoong44_sign(const uint8_t* sk, size_t sk_len,
                                                        const uint8_t* msg, size_t msg_len,
                                                        uint8_t** sig, size_t* sig_len);

/**
 * @brief This function verifies a Raccoon-G-44 signature
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
LIBDOGECOIN_API dogecoin_bool dogecoin_raccoong44_verify(const uint8_t* pk, size_t pk_len,
                                                          const uint8_t* msg, size_t msg_len,
                                                          const uint8_t* sig, size_t sig_len);

/**
 * @brief This function computes a 32-byte Raccoon-G-44
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
LIBDOGECOIN_API dogecoin_bool dogecoin_raccoong44_commit_bytes(const uint8_t* pk, size_t pk_len,
                                                                const uint8_t* signature, size_t signature_len,
                                                                uint8_t commit32[DOGECOIN_PQC_RACCOON_COMMIT_LEN]);

/**
 * @brief This function appends an OP_RETURN output carrying
 * the "RCG4" tag and a 32-byte Raccoon-G-44 commitment to a
 * transaction.
 *
 * @param tx The pointer to the transaction to modify.
 * @param commit32 The 32-byte commitment hash.
 *
 * @return true if the output was added, false on invalid input.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_tx_add_raccoong44_commit(dogecoin_tx* tx,
                                                                 const uint8_t commit32[DOGECOIN_PQC_RACCOON_COMMIT_LEN]);

/**
 * @brief This function extracts the first "RCG4" tagged
 * Raccoon-G-44 commitment from a transaction's outputs.
 *
 * @param tx The pointer to the transaction to search.
 * @param out_commit32 The output buffer for the 32-byte commitment.
 *
 * @return true if a commitment was found, false otherwise.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_tx_extract_raccoong44_commit(const dogecoin_tx* tx,
                                                                     uint8_t out_commit32[DOGECOIN_PQC_RACCOON_COMMIT_LEN]);

/**
 * @brief This function derives a child secret and public key
 * from a parent Raccoon-G-44 secret key using BIP32-style
 * hardened or non-hardened derivation.
 *
 * @param parent_sk The pointer to the parent secret key.
 * @param parent_sk_len The length of the parent secret key.
 * @param chaincode The 32-byte chaincode.
 * @param index The child index.
 * @param hardened Whether to use hardened derivation.
 * @param child_sk The pointer to receive the allocated child secret key.
 * @param child_sk_len The pointer to receive the child secret key length.
 * @param child_pk The pointer to receive the allocated child public key.
 * @param child_pk_len The pointer to receive the child public key length.
 *
 * @return true if derivation succeeded, false on error.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_raccoong44_hd_derive_priv(const uint8_t* parent_sk, size_t parent_sk_len,
                                                                  const uint8_t chaincode[DOGECOIN_PQC_RACCOON_CHAINCODE_LEN],
                                                                  uint32_t index, dogecoin_bool hardened,
                                                                  uint8_t** child_sk, size_t* child_sk_len,
                                                                  uint8_t** child_pk, size_t* child_pk_len);

/**
 * @brief This function derives a child public key from a
 * parent Raccoon-G-44 public key using non-hardened
 * derivation.
 *
 * @param parent_pk The pointer to the parent public key.
 * @param parent_pk_len The length of the parent public key.
 * @param chaincode The 32-byte chaincode.
 * @param index The child index (must not have bit 31 set).
 * @param child_pk The pointer to receive the allocated child public key.
 * @param child_pk_len The pointer to receive the child public key length.
 *
 * @return true if derivation succeeded, false on error.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_raccoong44_hd_derive_pub(const uint8_t* parent_pk, size_t parent_pk_len,
                                                                 const uint8_t chaincode[DOGECOIN_PQC_RACCOON_CHAINCODE_LEN],
                                                                 uint32_t index,
                                                                 uint8_t** child_pk, size_t* child_pk_len);
#endif

LIBDOGECOIN_END_DECL

#endif /* __LIBDOGECOIN_PQC_RACCOON_H__ */
