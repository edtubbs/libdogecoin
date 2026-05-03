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

#ifndef __LIBDOGECOIN_ZK_CARRIER_H__
#define __LIBDOGECOIN_ZK_CARRIER_H__

#include <stddef.h>
#include <stdint.h>

#include <dogecoin/cstr.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/tx.h>

LIBDOGECOIN_BEGIN_DECL

/*
 * ZK carrier — extends the PQ carrier pattern (src/pqc_carrier.c) so that
 * succinct zero-knowledge proofs (Groth16 today, PLONK/STARK in future) can
 * be committed and revealed on the Dogecoin chain using exactly the same
 * TX_C (commitment) + TX_R (reveal) flow.
 *
 * On-wire payload (TX_R reveal) layout, big-endian where multi-byte:
 *
 *    +---------+----+----+--------+----+------------+----+---------+----+--------+
 *    | "ZKP1"  | mo | vr | circID | pl | public[pl] | xl | proof[xl]| kl | vk[kl]|
 *    +---------+----+----+--------+----+------------+----+---------+----+--------+
 *      4 bytes  1B   1B    4B      2B    pl bytes     4B   xl bytes  4B   kl bytes
 *
 *   magic   : ASCII "ZKP1" (DOGECOIN_ZK_CARRIER_MAGIC)
 *   mode    : dogecoin_zk_mode_t selector (1B), aligned with the modular
 *             mode selector of the proposed OP_CHECKZKP opcode (185).
 *   version : 1B payload-format version.  0x00 = legacy (no embedded vk; vk
 *             distributed out-of-band).  0x01 = vk-included; the verification
 *             key bytes follow the proof so the reveal is fully self-contained
 *             for on-chain verification (no external file required).
 *   circID  : 4B big-endian application-defined circuit identifier.
 *   pl      : 2B big-endian length of public-input blob.
 *   public  : public-input bytes (proof-system specific encoding).
 *   xl      : 4B big-endian length of the proof bytes.
 *   proof   : proof bytes (proof-system specific encoding).
 *   kl      : 4B big-endian length of the embedded verification-key bytes.
 *             Present only when version == 0x01.  When version == 0x00 the
 *             trailing kl/vk fields are absent and the payload ends at proof.
 *   vk      : verification-key bytes (proof-system specific encoding;
 *             snarkjs verification_key.json for Groth16/PLONK).
 *
 * TX_C commits SHA256d(payload) inside an OP_RETURN of the form
 *      OP_RETURN <"DZKC"> <mode> <commitment32>
 * (40 bytes total — well below standardness).  TX_R reveals the same payload
 * through P2SH-carrier inputs chunked exactly like PQC carriers (the helpers
 * in pqc_carrier.c are reused; only the 8-byte tag changes to "ZKP1FULL").
 *
 * The C library only verifies and packages.  Proof generation lives outside
 * the library (snarkjs/circom client-side, or rapidsnark CLI on a host) so
 * libdogecoin stays mobile-friendly with no heavy runtime dependencies.
 */

#define DOGECOIN_ZK_CARRIER_MAGIC      "ZKP1"
#define DOGECOIN_ZK_CARRIER_MAGIC_LEN  4
#define DOGECOIN_ZK_CARRIER_TAG8       "ZKP1FULL"
#define DOGECOIN_ZK_CARRIER_HDR_FIXED  (DOGECOIN_ZK_CARRIER_MAGIC_LEN + 1 + 1 + 4 + 2)
#define DOGECOIN_ZK_OPRETURN_TAG       "DZKC"
#define DOGECOIN_ZK_OPRETURN_TAG_LEN   4
/* OP_RETURN <DZKC><mode><commit32> = 38 data bytes — fits in a single push. */
#define DOGECOIN_ZK_OPRETURN_DATA_LEN  (DOGECOIN_ZK_OPRETURN_TAG_LEN + 1 + 32)

/* Wire-format version byte (the 6th byte of the ZKP1 payload, immediately
 * after the mode byte).  v0 is the legacy "vk distributed out-of-band" layout;
 * v1 appends a 4-byte big-endian vk length and the vk bytes after the proof
 * section so the reveal is fully self-contained for on-chain verification. */
#define DOGECOIN_ZK_PAYLOAD_VERSION_V0 0x00
#define DOGECOIN_ZK_PAYLOAD_VERSION_V1 0x01

/* Selectable proof systems.  Stable numeric values — these are what would be
 * pushed onto the script stack as the OP_CHECKZKP mode argument. */
typedef enum {
    DOGECOIN_ZK_MODE_GROTH16  = 0,
    DOGECOIN_ZK_MODE_PLONK    = 1,
    DOGECOIN_ZK_MODE_STARK_S2 = 2  /* placeholder for future S-two STARK */
} dogecoin_zk_mode_t;

typedef enum {
    DOGECOIN_ZK_OK                = 0,
    DOGECOIN_ZK_ERR_INVALID_ARG   = -1,
    DOGECOIN_ZK_ERR_BAD_MAGIC     = -2,
    DOGECOIN_ZK_ERR_BAD_MODE      = -3,
    DOGECOIN_ZK_ERR_TRUNCATED     = -4,
    DOGECOIN_ZK_ERR_OOM           = -5,
    DOGECOIN_ZK_ERR_NOT_IMPLEMENTED = -6, /* PLONK / STARK / disabled prover  */
    DOGECOIN_ZK_ERR_DELEGATED     = -7,   /* prover lives outside libdogecoin */
    DOGECOIN_ZK_ERR_VERIFY_FAIL   = -8
} dogecoin_zk_err_t;

/*
 * Encode a proof + public inputs (and optional verification key) into the
 * canonical ZK carrier payload above.  When `vk_bytes` is NULL or `vk_len`
 * is zero the encoder emits a v0 (no-vk) payload; otherwise it emits a v1
 * payload with the verification-key bytes appended after the proof so the
 * reveal is fully self-contained for on-chain validation.  Caller frees
 * *out_payload with dogecoin_free().
 */
LIBDOGECOIN_API dogecoin_zk_err_t dogecoin_zk_encode_payload(
    dogecoin_zk_mode_t mode,
    uint32_t circuit_id,
    const uint8_t* public_inputs,
    size_t public_inputs_len,
    const uint8_t* proof,
    size_t proof_len,
    const uint8_t* vk_bytes,
    size_t vk_len,
    uint8_t** out_payload,
    size_t* out_payload_len);

/*
 * Decode a canonical ZK carrier payload.  All out_* pointers are aliased into
 * the input buffer (no allocation).  The caller must keep `payload` alive
 * while using the decoded fields.  When the payload is v0 (no embedded vk),
 * *out_vk is set to NULL and *out_vk_len to 0.  When the payload is v1,
 * *out_vk aliases the embedded vk bytes.  Pass NULL for out_vk / out_vk_len
 * if the caller does not care about the vk slot (legacy callers).
 */
LIBDOGECOIN_API dogecoin_zk_err_t dogecoin_zk_decode_payload(
    const uint8_t* payload,
    size_t payload_len,
    dogecoin_zk_mode_t* out_mode,
    uint32_t* out_circuit_id,
    const uint8_t** out_public_inputs,
    size_t* out_public_inputs_len,
    const uint8_t** out_proof,
    size_t* out_proof_len,
    const uint8_t** out_vk,
    size_t* out_vk_len);

/*
 * Compute the TX_C commitment value: SHA256d(payload).  This is the 32-byte
 * digest embedded in the OP_RETURN of TX_C.
 */
LIBDOGECOIN_API dogecoin_zk_err_t dogecoin_zk_get_commitment_hash(
    const uint8_t* payload,
    size_t payload_len,
    uint8_t out_commitment[32]);

/*
 * Build the OP_RETURN scriptPubKey for TX_C: OP_RETURN <DZKC><mode><commit32>.
 * Caller frees *out_spk with cstr_free(..., true).
 */
LIBDOGECOIN_API dogecoin_zk_err_t dogecoin_zk_build_opreturn_scriptpubkey(
    dogecoin_zk_mode_t mode,
    const uint8_t commitment[32],
    cstring** out_spk);

/*
 * Append the OP_RETURN commit output and the P2SH carrier outputs (one per
 * required reveal-part) to an existing in-progress transaction.  Mirrors
 * dogecoin_tx_add_*_commit + dogecoin_tx_add_pqc_carrier_outputs in one call.
 *
 * `payload` is the payload that will later be revealed in TX_R.  The number
 * of carrier outputs is derived from its length using the PQC chunking
 * constants.  `carrier_value` is the per-output value in koinu (>= dust).
 *
 * On success, *out_carrier_spk is the P2SH scriptPubKey of the carrier
 * outputs (caller frees with cstr_free(..., true)) and *out_part_total is
 * the number of parts that TX_R will need to spend.
 */
LIBDOGECOIN_API dogecoin_zk_err_t dogecoin_zk_build_carrier_tx_c(
    dogecoin_tx* tx,
    const uint8_t* payload,
    size_t payload_len,
    dogecoin_zk_mode_t mode,
    uint64_t carrier_value,
    cstring** out_carrier_spk,
    uint8_t* out_part_total);

/*
 * Build the per-part scriptSigs for TX_R.  `out_scriptsigs` is allocated
 * with dogecoin_calloc()-equivalent and contains `*out_part_total` cstrings;
 * caller frees each with cstr_free(..., true) and the array itself with
 * dogecoin_free().
 */
LIBDOGECOIN_API dogecoin_zk_err_t dogecoin_zk_build_carrier_tx_r_scriptsigs(
    const uint8_t* payload,
    size_t payload_len,
    cstring*** out_scriptsigs,
    uint8_t* out_part_total);

/*
 * Extract a previously-revealed payload from a TX_R by walking its inputs and
 * reassembling the carrier parts.  Caller frees *out_payload with
 * dogecoin_free().
 */
LIBDOGECOIN_API dogecoin_zk_err_t dogecoin_zk_extract_carrier_payload(
    const dogecoin_tx* tx_r,
    uint8_t** out_payload,
    size_t* out_payload_len);

/*
 * Walk a transaction's outputs looking for the canonical TX_C OP_RETURN
 * commitment script:
 *      OP_RETURN <push 37> "DZKC" <mode-byte> <commitment32>
 * On the first match, write the mode and 32-byte commitment to the out
 * parameters and return true.  Mirrors dogecoin_tx_extract_falcon512_commit
 * (src/pqc_falcon.c) so the SPV layer can detect ZK commitments alongside
 * Falcon/Dilithium/Raccoon ones.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_tx_extract_zk_commit(
    const dogecoin_tx* tx,
    dogecoin_zk_mode_t* out_mode,
    uint8_t out_commit32[32]);

/*
 * Verify a Groth16 proof.  If libdogecoin was built with --with-rapidsnark
 * (HAVE_RAPIDSNARK is defined) this calls into the rapidsnark verifier.
 * Otherwise it returns DOGECOIN_ZK_ERR_NOT_IMPLEMENTED so callers can fall
 * back to off-box verification.  `vk_json` is the snarkjs-style verification
 * key (bytes are JSON-encoded); `public_json` is the snarkjs `public.json`.
 */
LIBDOGECOIN_API dogecoin_zk_err_t dogecoin_zk_verify_groth16(
    const uint8_t* vk_json,
    size_t vk_json_len,
    const uint8_t* public_json,
    size_t public_json_len,
    const uint8_t* proof_json,
    size_t proof_json_len);

/*
 * Verify any ZK payload by mode.  Dispatches to the proof-system specific
 * verifier above.  The payload's public inputs and proof bytes are passed
 * verbatim to the verifier (proof systems are responsible for their own
 * encoding — for snarkjs/Groth16 they are JSON).  When the payload itself
 * carries an embedded verification key (v1 layout) it is preferred over the
 * caller-supplied `vk_blob`; the externally-supplied vk is only used as a
 * fallback for legacy v0 payloads.  `vk_blob` may be NULL/0 when the payload
 * is v1, which is the recommended self-contained-reveal flow.
 */
LIBDOGECOIN_API dogecoin_zk_err_t dogecoin_zk_verify_proof(
    const uint8_t* payload,
    size_t payload_len,
    const uint8_t* vk_blob,
    size_t vk_blob_len);

/*
 * Proof generation API — kept here for surface-area completeness and to
 * line up with the OP_CHECKZKP proposal terminology.  Always returns
 * DOGECOIN_ZK_ERR_DELEGATED in this build because libdogecoin's policy is
 * that proving lives in the wallet/UI (snarkjs) or in a host-side rapidsnark
 * CLI.  The contrib helper `contrib/zk_carrier/witness_helper.py`
 * is the supported way to drive it.
 */
LIBDOGECOIN_API dogecoin_zk_err_t dogecoin_zk_generate_groth16_proof(
    const uint8_t* witness_json,
    size_t witness_json_len,
    const char* circuit_path,
    uint8_t** out_proof,
    size_t* out_proof_len,
    uint8_t** out_public,
    size_t* out_public_len);

LIBDOGECOIN_API dogecoin_zk_err_t dogecoin_zk_generate_plonk_proof(
    const uint8_t* witness_json,
    size_t witness_json_len,
    const char* circuit_path,
    uint8_t** out_proof,
    size_t* out_proof_len,
    uint8_t** out_public,
    size_t* out_public_len);

/* Human-readable error string. Never returns NULL. */
LIBDOGECOIN_API const char* dogecoin_zk_strerror(dogecoin_zk_err_t err);

LIBDOGECOIN_END_DECL

#endif /* __LIBDOGECOIN_ZK_CARRIER_H__ */
