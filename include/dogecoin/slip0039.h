/**********************************************************************
 * Copyright (c) 2026 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef __LIBDOGECOIN_SLIP0039_H__
#define __LIBDOGECOIN_SLIP0039_H__

#include <dogecoin/dogecoin.h>

LIBDOGECOIN_BEGIN_DECL

/* SLIP-0039 mnemonic constants.
 * Each share is a space-separated list of words drawn from the official
 * 1024-word SLIP-0039 wordlist. A 256-bit secret produces 33 words per share
 * (max 8 chars/word + space), so 320 chars is a comfortable upper bound
 * including the terminating null. */
#ifndef SLIP0039_DECLS_DEFINED
#define SLIP0039_DECLS_DEFINED
#define SLIP0039_MAX_SHARES 16
#define SLIP0039_MAX_SHARE_STR_SIZE 320
#define SLIP0039_MIN_SECRET_BYTES 16
#define SLIP0039_MAX_SECRET_BYTES 32

typedef char SLIP0039_SHARE[SLIP0039_MAX_SHARE_STR_SIZE];

LIBDOGECOIN_API int dogecoin_slip0039_generate_shares(const uint8_t* secret, size_t secret_len, uint8_t threshold, uint8_t share_count, char shares[][SLIP0039_MAX_SHARE_STR_SIZE]);
LIBDOGECOIN_API int dogecoin_slip0039_recover_secret(const char* shares[], size_t share_count, const uint8_t* passphrase, size_t passphrase_len, uint8_t* secret_out, size_t* secret_len_out);
#endif /* SLIP0039_DECLS_DEFINED */

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_SLIP0039_H__
