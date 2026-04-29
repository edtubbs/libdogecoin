/**********************************************************************
 * Copyright (c) 2026 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <test/utest.h>

#include <dogecoin/mem.h>
#include <dogecoin/slip0039.h>
#include <dogecoin/utils.h>

#include <stdint.h>
#include <string.h>

/* Simple sanity check that a string contains only [a-z ] characters and at
 * least one space, i.e. looks like a SLIP-0039 mnemonic phrase. */
static int looks_like_mnemonic(const char* s)
{
    int spaces = 0;
    if (!s || !*s) return 0;
    for (const char* p = s; *p; ++p) {
        if (*p == ' ') { ++spaces; continue; }
        if (*p < 'a' || *p > 'z') return 0;
    }
    return spaces >= 19; /* min 20 words for a 128-bit secret = 19 spaces */
}

void test_slip0039()
{
    /* SLIP-0039 requires a master secret of at least 128 bits and a
     * multiple of 16 bits. Use a 16-byte fixture. */
    const uint8_t secret[16] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01
    };

    SLIP0039_SHARE shares[SLIP0039_MAX_SHARES];
    dogecoin_mem_zero(shares, sizeof(shares));

    /* Generate 3-of-5 shares. */
    u_assert_int_eq(dogecoin_slip0039_generate_shares(secret, sizeof(secret), 3, 5, shares), 0);
    for (int i = 0; i < 5; ++i) {
        u_assert_int_eq(looks_like_mnemonic(shares[i]), 1);
    }
    /* Recovery from any 3 distinct shares should work. */
    const char* set_a[] = { shares[0], shares[2], shares[4] };
    uint8_t recovered[32];
    size_t recovered_len = sizeof(recovered);
    dogecoin_mem_zero(recovered, sizeof(recovered));
    u_assert_int_eq(dogecoin_slip0039_recover_secret(set_a, 3, recovered, &recovered_len), 0);
    u_assert_uint64_eq(recovered_len, sizeof(secret));
    u_assert_mem_eq(recovered, secret, sizeof(secret));

    const char* set_b[] = { shares[1], shares[3], shares[4] };
    recovered_len = sizeof(recovered);
    dogecoin_mem_zero(recovered, sizeof(recovered));
    u_assert_int_eq(dogecoin_slip0039_recover_secret(set_b, 3, recovered, &recovered_len), 0);
    u_assert_mem_eq(recovered, secret, sizeof(secret));

    /* Insufficient shares (below threshold) must fail. */
    const char* set_short[] = { shares[0], shares[1] };
    recovered_len = sizeof(recovered);
    u_assert_int_eq(dogecoin_slip0039_recover_secret(set_short, 2, recovered, &recovered_len), -1);

    /* Duplicate share index must fail. */
    const char* set_dup[] = { shares[1], shares[1], shares[2] };
    recovered_len = sizeof(recovered);
    u_assert_int_eq(dogecoin_slip0039_recover_secret(set_dup, 3, recovered, &recovered_len), -1);

    /* Tampering with any character of a mnemonic must fail RS1024 checksum
     * (or fall back to a wrong word that fails decode/digest verification). */
    char tampered[SLIP0039_MAX_SHARE_STR_SIZE];
    strncpy(tampered, shares[0], sizeof(tampered) - 1);
    tampered[sizeof(tampered) - 1] = '\0';
    /* Find the first letter and bump it within [a-z]. */
    for (size_t i = 0; tampered[i]; ++i) {
        if (tampered[i] >= 'a' && tampered[i] <= 'z') {
            tampered[i] = (tampered[i] == 'z') ? 'a' : (char)(tampered[i] + 1);
            break;
        }
    }
    const char* set_bad[] = { tampered, shares[2], shares[4] };
    recovered_len = sizeof(recovered);
    u_assert_int_eq(dogecoin_slip0039_recover_secret(set_bad, 3, recovered, &recovered_len), -1);

    /* Output buffer too small must fail. */
    recovered_len = 4;
    u_assert_int_eq(dogecoin_slip0039_recover_secret(set_a, 3, recovered, &recovered_len), -1);

    /* threshold = 1 (single share equals secret) round-trip works for 1-of-1. */
    SLIP0039_SHARE single[1];
    dogecoin_mem_zero(single, sizeof(single));
    u_assert_int_eq(dogecoin_slip0039_generate_shares(secret, sizeof(secret), 1, 1, single), 0);
    const char* set_one[] = { single[0] };
    recovered_len = sizeof(recovered);
    dogecoin_mem_zero(recovered, sizeof(recovered));
    u_assert_int_eq(dogecoin_slip0039_recover_secret(set_one, 1, recovered, &recovered_len), 0);
    u_assert_uint64_eq(recovered_len, sizeof(secret));
    u_assert_mem_eq(recovered, secret, sizeof(secret));

    /* 32-byte (256-bit) secret round-trip with 2-of-3 shares. */
    uint8_t big_secret[32];
    for (size_t i = 0; i < sizeof(big_secret); ++i) big_secret[i] = (uint8_t)(0xA5 ^ i);
    SLIP0039_SHARE big_shares[3];
    dogecoin_mem_zero(big_shares, sizeof(big_shares));
    u_assert_int_eq(dogecoin_slip0039_generate_shares(big_secret, sizeof(big_secret), 2, 3, big_shares), 0);
    const char* big_set[] = { big_shares[0], big_shares[2] };
    uint8_t big_rec[32];
    size_t  big_len = sizeof(big_rec);
    u_assert_int_eq(dogecoin_slip0039_recover_secret(big_set, 2, big_rec, &big_len), 0);
    u_assert_uint64_eq(big_len, sizeof(big_secret));
    u_assert_mem_eq(big_rec, big_secret, sizeof(big_secret));

    /* Reject secrets that are too short or odd-length. */
    SLIP0039_SHARE bad[3];
    dogecoin_mem_zero(bad, sizeof(bad));
    uint8_t short_secret[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    u_assert_int_eq(dogecoin_slip0039_generate_shares(short_secret, sizeof(short_secret), 2, 3, bad), -1);
    uint8_t odd_secret[17] = { 0 };
    u_assert_int_eq(dogecoin_slip0039_generate_shares(odd_secret, sizeof(odd_secret), 2, 3, bad), -1);
}
