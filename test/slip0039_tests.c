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

void test_slip0039()
{
    const uint8_t secret[] = {
        0x10, 0x20, 0x30, 0x40,
        0x50, 0x60, 0x70, 0x80
    };
    SLIP0039_SHARE shares[SLIP0039_MAX_SHARES];
    dogecoin_mem_zero(shares, sizeof(shares));

    u_assert_int_eq(dogecoin_slip0039_generate_shares(secret, sizeof(secret), 2, 3, shares), 0);
    u_assert_str_has(shares[0], "slip0039:1:1:2:3:");
    u_assert_str_has(shares[1], "slip0039:1:2:2:3:");
    u_assert_str_has(shares[2], "slip0039:1:3:2:3:");

    const char* recovery_set[] = { shares[0], shares[2] };
    uint8_t recovered[MAX_SEED_SIZE];
    size_t recovered_len = sizeof(recovered);
    dogecoin_mem_zero(recovered, sizeof(recovered));
    u_assert_int_eq(dogecoin_slip0039_recover_secret(recovery_set, 2, recovered, &recovered_len), 0);
    u_assert_uint64_eq(recovered_len, sizeof(secret));
    u_assert_mem_eq(recovered, secret, sizeof(secret));

    const char* insufficient_set[] = { shares[1] };
    recovered_len = sizeof(recovered);
    u_assert_int_eq(dogecoin_slip0039_recover_secret(insufficient_set, 1, recovered, &recovered_len), -1);

    const char* duplicate_set[] = { shares[0], shares[0] };
    recovered_len = sizeof(recovered);
    u_assert_int_eq(dogecoin_slip0039_recover_secret(duplicate_set, 2, recovered, &recovered_len), -1);

    char tampered[SLIP0039_MAX_SHARE_STR_SIZE];
    strncpy(tampered, shares[0], sizeof(tampered) - 1);
    tampered[sizeof(tampered) - 1] = '\0';
    size_t tampered_len = strlen(tampered);
    tampered[tampered_len - 1] = (tampered[tampered_len - 1] == '0') ? '1' : '0';
    const char* tampered_set[] = { tampered, shares[1] };
    recovered_len = sizeof(recovered);
    u_assert_int_eq(dogecoin_slip0039_recover_secret(tampered_set, 2, recovered, &recovered_len), -1);

    recovered_len = 2;
    u_assert_int_eq(dogecoin_slip0039_recover_secret(recovery_set, 2, recovered, &recovered_len), -1);
}
