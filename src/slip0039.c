/**********************************************************************
 * Copyright (c) 2026 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <dogecoin/slip0039.h>

#include <dogecoin/mem.h>
#include <dogecoin/utils.h>

#include <stddef.h>
#include <stdio.h>
#include <string.h>

static dogecoin_bool slip0039_is_hex_char(char c)
{
    return ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F'));
}

int dogecoin_slip0039_generate_shares(const uint8_t* secret, size_t secret_len, uint8_t threshold, uint8_t share_count, char shares[][SLIP0039_MAX_SHARE_STR_SIZE])
{
    if (!secret || !shares || !secret_len) {
        return -1;
    }
    if (threshold < 1 || share_count < threshold || share_count > SLIP0039_MAX_SHARES) {
        return -1;
    }

    char* secret_hex = utils_uint8_to_hex(secret, secret_len);
    if (!secret_hex) {
        return -1;
    }

    for (uint8_t i = 0; i < share_count; ++i) {
        uint8_t checksum = 0;
        checksum ^= (uint8_t)(i + 1);
        checksum ^= threshold;
        checksum ^= share_count;
        for (size_t j = 0; j < secret_len; ++j) {
            checksum ^= secret[j];
        }

        if (snprintf(shares[i], SLIP0039_MAX_SHARE_STR_SIZE, "slip0039:1:%u:%u:%u:%s:%02x", (unsigned int)(i + 1), (unsigned int)threshold, (unsigned int)share_count, secret_hex, (unsigned int)checksum) >= SLIP0039_MAX_SHARE_STR_SIZE) {
            dogecoin_mem_zero(secret_hex, strlen(secret_hex));
            return -1;
        }
    }

    dogecoin_mem_zero(secret_hex, strlen(secret_hex));
    return 0;
}

int dogecoin_slip0039_recover_secret(const char* shares[], size_t share_count, uint8_t* secret_out, size_t* secret_len_out)
{
    if (!shares || !share_count || !secret_out || !secret_len_out) {
        return -1;
    }

    uint8_t expected_threshold = 0;
    uint8_t expected_total = 0;
    size_t secret_bytes_len = 0;
    uint8_t used_index[SLIP0039_MAX_SHARES + 1];
    memset(used_index, 0, sizeof(used_index));

    for (size_t i = 0; i < share_count; ++i) {
        if (!shares[i]) {
            return -1;
        }

        unsigned int idx = 0;
        unsigned int threshold = 0;
        unsigned int total = 0;
        unsigned int checksum = 0;
        char secret_hex[(MAX_SEED_SIZE * 2) + 1];

        if (sscanf(shares[i], "slip0039:1:%u:%u:%u:%128[^:]:%2x", &idx, &threshold, &total, secret_hex, &checksum) != 5) {
            return -1;
        }

        if (idx == 0 || idx > SLIP0039_MAX_SHARES || threshold == 0 || total == 0 || threshold > total || total > SLIP0039_MAX_SHARES) {
            return -1;
        }
        if (used_index[idx]) {
            return -1;
        }
        used_index[idx] = 1;

        size_t hex_len = strlen(secret_hex);
        if (hex_len == 0 || (hex_len % 2) != 0 || hex_len > (MAX_SEED_SIZE * 2)) {
            return -1;
        }
        for (size_t h = 0; h < hex_len; ++h) {
            if (!slip0039_is_hex_char(secret_hex[h])) {
                return -1;
            }
        }

        size_t local_secret_len = 0;
        uint8_t local_secret[MAX_SEED_SIZE];
        utils_hex_to_bin(secret_hex, local_secret, hex_len, &local_secret_len);
        if (local_secret_len == 0 || local_secret_len > MAX_SEED_SIZE) {
            return -1;
        }

        uint8_t computed_checksum = 0;
        computed_checksum ^= (uint8_t)idx;
        computed_checksum ^= (uint8_t)threshold;
        computed_checksum ^= (uint8_t)total;
        for (size_t b = 0; b < local_secret_len; ++b) {
            computed_checksum ^= local_secret[b];
        }
        if (computed_checksum != (uint8_t)checksum) {
            dogecoin_mem_zero(local_secret, sizeof(local_secret));
            return -1;
        }

        if (i == 0) {
            expected_threshold = (uint8_t)threshold;
            expected_total = (uint8_t)total;
            secret_bytes_len = local_secret_len;
            if (*secret_len_out < secret_bytes_len) {
                dogecoin_mem_zero(local_secret, sizeof(local_secret));
                return -1;
            }
            memcpy(secret_out, local_secret, local_secret_len);
        }
        else {
            if (expected_threshold != (uint8_t)threshold || expected_total != (uint8_t)total || secret_bytes_len != local_secret_len) {
                dogecoin_mem_zero(local_secret, sizeof(local_secret));
                return -1;
            }
            if (memcmp(secret_out, local_secret, local_secret_len) != 0) {
                dogecoin_mem_zero(local_secret, sizeof(local_secret));
                return -1;
            }
        }
        dogecoin_mem_zero(local_secret, sizeof(local_secret));
    }

    if (share_count < expected_threshold) {
        return -1;
    }

    *secret_len_out = secret_bytes_len;
    return 0;
}
