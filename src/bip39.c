/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 * Copyright (c) 2022 edtubbs
 * Copyright (c) 2022 bluezr
 * Copyright (c) 2022 michilumin
 * Copyright (c) 2023-2024 The Dogecoin Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <bip39/index.h>
#include <dogecoin/bip39.h>
#include <dogecoin/utils.h>
#include <dogecoin/random.h>
#include <dogecoin/sha2.h>
#include <dogecoin/utf8proc.h>

#ifdef _WIN32
#ifndef WINVER
#define WINVER 0x0600
#endif
#include <windows.h>
#endif

#include <bip39/electrum.h>  // For wordlist_electrum[1626]

/*
 * Electrum seed support (minimal, additive)
 *
 * Electrum v2+:
 * - seed version = int(prefix,16) where prefix comes from HMAC-SHA512("Seed version", prepared_seed)
 * - seed bytes   = PBKDF2-HMAC-SHA512(password=prepared_seed, salt="electrum"+passphrase, rounds=2048, dklen=64)
 *
 * Electrum v1 (pre-v2):
 * - 12 words from 1626-word list encode/decode a 16-byte (128-bit) seed
 * - seed bytes   = stretched seed (32 bytes):
 *     seed      = SHA256(mnemonic + (" " + passphrase if passphrase non-empty))
 *     stretched = seed
 *     repeat 100000 times: stretched = SHA256(stretched + seed)
 * - NOTE: v1 is 32 bytes. We place it in seed[0..31] and zero seed[32..63].
 */

#define ELECTRUM_V1_WORDLIST_SIZE 1626
#define ELECTRUM_V1_SEED_BYTES 16
/* Electrum v1 requires exactly 12 words (4 groups of 3) encoding 16 bytes.
 * Verified: bip-utils ElectrumV1MnemonicConst.MNEMONIC_WORD_NUM == [12] */
#define ELECTRUM_V1_WORDS 12

/* prepare Electrum v1 seed: lowercase + collapse whitespace.
 * The v1 wordlist is English-only (pure ASCII), so this is equivalent to
 * the NFKD normalization used by bip-utils Bip39Mnemonic._Normalize().
 * NFKD only differs from ASCII lowering for non-ASCII characters. */
static size_t electrum_prepare_seed_ascii(const char* in, char* out, size_t outlen)
{
    if (!in || !out || outlen == 0) return 0;

    size_t j = 0;
    int in_space = 1; /* trim leading spaces */

    for (size_t i = 0; in[i] != '\0'; i++) {
        unsigned char c = (unsigned char)in[i];

        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f') {
            if (!in_space) {
                if (j + 1 >= outlen) break;
                out[j++] = ' ';
                in_space = 1;
            }
            continue;
        }

        /* lowercase ASCII */
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');

        if (j + 1 >= outlen) break;
        out[j++] = (char)c;
        in_space = 0;
    }

    /* trim trailing space */
    if (j > 0 && out[j - 1] == ' ') j--;

    out[j] = '\0';
    return j;
}

/* HMAC-SHA512(key, msg) -> hex string */
static void electrum_hmac_sha512_hex(const unsigned char* key, size_t keylen,
                                     const unsigned char* msg, size_t msglen,
                                     char out_hex[129])
{
    unsigned char mac[SHA512_DIGEST_LENGTH];
    dogecoin_mem_zero(mac, sizeof(mac));
    dogecoin_mem_zero(out_hex, 129);

    /* libdogecoin sha2 provides hmac_sha512 */
    hmac_sha512(key, keylen, msg, msglen, mac);

    for (size_t i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(&out_hex[i * 2], "%02x", mac[i]);
    }
    out_hex[128] = '\0';
    dogecoin_mem_zero(mac, sizeof(mac));
}

/* Returns non-zero if mnemonic looks like an Electrum v2+ seed, and optionally its version. */
int dogecoin_mnemonic_is_electrum_seed(const char* mnemonic, uint32_t* out_version)
{
    if (!mnemonic) return 0;

    char seed_prepared[MAX_MNEMONIC_STRING_SIZE];
    dogecoin_mem_zero(seed_prepared, sizeof(seed_prepared));
    size_t seed_len = electrum_prepare_seed_ascii(mnemonic, seed_prepared, sizeof(seed_prepared));
    if (seed_len == 0) return 0;

    char mac_hex[129];
    electrum_hmac_sha512_hex((const unsigned char*)"Seed version", strlen("Seed version"),
                             (const unsigned char*)seed_prepared, seed_len,
                             mac_hex);

    /* prefix length = int(mac_hex[0],16) + 2 */
    int nibble = 0;
    if (mac_hex[0] >= '0' && mac_hex[0] <= '9') nibble = mac_hex[0] - '0';
    else if (mac_hex[0] >= 'a' && mac_hex[0] <= 'f') nibble = mac_hex[0] - 'a' + 10;
    else if (mac_hex[0] >= 'A' && mac_hex[0] <= 'F') nibble = mac_hex[0] - 'A' + 10;
    else return 0;

    int prefix_len = nibble + 2;
    if (prefix_len < 2 || prefix_len > 8) return 0; /* sanity */

    char prefix[9];
    dogecoin_mem_zero(prefix, sizeof(prefix));
    memcpy(prefix, mac_hex, (size_t)prefix_len);
    prefix[prefix_len] = '\0';

    uint32_t ver = (uint32_t)strtoul(prefix, NULL, 16);

    /* known Electrum v2+ versions */
    if (ver == 0x01 || ver == 0x100 || ver == 0x101) {
        if (out_version) *out_version = ver;
        return 1;
    }

    return 0;
}

/* Derive the 64-byte seed from an Electrum v2+ seed phrase and optional passphrase. */
int dogecoin_seed_from_electrum_mnemonic(const char* mnemonic, const char* passphrase, SEED seed)
{
    if (!mnemonic || !seed) {
        fprintf(stderr, "ERROR: invalid input arguments\n");
        return -1;
    }

    if (passphrase == NULL) {
        passphrase = "";
    }

    char seed_prepared[MAX_MNEMONIC_STRING_SIZE];
    dogecoin_mem_zero(seed_prepared, sizeof(seed_prepared));
    size_t seed_len = electrum_prepare_seed_ascii(mnemonic, seed_prepared, sizeof(seed_prepared));
    if (seed_len == 0) {
        fprintf(stderr, "ERROR: failed to prepare electrum seed\n");
        return -1;
    }

    size_t salt_len = strlen("electrum") + strlen(passphrase);
    char* salt = malloc(salt_len + 1);
    if (!salt) {
        fprintf(stderr, "ERROR: Failed to allocate memory for electrum salt\n");
        return -1;
    }
    salt[0] = '\0';
    strcat(salt, "electrum");
    strcat(salt, passphrase);

    /* PBKDF2-HMAC-SHA512, rounds=2048, dkLen=64 */
    memset(seed, 0, MAX_SEED_SIZE);
    pbkdf2_hmac_sha512((const unsigned char*)seed_prepared, seed_len,
                       (const unsigned char*)salt, strlen(salt),
                       ITERATIONS, seed);

    dogecoin_mem_zero(seed_prepared, sizeof(seed_prepared));
    dogecoin_mem_zero(salt, salt_len + 1);
    dogecoin_free(salt);
    return 0;
}

/*
 * Electrum v1 (pre-v2) seed support (minimal, additive)
 */

/*
 * Find word index in Electrum v1 wordlist.
 * Returns index 0-1625, or -1 if not found.
 */
static int electrum_v1_find_word(const char* word)
{
    if (!word) return -1;

    for (int i = 0; i < ELECTRUM_V1_WORDLIST_SIZE; i++) {
        if (strcmp(word, wordlist_electrum[i]) == 0) {
            return i;
        }
    }
    return -1;
}

/* Decode 12-word Electrum v1 mnemonic to 16-byte seed (old_mnemonic.mn_decode).
 * Electrum v1 requires exactly 12 words — each group of 3 words encodes 32 bits
 * via base-1626 arithmetic, yielding 4 × 4 = 16 bytes of entropy. */
static int electrum_v1_decode_mnemonic(const char* mnemonic,
                                       unsigned char seed16_out[ELECTRUM_V1_SEED_BYTES])
{
    if (!mnemonic || !seed16_out) return -1;

    /* normalize: lowercase + collapse whitespace */
    char buf[MAX_MNEMONIC_STRING_SIZE];
    dogecoin_mem_zero(buf, sizeof(buf));
    if (electrum_prepare_seed_ascii(mnemonic, buf, sizeof(buf)) == 0) return -1;

    /* parse 12 words */
    uint16_t idx[ELECTRUM_V1_WORDS];
    int wc = 0;
    char* saveptr = NULL;

    char* tok = strtok_r(buf, " ", &saveptr);
    while (tok) {
        if (wc >= ELECTRUM_V1_WORDS) return -1;
        int w = electrum_v1_find_word(tok);
        if (w < 0) return -1;
        idx[wc++] = (uint16_t)w;
        tok = strtok_r(NULL, " ", &saveptr);
    }
    if (wc != ELECTRUM_V1_WORDS) return -1;

    const uint32_t N = ELECTRUM_V1_WORDLIST_SIZE;

    /* each 3 words -> 32 bits */
    for (int g = 0; g < 4; g++) {
        uint32_t w1 = idx[g * 3 + 0];
        uint32_t w2 = idx[g * 3 + 1];
        uint32_t w3 = idx[g * 3 + 2];

        uint32_t d12 = (w2 + N - w1) % N;
        uint32_t d23 = (w3 + N - w2) % N;

        uint64_t x64 = (uint64_t)w1
                     + (uint64_t)N * (uint64_t)d12
                     + (uint64_t)N * (uint64_t)N * (uint64_t)d23;

        /* reject impossible triples (some word triples map above 2^32-1) */
        if (x64 > 0xFFFFFFFFULL) return -1;

        uint32_t x = (uint32_t)x64;

        seed16_out[g * 4 + 0] = (unsigned char)(x >> 24);
        seed16_out[g * 4 + 1] = (unsigned char)(x >> 16);
        seed16_out[g * 4 + 2] = (unsigned char)(x >> 8);
        seed16_out[g * 4 + 3] = (unsigned char)(x);
    }

    return 0;
}

/* Encode 16-byte seed to 12 Electrum v1 words (old_mnemonic.mn_encode). */
static int electrum_v1_encode_mnemonic(const unsigned char seed16[ELECTRUM_V1_SEED_BYTES],
                                       char* out, size_t outlen)
{
    if (!seed16 || !out || outlen == 0) return -1;

    const uint32_t N = ELECTRUM_V1_WORDLIST_SIZE;
    size_t pos = 0;
    out[0] = '\0';

    for (int g = 0; g < 4; g++) {
        uint32_t x =
            ((uint32_t)seed16[g * 4 + 0] << 24) |
            ((uint32_t)seed16[g * 4 + 1] << 16) |
            ((uint32_t)seed16[g * 4 + 2] << 8)  |
            ((uint32_t)seed16[g * 4 + 3]);

        uint32_t w1 = x % N;
        uint32_t w2 = ((x / N) + w1) % N;
        uint32_t w3 = ((x / (N * N)) + w2) % N;

        const char* a = wordlist_electrum[w1];
        const char* b = wordlist_electrum[w2];
        const char* c = wordlist_electrum[w3];

        const char* sp = (pos == 0) ? "" : " ";
        int n = snprintf(out + pos, outlen - pos, "%s%s %s %s", sp, a, b, c);
        if (n < 0 || (size_t)n >= outlen - pos) return -1;
        pos += (size_t)n;
    }

    return 0;
}


/*
 * Decode Electrum v1 seed from 12-word mnemonic.
 *
 * Decodes a valid 12-word Electrum v1 mnemonic (from the 1626-word list)
 * to a 16-byte seed using base-1626. The raw decoded seed is stored in
 * seed[0..15] and the remaining bytes are zeroed.
 *
 * In original Electrum v1, the seed is the raw decoded value (e.g.
 * '8edad31a95e7d59f8837667510d75a4d'). The stretch_key() operation is
 * applied later during key derivation, not during seed storage.
 *
 * Returns 0 on success, -1 if the mnemonic is not a valid Electrum v1 mnemonic.
 */
int dogecoin_seed_from_electrum_v1_mnemonic(const char* mnemonic, const char* passphrase, SEED seed)
{
    (void)passphrase; /* unused in Electrum v1 seed decoding */
    memset(seed, 0, MAX_SEED_SIZE);

    if (!mnemonic || !seed) {
        return -1;
    }

    /* Decode 12-word mnemonic to 16-byte seed */
    unsigned char seed16[ELECTRUM_V1_SEED_BYTES];
    dogecoin_mem_zero(seed16, sizeof(seed16));

    if (electrum_v1_decode_mnemonic(mnemonic, seed16) != 0) {
        return -1; /* Not a valid Electrum v1 mnemonic */
    }

    /* Store the raw decoded 16-byte seed directly */
    memcpy(seed, seed16, ELECTRUM_V1_SEED_BYTES);

    dogecoin_mem_zero(seed16, sizeof(seed16));
    return 0;
}

/*
 * This function implements the first part of the BIP-39 algorithm.
 * The randomness or entropy for the mnemonic must be a multiple of
 * 32 bits hence the use of 128,160,192,224,256.
 *
 * The CS values below represent a portion (in bits) of the first
 * byte of the checksum or SHA256 digest of the entropy that the user
 * chooses by program option. These checksum bits are added to the
 * entropy prior to splitting the entire random series (ENT+CS) of bits
 * into 11 bit words to be matched with the 2048 count language word
 * file chosen. The final output or mnemonic sentence consists of (MS) words.
 *
 * CS = ENT / 32
 * MS = (ENT + CS) / 11
 *
 * |  ENT  | CS | ENT+CS |  MS  |
 * +-------+----+--------+------+
 * |  128  |  4 |   132  |  12  |
 * |  160  |  5 |   165  |  15  |
 * |  192  |  6 |   198  |  18  |
 * |  224  |  7 |   231  |  21  |
 * |  256  |  8 |   264  |  24  |
 */

int get_mnemonic(const int entropysize, const char* entropy, const char* wordlist[], const char* space, char* entropy_out, char* mnemonic, size_t* mnemonic_size) {

    /* Check entropy size per BIP-39 */
    if (!(entropysize >= 128 && entropysize <= 256 && entropysize % 32 == 0)) {
        fprintf(stderr,
                "ERROR: Only the following values for entropy bit sizes may be used: 128, 160, 192, 224, and 256\n");
        return -1;
    }

    int entBytes = entropysize / 8; // bytes instead of bits
    int csAdd = entropysize / 32; // portion in bits of a single byte

    /*
     * ENT (Entropy)
     */
    char* entropyBits = dogecoin_char_vla(entropysize + 1);
    if (entropyBits == NULL) {
        fprintf(stderr, "ERROR: Failed to allocate memory for entropyBits\n");
        return -1;
    }
    entropyBits[0] = '\0';
    dogecoin_mem_zero(entropyBits, entropysize + 1);  // Initialize entropyBits to all zeros

    char binaryByte[9] = "";

    /* Allocate memory for local entropy */
    unsigned char* local_entropy = dogecoin_uchar_vla(entBytes);
    if (local_entropy == NULL) {
        fprintf(stderr, "ERROR: Failed to allocate memory for local entropy\n");
        dogecoin_free(entropyBits);
        return -1;
    }

    /* Gather entropy bytes locally unless optionally provided */
    if (entropy == NULL) {
        int rc = (int) dogecoin_random_bytes(local_entropy, entBytes, 0);
        if (rc != 1) {
            fprintf(stderr, "ERROR: Failed to generate random entropy\n");
            dogecoin_free(entropyBits);
            dogecoin_free(local_entropy);
            return -1;
        }
    }
    else {
        /* Convert optional entropy string to bytes */
        unsigned char* entropy_bytes = utils_hex_to_uint8(entropy);
        if (entropy_bytes == NULL) {
            fprintf(stderr, "ERROR: Failed to convert entropy string to bytes\n");
            dogecoin_free(entropyBits);
            dogecoin_free(local_entropy);
            return -1;
        }
        memcpy_safe(local_entropy, entropy_bytes, entBytes);
        utils_clear_buffers();
    }

    /* Convert local entropy and copy to entropy parameter if allocated */
    if (entropy_out != NULL) {
        strcpy(entropy_out, utils_uint8_to_hex(local_entropy, entBytes));
        utils_clear_buffers();
    }

    /* Concatenate string of bits from entropy bytes */
    for (int i = 0; i < entBytes; i++) {

        /* Convert valid byte to string of bits */
        sprintf(binaryByte, BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(local_entropy[i]));
        binaryByte[8] = '\0';  // null-terminate the binary byte

        /* Concatentate the bits */
        if (strcat(entropyBits, binaryByte) == NULL) {
            fprintf(stderr, "ERROR: Failed to concatenate entropy\n");
            dogecoin_free(entropyBits);
            dogecoin_free(local_entropy);
            return -1;
        }
    }

    /*
     * ENT SHA256 checksum
     */
    static char checksum[SHA256_DIGEST_STRING_LENGTH];
    dogecoin_mem_zero(checksum, sizeof(checksum));
    checksum[0] = '\0';

    /* SHA256 of entropy bytes */
    unsigned char hash[SHA256_DIGEST_LENGTH];
    sha256_raw(local_entropy, entBytes, hash);

    /* done with local_entropy */
    dogecoin_free(local_entropy);

    /* Checksum from SHA256 */
    dogecoin_mem_zero(checksum, sizeof(checksum));  // Initialize checksum to all zeros
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&checksum[i * 2], "%02x", hash[i]);
    }
    checksum[SHA256_DIGEST_STRING_LENGTH - 1] = '\0';  // null-terminate the checksum string

    /* Copy the checksum */
    char hexStr[3];
    memset(hexStr, 0, sizeof(hexStr));
    memcpy_safe(hexStr, &checksum[0], 2);
    hexStr[2] = '\0';

    /*
     * CS (Checksum portion) to add to entropy
     */

    int ret = produce_mnemonic_sentence(csAdd * 33 + 1, csAdd + 1, hexStr, entropyBits, wordlist, space, mnemonic, mnemonic_size);
    if (ret != 0) {
        fprintf(stderr, "ERROR: Failed to generate mnemonic sentence\n");
        dogecoin_free(entropyBits);
        return -1;
    }

    /* done with entropyBits */
    dogecoin_free(entropyBits);

    return 0;
}

/*
 * This function implements the second part of the BIP-39 algorithm.
 */

int get_root_seed(const char *pass, const char *passphrase, SEED seed) {

    /* Initialize seed */
    memset (seed, 0, MAX_SEED_SIZE);

    /* Validate inputs */
    if (pass == NULL || passphrase == NULL) {
        return -1;
    }

    /* create salt, passphrase could be empty string */
    char *salt = malloc(strlen(passphrase) + 9);
    if (salt == NULL) {
        fprintf(stderr, "ERROR: Failed to allocate memory for salt\n");
        return -1;
    }
    *salt = '\0';

    if (strcat(salt, "mnemonic") == NULL || strcat(salt, passphrase) == NULL) {
        fprintf(stderr, "ERROR: Failed to concatenate salt\n");
        dogecoin_free(salt);
        return -1;
    }

#ifdef _WIN32
    /* normalize the passphrase and salt */
    size_t norm_pass_len, norm_salt_len;

    int pass_len = strlen(pass);
    int salt_len = strlen(salt);

    /* Convert passphrase and salt to wide characters */
    int pass_wlen = MultiByteToWideChar(CP_UTF8, 0, pass, pass_len, NULL, 0);
    int salt_wlen = MultiByteToWideChar(CP_UTF8, 0, salt, salt_len, NULL, 0);

    if (pass_wlen == 0) {
        fprintf(stderr, "ERROR: converting passphrase to wide characters\n");
        dogecoin_free(salt);
        return -1;
    }
    if (salt_wlen == 0) {
        fprintf(stderr, "ERROR: converting salt to wide characters\n");
        dogecoin_free(salt);
        return -1;
    }

    LPWSTR pass_w = malloc((pass_wlen) * sizeof(WCHAR));
    if (pass_w == NULL) {
        fprintf(stderr, "ERROR: allocating memory for passphrase wide characters\n");
        dogecoin_free(salt);
        return -1;
    }
    LPWSTR salt_w = malloc((salt_wlen) * sizeof(WCHAR));
    if (salt_w == NULL) {
        fprintf(stderr, "ERROR: allocating memory for salt wide characters\n");
        dogecoin_free(salt);
        dogecoin_free(pass_w);
        return -1;
    }

    if (MultiByteToWideChar(CP_UTF8, 0, pass, pass_len, pass_w, pass_wlen) == 0) {
        fprintf(stderr, "ERROR: converting passphrase to wide characters\n");
        dogecoin_free(salt);
        dogecoin_free(pass_w);
        dogecoin_free(salt_w);
        return -1;
    }

    if (MultiByteToWideChar(CP_UTF8, 0, salt, salt_len, salt_w, salt_wlen) == 0) {
        fprintf(stderr, "ERROR: converting salt to wide characters\n");
        dogecoin_free(salt);
        dogecoin_free(pass_w);
        dogecoin_free(salt_w);
        return -1;
    }

    norm_pass_len = NormalizeString(NormalizationKD, pass_w, pass_wlen, NULL, 0);
    norm_salt_len = NormalizeString(NormalizationKD, salt_w, salt_wlen, NULL, 0);
    if (norm_pass_len <= 0) {
        LPVOID message;
        DWORD error = GetLastError();
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&message, 0, NULL);
        fprintf(stderr, "ERROR: getting length of normalized passphrase: %s\n", (char*)message);
        LocalFree(message);
        dogecoin_free(salt);
        dogecoin_free(pass_w);
        dogecoin_free(salt_w);
        return -1;
    }
    if (norm_salt_len <= 0) {
        fprintf(stderr, "ERROR: getting length of normalized salt\n");
        dogecoin_free(salt);
        dogecoin_free(pass_w);
        dogecoin_free(salt_w);
        return -1;
    }

    LPWSTR norm_pass = malloc((norm_pass_len) * sizeof(WCHAR));
    if (norm_pass == NULL) {
        fprintf(stderr, "ERROR: allocating memory for normalized passphrase\n");
        dogecoin_free(salt);
        dogecoin_free(pass_w);
        dogecoin_free(salt_w);
        return -1;
    }
    LPWSTR norm_salt = malloc((norm_salt_len) * sizeof(WCHAR));
    if (norm_salt == NULL) {
        dogecoin_free(salt);
        dogecoin_free(pass_w);
        dogecoin_free(salt_w);
        dogecoin_free(norm_pass);
        fprintf(stderr, "ERROR: allocating memory for normalized salt\n");
        return -1;
    }

    norm_pass_len = NormalizeString(NormalizationKD, pass_w, pass_wlen, norm_pass, norm_pass_len);
    norm_salt_len = NormalizeString(NormalizationKD, salt_w, salt_wlen, norm_salt, norm_salt_len);

    if (norm_pass_len <= 0) {
        fprintf(stderr, "ERROR: getting normalized passphrase\n");
        dogecoin_free(salt);
        dogecoin_free(pass_w);
        dogecoin_free(salt_w);
        dogecoin_free(norm_pass);
        dogecoin_free(norm_salt);
        return -1;
    }
    if (norm_salt_len <= 0) {
        fprintf(stderr, "ERROR: getting normalized salt\n");
        dogecoin_free(salt);
        dogecoin_free(pass_w);
        dogecoin_free(salt_w);
        dogecoin_free(norm_pass);
        dogecoin_free(norm_salt);
        return -1;
    }

    /* Convert normalized passphrase and salt to multi-byte characters */
    int norm_pass_mb_len = WideCharToMultiByte(CP_UTF8, 0, norm_pass, (int)norm_pass_len, NULL, 0, NULL, NULL);
    int norm_salt_mb_len = WideCharToMultiByte(CP_UTF8, 0, norm_salt, (int)norm_salt_len, NULL, 0, NULL, NULL);

    if (norm_pass_mb_len == 0) {
        fprintf(stderr, "ERROR: converting normalized passphrase to multi-byte characters\n");
        dogecoin_free(salt);
        dogecoin_free(pass_w);
        dogecoin_free(salt_w);
        dogecoin_free(norm_pass);
        dogecoin_free(norm_salt);
        return -1;
    }
    if (norm_salt_mb_len == 0) {
        fprintf(stderr, "ERROR: converting normalized salt to multi-byte characters\n");
        dogecoin_free(salt);
        dogecoin_free(pass_w);
        dogecoin_free(salt_w);
        dogecoin_free(norm_pass);
        dogecoin_free(norm_salt);
        return -1;
    }

    char* norm_pass_mb = malloc((size_t)norm_pass_mb_len);
    if (norm_pass_mb == NULL) {
        fprintf(stderr, "ERROR: allocating memory for normalized passphrase multi-byte characters\n");
        dogecoin_free(salt);
        dogecoin_free(pass_w);
        dogecoin_free(salt_w);
        dogecoin_free(norm_pass);
        dogecoin_free(norm_salt);
        return -1;
    }
    char* norm_salt_mb = malloc((size_t)norm_salt_mb_len);
    if (norm_salt_mb == NULL) {
        fprintf(stderr, "ERROR: allocating memory for normalized salt multi-byte characters\n");
        dogecoin_free(salt);
        dogecoin_free(pass_w);
        dogecoin_free(salt_w);
        dogecoin_free(norm_pass);
        dogecoin_free(norm_salt);
        dogecoin_free(norm_pass_mb);
        return -1;
    }

    if (WideCharToMultiByte(CP_UTF8, 0, norm_pass, (int)norm_pass_len, norm_pass_mb, norm_pass_mb_len, NULL, NULL) == 0) {
        fprintf(stderr, "ERROR: converting normalized passphrase to multi-byte characters\n");
        dogecoin_free(salt);
        dogecoin_free(pass_w);
        dogecoin_free(salt_w);
        dogecoin_free(norm_pass);
        dogecoin_free(norm_salt);
        dogecoin_free(norm_pass_mb);
        dogecoin_free(norm_salt_mb);
        return -1;
    }

    if (WideCharToMultiByte(CP_UTF8, 0, norm_salt, (int)norm_salt_len, norm_salt_mb, norm_salt_mb_len, NULL, NULL) == 0) {
        fprintf(stderr, "ERROR: converting normalized salt to multi-byte characters\n");
        dogecoin_free(salt);
        dogecoin_free(pass_w);
        dogecoin_free(salt_w);
        dogecoin_free(norm_pass);
        dogecoin_free(norm_salt);
        dogecoin_free(norm_pass_mb);
        dogecoin_free(norm_salt_mb);
        return -1;
    }

    /* we're done with salt */
    dogecoin_free(salt);
    dogecoin_free(pass_w);
    dogecoin_free(salt_w);
    dogecoin_free(norm_pass);
    dogecoin_free(norm_salt);

    /* pbkdf2 hmac sha512 */
    pbkdf2_hmac_sha512((const unsigned char*) norm_pass_mb, (size_t)norm_pass_mb_len,
                       (const unsigned char*) norm_salt_mb, (size_t)norm_salt_mb_len,
                       ITERATIONS, seed);

    dogecoin_free(norm_pass_mb);
    dogecoin_free(norm_salt_mb);

    return 0;

#else
    /* normalise passphrase and salt (NFKD) */
    uint8_t *norm_pass = (uint8_t *)utf8proc_NFKD(
                             (const utf8proc_uint8_t *)pass);
    if (!norm_pass) {
        fprintf(stderr, "ERROR: normalising passphrase\n");
        dogecoin_free(salt);
        return -1;
    }

    uint8_t *norm_salt = (uint8_t *)utf8proc_NFKD(
                             (const utf8proc_uint8_t *)salt);
    if (!norm_salt) {
        fprintf(stderr, "ERROR: normalising salt\n");
        dogecoin_free(salt);
        dogecoin_free(norm_pass);
        return -1;
    }

    /* done with the original salt buffer */
    dogecoin_free(salt);

    size_t norm_pass_len = strlen((const char *)norm_pass);
    size_t norm_salt_len = strlen((const char *)norm_salt);

    /* PBKDF2-HMAC-SHA512 */
    pbkdf2_hmac_sha512(norm_pass,  norm_pass_len,
                       norm_salt,  norm_salt_len,
                       ITERATIONS, seed);

    dogecoin_free(norm_pass);
    dogecoin_free(norm_salt);
    return 0;
#endif

}

/*
 * This function reads the language file once and loads an array of words for
 * repeated use.
 */

int get_custom_words(const char *filepath, char* wordlist[]) {
#ifndef USE_OPTEE /* OPTEE does not support file I/O */
    int i = 0;
    FILE * fp;
    char word[1024];

    /* Check that file path is valid */
    if (filepath == NULL) {
        fprintf(stderr, "ERROR: file path error\n");
        return -1;
    }

    fp = fopen(filepath, "r");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: file read error\n");
        return -1;
    }

    while (fscanf(fp, "%s", word) == 1) {
        if (i >= LANG_WORD_CNT) {
            fprintf(stderr, "ERROR: too many words in file\n");
            fclose(fp);
            return -1;
        }
        wordlist[i] = malloc(strlen(word) + 1);
        if (wordlist[i] == NULL) {
            fprintf(stderr, "ERROR: cannot allocate memory\n");
            fclose(fp);
            return -1;
        }
        strcpy(wordlist[i], word);
        i++;
    }

    fclose(fp);

    if (i != LANG_WORD_CNT) {
        fprintf(stderr, "ERROR: not 2048 words\n");
        return -1;
    }

    return 0;
#else
    (void)filepath;
    (void)wordlist;
    return -1;
#endif
}

/*
 * This function reads a wordlist and loads an array of words for
 * repeated use.
 */

int get_words(const char *lang, char* wordlist[]) {
    int i = 0;

    /* Check that language is valid */
    if (lang == NULL) {
        fprintf(stderr, "ERROR: invalid language\n");
        return -1;
    }

    /* Check that wordlist is valid */
    if (wordlist == NULL) {
        fprintf(stderr, "ERROR: invalid value of wordlist\n");
        return -1;
    }

    for (; i < 2048; i++) {
      if (strcmp(lang,"spa") == 0) {
          wordlist[i]=(char*)wordlist_spa[i];
      } else if (strcmp(lang,"eng") == 0) {
          wordlist[i]=(char*)wordlist_eng[i];
      } else if (strcmp(lang,"jpn") == 0) {
          wordlist[i]=(char*)wordlist_jpn[i];
      } else if (strcmp(lang,"ita") == 0) {
          wordlist[i]=(char*)wordlist_ita[i];
      } else if (strcmp(lang,"fra") == 0) {
          wordlist[i]=(char*)wordlist_fra[i];
      } else if (strcmp(lang,"kor") == 0) {
          wordlist[i]=(char*)wordlist_kor[i];
      } else if (strcmp(lang,"sc") == 0) {
          wordlist[i]=(char*)wordlist_sc[i];
      } else if (strcmp(lang,"tc") == 0) {
          wordlist[i]=(char*)wordlist_tc[i];
      } else if (strcmp(lang,"cze") == 0) {
          wordlist[i]=(char*)wordlist_cze[i];
      } else if (strcmp(lang,"por") == 0) {
          wordlist[i]=(char*)wordlist_por[i];
      } else {
          fprintf(stderr, "ERROR: invalid language\n");
          return -1;
      }
    }
   return 0;
}

/*
 * This function prints the mnemonic sentence of size based on the segment
 * size and number of checksum bits appended to the entropy bits.
 */

int produce_mnemonic_sentence(const int segSize, const int checksumBits, const char* firstByte, const char* entropy, const char* wordlist[], const char* space, char* mnemonic, size_t* mnemonic_size) {

    /* Check if the input arguments are valid, mnemonic may be NULL */
    if (segSize <= 0 || checksumBits <= 0 || !firstByte || !entropy || !wordlist || !space || !mnemonic_size) {
        fprintf(stderr, "ERROR: invalid input arguments\n");
        return -1;
    }

    /* Check that wordlist is valid */
    if (*wordlist == NULL) {
        fprintf(stderr, "ERROR: invalid value of wordlist\n");
        return -1;
    }

    /* Define and initialize segment and csBits */
    char *segment = dogecoin_string_vla (segSize);
    if (segment == NULL) {
        fprintf(stderr, "ERROR: Failed to allocate memory for segment\n");
        return -1;
    }
    strcpy(segment, "");

    char *csBits = dogecoin_string_vla (checksumBits);
    if (csBits == NULL) {
        fprintf(stderr, "ERROR: Failed to allocate memory for csBits\n");
        dogecoin_free (segment);
        return -1;
    }
    strcpy(csBits, "");

    /* Convert the checksum string to a byte */
    unsigned char *bytes = utils_hex_to_uint8(firstByte);
    if (bytes == NULL) {
        /* Invalid byte, return from the function */
        fprintf(stderr, "ERROR: Failed to convert first byte\n");
        dogecoin_free (segment);
        dogecoin_free (csBits);
        return -1;
    }

    /* Convert the byte to bits */
    switch(checksumBits) {
        case 5:
            sprintf(csBits, BYTE_TO_FIRST_FOUR_BINARY_PATTERN, BYTE_TO_FIRST_FOUR_BINARY(bytes[0]));
            break;
        case 6:
            sprintf(csBits, BYTE_TO_FIRST_FIVE_BINARY_PATTERN, BYTE_TO_FIRST_FIVE_BINARY(bytes[0]));
            break;
        case 7:
            sprintf(csBits, BYTE_TO_FIRST_SIX_BINARY_PATTERN, BYTE_TO_FIRST_SIX_BINARY(bytes[0]));
            break;
        case 8:
            sprintf(csBits, BYTE_TO_FIRST_SEVEN_BINARY_PATTERN, BYTE_TO_FIRST_SEVEN_BINARY(bytes[0]));
            break;
        case 9:
            sprintf(csBits, BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(bytes[0]));
            break;
        default:
            /* Invalid byte, return from the function */
            fprintf(stderr, "ERROR: Failed to convert first byte\n");
            dogecoin_free (segment);
            dogecoin_free (csBits);
            utils_clear_buffers();
            return -1;
    }
    /* Clear the bytes buffer */
    utils_clear_buffers();

    csBits[checksumBits - 1] = '\0';   // null-terminate the checksum string

    /* Concatenate the entropy and checksum bits onto the segment array,
     * ensuring that the segment array does not overflow.
     */

    strncat(segment, entropy, segSize - (int)strlen(segment) - 1);
    strncat(segment, csBits, segSize - (int)strlen(segment) - 1);

    dogecoin_free (csBits);

    /* Initialize the mnemonic array with a null terminator */
    if (mnemonic != NULL) {
        mnemonic[0] = '\0';
    }
    *mnemonic_size = 0;

    char elevenBits[12] = {""};

    int elevenBitIndex = 0;
    for (int i = 0; i < segSize; i++) {

        if (elevenBitIndex == 11) {
            elevenBits[11] = '\0';
            /* Compute the decimal value of the 11-bit binary chunk */
            long real = 0;
            for (int j = 0; j < 11; j++) {
                real = (real << 1) | (elevenBits[j] - '0');
            }
            /* Check that real is a valid index into the wordlist array */
            if (real < 0 || real >= LANG_WORD_CNT) {
                fprintf(stderr, "ERROR: invalid 11-bit binary chunk\n");
                dogecoin_free (segment);
                return -1;
            }

            const char *word = wordlist[real];

            /* Check for allocation */
            if (mnemonic == NULL) {
                /* update mnemonic_size with the length of what the mnemonic should be */
                *mnemonic_size += strlen(word);

                /* Only count the space if it's not the last word */
                if (i < segSize - 1) {
                    *mnemonic_size += strlen(space);
                }
            }
            else {
                /* Concatenate the word from the wordlist to the mnemonic */
                strcat(mnemonic, word);

                /* update mnemonic_size with the length of the mnemonic */
                *mnemonic_size += strlen(word);

                /* Concatenate a space to the mnemonic only if it's not the last word */
                if (i < segSize - 1) {
                    strcat(mnemonic, space);
                    *mnemonic_size += strlen(space);
                }
            }

            elevenBitIndex = 0;
        }

        elevenBits[elevenBitIndex] = segment[i];
        elevenBitIndex++;
    }

    dogecoin_free (segment);

   /* Increment mnemonic_size to account for the null terminator */
   *mnemonic_size = *mnemonic_size + 1;

   return 0;
}

/**
 * @brief This function verifies the mnemonic sentence.
 *
 * @param mnemonic The mnemonic sentence to verify.
 * @param wordlist The wordlist to use for verification.
 * @param space The character to separate mnemonic words.
 *
 * @return 0 (success), -1 (fail)
*/
int verify_mnemonic_sentence(const char* mnemonic, const char* wordlist[], const char* space)
{
    if (!mnemonic || !wordlist || !space) {
        fprintf(stderr, "ERROR: invalid input arguments\n");
        return -1;
    }

    /* make a mutable copy so we can insert '\0' */
    size_t mlen = strlen(mnemonic);
    char* buf = malloc(mlen + 1);
    if (!buf) {
        fprintf(stderr, "ERROR: malloc failed for mnemonic copy\n");
        return -1;
    }
    memcpy(buf, mnemonic, mlen + 1);

    size_t delim_len = strlen(space);
    if (delim_len == 0) {
        fprintf(stderr, "ERROR: empty separator\n");
        dogecoin_free(buf);
        return -1;
    }

    /* count words by scanning for full 'space' substring */
    size_t word_count = 1;
    for (char* p = buf; (p = strstr(p, space)); p += delim_len) {
        word_count++;
    }

    /* valid word counts are 12,15,18,21,24 */
    if (word_count < 12 || word_count > 24 || (word_count % 3) != 0) {
        fprintf(stderr, "ERROR: invalid mnemonic word count: %zu\n", word_count);
        dogecoin_free(buf);
        return -1;
    }

    /* compute bit lengths */
    int total_bits    = (int)(word_count * BITS_PER_WORD);
    int checksum_bits = total_bits / 33;
    int entropy_bits  = total_bits - checksum_bits;
    int entropy_bytes = entropy_bits / 8;

    /* prepare bit buffer */
    char* bitstr = dogecoin_string_vla(total_bits);
    if (!bitstr) {
        fprintf(stderr, "ERROR: allocation failed for bit buffer\n");
        dogecoin_free(buf);
        return -1;
    }
    size_t bit_pos = 0;

    /* iterate tokens by null-terminating at each delimiter */
    char* start = buf;
    while (1) {
        char* next = strstr(start, space);
        size_t toklen = next ? (size_t)(next - start) : strlen(start);

        /* find index of this token in wordlist */
        int idx = -1;
        for (int i = 0; i < LANG_WORD_CNT; i++) {
            /* exact match: length and content */
            if (strncmp(start, wordlist[i], toklen) == 0 && wordlist[i][toklen] == '\0') {
                idx = i;
                break;
            }
        }
        if (idx < 0) {
            fprintf(stderr, "ERROR: invalid mnemonic word: '%.*s'\n", (int)toklen, start);
            dogecoin_free(bitstr);
            dogecoin_free(buf);
            return -1;
        }

        /* append its 11 bits */
        for (int b = BITS_PER_WORD - 1; b >= 0; b--) {
            bitstr[bit_pos++] = ((idx >> b) & 1) ? '1' : '0';
        }

        if (!next) break;
        start = next + delim_len;
    }
    bitstr[bit_pos] = '\0';

    /* reconstruct entropy from first entropy_bits */
    unsigned char* entropy = dogecoin_uchar_vla(entropy_bytes);
    if (!entropy) {
        fprintf(stderr, "ERROR: allocation failed for entropy buffer\n");
        dogecoin_free(bitstr);
        dogecoin_free(buf);
        return -1;
    }
    dogecoin_mem_zero(entropy, (size_t)entropy_bytes);
    for (int i = 0; i < entropy_bytes; i++) {
        unsigned char byte = 0;
        for (int b = 0; b < 8; b++) {
            if (bitstr[i * 8 + b] == '1') {
                byte |= (unsigned char)(1 << (7 - b));
            }
        }
        entropy[i] = byte;
    }

    /* SHA-256 and compare checksum bits */
    unsigned char hash[SHA256_DIGEST_LENGTH];
    sha256_raw(entropy, (size_t)entropy_bytes, hash);

    for (int i = 0; i < checksum_bits; i++) {
        char expected = ((hash[0] >> (7 - i)) & 1) ? '1' : '0';
        if (bitstr[entropy_bits + i] != expected) {
            fprintf(stderr, "ERROR: checksum verification failed\n");
            utils_clear_buffers();
            dogecoin_free(bitstr);
            dogecoin_free(entropy);
            dogecoin_free(buf);
            return -1;
        }
    }

    /* clean up */
    utils_clear_buffers();
    dogecoin_mem_zero(entropy, (size_t)entropy_bytes);
    dogecoin_mem_zero(bitstr, (size_t)total_bits);
    dogecoin_mem_zero(buf, mlen + 1);
    dogecoin_free(bitstr);
    dogecoin_free(entropy);
    dogecoin_free(buf);
    return 0;
}

/**
 * @brief This function generates a mnemonic for a given entropy size and language.
 *
 * @param entropy_size The "128", "160", "192", "224", or "256" bits of entropy.
 * @param language The ISO 639-2 code for the mnemonic language.
 * @param space The character to seperate mnemonic words.
 * @param entropy The entropy to generate the mnemonic (optional).
 * @param filepath The path to a custom word file (optional).
 * @param entropy_out The entropy of a given size as a hex string.
 * @param size The size of the generated mnemonic in bytes (including '\0').
 * @param words The generated mnemonic code words.
 *
 * @return 0 (success), -1 (fail)
*/
int dogecoin_generate_mnemonic (const ENTROPY_SIZE entropy_size, const char* language, const char* space, const char* entropy, const char* filepath, char* entropy_out, size_t* size, char* words)
{
    char *wordlist[LANG_WORD_CNT] = {0};

    /* validate input, optional entropy checked below */
    if (entropy_size != NULL) {

        /* load custom word file into memory if path is valid */
        if (filepath != NULL) {
            if (get_custom_words (filepath, (char **) wordlist) == -1) {

                /* Free memory for custom words */
                for (int i = 0; i < LANG_WORD_CNT; i++) {
                    dogecoin_free(wordlist[i]);
                }
                return -1;
            }
        }
        /* otherwise, load language word list into memory */
        else if (language != NULL) {
           if (get_words(language, wordlist) == -1) {
               return -1;
           }
        }
        /* handle input validation errors */
        else {
            fprintf(stderr, "ERROR: Failed to get language or custom words file\n");
            return -1;
        }

        /* Validate optional entropy */
        if (entropy != NULL) {

            /* Calculate expected size of entropy hex string */
            size_t expected_entropy_size = (size_t)strtol(entropy_size, NULL, 10) / 8 * HEX_CHARS_PER_BYTE;

            /* Verify size of the string equals the entropy_size specified */
            if (strlen(entropy) != expected_entropy_size) {
                fprintf(stderr, "ERROR: invalid entropy string, expected %ld characters\n", (long)expected_entropy_size);

                /* Free memory for custom words */
                if (filepath != NULL) {
                    for (int i = 0; i < LANG_WORD_CNT; i++) {
                        dogecoin_free(wordlist[i]);
                    }
                }
                return -1;
            }
        }

        /* convert string value for entropy size to base 10 and get mnemonic */
        if (get_mnemonic((int)strtol(entropy_size, NULL, 10), entropy, (const char **) wordlist, space, entropy_out, words, size) == -1) {
            fprintf(stderr, "ERROR: Failed to get mnemonic\n");

            /* Free memory for custom words */
            if (filepath != NULL) {
                for (int i = 0; i < LANG_WORD_CNT; i++) {
                    dogecoin_free(wordlist[i]);
                }
            }
            return -1;
        }

        /* Free memory for custom words */
        if (filepath != NULL) {
            for (int i = 0; i < LANG_WORD_CNT; i++) {
                dogecoin_free(wordlist[i]);
            }
        }
    }
    else {
        fprintf(stderr, "ERROR: Failed to get entropy size\n");
        return -1;
    }

    return 0;
}

/**
 * @brief This function verifies the mnemonic sentence.
 *
 * @param mnemonic The mnemonic sentence to verify.
 * @param language The ISO 639-2 code for the mnemonic language.
 * @param space The character to separate mnemonic words.
 * @param filename The path to a custom word file (optional).
 *
 * @return 0 (success), -1 (fail)
*/
int dogecoin_verify_mnemonic (const char* mnemonic, const char* language, const char* space, const char* filename)
{
    char *wordlist[LANG_WORD_CNT] = {0};

    /* Check if the input arguments are valid */
    if (!mnemonic || !space || (!language && !filename)) {
        fprintf(stderr, "ERROR: invalid input arguments\n");
        return -1;
    }

    /* load custom word file into memory if path is valid */
    if (filename != NULL) {
        if (get_custom_words (filename, (char **) wordlist) == -1) {
            return -1;
        }
    }
    /* otherwise, load language word list into memory */
    else {
        if (get_words(language, wordlist) == -1) {
            return -1;
        }
    }

    /* Verify the mnemonic sentence */
    int ret = verify_mnemonic_sentence(mnemonic, (const char **) wordlist, space);

    /* Free memory for custom words */
    if (filename != NULL) {
        for (int i = 0; i < LANG_WORD_CNT; i++) {
            dogecoin_free(wordlist[i]);
        }
    }

    return ret;
}

/**
 * @brief This function derives the seed from the mnemonic.
 *
 * @param mnemonic The mnemonic code words.
 * @param passphrase The passphrase (optional).
 * @param seed The 512-bit seed.
 *
 * @return 0 (success), -1 (fail)
*/
int dogecoin_seed_from_mnemonic (const char* mnemonic, const char* passphrase, SEED seed)
{
    /* Check if the input arguments are valid */
    if (!mnemonic || !seed) {
        fprintf(stderr, "ERROR: invalid input arguments\n");
        return -1;
    }

    /* set passphrase to empty string if null */
    if (passphrase == NULL) {
        passphrase = "";
    }

    /* Electrum v2+ (post-v2) auto-detect */
    if (dogecoin_mnemonic_is_electrum_seed(mnemonic, NULL)) {
        if (dogecoin_seed_from_electrum_mnemonic(mnemonic, passphrase, seed) == 0) {
            return 0;
        }
        /* fall through to BIP39 if something failed */
    }

    /* BIP39 seed derivation */
    if (get_root_seed(mnemonic, passphrase, seed) == -1) {
        fprintf(stderr, "ERROR: Failed to get root seed\n");
        return -1;
    }

    return 0;
}

/**
 * @brief This function generates a random English mnemonic phrase.
 *
 * @param size The size of entropy in bits.
 * @param mnemonic The mnemonic code words.
 *
 * @return 0 (success), -1 (fail)
*/
int generateRandomEnglishMnemonic (const ENTROPY_SIZE size, MNEMONIC mnemonic) {

    /* generate an English mnemonic without random entropy */
    return generateEnglishMnemonic (NULL, size, mnemonic);
}

/**
 * @brief This function gnerates an English mnemonic phrase of given size or from hex entropy.
 *
 * @param entropy The hex string of entropy.
 * @param size The size of entropy in bits.
 * @param mnemonic The mnemonic code words.
 *
 * @return 0 (success), -1 (fail)
*/
int generateEnglishMnemonic (const HEX_ENTROPY entropy, const ENTROPY_SIZE size, MNEMONIC mnemonic) {

    /* Initialize variables */
    const char* lang = "eng";     /* default english (eng) */
    const char* space = " ";      /* default utf8 ( ) */
    const char* words = 0;        /* default no custom words (NULL) */
    char* entropy_out = 0;
    size_t mnemonic_size = 0;

    /* allocate space for entropy if valid */
    if (entropy) {
        entropy_out = malloc(sizeof(char) * MAX_ENTROPY_STRING_SIZE);
        if (entropy_out == NULL) {

            fprintf(stderr, "ERROR: Failed to allocate memory for mnemonic\n");
            return -1;
        }
        memset(entropy_out, '\0', MAX_ENTROPY_STRING_SIZE);
    }

    /* first determine size of mnemonic */
    if (dogecoin_generate_mnemonic (size, lang, space, entropy, words, entropy_out, &mnemonic_size, NULL) == -1) {
        dogecoin_free (entropy_out);
        return -1;
    }

    /* generate mnemonic with entropy out */
    if (dogecoin_generate_mnemonic (size, lang, space, entropy_out, words, NULL, &mnemonic_size, mnemonic) == -1) {
        dogecoin_free (entropy_out);
        return -1;
    }

    dogecoin_free (entropy_out);

    return 0;
}
