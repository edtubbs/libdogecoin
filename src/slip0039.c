/**********************************************************************
 * Copyright (c) 2026 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 *                                                                    *
 * SLIP-0039 (Shamir's Secret-Sharing for Mnemonic Codes)             *
 *   Single group implementation: group_threshold=1, group_count=1.   *
 *   Non-extendable shares (customization string "shamir").           *
 *   Default iteration_exponent = 1 (10000 PBKDF2 iterations).        *
 *                                                                    *
 *   Reference: https://github.com/satoshilabs/slips/blob/master/     *
 *              slip-0039.md                                          *
 **********************************************************************/

#include <dogecoin/slip0039.h>

#include <dogecoin/mem.h>
#include <dogecoin/random.h>
#include <dogecoin/sha2.h>
#include <dogecoin/utils.h>

#include "slip0039_wordlist.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SLIP0039_RADIX_BITS              10
#define SLIP0039_ID_BITS                 15
#define SLIP0039_EXT_BITS                 1
#define SLIP0039_ITER_EXP_BITS            4
#define SLIP0039_METADATA_BITS           40   /* 4 mnemonic words */
#define SLIP0039_CHECKSUM_WORDS           3   /* 30-bit RS1024 checksum */
#define SLIP0039_DIGEST_INDEX           254
#define SLIP0039_SECRET_INDEX           255
#define SLIP0039_DIGEST_LENGTH_BYTES      4
#define SLIP0039_BASE_ITERATION_COUNT 10000
#define SLIP0039_ROUND_COUNT              4
#define SLIP0039_DEFAULT_ITER_EXP         1
#define SLIP0039_CUSTOMIZATION_STRING    "shamir"

/* "shamir" mapped to wordlist 10-bit indices for the RS1024 customization. */
static const uint16_t SLIP0039_RS1024_CUSTOMIZATION[6] = {
    's', 'h', 'a', 'm', 'i', 'r'
};

static const uint32_t SLIP0039_RS1024_GEN[10] = {
    0x00E0E040UL, 0x01C1C080UL, 0x03838100UL, 0x07070200UL, 0x0E0E0009UL,
    0x1C0C2412UL, 0x38086C24UL, 0x3090FC48UL, 0x21B1F890UL, 0x03F3F120UL
};

/* ---------------------------------------------------------------------- */
/*                              GF(256) helpers                            */
/* ---------------------------------------------------------------------- */

static uint8_t gf256_mul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) r ^= a;
        uint8_t hi = a & 0x80;
        a = (uint8_t)(a << 1);
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return r;
}

static uint8_t gf256_pow(uint8_t a, uint8_t exp)
{
    uint8_t r = 1;
    while (exp) {
        if (exp & 1) r = gf256_mul(r, a);
        a = gf256_mul(a, a);
        exp >>= 1;
    }
    return r;
}

/* a^254 = a^-1 in GF(256) for a != 0. */
static uint8_t gf256_inv(uint8_t a)
{
    return gf256_pow(a, 254);
}

/* Lagrange interpolation in GF(256) byte-wise.
 * xs: n distinct x-coordinates (each in 0..255)
 * ys: n*ylen bytes (n y-vectors of length ylen)
 * Computes the polynomial through the n points and evaluates at target_x.
 * Result is written to out[ylen]. Returns 0 on success, -1 if xs has dup.
 */
static int gf256_lagrange(uint8_t target_x,
                          const uint8_t* xs, size_t n,
                          const uint8_t* ys, size_t ylen,
                          uint8_t* out)
{
    memset(out, 0, ylen);
    /* If target_x matches a known x, copy that y directly. */
    for (size_t i = 0; i < n; ++i) {
        if (xs[i] == target_x) {
            memcpy(out, ys + i * ylen, ylen);
            return 0;
        }
    }
    for (size_t i = 0; i < n; ++i) {
        uint8_t num = 1;
        uint8_t den = 1;
        for (size_t j = 0; j < n; ++j) {
            if (j == i) continue;
            num = gf256_mul(num, (uint8_t)(target_x ^ xs[j]));
            den = gf256_mul(den, (uint8_t)(xs[i] ^ xs[j]));
        }
        if (den == 0) {
            /* Duplicate x in input. */
            return -1;
        }
        uint8_t lag = gf256_mul(num, gf256_inv(den));
        for (size_t k = 0; k < ylen; ++k) {
            out[k] ^= gf256_mul(ys[i * ylen + k], lag);
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------- */
/*                              RS1024 checksum                            */
/* ---------------------------------------------------------------------- */

static uint32_t rs1024_polymod(const uint16_t* values, size_t n)
{
    uint32_t chk = 1;
    for (size_t i = 0; i < n; ++i) {
        uint8_t b = (uint8_t)(chk >> 20);
        chk = ((chk & 0xFFFFFUL) << 10) ^ (uint32_t)values[i];
        for (int j = 0; j < 10; ++j) {
            if ((b >> j) & 1) chk ^= SLIP0039_RS1024_GEN[j];
        }
    }
    return chk;
}

static void rs1024_create_checksum(uint16_t* words, size_t total_words)
{
    /* total_words includes the 3 checksum slots (already zeroed by caller). */
    enum { CUST_LEN = 6, RS1024_MAX_DATA = 64 };
    uint16_t buf[CUST_LEN + RS1024_MAX_DATA];
    if (total_words > RS1024_MAX_DATA) {
        return; /* unreachable for supported sizes (<= 33) */
    }
    memcpy(buf, SLIP0039_RS1024_CUSTOMIZATION, CUST_LEN * sizeof(uint16_t));
    memcpy(buf + CUST_LEN, words, total_words * sizeof(uint16_t));
    uint32_t poly = rs1024_polymod(buf, CUST_LEN + total_words) ^ 1UL;
    for (size_t i = 0; i < SLIP0039_CHECKSUM_WORDS; ++i) {
        words[total_words - SLIP0039_CHECKSUM_WORDS + i] =
            (uint16_t)((poly >> (10 * (SLIP0039_CHECKSUM_WORDS - 1 - i))) & 0x3FFU);
    }
}

static int rs1024_verify_checksum(const uint16_t* words, size_t total_words)
{
    enum { CUST_LEN = 6, RS1024_MAX_DATA = 64 };
    uint16_t buf[CUST_LEN + RS1024_MAX_DATA];
    if (total_words > RS1024_MAX_DATA) return -1;
    memcpy(buf, SLIP0039_RS1024_CUSTOMIZATION, CUST_LEN * sizeof(uint16_t));
    memcpy(buf + CUST_LEN, words, total_words * sizeof(uint16_t));
    return (rs1024_polymod(buf, CUST_LEN + total_words) == 1UL) ? 0 : -1;
}

/* ---------------------------------------------------------------------- */
/*                          Bit packing helpers                            */
/* ---------------------------------------------------------------------- */

typedef struct {
    uint16_t* words;
    size_t    capacity;
    size_t    count;       /* number of complete 10-bit words emitted */
    uint32_t  buf;         /* pending bit accumulator */
    int       bits;        /* number of pending bits (0..9) */
} bitpack_writer;

static void bw_init(bitpack_writer* w, uint16_t* words, size_t capacity)
{
    w->words = words;
    w->capacity = capacity;
    w->count = 0;
    w->buf = 0;
    w->bits = 0;
}

static int bw_put(bitpack_writer* w, uint32_t value, int nbits)
{
    while (nbits > 0) {
        int take = (nbits >= (10 - w->bits)) ? (10 - w->bits) : nbits;
        w->buf = (w->buf << take) | ((value >> (nbits - take)) & ((1U << take) - 1U));
        w->bits += take;
        nbits   -= take;
        if (w->bits == 10) {
            if (w->count >= w->capacity) return -1;
            w->words[w->count++] = (uint16_t)(w->buf & 0x3FFU);
            w->buf  = 0;
            w->bits = 0;
        }
    }
    return 0;
}

typedef struct {
    const uint16_t* words;
    size_t          total;
    size_t          idx;        /* index of the next 10-bit word to consume */
    uint32_t        buf;        /* bits available in buf, MSB-first */
    int             bits;       /* number of bits available in buf */
} bitpack_reader;

static void br_init(bitpack_reader* r, const uint16_t* words, size_t total)
{
    r->words = words;
    r->total = total;
    r->idx   = 0;
    r->buf   = 0;
    r->bits  = 0;
}

static int br_get(bitpack_reader* r, int nbits, uint32_t* out)
{
    while (r->bits < nbits) {
        if (r->idx >= r->total) return -1;
        r->buf = (r->buf << 10) | (uint32_t)(r->words[r->idx++] & 0x3FFU);
        r->bits += 10;
    }
    r->bits -= nbits;
    *out = (r->buf >> r->bits) & ((nbits == 32) ? 0xFFFFFFFFU : ((1U << nbits) - 1U));
    r->buf &= (r->bits == 0) ? 0U : ((1U << r->bits) - 1U);
    return 0;
}

/* ---------------------------------------------------------------------- */
/*                          Wordlist lookup                                */
/* ---------------------------------------------------------------------- */

static int slip0039_word_to_index(const char* word, size_t word_len)
{
    /* Wordlist is sorted alphabetically; binary search by full string. */
    int lo = 0, hi = SLIP0039_WORDLIST_SIZE - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        const char* m = slip0039_wordlist[mid];
        size_t mlen = strlen(m);
        size_t cmp_len = (mlen < word_len) ? mlen : word_len;
        int cmp = strncmp(m, word, cmp_len);
        if (cmp == 0) {
            if (mlen == word_len) return mid;
            cmp = (mlen < word_len) ? -1 : 1;
        }
        if (cmp < 0) lo = mid + 1;
        else         hi = mid - 1;
    }
    return -1;
}

/* ---------------------------------------------------------------------- */
/*                  Encrypted Master Secret (Feistel)                      */
/* ---------------------------------------------------------------------- */

static int slip0039_round_function(uint8_t round_index,
                                   const uint8_t* passphrase, size_t passlen,
                                   uint16_t identifier,
                                   uint8_t iter_exp,
                                   const uint8_t* r_half, size_t half_len,
                                   uint8_t* out)
{
    /* Password = round_index byte || passphrase. */
    uint8_t pass_buf[1 + 256];
    if (passlen > sizeof(pass_buf) - 1) return -1;
    pass_buf[0] = round_index;
    if (passphrase && passlen) memcpy(pass_buf + 1, passphrase, passlen);

    /* Salt = customization || id (BE 2 bytes) || R. */
    const size_t cust_len = strlen(SLIP0039_CUSTOMIZATION_STRING);
    uint8_t salt_buf[16 + 64];
    if (cust_len + 2 + half_len > sizeof(salt_buf)) return -1;
    memcpy(salt_buf, SLIP0039_CUSTOMIZATION_STRING, cust_len);
    salt_buf[cust_len + 0] = (uint8_t)((identifier >> 8) & 0xFF);
    salt_buf[cust_len + 1] = (uint8_t)(identifier & 0xFF);
    memcpy(salt_buf + cust_len + 2, r_half, half_len);

    uint32_t iters = ((uint32_t)SLIP0039_BASE_ITERATION_COUNT << iter_exp) / SLIP0039_ROUND_COUNT;
    pbkdf2_hmac_sha256(pass_buf, (int)(1 + passlen),
                       salt_buf, (int)(cust_len + 2 + half_len),
                       iters, out, (int)half_len);
    dogecoin_mem_zero(pass_buf, sizeof(pass_buf));
    dogecoin_mem_zero(salt_buf, sizeof(salt_buf));
    return 0;
}

static int slip0039_encrypt(const uint8_t* ms, size_t ms_len,
                            const uint8_t* passphrase, size_t passlen,
                            uint16_t identifier, uint8_t iter_exp,
                            uint8_t* ems_out)
{
    if (ms_len < 2 || (ms_len & 1)) return -1;
    size_t half = ms_len / 2;
    uint8_t L[SLIP0039_MAX_SECRET_BYTES / 2];
    uint8_t R[SLIP0039_MAX_SECRET_BYTES / 2];
    uint8_t F[SLIP0039_MAX_SECRET_BYTES / 2];
    if (half > sizeof(L)) return -1;
    memcpy(L, ms, half);
    memcpy(R, ms + half, half);
    for (uint8_t i = 0; i < SLIP0039_ROUND_COUNT; ++i) {
        if (slip0039_round_function(i, passphrase, passlen, identifier, iter_exp, R, half, F) != 0) {
            dogecoin_mem_zero(L, sizeof(L));
            dogecoin_mem_zero(R, sizeof(R));
            dogecoin_mem_zero(F, sizeof(F));
            return -1;
        }
        for (size_t k = 0; k < half; ++k) F[k] ^= L[k];
        memcpy(L, R, half);
        memcpy(R, F, half);
    }
    /* EMS = R || L per spec. */
    memcpy(ems_out, R, half);
    memcpy(ems_out + half, L, half);
    dogecoin_mem_zero(L, sizeof(L));
    dogecoin_mem_zero(R, sizeof(R));
    dogecoin_mem_zero(F, sizeof(F));
    return 0;
}

static int slip0039_decrypt(const uint8_t* ems, size_t ems_len,
                            const uint8_t* passphrase, size_t passlen,
                            uint16_t identifier, uint8_t iter_exp,
                            uint8_t* ms_out)
{
    if (ems_len < 2 || (ems_len & 1)) return -1;
    size_t half = ems_len / 2;
    uint8_t L[SLIP0039_MAX_SECRET_BYTES / 2];
    uint8_t R[SLIP0039_MAX_SECRET_BYTES / 2];
    uint8_t F[SLIP0039_MAX_SECRET_BYTES / 2];
    if (half > sizeof(L)) return -1;
    memcpy(L, ems, half);
    memcpy(R, ems + half, half);
    for (int i = SLIP0039_ROUND_COUNT - 1; i >= 0; --i) {
        if (slip0039_round_function((uint8_t)i, passphrase, passlen, identifier, iter_exp, R, half, F) != 0) {
            dogecoin_mem_zero(L, sizeof(L));
            dogecoin_mem_zero(R, sizeof(R));
            dogecoin_mem_zero(F, sizeof(F));
            return -1;
        }
        for (size_t k = 0; k < half; ++k) F[k] ^= L[k];
        memcpy(L, R, half);
        memcpy(R, F, half);
    }
    memcpy(ms_out, R, half);
    memcpy(ms_out + half, L, half);
    dogecoin_mem_zero(L, sizeof(L));
    dogecoin_mem_zero(R, sizeof(R));
    dogecoin_mem_zero(F, sizeof(F));
    return 0;
}

/* ---------------------------------------------------------------------- */
/*                          Mnemonic encode / decode                       */
/* ---------------------------------------------------------------------- */

/* Encodes a single share into a mnemonic phrase.
 *  identifier   : 15-bit random
 *  iter_exp     : iteration exponent (0..15)
 *  group_idx    : GI (0..15)
 *  group_thr    : Gt (1..16)
 *  group_count  : g  (1..16)
 *  member_idx   : I  (0..15)
 *  member_thr   : t  (1..16)
 *  share_value  : raw share bytes (length = ems_len bytes)
 *  ems_len      : length in bytes (16..32, even)
 *  out          : caller buffer (must hold SLIP0039_MAX_SHARE_STR_SIZE)
 */
static int slip0039_encode_mnemonic(uint16_t identifier,
                                    uint8_t  iter_exp,
                                    uint8_t  group_idx,
                                    uint8_t  group_thr,
                                    uint8_t  group_count,
                                    uint8_t  member_idx,
                                    uint8_t  member_thr,
                                    const uint8_t* share_value,
                                    size_t   ems_len,
                                    char*    out, size_t out_size)
{
    if (group_thr < 1 || group_count < 1 || member_thr < 1) return -1;
    if (group_thr > 16 || group_count > 16 || member_thr > 16) return -1;
    if (group_idx > 15 || member_idx > 15) return -1;
    if (iter_exp > 15) return -1;
    if (identifier > ((1U << SLIP0039_ID_BITS) - 1)) return -1;
    if (ems_len < SLIP0039_MIN_SECRET_BYTES || ems_len > SLIP0039_MAX_SECRET_BYTES || (ems_len & 1)) return -1;

    /* Number of words for the share value section (including pad bits). */
    size_t share_bits = ems_len * 8;
    size_t pad_bits = (10 - (share_bits % 10)) % 10;
    size_t share_words = (share_bits + pad_bits) / 10;
    size_t total_words = (SLIP0039_METADATA_BITS / 10) + share_words + SLIP0039_CHECKSUM_WORDS;

    uint16_t words[40];
    if (total_words > sizeof(words) / sizeof(words[0])) return -1;
    memset(words, 0, sizeof(words));

    bitpack_writer w;
    bw_init(&w, words, total_words - SLIP0039_CHECKSUM_WORDS);

    if (bw_put(&w, identifier, SLIP0039_ID_BITS)            != 0) return -1;
    if (bw_put(&w, 0, SLIP0039_EXT_BITS)                    != 0) return -1; /* non-extendable */
    if (bw_put(&w, iter_exp, SLIP0039_ITER_EXP_BITS)        != 0) return -1;
    if (bw_put(&w, group_idx, 4)                            != 0) return -1;
    if (bw_put(&w, (uint32_t)(group_thr - 1), 4)            != 0) return -1;
    if (bw_put(&w, (uint32_t)(group_count - 1), 4)          != 0) return -1;
    if (bw_put(&w, member_idx, 4)                           != 0) return -1;
    if (bw_put(&w, (uint32_t)(member_thr - 1), 4)           != 0) return -1;

    /* Pad bits (zeros) to align share value on 10-bit boundary. */
    if (pad_bits) {
        if (bw_put(&w, 0, (int)pad_bits)                    != 0) return -1;
    }

    /* Share value, byte-by-byte MSB first. */
    for (size_t i = 0; i < ems_len; ++i) {
        if (bw_put(&w, share_value[i], 8)                   != 0) return -1;
    }

    /* RS1024 checksum (computed over data + zero placeholders). */
    rs1024_create_checksum(words, total_words);

    /* Render to space-separated mnemonic string. */
    size_t pos = 0;
    for (size_t i = 0; i < total_words; ++i) {
        if (words[i] >= SLIP0039_WORDLIST_SIZE) return -1;
        const char* mn = slip0039_wordlist[words[i]];
        size_t mn_len = strlen(mn);
        size_t need = mn_len + (i + 1 < total_words ? 1 : 1); /* word + space or word + null */
        if (pos + need >= out_size) return -1;
        memcpy(out + pos, mn, mn_len);
        pos += mn_len;
        if (i + 1 < total_words) out[pos++] = ' ';
    }
    out[pos] = '\0';
    return 0;
}

/* Decodes a mnemonic phrase.
 * Outputs metadata fields and the raw share value into *share_value
 * (must hold SLIP0039_MAX_SECRET_BYTES) with length in *value_len.
 */
static int slip0039_decode_mnemonic(const char* mnemonic,
                                    uint16_t* identifier_out,
                                    uint8_t*  iter_exp_out,
                                    uint8_t*  group_idx_out,
                                    uint8_t*  group_thr_out,
                                    uint8_t*  group_count_out,
                                    uint8_t*  member_idx_out,
                                    uint8_t*  member_thr_out,
                                    uint8_t*  share_value, size_t* value_len)
{
    if (!mnemonic || !share_value || !value_len) return -1;

    /* Tokenize words into 10-bit indices. */
    uint16_t words[40];
    size_t   total_words = 0;
    const char* p = mnemonic;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') ++p;
        if (!*p) break;
        const char* start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') ++p;
        size_t wlen = (size_t)(p - start);
        if (wlen == 0 || wlen > 8) return -1;
        if (total_words >= sizeof(words) / sizeof(words[0])) return -1;
        int idx = slip0039_word_to_index(start, wlen);
        if (idx < 0) return -1;
        words[total_words++] = (uint16_t)idx;
    }

    if (total_words < (SLIP0039_METADATA_BITS / 10) + SLIP0039_CHECKSUM_WORDS + 1) return -1;
    if (total_words > sizeof(words) / sizeof(words[0])) return -1;

    /* Verify RS1024 checksum. */
    if (rs1024_verify_checksum(words, total_words) != 0) return -1;

    size_t share_words = total_words - (SLIP0039_METADATA_BITS / 10) - SLIP0039_CHECKSUM_WORDS;
    size_t share_bits  = share_words * 10;
    /* Determine padding so share_bits - pad is a whole-byte share value. */
    /* For 16-byte share: share_words=13 -> share_bits=130 -> pad=2 -> 128 = 16 bytes. */
    /* For 32-byte share: share_words=26 -> share_bits=260 -> pad=4 -> 256 = 32 bytes. */
    if (share_bits < 8) return -1;
    size_t pad_bits = share_bits % 8;
    if (pad_bits >= 10) return -1; /* per spec: pad must be < radix */
    size_t value_bits = share_bits - pad_bits;
    if ((value_bits & 7) != 0) return -1;
    size_t ems_len = value_bits / 8;
    if (ems_len < SLIP0039_MIN_SECRET_BYTES || ems_len > SLIP0039_MAX_SECRET_BYTES) return -1;
    if (*value_len < ems_len) return -1;

    bitpack_reader r;
    br_init(&r, words, total_words - SLIP0039_CHECKSUM_WORDS);

    uint32_t v = 0;
    if (br_get(&r, SLIP0039_ID_BITS, &v) != 0)        return -1;
    *identifier_out = (uint16_t)v;
    if (br_get(&r, SLIP0039_EXT_BITS, &v) != 0)       return -1;
    /* Only non-extendable (ext == 0) is supported. */
    if (v != 0)                                       return -1;
    if (br_get(&r, SLIP0039_ITER_EXP_BITS, &v) != 0)  return -1;
    *iter_exp_out = (uint8_t)v;
    if (br_get(&r, 4, &v) != 0) return -1;
    *group_idx_out = (uint8_t)v;
    if (br_get(&r, 4, &v) != 0) return -1;
    *group_thr_out = (uint8_t)(v + 1);
    if (br_get(&r, 4, &v) != 0) return -1;
    *group_count_out = (uint8_t)(v + 1);
    if (br_get(&r, 4, &v) != 0) return -1;
    *member_idx_out = (uint8_t)v;
    if (br_get(&r, 4, &v) != 0) return -1;
    *member_thr_out = (uint8_t)(v + 1);

    /* Verify pad bits are zero. */
    if (pad_bits) {
        if (br_get(&r, (int)pad_bits, &v) != 0) return -1;
        if (v != 0) return -1;
    }
    /* Read share bytes. */
    for (size_t i = 0; i < ems_len; ++i) {
        if (br_get(&r, 8, &v) != 0) return -1;
        share_value[i] = (uint8_t)v;
    }
    *value_len = ems_len;
    return 0;
}

/* ---------------------------------------------------------------------- */
/*                Shamir split / combine over EMS bytes                    */
/* ---------------------------------------------------------------------- */

/* Computes the digest share value of length ems_len:
 *   digest = HMAC-SHA256(R, secret)[:4]
 *   value  = digest || R   (R is provided in random_pad of length ems_len-4)
 */
static void slip0039_make_digest_share(const uint8_t* secret, size_t ems_len,
                                       const uint8_t* random_pad,
                                       uint8_t* out)
{
    uint8_t mac[32];
    hmac_sha256(random_pad, ems_len - SLIP0039_DIGEST_LENGTH_BYTES,
                secret, ems_len, mac);
    memcpy(out, mac, SLIP0039_DIGEST_LENGTH_BYTES);
    memcpy(out + SLIP0039_DIGEST_LENGTH_BYTES, random_pad,
           ems_len - SLIP0039_DIGEST_LENGTH_BYTES);
    dogecoin_mem_zero(mac, sizeof(mac));
}

static int slip0039_verify_digest_share(const uint8_t* secret, size_t ems_len,
                                        const uint8_t* digest_share)
{
    uint8_t mac[32];
    hmac_sha256(digest_share + SLIP0039_DIGEST_LENGTH_BYTES,
                ems_len - SLIP0039_DIGEST_LENGTH_BYTES,
                secret, ems_len, mac);
    int ok = (memcmp(mac, digest_share, SLIP0039_DIGEST_LENGTH_BYTES) == 0) ? 0 : -1;
    dogecoin_mem_zero(mac, sizeof(mac));
    return ok;
}

/* Split EMS into n member shares with threshold t.
 *  shares_x[i]      = i for i in [0, n)
 *  shares_y[i*ems_len .. (i+1)*ems_len] = share value
 */
static int slip0039_split(const uint8_t* ems, size_t ems_len,
                          uint8_t threshold, uint8_t share_count,
                          uint8_t* shares_y_out)
{
    if (threshold < 1 || share_count < threshold || share_count > SLIP0039_MAX_SHARES) return -1;

    if (threshold == 1) {
        for (uint8_t i = 0; i < share_count; ++i) {
            memcpy(shares_y_out + i * ems_len, ems, ems_len);
        }
        return 0;
    }

    /* Build T known points: indices 0..T-3 random, plus digest at 254 and secret at 255. */
    uint8_t known_x[SLIP0039_MAX_SHARES + 2];
    uint8_t known_y[(SLIP0039_MAX_SHARES + 2) * SLIP0039_MAX_SECRET_BYTES];
    size_t  known_n = 0;

    /* Random shares with x = 0..T-3, becoming the first T-2 user shares. */
    for (uint8_t i = 0; i + 2 < threshold; ++i) {
        if (!dogecoin_random_bytes(known_y + known_n * ems_len, (uint32_t)ems_len, 0)) {
            return -1;
        }
        known_x[known_n] = i;
        memcpy(shares_y_out + i * ems_len, known_y + known_n * ems_len, ems_len);
        ++known_n;
    }

    /* Digest share at x = 254. */
    uint8_t random_pad[SLIP0039_MAX_SECRET_BYTES];
    if (!dogecoin_random_bytes(random_pad, (uint32_t)(ems_len - SLIP0039_DIGEST_LENGTH_BYTES), 0)) {
        return -1;
    }
    uint8_t digest_share[SLIP0039_MAX_SECRET_BYTES];
    slip0039_make_digest_share(ems, ems_len, random_pad, digest_share);
    known_x[known_n] = SLIP0039_DIGEST_INDEX;
    memcpy(known_y + known_n * ems_len, digest_share, ems_len);
    ++known_n;

    /* Secret share at x = 255. */
    known_x[known_n] = SLIP0039_SECRET_INDEX;
    memcpy(known_y + known_n * ems_len, ems, ems_len);
    ++known_n;

    /* Interpolate remaining user shares for x = T-2 .. share_count-1. */
    for (uint8_t i = (uint8_t)(threshold - 2); i < share_count; ++i) {
        uint8_t y[SLIP0039_MAX_SECRET_BYTES];
        if (gf256_lagrange(i, known_x, known_n, known_y, ems_len, y) != 0) {
            dogecoin_mem_zero(known_y, sizeof(known_y));
            dogecoin_mem_zero(random_pad, sizeof(random_pad));
            dogecoin_mem_zero(digest_share, sizeof(digest_share));
            return -1;
        }
        memcpy(shares_y_out + i * ems_len, y, ems_len);
        dogecoin_mem_zero(y, sizeof(y));
    }

    dogecoin_mem_zero(known_y, sizeof(known_y));
    dogecoin_mem_zero(random_pad, sizeof(random_pad));
    dogecoin_mem_zero(digest_share, sizeof(digest_share));
    return 0;
}

/* Combine T shares (indices in xs[], values stacked in ys[]) into the
 * encrypted master secret, verifying the digest share when threshold > 1.
 */
static int slip0039_combine(const uint8_t* xs, const uint8_t* ys,
                            size_t n, size_t ems_len, uint8_t threshold,
                            uint8_t* ems_out)
{
    if (n != threshold) return -1;
    if (threshold == 1) {
        memcpy(ems_out, ys, ems_len);
        return 0;
    }

    /* Recover secret at x=255. */
    if (gf256_lagrange(SLIP0039_SECRET_INDEX, xs, n, ys, ems_len, ems_out) != 0) return -1;

    /* Recover digest share at x=254 and verify. */
    uint8_t digest_share[SLIP0039_MAX_SECRET_BYTES];
    if (gf256_lagrange(SLIP0039_DIGEST_INDEX, xs, n, ys, ems_len, digest_share) != 0) {
        dogecoin_mem_zero(digest_share, sizeof(digest_share));
        return -1;
    }
    int ok = slip0039_verify_digest_share(ems_out, ems_len, digest_share);
    dogecoin_mem_zero(digest_share, sizeof(digest_share));
    if (ok != 0) return -1;
    return 0;
}

/* ---------------------------------------------------------------------- */
/*                              Public API                                 */
/* ---------------------------------------------------------------------- */

int dogecoin_slip0039_generate_shares(const uint8_t* secret, size_t secret_len,
                                      uint8_t threshold, uint8_t share_count,
                                      char shares[][SLIP0039_MAX_SHARE_STR_SIZE])
{
    if (!secret || !shares) return -1;
    if (secret_len < SLIP0039_MIN_SECRET_BYTES ||
        secret_len > SLIP0039_MAX_SECRET_BYTES ||
        (secret_len & 1)) {
        return -1;
    }
    if (threshold < 1 || share_count < threshold || share_count > SLIP0039_MAX_SHARES) {
        return -1;
    }

    /* Pick a random 15-bit identifier. */
    uint8_t id_bytes[2];
    if (!dogecoin_random_bytes(id_bytes, sizeof(id_bytes), 0)) return -1;
    uint16_t identifier = (uint16_t)((((uint16_t)id_bytes[0] << 8) | id_bytes[1]) & 0x7FFFU);
    uint8_t  iter_exp = SLIP0039_DEFAULT_ITER_EXP;

    /* Encrypt master secret to EMS. */
    uint8_t ems[SLIP0039_MAX_SECRET_BYTES];
    if (slip0039_encrypt(secret, secret_len, NULL, 0, identifier, iter_exp, ems) != 0) {
        return -1;
    }

    /* Shamir split EMS into share values. */
    uint8_t share_y[SLIP0039_MAX_SHARES * SLIP0039_MAX_SECRET_BYTES];
    if (slip0039_split(ems, secret_len, threshold, share_count, share_y) != 0) {
        dogecoin_mem_zero(ems, sizeof(ems));
        dogecoin_mem_zero(share_y, sizeof(share_y));
        return -1;
    }

    /* Encode each share as a mnemonic. */
    for (uint8_t i = 0; i < share_count; ++i) {
        if (slip0039_encode_mnemonic(identifier, iter_exp,
                                     0 /* GI */, 1 /* Gt */, 1 /* g */,
                                     i /* I */, threshold /* t */,
                                     share_y + (size_t)i * secret_len, secret_len,
                                     shares[i], SLIP0039_MAX_SHARE_STR_SIZE) != 0) {
            dogecoin_mem_zero(ems, sizeof(ems));
            dogecoin_mem_zero(share_y, sizeof(share_y));
            return -1;
        }
    }

    dogecoin_mem_zero(ems, sizeof(ems));
    dogecoin_mem_zero(share_y, sizeof(share_y));
    return 0;
}

int dogecoin_slip0039_recover_secret(const char* shares[], size_t share_count,
                                     uint8_t* secret_out, size_t* secret_len_out)
{
    if (!shares || !share_count || !secret_out || !secret_len_out) return -1;
    if (share_count > SLIP0039_MAX_SHARES) return -1;

    uint16_t common_id = 0;
    uint8_t  common_iter = 0;
    uint8_t  common_thr = 0;
    size_t   common_len = 0;
    uint8_t  used_idx[16];
    memset(used_idx, 0, sizeof(used_idx));

    uint8_t xs[SLIP0039_MAX_SHARES];
    uint8_t ys[SLIP0039_MAX_SHARES * SLIP0039_MAX_SECRET_BYTES];

    for (size_t i = 0; i < share_count; ++i) {
        if (!shares[i]) return -1;

        uint16_t id; uint8_t e, gi, gt, gc, mi, mt;
        uint8_t value[SLIP0039_MAX_SECRET_BYTES];
        size_t  vlen = sizeof(value);
        if (slip0039_decode_mnemonic(shares[i], &id, &e, &gi, &gt, &gc, &mi, &mt, value, &vlen) != 0) {
            dogecoin_mem_zero(value, sizeof(value));
            return -1;
        }
        /* This implementation only supports a single group. */
        if (gt != 1 || gc != 1 || gi != 0) {
            dogecoin_mem_zero(value, sizeof(value));
            return -1;
        }
        if (i == 0) {
            common_id = id; common_iter = e; common_thr = mt; common_len = vlen;
        } else if (id != common_id || e != common_iter || mt != common_thr || vlen != common_len) {
            dogecoin_mem_zero(value, sizeof(value));
            return -1;
        }
        if (mi >= SLIP0039_MAX_SHARES || used_idx[mi]) {
            dogecoin_mem_zero(value, sizeof(value));
            return -1;
        }
        used_idx[mi] = 1;
        xs[i] = mi;
        memcpy(ys + i * common_len, value, common_len);
        dogecoin_mem_zero(value, sizeof(value));
    }

    if (share_count != common_thr) return -1;

    /* Combine to recover the EMS, then decrypt to get the master secret. */
    uint8_t ems[SLIP0039_MAX_SECRET_BYTES];
    if (slip0039_combine(xs, ys, share_count, common_len, common_thr, ems) != 0) {
        dogecoin_mem_zero(ys, sizeof(ys));
        return -1;
    }

    if (*secret_len_out < common_len) {
        dogecoin_mem_zero(ems, sizeof(ems));
        dogecoin_mem_zero(ys, sizeof(ys));
        return -1;
    }

    if (slip0039_decrypt(ems, common_len, NULL, 0, common_id, common_iter, secret_out) != 0) {
        dogecoin_mem_zero(ems, sizeof(ems));
        dogecoin_mem_zero(ys, sizeof(ys));
        return -1;
    }
    *secret_len_out = common_len;

    dogecoin_mem_zero(ems, sizeof(ems));
    dogecoin_mem_zero(ys, sizeof(ys));
    return 0;
}
