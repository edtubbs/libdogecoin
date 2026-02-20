/*

 The MIT License (MIT)

 Copyright (c) 2023-2024 The Dogecoin Foundation

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

#include <string.h>

#include <dogecoin/bip37.h>
#include <dogecoin/hash.h>
#include <dogecoin/protocol.h>
#include <dogecoin/random.h>
#include <dogecoin/utils.h>

static void bip37_hash_to_hex(const uint8_t hash[32], char out_hex[65])
{
    unsigned char tmp[32];
    memcpy(tmp, hash, 32);
    utils_bin_to_hex(tmp, 32, out_hex);
}

/**
 * MurmurHash3 (x86 32-bit) used by BIP37 bloom filters.
 */
static uint32_t bip37_murmur3(const uint8_t* key, size_t len, uint32_t seed)
{
    uint32_t h = seed;
    size_t i = 0;
    for (; i + 4 <= len; i += 4) {
        uint32_t k = key[i] | (key[i + 1] << 8) | (key[i + 2] << 16) | (key[i + 3] << 24);
        k *= 0xcc9e2d51u;
        k = (k << 15) | (k >> 17);
        k *= 0x1b873593u;
        h ^= k;
        h = (h << 13) | (h >> 19);
        h = h * 5 + 0xe6546b64u;
    }

    uint32_t k = 0;
    switch (len - i) {
        case 3: k ^= key[i + 2] << 16; /* fall through */
        case 2: k ^= key[i + 1] << 8;  /* fall through */
        case 1: k ^= key[i];
    }

    if (len - i > 0) {
        k *= 0xcc9e2d51u;
        k = (k << 15) | (k >> 17);
        k *= 0x1b873593u;
        h ^= k;
    }

    h ^= (uint32_t)len;
    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    h *= 0xc2b2ae35u;
    h ^= h >> 16;
    return h;
}

typedef struct bip37_merkle_match_ {
    uint256_t txid;
    uint32_t pos;
    dogecoin_bool consumed;
} bip37_merkle_match;

static int bip37_merkle_match_cmp(const void* a, const void* b)
{
    const bip37_merkle_match* ma = (const bip37_merkle_match*)a;
    const bip37_merkle_match* mb = (const bip37_merkle_match*)b;
    return memcmp(ma->txid, mb->txid, 32);
}

typedef struct bip37_merkle_collect_ctx_ {
    void** match_tree;
    uint32_t* match_pending;
} bip37_merkle_collect_ctx;

/* Callback bridge used by bip37 merkle traversal to collect matched txids. */
static dogecoin_bool bip37_merkle_collect_match(const uint8_t txid[32], uint32_t pos, void* ctx)
{
    bip37_merkle_collect_ctx* c = (bip37_merkle_collect_ctx*)ctx;
    if (!c || !c->match_tree || !c->match_pending) return false;

    bip37_merkle_match* m = (bip37_merkle_match*)dogecoin_calloc(1, sizeof(bip37_merkle_match));
    if (!m) return false;

    memcpy(m->txid, txid, 32);
    m->pos = pos;
    m->consumed = false;

    dogecoin_btree_node_t* nn = (dogecoin_btree_node_t*)dogecoin_btree_tsearch(
        m, c->match_tree, bip37_merkle_match_cmp);
    if (!nn) {
        dogecoin_free(m);
        return false;
    }
    char txid_hex[65];
    bip37_hash_to_hex(txid, txid_hex);
    if (nn->key != m) {
        debug_print("[bip37][collect] duplicate txid=%s pos=%u\n", txid_hex, pos);
        dogecoin_free(m);
    } else {
        debug_print("[bip37][collect] insert txid=%s pos=%u\n", txid_hex, pos);
        (*c->match_pending)++;
    }
    return true;
}

/**
 * Traverse a BIP37 partial merkle tree and verify the calculated root.
 *
 * The function follows the same depth-first walk as Bitcoin Core's
 * TraverseAndExtract logic. For every matched leaf (tx hash where the
 * parent bit is set), it invokes @p on_match with the txid and leaf position.
 *
 * @return true when traversal succeeds and calculated root equals header_merkle.
 */
dogecoin_bool dogecoin_bip37_traverse_merkle_matches(uint32_t nTx,
                                                     const uint8_t* hashes,
                                                     uint32_t hashCount,
                                                     const uint8_t* flags,
                                                     uint32_t flags_len,
                                                     const uint8_t header_merkle[32],
                                                     dogecoin_bip37_match_cb on_match,
                                                     void* match_ctx)
{
    if (!hashes || !flags || !header_merkle || hashCount == 0 || flags_len == 0) return false;

    uint32_t height = 0;
    while (1) {
        uint64_t width = ((uint64_t)nTx + ((1ULL << height) - 1ULL)) >> height;
        if (width <= 1) break;
        height++;
        if (height > 32) return false;
    }
    debug_print("[bip37][traverse] start nTx=%u hashCount=%u flags_len=%u tree_height=%u\n",
                nTx, hashCount, flags_len, height);

    uint32_t bitsUsed = 0;
    uint32_t hashesUsed = 0;

    struct {
        uint32_t height;
        uint32_t pos;
        uint8_t stage;
        uint8_t parentMatch;
        uint256_t left;
    } st[64];

    int sp = 0;
    st[0].height = height;
    st[0].pos = 0;
    st[0].stage = 0;
    st[0].parentMatch = 0;

    uint256_t ret;
    dogecoin_bool have_ret = false;
    dogecoin_bool ok_extract = true;

    while (sp >= 0) {
        if (st[sp].stage == 0) {
            if (bitsUsed >= (uint32_t)flags_len * 8U) { ok_extract = false; break; }
            st[sp].parentMatch = (flags[bitsUsed >> 3] >> (bitsUsed & 7)) & 1;
            debug_print("[bip37][traverse] visit h=%u pos=%u parentMatch=%u bitsUsed=%u hashesUsed=%u\n",
                        st[sp].height, st[sp].pos, st[sp].parentMatch, bitsUsed, hashesUsed);
            bitsUsed++;

            /* Leaf node, or an internal node that does not match: consume one hash. */
            if (st[sp].height == 0 || st[sp].parentMatch == 0) {
                if (hashesUsed >= hashCount) { ok_extract = false; break; }
                memcpy(ret, hashes + (hashesUsed * 32), 32);
                hashesUsed++;
                have_ret = true;

                if (st[sp].height == 0 && st[sp].parentMatch && on_match &&
                    !on_match(ret, st[sp].pos, match_ctx)) {
                    ok_extract = false;
                    break;
                }
                if (st[sp].height == 0 && st[sp].parentMatch) {
                    char txid_hex[65];
                    bip37_hash_to_hex(ret, txid_hex);
                    debug_print("[bip37][traverse] matched leaf txid=%s pos=%u\n", txid_hex, st[sp].pos);
                }

                sp--;
                continue;
            }

            /* Internal matched node: recurse into left child first. */
            st[sp].stage = 1;
            sp++;
            st[sp].height = st[sp - 1].height - 1;
            st[sp].pos = st[sp - 1].pos * 2;
            st[sp].stage = 0;
            st[sp].parentMatch = 0;
            continue;
        }

        if (st[sp].stage == 1) {
            if (!have_ret) { ok_extract = false; break; }
            memcpy(st[sp].left, ret, 32);

            uint64_t width = ((uint64_t)nTx + ((1ULL << (st[sp].height - 1)) - 1ULL)) >> (st[sp].height - 1);
            uint32_t rightPos = st[sp].pos * 2 + 1;

            if ((uint64_t)rightPos < width) {
                /* Right child exists: recurse into it. */
                st[sp].stage = 2;
                sp++;
                st[sp].height = st[sp - 1].height - 1;
                st[sp].pos = rightPos;
                st[sp].stage = 0;
                st[sp].parentMatch = 0;
                have_ret = false;
                continue;
            } else {
                /* Right child absent at this width, duplicate left hash. */
                uint8_t buf64[64];
                memcpy(buf64, st[sp].left, 32);
                memcpy(buf64 + 32, st[sp].left, 32);
                dogecoin_hash(buf64, 64, ret);
                have_ret = true;
                sp--;
                continue;
            }
        }

        if (st[sp].stage == 2) {
            /* Combine left and right child hashes and bubble up. */
            if (!have_ret) { ok_extract = false; break; }
            uint8_t buf64[64];
            memcpy(buf64, st[sp].left, 32);
            memcpy(buf64 + 32, ret, 32);
            dogecoin_hash(buf64, 64, ret);
            have_ret = true;
            sp--;
            continue;
        }

        ok_extract = false;
        break;
    }
    dogecoin_bool ok = (ok_extract && have_ret && memcmp(ret, header_merkle, 32) == 0);
    debug_print("[bip37][traverse] done ok=%d bitsUsed=%u hashesUsed=%u\n",
                ok, bitsUsed, hashesUsed);
    return ok;
}

dogecoin_bool dogecoin_bip37_merkle_extract_match_tree(uint32_t nTx,
                                                       const uint8_t* hashes,
                                                       uint32_t hashCount,
                                                       const uint8_t* flags,
                                                       uint32_t flags_len,
                                                       const uint8_t header_merkle[32],
                                                       void** match_tree,
                                                       uint32_t* match_pending)
{
    if (!match_tree || !match_pending) return false;
    *match_pending = 0;

    bip37_merkle_collect_ctx ctx;
    ctx.match_tree = match_tree;
    ctx.match_pending = match_pending;

    return dogecoin_bip37_traverse_merkle_matches(nTx,
                                                  hashes,
                                                  hashCount,
                                                  flags,
                                                  flags_len,
                                                  header_merkle,
                                                  bip37_merkle_collect_match,
                                                  &ctx);
}

dogecoin_bool dogecoin_bip37_merkle_match_consume(void** match_tree,
                                                  uint32_t* match_pending,
                                                  const uint8_t txid[32],
                                                  uint32_t* out_pos)
{
    if (!match_tree || !*match_tree || !match_pending || !txid) return false;

    bip37_merkle_match key;
    memset(&key, 0, sizeof(key));
    memcpy(key.txid, txid, 32);

    dogecoin_btree_node_t* found = (dogecoin_btree_node_t*)dogecoin_btree_tfind(
        &key, (void* const*)match_tree, bip37_merkle_match_cmp);
    if (!found || !found->key) return false;

    bip37_merkle_match* m = (bip37_merkle_match*)found->key;
    if (m->consumed) return false;

    m->consumed = true;
    if (*match_pending > 0) (*match_pending)--;
    if (out_pos) *out_pos = m->pos;
    return true;
}

static dogecoin_bool bip37_walk_merkle_matches(const dogecoin_btree_node_t* node,
                                               dogecoin_bip37_match_info_cb cb,
                                               void* ctx)
{
    if (!node) return true;
    if (!bip37_walk_merkle_matches(node->left, cb, ctx)) return false;

    if (cb && node->key) {
        const bip37_merkle_match* m = (const bip37_merkle_match*)node->key;
        if (!cb(m->txid, m->pos, m->consumed, ctx)) return false;
    }

    if (!bip37_walk_merkle_matches(node->right, cb, ctx)) return false;
    return true;
}

dogecoin_bool dogecoin_bip37_merkle_for_each_match(void* match_tree,
                                                   dogecoin_bip37_match_info_cb cb,
                                                   void* ctx)
{
    if (!match_tree || !cb) return false;
    return bip37_walk_merkle_matches((const dogecoin_btree_node_t*)match_tree, cb, ctx);
}

/**
 * Create a fixed-size BIP37 bloom filter using protocol maximums.
 *
 * This helper avoids floating-point sizing logic and mirrors the existing
 * CLI behavior of using maximum size/hash-function limits.
 */
dogecoin_bip37_filter* dogecoin_bip37_filter_new(uint32_t tweak, uint8_t flags)
{
    dogecoin_bip37_filter* filter = (dogecoin_bip37_filter*)dogecoin_calloc(1, sizeof(dogecoin_bip37_filter));
    if (!filter) return NULL;

    filter->data_len = 36000;     /* BIP37 max filter size in bytes */
    filter->n_hash_funcs = 50;    /* BIP37 max hash function count */
    filter->data = (uint8_t*)dogecoin_calloc(filter->data_len, 1);
    if (!filter->data) {
        dogecoin_free(filter);
        return NULL;
    }
    if (tweak) {
        filter->n_tweak = tweak;
    } else {
        /* Use secure RNG for tweak when caller doesn't provide one. */
        uint8_t tweak_bytes[4];
        if (!dogecoin_random_bytes(tweak_bytes, sizeof(tweak_bytes), 0)) {
            dogecoin_bip37_filter_free(filter);
            return NULL;
        }
        filter->n_tweak = (uint32_t)tweak_bytes[0]
                        | ((uint32_t)tweak_bytes[1] << 8)
                        | ((uint32_t)tweak_bytes[2] << 16)
                        | ((uint32_t)tweak_bytes[3] << 24);
    }
    filter->n_flags = flags;
    return filter;
}

/**
 * Add an element to a BIP37 bloom filter.
 *
 * @return true when input was accepted and bits were updated.
 */
dogecoin_bool dogecoin_bip37_filter_add(dogecoin_bip37_filter* filter,
                                        const uint8_t* data,
                                        size_t data_len)
{
    if (!filter || !filter->data || !data || data_len == 0 || filter->data_len == 0) return false;

    for (uint32_t i = 0; i < filter->n_hash_funcs; i++) {
        uint32_t seed = i * 0xfba4c795u + filter->n_tweak;
        uint32_t idx = bip37_murmur3(data, data_len, seed) % (uint32_t)(filter->data_len * 8);
        filter->data[idx / 8] |= (1u << (idx % 8));
    }
    return true;
}

/**
 * Free a BIP37 bloom filter allocated by dogecoin_bip37_filter_new.
 */
void dogecoin_bip37_filter_free(dogecoin_bip37_filter* filter)
{
    if (!filter) return;
    if (filter->data) dogecoin_free(filter->data);
    dogecoin_free(filter);
}

/**
 * Rewrite a getdata/inv payload so BLOCK entries become FILTERED_BLOCK entries.
 *
 * Used when a bloom filter is active and the SPV client wants merkleblock+tx
 * responses instead of full blocks.
 */
dogecoin_bool dogecoin_bip37_build_filtered_getdata_payload(const struct const_buffer* inv_payload,
                                                            uint8_t** out_payload,
                                                            uint32_t* out_len,
                                                            uint32_t* item_count)
{
    if (!inv_payload || !out_payload || !out_len || !item_count) return false;

    *out_payload = NULL;
    *out_len = 0;
    *item_count = 0;

    struct const_buffer inv = { inv_payload->p, inv_payload->len };
    uint32_t n = 0;
    if (!deser_varlen(&n, &inv)) return false;

    cstring* out = cstr_new_sz(inv_payload->len);
    if (!out) return false;
    ser_varlen(out, n);

    for (uint32_t i = 0; i < n; i++) {
        uint32_t type = 0;
        uint256_t h;
        if (!deser_u32(&type, &inv) || !deser_u256(h, &inv)) {
            cstr_free(out, true);
            return false;
        }

        if (type == DOGECOIN_INV_TYPE_BLOCK) {
            type = DOGECOIN_INV_TYPE_FILTERED_BLOCK;
        }

        ser_u32(out, type);
        ser_u256(out, h);
    }

    *out_payload = (uint8_t*)dogecoin_calloc(1, out->len);
    if (!*out_payload) {
        cstr_free(out, true);
        return false;
    }
    memcpy(*out_payload, out->str, out->len);
    *out_len = (uint32_t)out->len;
    *item_count = n;
    cstr_free(out, true);
    return true;
}
