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
#include <dogecoin/protocol.h>
#include <dogecoin/random.h>
#include <dogecoin/spv.h>
#include <dogecoin/utils.h>
#include <dogecoin/vector.h>

/**
 * Serialize a compactSize integer into a caller-provided buffer.
 *
 * @return Number of bytes written to @p out.
 */
static size_t bip37_write_varint(uint64_t val, uint8_t out[9])
{
    if (val < 0xfdULL) {
        out[0] = (uint8_t)val;
        return 1;
    }
    if (val <= 0xffffULL) {
        out[0] = 0xfd;
        out[1] = (uint8_t)(val & 0xff);
        out[2] = (uint8_t)((val >> 8) & 0xff);
        return 3;
    }
    if (val <= 0xffffffffULL) {
        out[0] = 0xfe;
        out[1] = (uint8_t)(val & 0xff);
        out[2] = (uint8_t)((val >> 8) & 0xff);
        out[3] = (uint8_t)((val >> 16) & 0xff);
        out[4] = (uint8_t)((val >> 24) & 0xff);
        return 5;
    }
    out[0] = 0xff;
    out[1] = (uint8_t)(val & 0xff);
    out[2] = (uint8_t)((val >> 8) & 0xff);
    out[3] = (uint8_t)((val >> 16) & 0xff);
    out[4] = (uint8_t)((val >> 24) & 0xff);
    out[5] = (uint8_t)((val >> 32) & 0xff);
    out[6] = (uint8_t)((val >> 40) & 0xff);
    out[7] = (uint8_t)((val >> 48) & 0xff);
    out[8] = (uint8_t)((val >> 56) & 0xff);
    return 9;
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

    return (ok_extract && have_ret && memcmp(ret, header_merkle, 32) == 0);
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
 * Build and send a BIP37 filterload message to a peer.
 *
 * @return true if the message was built and queued for send, false otherwise.
 */
dogecoin_bool dogecoin_bip37_send_filterload(struct dogecoin_node_* node,
                                             const uint8_t* filter,
                                             uint32_t filter_len,
                                             uint32_t nHashFuncs,
                                             uint32_t nTweak,
                                             uint8_t flags)
{
    if (!node || !filter || filter_len == 0) return false;

    uint8_t vi[9];
    size_t vi_len = bip37_write_varint((uint64_t)filter_len, vi);
    size_t payload_len = vi_len + (size_t)filter_len + 4 + 4 + 1;
    uint8_t* payload = (uint8_t*)dogecoin_calloc(1, payload_len);
    if (!payload) return false;

    size_t off = 0;
    memcpy(payload + off, vi, vi_len); off += vi_len;
    memcpy(payload + off, filter, filter_len); off += filter_len;

    payload[off + 0] = (uint8_t)(nHashFuncs & 0xff);
    payload[off + 1] = (uint8_t)((nHashFuncs >> 8) & 0xff);
    payload[off + 2] = (uint8_t)((nHashFuncs >> 16) & 0xff);
    payload[off + 3] = (uint8_t)((nHashFuncs >> 24) & 0xff);
    off += 4;

    payload[off + 0] = (uint8_t)(nTweak & 0xff);
    payload[off + 1] = (uint8_t)((nTweak >> 8) & 0xff);
    payload[off + 2] = (uint8_t)((nTweak >> 16) & 0xff);
    payload[off + 3] = (uint8_t)((nTweak >> 24) & 0xff);
    off += 4;

    payload[off] = flags;

    cstring* msg = dogecoin_p2p_message_new(
        node->nodegroup->chainparams->netmagic,
        DOGECOIN_MSG_FILTERLOAD,
        payload,
        (uint32_t)payload_len
    );
    dogecoin_node_send(node, msg);
    cstr_free(msg, true);
    dogecoin_free(payload);
    return true;
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

    uint8_t* out = (uint8_t*)dogecoin_calloc(1, inv_payload->len);
    if (!out) return false;

    size_t off = bip37_write_varint((uint64_t)n, out);
    for (uint32_t i = 0; i < n; i++) {
        uint32_t type = 0;
        uint256_t h;
        if (!deser_u32(&type, &inv) || !deser_u256(h, &inv)) {
            dogecoin_free(out);
            return false;
        }

        if (type == DOGECOIN_INV_TYPE_BLOCK) {
            type = DOGECOIN_INV_TYPE_FILTERED_BLOCK;
        }

        out[off + 0] = (uint8_t)(type & 0xff);
        out[off + 1] = (uint8_t)((type >> 8) & 0xff);
        out[off + 2] = (uint8_t)((type >> 16) & 0xff);
        out[off + 3] = (uint8_t)((type >> 24) & 0xff);
        off += 4;
        memcpy(out + off, h, 32);
        off += 32;
    }

    *out_payload = out;
    *out_len = (uint32_t)off;
    *item_count = n;
    return true;
}

LIBDOGECOIN_API dogecoin_bool dogecoin_spv_client_filterload(
    dogecoin_spv_client* client,
    const uint8_t* filter,
    uint32_t filter_len,
    uint32_t nHashFuncs,
    uint32_t nTweak,
    uint8_t flags)
{
    if (!client || !filter || filter_len == 0) return false;

    if (client->bloom_filter) {
        dogecoin_free(client->bloom_filter);
        client->bloom_filter = NULL;
    }

    client->bloom_filter = (uint8_t*)dogecoin_calloc(filter_len, 1);
    if (!client->bloom_filter) return false;

    memcpy(client->bloom_filter, filter, filter_len);
    client->bloom_filter_len = filter_len;
    client->bloom_nhashfunc = nHashFuncs;
    client->bloom_ntweak = nTweak;
    client->bloom_flags = flags;

    if (!client->nodegroup || !client->nodegroup->nodes) return true;

    for (unsigned int i = 0; i < (unsigned int)client->nodegroup->nodes->len; i++) {
        dogecoin_node* n = (dogecoin_node*)vector_idx(client->nodegroup->nodes, i);
        if (!n) continue;
        if (((n->state & NODE_CONNECTED) != NODE_CONNECTED) || !n->version_handshake) continue;
        dogecoin_bip37_send_filterload(n, filter, filter_len, nHashFuncs, nTweak, flags);
    }

    if (client->nodegroup && client->nodegroup->log_write_cb)
        client->nodegroup->log_write_cb("[spv] filterload set (len=%u)\n", filter_len);

    return true;
}

/**
 * Send a BIP37 filteradd message to all connected, handshaked peers.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_spv_client_filteradd(
    dogecoin_spv_client* client,
    const uint8_t* data,
    uint32_t data_len)
{
    if (!client || !data || data_len == 0) return false;
    if (!client->nodegroup || !client->nodegroup->nodes) return true;

    uint8_t vi[9];
    size_t vi_len = bip37_write_varint((uint64_t)data_len, vi);
    size_t payload_len = vi_len + (size_t)data_len;
    uint8_t* payload = (uint8_t*)dogecoin_calloc(1, payload_len);
    if (!payload) return false;

    memcpy(payload, vi, vi_len);
    memcpy(payload + vi_len, data, data_len);

    for (unsigned int i = 0; i < (unsigned int)client->nodegroup->nodes->len; i++) {
        dogecoin_node* n = (dogecoin_node*)vector_idx(client->nodegroup->nodes, i);
        if (!n) continue;
        if (((n->state & NODE_CONNECTED) != NODE_CONNECTED) || !n->version_handshake) continue;

        cstring* msg = dogecoin_p2p_message_new(
            n->nodegroup->chainparams->netmagic,
            DOGECOIN_MSG_FILTERADD,
            payload,
            (uint32_t)payload_len
        );
        dogecoin_node_send(n, msg);
        cstr_free(msg, true);
    }

    dogecoin_free(payload);

    if (client->nodegroup && client->nodegroup->log_write_cb)
        client->nodegroup->log_write_cb("[spv] sent filteradd (len=%u)\n", data_len);

    return true;
}

/**
 * Clear local BIP37 filter state and send filterclear to active peers.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_spv_client_filterclear(dogecoin_spv_client* client)
{
    if (!client) return false;

    if (client->bloom_filter) {
        dogecoin_free(client->bloom_filter);
        client->bloom_filter = NULL;
    }
    client->bloom_filter_len = 0;
    client->bloom_nhashfunc = 0;
    client->bloom_ntweak = 0;
    client->bloom_flags = 0;

    if (!client->nodegroup || !client->nodegroup->nodes) return true;

    for (unsigned int i = 0; i < (unsigned int)client->nodegroup->nodes->len; i++) {
        dogecoin_node* n = (dogecoin_node*)vector_idx(client->nodegroup->nodes, i);
        if (!n) continue;
        if (((n->state & NODE_CONNECTED) != NODE_CONNECTED) || !n->version_handshake) continue;

        cstring* payload = cstr_new_sz(0);
        cstring* msg = dogecoin_p2p_message_new(
            n->nodegroup->chainparams->netmagic,
            DOGECOIN_MSG_FILTERCLEAR,
            payload->str,
            payload->len
        );
        cstr_free(payload, true);
        dogecoin_node_send(n, msg);
        cstr_free(msg, true);
    }

    if (client->nodegroup && client->nodegroup->log_write_cb)
        client->nodegroup->log_write_cb("[spv] sent filterclear\n");

    return true;
}
