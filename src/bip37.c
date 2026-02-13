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
#include <dogecoin/spv.h>
#include <dogecoin/utils.h>
#include <dogecoin/vector.h>

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
