/*

 The MIT License (MIT)

 Copyright (c) 2016 Jonas Schnelli
 Copyright (c) 2023 bluezr
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

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <conio.h>
#else
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <math.h>

#include <dogecoin/block.h>
#include <dogecoin/blockchain.h>
#include <dogecoin/headersdb.h>
#include <dogecoin/headersdb_file.h>
#include <dogecoin/net.h>
#include <dogecoin/protocol.h>
#include <dogecoin/serialize.h>
#include <dogecoin/spv.h>
#include <dogecoin/smpv.h>
#include <dogecoin/tx.h>
#include <dogecoin/utils.h>
#include <dogecoin/vector.h>
#include <event2/event.h>

#define DOGECOIN_KOINU_PER_COIN 100000000ULL
/* Dogecoin block subsidy has been 10,000 DOGE for years; good for 24h stats */
#define DOGECOIN_CURRENT_SUBSIDY_KOINU (10000ULL * DOGECOIN_KOINU_PER_COIN)

/* BIP37 fallbacks (in case protocol.h doesn't provide them) */
#ifndef DOGECOIN_INV_TYPE_FILTERED_BLOCK
#define DOGECOIN_INV_TYPE_FILTERED_BLOCK 3
#endif
#ifndef DOGECOIN_MSG_FILTERLOAD
#define DOGECOIN_MSG_FILTERLOAD "filterload"
#endif
#ifndef DOGECOIN_MSG_FILTERADD
#define DOGECOIN_MSG_FILTERADD "filteradd"
#endif
#ifndef DOGECOIN_MSG_FILTERCLEAR
#define DOGECOIN_MSG_FILTERCLEAR "filterclear"
#endif
#ifndef DOGECOIN_MSG_MERKLEBLOCK
#define DOGECOIN_MSG_MERKLEBLOCK "merkleblock"
#endif

typedef struct spv_merkle_match_ {
    uint256_t txid;
    uint32_t pos;
    dogecoin_bool consumed;
} spv_merkle_match;

static int spv_merkle_match_cmp(const void* a, const void* b)
{
    const spv_merkle_match* ma = (const spv_merkle_match*)a;
    const spv_merkle_match* mb = (const spv_merkle_match*)b;
    return memcmp(ma->txid, mb->txid, 32);
}

static const unsigned int HEADERS_MAX_RESPONSE_TIME = 120;
static const unsigned int MIN_TIME_DELTA_FOR_STATE_CHECK = 5;
static const unsigned int BLOCK_GAP_TO_DEDUCT_TO_START_SCAN_FROM = 5;
static const unsigned int BLOCKS_DELTA_IN_S = 60;
static const unsigned int COMPLETED_WHEN_NUM_NODES_AT_SAME_HEIGHT = 2;

static dogecoin_bool dogecoin_net_spv_node_timer_callback(dogecoin_node *node, uint64_t *now);
void dogecoin_net_spv_post_cmd(dogecoin_node *node, dogecoin_p2p_msg_hdr *hdr, struct const_buffer *buf);
void dogecoin_net_spv_node_handshake_done(dogecoin_node *node);

void dogecoin_node_connection_state_changed_cb(dogecoin_node *node) {
    if (node->nodegroup->should_connect_to_more_nodes_cb) {
        if (node->nodegroup->should_connect_to_more_nodes_cb(node)) {
            dogecoin_spv_client_discover_peers((dogecoin_spv_client*)node->nodegroup->ctx, NULL);
            dogecoin_node_group_connect_next_nodes(node->nodegroup);
        }
    }
}

/**
 * @brief This function deterimines if we should connect to more nodes.
 *
 * @param node the node that we are connected to.
 *
 * @return dogecoin_bool (uint8_t)
 */
dogecoin_bool dogecoin_node_should_connect_to_more_cb(dogecoin_node* node) {
    int connected_amount = dogecoin_node_group_amount_of_connected_nodes(node->nodegroup, NODE_CONNECTED) + dogecoin_node_group_amount_of_connected_nodes(node->nodegroup, NODE_CONNECTING);
    node->nodegroup->log_write_cb("check if more nodes are required (connected to already: %d): %s\n", connected_amount, connected_amount < node->nodegroup->desired_amount_connected_nodes ? "true" : "false");
    if (connected_amount < node->nodegroup->desired_amount_connected_nodes) {
        return true;
        }
    return false;
    }

/**
 * The function sets the nodegroup's postcmd_cb to dogecoin_net_spv_post_cmd,
 * the nodegroup's handshake_done_cb to dogecoin_net_spv_node_handshake_done,
 * the nodegroup's node_connection_state_changed_cb to NULL, and the
 * nodegroup's periodic_timer_cb to dogecoin_net_spv_node_timer_callback
 *
 * @param nodegroup The nodegroup to set the callbacks for.
 */
void dogecoin_net_set_spv(dogecoin_node_group *nodegroup)
{
    nodegroup->postcmd_cb = dogecoin_net_spv_post_cmd;
    nodegroup->handshake_done_cb = dogecoin_net_spv_node_handshake_done;
    nodegroup->should_connect_to_more_nodes_cb = dogecoin_node_should_connect_to_more_cb;
    nodegroup->node_connection_state_changed_cb = dogecoin_node_connection_state_changed_cb;
    nodegroup->periodic_timer_cb = dogecoin_net_spv_node_timer_callback;
}

/**
 * The function creates a new dogecoin_spv_client object and initializes it
 *
 * @param params The chainparams struct that we created earlier.
 * @param debug If true, the node will print out debug messages to stdout.
 * @param headers_memonly If true, the headers database will not be loaded from disk.
 * @param use_checkpoints If true, the client will use checkpoints.
 * @param full_sync If true, the client will do a full sync.
 * @param maxnodes The maximum amount of nodes that the client will connect to.
 * @param http_server The IP and port for the HTTP server; if NULL, the HTTP server will not be initialized.
 *
 * @return A pointer to a dogecoin_spv_client object.
 */
dogecoin_spv_client* dogecoin_spv_client_new(const dogecoin_chainparams *params, dogecoin_bool debug, dogecoin_bool headers_memonly, dogecoin_bool use_checkpoints, dogecoin_bool full_sync, int maxnodes, const char* http_server)
{
    dogecoin_spv_client* client;
    client = dogecoin_calloc(1, sizeof(*client));

    client->last_headersrequest_time = 0; //!< time when we requested the last header package
    client->last_statecheck_time = 0;
    client->oldest_item_of_interest = time(NULL)-5*60;
    client->stateflags = full_sync ? SPV_FULLBLOCK_SYNC_FLAG : SPV_HEADER_SYNC_FLAG;

    client->chainparams = params;

    client->nodegroup = dogecoin_node_group_new(params);
    client->nodegroup->ctx = client;
    if (maxnodes > 120) {
        maxnodes = 120;
    }
    client->nodegroup->desired_amount_connected_nodes = maxnodes;

    dogecoin_net_set_spv(client->nodegroup);

    if (debug) {
        client->nodegroup->log_write_cb = net_write_log_printf;
    }

    if (params == &dogecoin_chainparams_main || params == &dogecoin_chainparams_test) {
        client->use_checkpoints = use_checkpoints;
    }
    client->headers_db = &dogecoin_headers_db_interface_file;
    client->headers_db_ctx = client->headers_db->init(params, headers_memonly);

    // set callbacks
    client->header_connected = NULL;
    client->called_sync_completed = false;
    client->sync_completed = NULL;
    client->header_message_processed = NULL;
    client->sync_transaction = NULL;
    client->sync_transaction_ctx = NULL;

    // BIP37 filter state (off by default)
    client->bloom_filter = NULL;
    client->bloom_filter_len = 0;
    client->bloom_nhashfunc = 0;
    client->bloom_ntweak = 0;
    client->bloom_flags = 0;

    // merkleblock -> matched tx state (btree keyed by txid)
    client->merkle_match_tree = NULL;
    client->merkle_match_pending = 0;
    client->merkle_match_active = false;
    client->merkle_match_blockindex = NULL;

    if (http_server) {
        // split ip and port
        char* http_server_copy = strdup(http_server);
        char* ip = strtok(http_server_copy, ":");
        char* port = strtok(NULL, ":");

        // HTTP server initialization
        dogecoin_http_server_init(client->nodegroup, ip, atoi(port));
        client->nodegroup->log_write_cb("HTTP server initialized\n");
        free(http_server_copy);
    }

    client->stats_ring_len = 0;
    client->stats_ring_head = 0;
    client->stats_blocks_total = 0;
    client->stats_txs_total = 0;
    client->stats_outputs_total = 0;
    client->stats_out_value_total = 0;
    client->stats_fees_total = 0;
    client->stats_block_bytes_total = 0;
    client->start_ts = (uint64_t)time(NULL);

    // SMPV default off
    client->smpv_ctx = NULL;
    client->smpv_enabled = false;

    return client;
}

/**
 * It adds peers to the nodegroup.
 *
 * @param client the dogecoin_spv_client object
 * @param ips A comma-separated list of IPs or seeds to connect to.
 */
void dogecoin_spv_client_discover_peers(dogecoin_spv_client* client, const char *ips)
{
#ifndef _WIN32
    // set stdin to non-blocking for quit command
    int stdin_flags = fcntl(STDIN_FILENO, F_GETFL);
    fcntl(STDIN_FILENO, F_SETFL, stdin_flags | O_NONBLOCK);
#endif

    dogecoin_node_group_add_peers_by_ip_or_seed(client->nodegroup, ips);
}

/**
 * The function loops through all the nodes in the node group and connects to the next nodes in the
 * node group
 *
 * @param client The dogecoin_spv_client object.
 */
void dogecoin_spv_client_runloop(dogecoin_spv_client* client)
{
    dogecoin_node_group_connect_next_nodes(client->nodegroup);
    dogecoin_node_group_event_loop(client->nodegroup);
}

/**
 * It frees the memory allocated for the client
 *
 * @param client The client object to be freed.
 *
 * @return Nothing.
 */
void dogecoin_spv_client_free(dogecoin_spv_client *client)
{
    if (!client)
        return;

#ifndef _WIN32
    // set stdin to back to blocking
    int stdin_flags = fcntl(STDIN_FILENO, F_GETFL);
    if (stdin_flags != -1 && (stdin_flags & O_NONBLOCK))
    {
        fcntl(STDIN_FILENO, F_SETFL, stdin_flags & ~O_NONBLOCK);
    }
#endif

    if (client->smpv_enabled && client->smpv_ctx) {
        dogecoin_smpv_stop((dogecoin_smpv_client*)client->smpv_ctx);
        dogecoin_smpv_client_free((dogecoin_smpv_client*)client->smpv_ctx);
        client->smpv_ctx = NULL;
        client->smpv_enabled = false;
    }

    if (client->bloom_filter) {
        dogecoin_free(client->bloom_filter);
        client->bloom_filter = NULL;
    }
    client->bloom_filter_len = 0;
    client->bloom_nhashfunc = 0;
    client->bloom_ntweak = 0;
    client->bloom_flags = 0;

    if (client->merkle_match_tree) {
        dogecoin_btree_tdestroy(client->merkle_match_tree, dogecoin_free);
        client->merkle_match_tree = NULL;
    }
    client->merkle_match_pending = 0;
    client->merkle_match_active = false;
    client->merkle_match_blockindex = NULL;

    if (client->headers_db)
    {
        if (client->headers_db_ctx)
        {
            client->headers_db->free(client->headers_db_ctx);
        }
        client->headers_db_ctx = NULL;
        client->headers_db = NULL;
    }

    if (client->nodegroup) {
        dogecoin_node_group_free(client->nodegroup);
        client->nodegroup = NULL;
    }

    dogecoin_free(client);
}

/**
 * Loads the headers database from a file
 *
 * @param client the client object
 * @param file_path The path to the headers database file.
 * @param prompt If true, the user will be prompted to confirm loading the database.
 *
 * @return A boolean value.
 */
dogecoin_bool dogecoin_spv_client_load(dogecoin_spv_client *client, const char *file_path, dogecoin_bool prompt)
{
    if (!client)
        return false;

    if (!client->headers_db)
        return false;

    return client->headers_db->load(client->headers_db_ctx, file_path, prompt);

}

/**
 * If we are in the header sync state, we request headers from a random node
 *
 * @param node the node that we are checking
 * @param now The current time in seconds.
 */
void dogecoin_net_spv_periodic_statecheck(dogecoin_node *node, uint64_t *now)
{
    /* statecheck logic */
    /* ================ */

    dogecoin_spv_client *client = (dogecoin_spv_client*)node->nodegroup->ctx;
    dogecoin_blockindex *pindex = client->headers_db->getchaintip(client->headers_db_ctx);
    client->nodegroup->log_write_cb("Statecheck: amount of connected nodes: %d\nchaintip hash: %s\nchaintip height: %d\n", dogecoin_node_group_amount_of_connected_nodes(client->nodegroup, NODE_CONNECTED), hash_to_string(pindex->hash), pindex->height);

    if (client->last_headersrequest_time > 0 && *now > client->last_headersrequest_time)
    {
        int64_t timedetla = *now - client->last_headersrequest_time;
        client->nodegroup->log_write_cb("No header response in time (used %d) for node %d\n", timedetla, node->nodeid);
        if (timedetla > HEADERS_MAX_RESPONSE_TIME)
        {
            node->state &= ~NODE_HEADERSYNC;
            dogecoin_node_misbehave(node);
        }
    }
    if (node->time_last_request > 0 && *now > node->time_last_request)
    {
        // we are downloading blocks from this peer
        int64_t timedelta = *now - node->time_last_request;
        client->nodegroup->log_write_cb("No block response in time (used %d) for node %d\n", timedelta, node->nodeid);
        if (timedelta > HEADERS_MAX_RESPONSE_TIME)
        {
            node->state &= ~NODE_BLOCKSYNC;
            dogecoin_node_misbehave(node);
        }
    }

    if ((client->stateflags & SPV_HEADER_SYNC_FLAG) == SPV_HEADER_SYNC_FLAG)
    {
        client->last_headersrequest_time = 0;
        dogecoin_net_spv_request_headers(client);
    }

    if ((client->stateflags & SPV_FULLBLOCK_SYNC_FLAG) == SPV_FULLBLOCK_SYNC_FLAG)
    {
        node->time_last_request = 0;
        dogecoin_net_spv_request_headers(client);
    }

    client->last_statecheck_time = *now;
}

/**
 * This function is called by the dogecoin_node_timer_callback function.
 *
 * It checks if the last_statecheck_time is greater than the minimum time delta for state checks.
 *
 * If it is, it calls the dogecoin_net_spv_periodic_statecheck function.
 *
 * The dogecoin_net_spv_periodic_statecheck function checks if the node is connected to the network.
 *
 * @param node The node that the timer is being called on.
 * @param now the current time in seconds since the epoch
 *
 * @return A boolean value.
 */
static dogecoin_bool dogecoin_net_spv_node_timer_callback(dogecoin_node *node, uint64_t *now)
{
    dogecoin_spv_client *client = (dogecoin_spv_client*)node->nodegroup->ctx;

    if (client->last_statecheck_time + MIN_TIME_DELTA_FOR_STATE_CHECK < *now)
    {
        dogecoin_net_spv_periodic_statecheck(node, now);
    }

    return true;
}

/**
 * Fill up the blocklocators vector_t with the blocklocators from the headers database
 *
 * @param client the spv client
 * @param blocklocators a vector_t of block hashes that we want to scan from
 *
 * @return The blocklocators are being returned.
 */
void dogecoin_net_spv_fill_block_locator(dogecoin_spv_client *client, vector_t *blocklocators) {
    int64_t min_timestamp = client->oldest_item_of_interest - BLOCK_GAP_TO_DEDUCT_TO_START_SCAN_FROM * BLOCKS_DELTA_IN_S; /* ensure we going back ~300 blocks */
    if (client->headers_db->getchaintip(client->headers_db_ctx)->height == 0) {
        if (client->use_checkpoints && client->oldest_item_of_interest > BLOCK_GAP_TO_DEDUCT_TO_START_SCAN_FROM * BLOCKS_DELTA_IN_S) {
            const dogecoin_checkpoint *checkpoint = memcmp(client->chainparams, &dogecoin_chainparams_main, 4) == 0 ? dogecoin_mainnet_checkpoint_array : dogecoin_testnet_checkpoint_array;
            size_t mainnet_checkpoint_size = sizeof(dogecoin_mainnet_checkpoint_array) / sizeof(dogecoin_mainnet_checkpoint_array[0]);
            size_t testnet_checkpoint_size = sizeof(dogecoin_testnet_checkpoint_array) / sizeof(dogecoin_testnet_checkpoint_array[0]);
            size_t length = memcmp(client->chainparams, &dogecoin_chainparams_main, 8) == 0 ? mainnet_checkpoint_size : testnet_checkpoint_size;
            int i;
            for (i = (int)length - 1; i >= 0; i--) {
                if (checkpoint[i].timestamp < min_timestamp) {
                    uint256_t *hash = dogecoin_calloc(1, sizeof(uint256_t));
                    utils_uint256_sethex((char *)checkpoint[i].hash, (uint8_t *)hash);
                    vector_add(blocklocators, (void *)hash);
                    if (!client->headers_db->has_checkpoint_start(client->headers_db_ctx)) {
                        client->headers_db->set_checkpoint_start(client->headers_db_ctx, *hash, checkpoint[i].height, (uint8_t*)client->chainparams->minimumchainwork);
                    }
                }
            }
            if (blocklocators->len > 0) return; // return if we could fill up the blocklocator with checkpoints
        }
        uint256_t *hash = dogecoin_calloc(1, sizeof(uint256_t));
        memcpy_safe(hash, &client->chainparams->genesisblockhash, sizeof(uint256_t));
        vector_add(blocklocators, (void *)hash);
        client->nodegroup->log_write_cb("Setting blocklocator with genesis block\n");
    } else {
        client->headers_db->fill_blocklocator_tip(client->headers_db_ctx, blocklocators);
    }
}

/**
 * This function is called when a node is in headers sync state. It will request the next block headers
 * from the node
 *
 * @param node The node that is requesting headers or blocks.
 * @param blocks boolean, true if we want to request blocks, false if we want to request headers
 */
void dogecoin_net_spv_node_request_headers_or_blocks(dogecoin_node *node, dogecoin_bool blocks)
{
    // request next headers
    vector_t *blocklocators = vector_new(1, free);

    dogecoin_net_spv_fill_block_locator((dogecoin_spv_client *)node->nodegroup->ctx, blocklocators);

    cstring *getheader_msg = cstr_new_sz(256);
    dogecoin_p2p_msg_getheaders(blocklocators, NULL, getheader_msg);

    cstring *p2p_msg = dogecoin_p2p_message_new(node->nodegroup->chainparams->netmagic, (blocks ? DOGECOIN_MSG_GETBLOCKS : DOGECOIN_MSG_GETHEADERS), getheader_msg->str, getheader_msg->len);
    cstr_free(getheader_msg, true);

    dogecoin_node_send(node, p2p_msg);
    node->state |= ( blocks ? NODE_BLOCKSYNC : NODE_HEADERSYNC);

    if (blocks) {
        node->time_last_request = time(NULL);
    } else {
        ((dogecoin_spv_client*)node->nodegroup->ctx)->last_headersrequest_time = time(NULL);
    }

    vector_free(blocklocators, true);
    cstr_free(p2p_msg, true);
}

/**
 * If we have not yet reached the height of the blockchain tip, we request headers from a peer. If we
 * have reached the height of the blockchain tip, we request blocks from a peer
 *
 * @param client the spv client
 *
 * @return dogecoin_bool
 */
dogecoin_bool dogecoin_net_spv_request_headers(dogecoin_spv_client *client)
{
    size_t i;
    dogecoin_bool new_headers_available = false;
    for(i = 0; i < client->nodegroup->nodes->len; ++i)
    {
        dogecoin_node *check_node = vector_idx(client->nodegroup->nodes, i);
        if (((check_node->state & NODE_HEADERSYNC) == NODE_HEADERSYNC || (check_node->state & NODE_BLOCKSYNC) == NODE_BLOCKSYNC) && (check_node->state & NODE_CONNECTED) == NODE_CONNECTED) { return true; }
    }

    // If in header or block sync state, request headers or blocks from the node with the longest chain
    if ((client->stateflags & SPV_HEADER_SYNC_FLAG) == SPV_HEADER_SYNC_FLAG || (client->stateflags & SPV_FULLBLOCK_SYNC_FLAG) == SPV_FULLBLOCK_SYNC_FLAG)
    {
        dogecoin_node *node_with_longest_chain = NULL;
        unsigned int longest_chain_height = 0;
        for(i = 0; i < client->nodegroup->nodes->len; ++i)
        {
            dogecoin_node *check_node = vector_idx(client->nodegroup->nodes, i);
            if (((check_node->state & NODE_CONNECTED) == NODE_CONNECTED) && check_node->version_handshake)
            {
                if (check_node->bestknownheight > longest_chain_height)
                {
                    longest_chain_height = check_node->bestknownheight;
                    node_with_longest_chain = check_node;
                }
            }
        }

        // Request headers or blocks from the node with the longest chain
        if (node_with_longest_chain != NULL) {
            dogecoin_net_spv_node_request_headers_or_blocks(node_with_longest_chain, (client->stateflags & SPV_FULLBLOCK_SYNC_FLAG) == SPV_FULLBLOCK_SYNC_FLAG);
            new_headers_available = true;
        }
    }

    // Fallback: original logic for handling cases where no suitable node was found
    unsigned int nodes_at_same_height = 0;
    if (!new_headers_available && client->headers_db->getchaintip(client->headers_db_ctx)->header.timestamp < client->oldest_item_of_interest - (BLOCK_GAP_TO_DEDUCT_TO_START_SCAN_FROM * BLOCKS_DELTA_IN_S) && client->stateflags == SPV_HEADER_SYNC_FLAG)
    {
        for(i = 0; i < client->nodegroup->nodes->len; i++)
        {
            dogecoin_node *check_node = vector_idx(client->nodegroup->nodes, i);
            if (((check_node->state & NODE_CONNECTED) == NODE_CONNECTED) && check_node->version_handshake)
            {
                if (check_node->bestknownheight > client->headers_db->getchaintip(client->headers_db_ctx)->height) {
                    dogecoin_net_spv_node_request_headers_or_blocks(check_node, false);
                    new_headers_available = true;
                    break;
                } else if (check_node->bestknownheight == client->headers_db->getchaintip(client->headers_db_ctx)->height) {
                    nodes_at_same_height++;
                }
            }
        }
    }
    if (!new_headers_available && (dogecoin_node_group_amount_of_connected_nodes(client->nodegroup, NODE_CONNECTED) > 0) && client->stateflags == SPV_FULLBLOCK_SYNC_FLAG) {
        // try to fetch blocks if no new headers are available but connected nodes are reachable
        for(i = 0; i< client->nodegroup->nodes->len; i++)
        {
            dogecoin_node *check_node = vector_idx(client->nodegroup->nodes, i);
            if (((check_node->state & NODE_CONNECTED) == NODE_CONNECTED) && check_node->version_handshake)
            {
                if (check_node->bestknownheight == client->headers_db->getchaintip(client->headers_db_ctx)->height) {
                    nodes_at_same_height++;
                }
                dogecoin_net_spv_node_request_headers_or_blocks(check_node, true);
                new_headers_available = true;
            }
        }
    }

    if (nodes_at_same_height >= COMPLETED_WHEN_NUM_NODES_AT_SAME_HEIGHT && !client->called_sync_completed && client->sync_completed)
    {
        client->sync_completed(client);
        client->called_sync_completed = true;
    }

    return new_headers_available;
}

/**
 * When the handshake is done, we request the headers
 *
 * @param node The node that just completed the handshake.
 */
void dogecoin_net_spv_node_handshake_done(dogecoin_node *node)
{
    dogecoin_spv_client* client = (dogecoin_spv_client*)node->nodegroup->ctx;

    /* If a BIP37 filter is configured, load it on this peer before requesting blocks. */
    if (client && client->bloom_filter && client->bloom_filter_len > 0) {
        uint64_t flen = (uint64_t)client->bloom_filter_len;
        uint8_t vi[9];
        size_t vi_len = 0;

        if (flen < 0xfdULL) {
            vi[0] = (uint8_t)flen;
            vi_len = 1;
        } else if (flen <= 0xffffULL) {
            vi[0] = 0xfd;
            vi[1] = (uint8_t)(flen & 0xff);
            vi[2] = (uint8_t)((flen >> 8) & 0xff);
            vi_len = 3;
        } else if (flen <= 0xffffffffULL) {
            vi[0] = 0xfe;
            vi[1] = (uint8_t)(flen & 0xff);
            vi[2] = (uint8_t)((flen >> 8) & 0xff);
            vi[3] = (uint8_t)((flen >> 16) & 0xff);
            vi[4] = (uint8_t)((flen >> 24) & 0xff);
            vi_len = 5;
        } else {
            vi[0] = 0xff;
            vi[1] = (uint8_t)(flen & 0xff);
            vi[2] = (uint8_t)((flen >> 8) & 0xff);
            vi[3] = (uint8_t)((flen >> 16) & 0xff);
            vi[4] = (uint8_t)((flen >> 24) & 0xff);
            vi[5] = (uint8_t)((flen >> 32) & 0xff);
            vi[6] = (uint8_t)((flen >> 40) & 0xff);
            vi[7] = (uint8_t)((flen >> 48) & 0xff);
            vi[8] = (uint8_t)((flen >> 56) & 0xff);
            vi_len = 9;
        }

        size_t payload_len = vi_len + (size_t)client->bloom_filter_len + 4 + 4 + 1;
        uint8_t* payload = (uint8_t*)dogecoin_calloc(1, payload_len);
        if (payload) {
            size_t off = 0;
            memcpy(payload + off, vi, vi_len);
            off += vi_len;

            memcpy(payload + off, client->bloom_filter, client->bloom_filter_len);
            off += client->bloom_filter_len;

            payload[off + 0] = (uint8_t)(client->bloom_nhashfunc & 0xff);
            payload[off + 1] = (uint8_t)((client->bloom_nhashfunc >> 8) & 0xff);
            payload[off + 2] = (uint8_t)((client->bloom_nhashfunc >> 16) & 0xff);
            payload[off + 3] = (uint8_t)((client->bloom_nhashfunc >> 24) & 0xff);
            off += 4;

            payload[off + 0] = (uint8_t)(client->bloom_ntweak & 0xff);
            payload[off + 1] = (uint8_t)((client->bloom_ntweak >> 8) & 0xff);
            payload[off + 2] = (uint8_t)((client->bloom_ntweak >> 16) & 0xff);
            payload[off + 3] = (uint8_t)((client->bloom_ntweak >> 24) & 0xff);
            off += 4;

            payload[off] = (uint8_t)client->bloom_flags;
            off += 1;

            cstring* msg = dogecoin_p2p_message_new(
                node->nodegroup->chainparams->netmagic,
                DOGECOIN_MSG_FILTERLOAD,
                payload,
                (uint32_t)payload_len
            );
            dogecoin_node_send(node, msg);
            cstr_free(msg, true);
            dogecoin_free(payload);

            if (client->nodegroup && client->nodegroup->log_write_cb)
                client->nodegroup->log_write_cb("[spv] sent filterload to node %d (len=%u)\n", node->nodeid, client->bloom_filter_len);
        }
    }

    dogecoin_net_spv_request_headers((dogecoin_spv_client*)node->nodegroup->ctx);
}

/**
 * The function is called when a new message is received from a peer
 *
 * @param node
 * @param hdr
 * @param buf
 *
 * @return Nothing.
 */
void dogecoin_net_spv_post_cmd(dogecoin_node *node, dogecoin_p2p_msg_hdr *hdr, struct const_buffer *buf)
{
    dogecoin_spv_client *client = (dogecoin_spv_client *)node->nodegroup->ctx;

    if (strcmp(hdr->command, DOGECOIN_MSG_INV) == 0 && (node->state & NODE_BLOCKSYNC) == NODE_BLOCKSYNC)
    {
        struct const_buffer original_inv = { buf->p, buf->len };
        uint32_t varlen;
        deser_varlen(&varlen, buf);
        dogecoin_bool contains_block = false;
        dogecoin_bool contains_tx = false;

        client->nodegroup->log_write_cb("Get inv request with %d items\n", varlen);

        unsigned int i;
        for (i = 0; i < varlen; i++)
        {
            uint32_t type;
            deser_u32(&type, buf);
            if (type == DOGECOIN_INV_TYPE_BLOCK && ((varlen >= 500) || (client->headers_db->getchaintip(client->headers_db_ctx)->height > node->bestknownheight - 1440))) {
                contains_block = true;
                deser_u256(node->last_requested_inv, buf);
           } else if (type == DOGECOIN_INV_TYPE_TX) {
                contains_tx = true;
                deser_skip(buf, 32);
            } else {
                deser_skip(buf, 32);
            }
        }

        if (contains_block) {
            node->time_last_request = time(NULL);

            dogecoin_bool use_filtered = (client->bloom_filter && client->bloom_filter_len > 0);

            if (use_filtered) {
                /* Rebuild getdata payload, rewriting BLOCK -> FILTERED_BLOCK so peer answers:
                   merkleblock + (matched) tx messages, and we drive sync_transaction only for matches. */
                struct const_buffer inv2 = { original_inv.p, original_inv.len };
                uint32_t n = 0;
                if (!deser_varlen(&n, &inv2)) {
                    node->state &= ~NODE_BLOCKSYNC;
                    node->nodegroup->node_connection_state_changed_cb(node);
                    return;
                }

                uint8_t* out = (uint8_t*)dogecoin_calloc(1, original_inv.len);
                if (!out) {
                    node->state &= ~NODE_BLOCKSYNC;
                    node->nodegroup->node_connection_state_changed_cb(node);
                    return;
                }

                size_t off = 0;
                {
                    uint64_t vv = (uint64_t)n;
                    if (vv < 0xfdULL) {
                        out[off++] = (uint8_t)vv;
                    } else if (vv <= 0xffffULL) {
                        out[off++] = 0xfd;
                        out[off++] = (uint8_t)(vv & 0xff);
                        out[off++] = (uint8_t)((vv >> 8) & 0xff);
                    } else if (vv <= 0xffffffffULL) {
                        out[off++] = 0xfe;
                        out[off++] = (uint8_t)(vv & 0xff);
                        out[off++] = (uint8_t)((vv >> 8) & 0xff);
                        out[off++] = (uint8_t)((vv >> 16) & 0xff);
                        out[off++] = (uint8_t)((vv >> 24) & 0xff);
                    } else {
                        out[off++] = 0xff;
                        out[off++] = (uint8_t)(vv & 0xff);
                        out[off++] = (uint8_t)((vv >> 8) & 0xff);
                        out[off++] = (uint8_t)((vv >> 16) & 0xff);
                        out[off++] = (uint8_t)((vv >> 24) & 0xff);
                        out[off++] = (uint8_t)((vv >> 32) & 0xff);
                        out[off++] = (uint8_t)((vv >> 40) & 0xff);
                        out[off++] = (uint8_t)((vv >> 48) & 0xff);
                        out[off++] = (uint8_t)((vv >> 56) & 0xff);
                    }
                }

                for (i = 0; i < n; i++) {
                    uint32_t type = 0;
                    uint256_t h;
                    if (!deser_u32(&type, &inv2) || !deser_u256(h, &inv2)) {
                        dogecoin_free(out);
                        node->state &= ~NODE_BLOCKSYNC;
                        node->nodegroup->node_connection_state_changed_cb(node);
                        return;
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

                client->nodegroup->log_write_cb("Requesting %d filtered blocks (merkleblock+tx)\n", n);
                cstring *p2p_msg = dogecoin_p2p_message_new(
                    node->nodegroup->chainparams->netmagic,
                    DOGECOIN_MSG_GETDATA,
                    out,
                    (uint32_t)original_inv.len
                );
                dogecoin_node_send(node, p2p_msg);
                cstr_free(p2p_msg, true);
                dogecoin_free(out);
            } else {
                client->nodegroup->log_write_cb("Requesting %d blocks\n", varlen);
                cstring *p2p_msg = dogecoin_p2p_message_new(node->nodegroup->chainparams->netmagic, DOGECOIN_MSG_GETDATA, original_inv.p, original_inv.len);
                dogecoin_node_send(node, p2p_msg);
                cstr_free(p2p_msg, true);
            }
        }

        if (contains_tx && client->smpv_enabled) {
            client->nodegroup->log_write_cb("Requesting %d tx (mempool INV)\n", varlen);
            cstring *p2p_msg = dogecoin_p2p_message_new(
                node->nodegroup->chainparams->netmagic,
                DOGECOIN_MSG_GETDATA,
                original_inv.p, original_inv.len);
            dogecoin_node_send(node, p2p_msg);
            cstr_free(p2p_msg, true);
        }
    }

    if (strcmp(hdr->command, DOGECOIN_MSG_BLOCK) == 0)
    {
        dogecoin_bool connected;
        dogecoin_blockindex *pindex = client->headers_db->connect_hdr(client->headers_db_ctx, buf, false, &connected);

        node->time_last_request = time(NULL);

        if (connected) {
            if (client->header_connected) { client->header_connected(client); }

            // for now, turn of stall checks if we are near the tip
            if (pindex->header.timestamp > node->time_last_request - 30*60) {
                node->time_last_request = 0;
            }

            time_t lasttime = pindex->header.timestamp;
            char s[1000];
            time_t t = lasttime;
            struct tm *p = localtime(&t);
            strftime(s, sizeof s, "%F %T", p);
            char *ctime_no_newline;
            ctime_no_newline = strtok(s, "\n");
            printf("%s|%d|%s|%d\n", hash_to_string(pindex->hash), pindex->height, ctime_no_newline, hdr->data_len);
            uint64_t start = time(NULL);

            uint32_t amount_of_txs;
            if (!deser_varlen(&amount_of_txs, buf)) {
                if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                    dogecoin_free(pindex);
                }
                client->nodegroup->log_write_cb("Error deserializing amount of transactions from node %d\n", node->nodeid);
                node->state &= ~NODE_BLOCKSYNC;
                node->nodegroup->node_connection_state_changed_cb(node);
                return;
            }

            client->nodegroup->log_write_cb("Start parsing %d transactions...\n", (int)amount_of_txs);

            // update the last block info for the client
            client->last_block_tx_count = amount_of_txs;
            client->last_block_size = hdr->data_len;

            uint64_t total_tx_size = 0;

            // per-block accumulation for stats
            uint64_t block_outputs_value = 0;
            uint32_t block_outputs_count = 0;
            uint64_t coinbase_value = 0;

            size_t consumedlength = 0;
            unsigned int i;
            for (i = 0; i < amount_of_txs; i++)
            {
                dogecoin_tx* tx = dogecoin_tx_new();
                if (!dogecoin_tx_deserialize(buf->p, buf->len, tx, &consumedlength)) {
                    client->nodegroup->log_write_cb("Error deserializing transaction\n");
                    if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                        dogecoin_free(pindex);
                    }
                    dogecoin_tx_free(tx);
                    node->state &= ~NODE_BLOCKSYNC;
                    node->nodegroup->node_connection_state_changed_cb(node);
                    return;
                }
                deser_skip(buf, consumedlength);
                if (client->sync_transaction) { client->sync_transaction(client->sync_transaction_ctx, tx, i, pindex); }
                total_tx_size += consumedlength;

                // accumulate outputs for this tx
                uint64_t tx_out_sum = 0;
                unsigned int oi;
                for (oi = 0; oi < tx->vout->len; oi++)
                {
                    dogecoin_tx_out *txout = vector_idx(tx->vout, oi);
                    tx_out_sum += txout->value;
                    block_outputs_value += txout->value;
                    block_outputs_count++;
                }
                if (i == 0 && dogecoin_tx_is_coinbase(tx)) {
                    coinbase_value = tx_out_sum; // coinbase tx is always the first tx in a block
                }
                dogecoin_tx_free(tx);
            }
            client->last_block_total_tx_size = total_tx_size;

            // approximate fees (OK for recent blocks where subsidy is 10k0 DOGE)
            uint64_t block_fees = 0;
            if (coinbase_value > DOGECOIN_CURRENT_SUBSIDY_KOINU) {
                block_fees = coinbase_value - DOGECOIN_CURRENT_SUBSIDY_KOINU;
            }

            // session totals
            client->stats_blocks_total++;
            client->stats_txs_total += amount_of_txs;
            client->stats_outputs_total += block_outputs_count;
            client->stats_out_value_total += block_outputs_value;
            client->stats_fees_total += block_fees;
            client->stats_block_bytes_total += hdr->data_len;

            // ring insert (latest)
            spv_block_sample *smp = &client->stats_ring[client->stats_ring_head];
            smp->ts = pindex->header.timestamp;
            smp->txs = amount_of_txs;
            smp->outputs = block_outputs_count;
            smp->out_value = block_outputs_value;
            smp->size = hdr->data_len;
            smp->fees = block_fees;

            client->stats_ring_head = (client->stats_ring_head + 1) % SPV_STATS_RING;
            if (client->stats_ring_len < SPV_STATS_RING) {
                client->stats_ring_len++;
            }

            client->nodegroup->log_write_cb("done (took %lld secs)\n", (unsigned long long)(time(NULL) - start));
        }
        else
        {
            client->nodegroup->log_write_cb("Got invalid block (not in sequence) from node %d\n", node->nodeid);
            node->state &= ~NODE_BLOCKSYNC;
            node->state |= NODE_MISSBEHAVED;
            node->nodegroup->node_connection_state_changed_cb(node);
            dogecoin_free(pindex);
            return;
        }

        if (dogecoin_hash_equal((uint8_t *)node->last_requested_inv, (uint8_t *)pindex->hash)) {
            // instead of querying whether the last connected header timestamp is greater than the oldest item of interest
            // we check if the height is greater than or equal to the node's bestknown height minus 5 minutes
            if (client->headers_db->getchaintip(client->headers_db_ctx)->height >= node->bestknownheight - 5) {
                // last requested block reached, consider stop syncing
                if (!client->called_sync_completed && client->sync_completed) {
                    // enable mempool requests if smpv is enabled
                    if (client->smpv_enabled) dogecoin_net_spv_request_mempool(client);
                    client->sync_completed(client);
                    client->called_sync_completed = true;
                }
            } else if (client->headers_db->getchaintip(client->headers_db_ctx)->height < node->bestknownheight - 1440) {
                node->time_last_request = time(NULL);
                dogecoin_net_spv_node_request_headers_or_blocks(node, true);
            }
        }
    }

    if (strcmp(hdr->command, DOGECOIN_MSG_HEADERS) == 0)
    {
        uint32_t amount_of_headers;
        if (!deser_varlen(&amount_of_headers, buf)) return;
        uint64_t now = time(NULL);
        client->nodegroup->log_write_cb("Got %d headers (took %d s) from node %d\n", amount_of_headers, now - client->last_headersrequest_time, node->nodeid);

        // flag off the request stall check
        client->last_headersrequest_time = 0;

        unsigned int connected_headers = 0;
        unsigned int i;
        for (i = 0; i < amount_of_headers; i++)
        {
            dogecoin_bool connected;
            dogecoin_blockindex *pindex = client->headers_db->connect_hdr(client->headers_db_ctx, buf, false, &connected);
            if (!pindex)
            {
                client->nodegroup->log_write_cb("Header deserialization failed (node %d)\n", node->nodeid);
            }
            if (!deser_skip(buf, 1)) {
                client->nodegroup->log_write_cb("Header deserialization (tx count skip) failed (node %d)\n", node->nodeid);
            }

            if (!connected)
            {
                client->nodegroup->log_write_cb("Got invalid headers (not in sequence) from node %d\n", node->nodeid);
                node->state &= ~NODE_HEADERSYNC;
                node->nodegroup->node_connection_state_changed_cb(node);
                dogecoin_free(pindex);
                break;
            } else {
                if (client->header_connected) { client->header_connected(client); }
                connected_headers++;
                if (pindex->height >= node->bestknownheight - 5) {
                    client->stateflags &= ~SPV_HEADER_SYNC_FLAG;
                    client->stateflags |= SPV_FULLBLOCK_SYNC_FLAG;
                    node->state &= ~NODE_HEADERSYNC;
                    node->state |= NODE_BLOCKSYNC;
                    client->nodegroup->log_write_cb("start loading block from node %d at height %d at time: %ld\n", node->nodeid, client->headers_db->getchaintip(client->headers_db_ctx)->height, client->headers_db->getchaintip(client->headers_db_ctx)->header.timestamp);
                    dogecoin_net_spv_node_request_headers_or_blocks(node, true);
                    break;
                }
            }
        }
        dogecoin_blockindex *chaintip = client->headers_db->getchaintip(client->headers_db_ctx);

        client->nodegroup->log_write_cb("Connected %d headers\n", connected_headers);
        client->nodegroup->log_write_cb("Chaintip at height %d\n", chaintip->height);

        if (client->header_message_processed && client->header_message_processed(client, node, chaintip) == false)
            return;

        if (amount_of_headers == MAX_HEADERS_RESULTS && ((node->state & NODE_BLOCKSYNC) != NODE_BLOCKSYNC))
        {
            time_t lasttime = chaintip->header.timestamp;
            client->nodegroup->log_write_cb("chain size: %d, last time %s", chaintip->height, ctime(&lasttime));
            dogecoin_net_spv_node_request_headers_or_blocks(node, false);
        }
    }

    if (strcmp(hdr->command, DOGECOIN_MSG_MERKLEBLOCK) == 0) {
        dogecoin_bool connected = false;

        /* connect header first (advances buf past 80-byte header) */
        const unsigned char* merkleblock_start = (const unsigned char*)buf->p;
        dogecoin_blockindex *pindex = client->headers_db->connect_hdr(client->headers_db_ctx, buf, false, &connected);
        node->time_last_request = time(NULL);

        if (!connected || !pindex) {
            client->nodegroup->log_write_cb("Got invalid merkleblock (not in sequence) from node %d\n", node->nodeid);
            node->state &= ~NODE_BLOCKSYNC;
            node->state |= NODE_MISSBEHAVED;
            node->nodegroup->node_connection_state_changed_cb(node);
            if (pindex) dogecoin_free(pindex);
            return;
        }

        if (client->header_connected) { client->header_connected(client); }

        /* reset prior match state */
        if (client->merkle_match_tree) {
            dogecoin_btree_tdestroy(client->merkle_match_tree, dogecoin_free);
            client->merkle_match_tree = NULL;
        }
        client->merkle_match_pending = 0;
        client->merkle_match_active = false;
        client->merkle_match_blockindex = NULL;

        /* header merkle root (from original 80-byte header at message start) */
        uint256_t header_merkle;
        memcpy(header_merkle, merkleblock_start + 36, 32);

        /* after connect_hdr, buf points at nTx (uint32) */
        uint32_t nTx = 0;
        if (!deser_u32(&nTx, buf)) {
            if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                dogecoin_free(pindex);
            }
            client->nodegroup->log_write_cb("Merkleblock nTx deser failed (node %d)\n", node->nodeid);
            node->state &= ~NODE_BLOCKSYNC;
            node->nodegroup->node_connection_state_changed_cb(node);
            return;
        }

        uint32_t hashCount = 0;
        if (!deser_varlen(&hashCount, buf) || hashCount == 0) {
            if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                dogecoin_free(pindex);
            }
            client->nodegroup->log_write_cb("Merkleblock hashCount deser failed/zero (node %d)\n", node->nodeid);
            node->state &= ~NODE_BLOCKSYNC;
            node->nodegroup->node_connection_state_changed_cb(node);
            return;
        }

        uint256_t* hashes = (uint256_t*)dogecoin_calloc(hashCount, sizeof(uint256_t));
        if (!hashes) {
            if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                dogecoin_free(pindex);
            }
            node->state &= ~NODE_BLOCKSYNC;
            node->nodegroup->node_connection_state_changed_cb(node);
            return;
        }

        unsigned int i;
        for (i = 0; i < hashCount; i++) {
            if (!deser_u256(hashes[i], buf)) {
                dogecoin_free(hashes);
                if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                    dogecoin_free(pindex);
                }
                client->nodegroup->log_write_cb("Merkleblock hash deser failed (node %d)\n", node->nodeid);
                node->state &= ~NODE_BLOCKSYNC;
                node->nodegroup->node_connection_state_changed_cb(node);
                return;
            }
        }

        uint32_t flags_len = 0;
        if (!deser_varlen(&flags_len, buf) || flags_len == 0 || flags_len > buf->len) {
            dogecoin_free(hashes);
            if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                dogecoin_free(pindex);
            }
            client->nodegroup->log_write_cb("Merkleblock flags deser failed/badlen (node %d)\n", node->nodeid);
            node->state &= ~NODE_BLOCKSYNC;
            node->nodegroup->node_connection_state_changed_cb(node);
            return;
        }

        uint8_t* flags = (uint8_t*)dogecoin_calloc(flags_len, 1);
        if (!flags) {
            dogecoin_free(hashes);
            if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                dogecoin_free(pindex);
            }
            node->state &= ~NODE_BLOCKSYNC;
            node->nodegroup->node_connection_state_changed_cb(node);
            return;
        }
        memcpy(flags, buf->p, flags_len);
        if (!deser_skip(buf, flags_len)) {
            dogecoin_free(flags);
            dogecoin_free(hashes);
            if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                dogecoin_free(pindex);
            }
            node->state &= ~NODE_BLOCKSYNC;
            node->nodegroup->node_connection_state_changed_cb(node);
            return;
        }

        /* compute tree height */
        uint32_t height = 0;
        while (1) {
            uint64_t width = ((uint64_t)nTx + ((1ULL << height) - 1ULL)) >> height;
            if (width <= 1) break;
            height++;
            if (height > 32) break;
        }
        if (height > 32) {
            dogecoin_free(flags);
            dogecoin_free(hashes);
            if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                dogecoin_free(pindex);
            }
            client->nodegroup->log_write_cb("Merkleblock height too large (node %d)\n", node->nodeid);
            node->state &= ~NODE_BLOCKSYNC;
            node->nodegroup->node_connection_state_changed_cb(node);
            return;
        }

        /* TraverseAndExtract (inline) */
        uint32_t bitsUsed = 0;
        uint32_t hashesUsed = 0;

        struct {
            uint32_t height;
            uint32_t pos;
            uint8_t stage;       // 0=enter, 1=after-left, 2=after-right
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

                if (st[sp].height == 0 || st[sp].parentMatch == 0) {
                    if (hashesUsed >= hashCount) { ok_extract = false; break; }
                    memcpy(ret, hashes[hashesUsed], 32);
                    hashesUsed++;
                    have_ret = true;

                    if (st[sp].height == 0 && st[sp].parentMatch) {
                        spv_merkle_match* m = (spv_merkle_match*)dogecoin_calloc(1, sizeof(spv_merkle_match));
                        if (!m) { ok_extract = false; break; }

                        memcpy(m->txid, ret, 32);
                        m->pos = st[sp].pos;
                        m->consumed = false;

                        dogecoin_btree_node_t* nn = (dogecoin_btree_node_t*)dogecoin_btree_tsearch(
                            m, &client->merkle_match_tree, spv_merkle_match_cmp);
                        if (!nn) {
                            dogecoin_free(m);
                            ok_extract = false;
                            break;
                        }
                        if (nn->key != m) {
                            dogecoin_free(m);
                        } else {
                            client->merkle_match_pending++;
                        }
                    }

                    sp--;
                    continue;
                }

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
                    st[sp].stage = 2;
                    sp++;
                    st[sp].height = st[sp - 1].height - 1;
                    st[sp].pos = rightPos;
                    st[sp].stage = 0;
                    st[sp].parentMatch = 0;
                    have_ret = false;
                    continue;
                } else {
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

        if (!ok_extract || !have_ret || memcmp(ret, header_merkle, 32) != 0) {
            if (client->merkle_match_tree) {
                dogecoin_btree_tdestroy(client->merkle_match_tree, dogecoin_free);
                client->merkle_match_tree = NULL;
            }
            client->merkle_match_pending = 0;
            client->merkle_match_active = false;
            client->merkle_match_blockindex = NULL;

            dogecoin_free(flags);
            dogecoin_free(hashes);

            if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                dogecoin_free(pindex);
            }

            client->nodegroup->log_write_cb("Merkleblock verify failed (node %d)\n", node->nodeid);
            node->state &= ~NODE_BLOCKSYNC;
            node->nodegroup->node_connection_state_changed_cb(node);
            return;
        }

        client->merkle_match_active = (client->merkle_match_pending > 0);
        client->merkle_match_blockindex = pindex;

        client->nodegroup->log_write_cb("[merkle] block at height %d: nTx=%u matched=%u active=%d\n",
            pindex->height, nTx, client->merkle_match_pending,
            client->merkle_match_active ? 1 : 0);

        dogecoin_free(flags);
        dogecoin_free(hashes);

        if (dogecoin_hash_equal((uint8_t *)node->last_requested_inv, (uint8_t *)pindex->hash)) {
            if (client->headers_db->getchaintip(client->headers_db_ctx)->height >= node->bestknownheight - 5) {
                if (!client->called_sync_completed && client->sync_completed) {
                    if (client->smpv_enabled) dogecoin_net_spv_request_mempool(client);
                    client->sync_completed(client);
                    client->called_sync_completed = true;
                }
            } else if (client->headers_db->getchaintip(client->headers_db_ctx)->height < node->bestknownheight - 1440) {
                node->time_last_request = time(NULL);
                dogecoin_net_spv_node_request_headers_or_blocks(node, true);
            }
        }
    }

    if (strcmp(hdr->command, DOGECOIN_MSG_TX) == 0) {
        if (client && client->merkle_match_active && client->merkle_match_pending > 0 &&
            client->merkle_match_tree && client->sync_transaction) {
            size_t consumedlength = 0;
            dogecoin_tx* tx = dogecoin_tx_new();
            if (tx && dogecoin_tx_deserialize(buf->p, buf->len, tx, &consumedlength)) {
                uint256_t txid;
                dogecoin_tx_hash(tx, txid);

                char txid_hex[65];
                utils_bin_to_hex(txid, 32, txid_hex);
                client->nodegroup->log_write_cb("[merkle-tx] received tx %s (match_pending=%u)\n",
                    txid_hex, client->merkle_match_pending);

                spv_merkle_match key;
                memset(&key, 0, sizeof(key));
                memcpy(key.txid, txid, 32);

                dogecoin_btree_node_t* found = (dogecoin_btree_node_t*)dogecoin_btree_tfind(
                    &key, (void* const*)&client->merkle_match_tree, spv_merkle_match_cmp);
                if (found && found->key) {
                    spv_merkle_match* m = (spv_merkle_match*)found->key;
                    if (!m->consumed) {
                        unsigned int pos = (unsigned int)m->pos;
                        dogecoin_blockindex* bi = client->merkle_match_blockindex;

                        m->consumed = true;
                        if (client->merkle_match_pending > 0) client->merkle_match_pending--;

                        client->nodegroup->log_write_cb("[merkle-tx] MATCH at pos %u, calling sync_transaction (height=%d)\n",
                            pos, bi ? bi->height : -1);
                        client->sync_transaction(client->sync_transaction_ctx, tx, pos, bi);

                        if (client->merkle_match_pending == 0) {
                            client->merkle_match_active = false;
                            client->merkle_match_blockindex = NULL;
                            if (client->merkle_match_tree) {
                                dogecoin_btree_tdestroy(client->merkle_match_tree, dogecoin_free);
                                client->merkle_match_tree = NULL;
                            }
                        }
                    }
                } else {
                    client->nodegroup->log_write_cb("[merkle-tx] tx NOT found in match tree\n");
                }
            }
            if (tx) dogecoin_tx_free(tx);
        }

        if (client && client->smpv_enabled && client->smpv_ctx) {
            // allocate hex buffer (2 chars per byte + NUL)
            size_t hex_len = ((size_t)hdr->data_len * 2) + 1;
            char* hex = (char*)dogecoin_calloc(1, hex_len);
            if (hex) {
                // convert raw bytes to hex using utils.c
                utils_bin_to_hex((unsigned char*)buf->p, (size_t)hdr->data_len, hex);

                dogecoin_bool ok = dogecoin_spv_handle_mempool_tx_hex(client, hex);

                if (client->nodegroup && client->nodegroup->log_write_cb) {
                    client->nodegroup->log_write_cb(
                        "[smpv] mempool tx seen len=%u dispatched=%s\n",
                        hdr->data_len, ok ? "true" : "false"
                    );
                }
                dogecoin_free(hex);
            } else {
                if (client->nodegroup && client->nodegroup->log_write_cb) {
                    client->nodegroup->log_write_cb(
                        "[smpv] hex alloc failed for len=%u\n",
                        hdr->data_len
                    );
                }
            }
        }
    }

    // Check for a 'Q' or 'q' on stdin, to quit.
#ifdef _WIN32
    if (_kbhit()) {
        char c = fgetc(stdin);
        if (c == 'Q' || c == 'q') {
            printf("Disconnecting...\n");
            dogecoin_node_group_shutdown(client->nodegroup);

        // exit the event loop immediately
        if (client->nodegroup && client->nodegroup->event_base)
            event_base_loopbreak(client->nodegroup->event_base);
        }
    }
#else
    char c = fgetc(stdin);
    if (c == 'Q' || c == 'q') {
        // Reset standard input back to blocking mode
        int stdin_flags = fcntl(STDIN_FILENO, F_GETFL);
        fcntl(STDIN_FILENO, F_SETFL, stdin_flags & ~O_NONBLOCK);

        printf("Disconnecting...\n");
        dogecoin_node_group_shutdown(client->nodegroup);

        // exit the event loop immediately
        if (client->nodegroup && client->nodegroup->event_base)
            event_base_loopbreak(client->nodegroup->event_base);
    }
#endif
}

static void smpv_tx_cb(const dogecoin_smpv_tx* tx, const char* addr, void* user)
{
    dogecoin_spv_client* client = (dogecoin_spv_client*)user;
    if (!client || !client->nodegroup || !client->nodegroup->log_write_cb || !tx) return;

    client->nodegroup->log_write_cb(
        "[smpv] tx=%s size=%lluB vin=%u vout=%u coinbase=%d "
        "outval=%llu koinu types{p2pk=%u,p2pkh=%u,p2sh=%u,multi=%u,opret=%u,nonstd=%u}%s%s\n",
        tx->txid ? tx->txid : "(null)",
        (unsigned long long)tx->size,
        tx->vin_count, tx->vout_count,
        tx->is_coinbase ? 1 : 0,
        (unsigned long long)tx->total_output_value,
        tx->pubkey_out, tx->p2pkh_out, tx->p2sh_out,
        tx->multisig_out, tx->opreturn_out, tx->nonstandard_out,
        addr ? " addr=" : "", addr ? addr : ""
    );
}

LIBDOGECOIN_API void dogecoin_spv_enable_smpv(dogecoin_spv_client* client, dogecoin_bool enable)
{
    if (!client) return;

    if (enable && !client->smpv_enabled) {
        client->smpv_ctx = dogecoin_smpv_client_new(client->chainparams);
        if (client->smpv_ctx && dogecoin_smpv_start((dogecoin_smpv_client*)client->smpv_ctx)) {
            client->smpv_enabled = true;
            if (client->nodegroup && client->nodegroup->log_write_cb)
                client->nodegroup->log_write_cb("[smpv] enabled\n");
        } else {
            if (client->nodegroup && client->nodegroup->log_write_cb)
                client->nodegroup->log_write_cb("[smpv] failed to enable (alloc/start)\n");
            if (client->smpv_ctx) {
                dogecoin_smpv_client_free((dogecoin_smpv_client*)client->smpv_ctx);
                client->smpv_ctx = NULL;
            }
        }
        return;
    }

    if (!enable && client->smpv_enabled) {
        if (client->nodegroup && client->nodegroup->log_write_cb)
            client->nodegroup->log_write_cb("[smpv] disabling\n");
        dogecoin_smpv_stop((dogecoin_smpv_client*)client->smpv_ctx);
        dogecoin_smpv_client_free((dogecoin_smpv_client*)client->smpv_ctx);
        client->smpv_ctx = NULL;
        client->smpv_enabled = false;
    }
}

LIBDOGECOIN_API dogecoin_bool dogecoin_spv_handle_mempool_tx_hex(dogecoin_spv_client* client, const char* raw_tx_hex)
{
    if (!client || !client->smpv_enabled || !client->smpv_ctx || !raw_tx_hex) return false;
    return dogecoin_smpv_process_tx(
        (dogecoin_smpv_client*)client->smpv_ctx,
        raw_tx_hex,
        smpv_tx_cb,
        client
    );
}

LIBDOGECOIN_API void dogecoin_spv_get_smpv_stats(dogecoin_spv_client* client, uint32_t* total_txs, uint32_t* watched_addrs)
{
    if (total_txs) *total_txs = 0;
    if (watched_addrs) *watched_addrs = 0;
    if (!client || !client->smpv_enabled || !client->smpv_ctx) return;
    dogecoin_smpv_get_stats(
        (dogecoin_smpv_client*)client->smpv_ctx,
        total_txs, watched_addrs);
}

LIBDOGECOIN_API void dogecoin_net_spv_request_mempool(dogecoin_spv_client *client)
{
    if (!client || !client->nodegroup || !client->nodegroup->nodes) return;
    vector_t* nodes = client->nodegroup->nodes;
    for (unsigned int i = 0; i < (unsigned int)nodes->len; i++) {
        dogecoin_node* n = (dogecoin_node*)vector_idx(nodes, i);
        if (!n) continue;
        cstring* payload = cstr_new_sz(0);
        cstring* msg = dogecoin_p2p_message_new(
            n->nodegroup->chainparams->netmagic,
            DOGECOIN_MSG_MEMPOOL,
            payload->str,
            payload->len
        );
        cstr_free(payload, true);
        dogecoin_node_send(n, msg);
        cstr_free(msg, true);
    }
    if (client->nodegroup && client->nodegroup->log_write_cb)
        client->nodegroup->log_write_cb("[spv] sent 'mempool' to peers\n");
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

        uint64_t flen = (uint64_t)filter_len;
        uint8_t vi[9];
        size_t vi_len = 0;

        if (flen < 0xfdULL) {
            vi[0] = (uint8_t)flen; vi_len = 1;
        } else if (flen <= 0xffffULL) {
            vi[0] = 0xfd;
            vi[1] = (uint8_t)(flen & 0xff);
            vi[2] = (uint8_t)((flen >> 8) & 0xff);
            vi_len = 3;
        } else if (flen <= 0xffffffffULL) {
            vi[0] = 0xfe;
            vi[1] = (uint8_t)(flen & 0xff);
            vi[2] = (uint8_t)((flen >> 8) & 0xff);
            vi[3] = (uint8_t)((flen >> 16) & 0xff);
            vi[4] = (uint8_t)((flen >> 24) & 0xff);
            vi_len = 5;
        } else {
            vi[0] = 0xff;
            vi[1] = (uint8_t)(flen & 0xff);
            vi[2] = (uint8_t)((flen >> 8) & 0xff);
            vi[3] = (uint8_t)((flen >> 16) & 0xff);
            vi[4] = (uint8_t)((flen >> 24) & 0xff);
            vi[5] = (uint8_t)((flen >> 32) & 0xff);
            vi[6] = (uint8_t)((flen >> 40) & 0xff);
            vi[7] = (uint8_t)((flen >> 48) & 0xff);
            vi[8] = (uint8_t)((flen >> 56) & 0xff);
            vi_len = 9;
        }

        size_t payload_len = vi_len + (size_t)filter_len + 4 + 4 + 1;
        uint8_t* payload = (uint8_t*)dogecoin_calloc(1, payload_len);
        if (!payload) continue;

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

        payload[off] = (uint8_t)flags;

        cstring* msg = dogecoin_p2p_message_new(
            n->nodegroup->chainparams->netmagic,
            DOGECOIN_MSG_FILTERLOAD,
            payload,
            (uint32_t)payload_len
        );
        dogecoin_node_send(n, msg);
        cstr_free(msg, true);
        dogecoin_free(payload);
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

    for (unsigned int i = 0; i < (unsigned int)client->nodegroup->nodes->len; i++) {
        dogecoin_node* n = (dogecoin_node*)vector_idx(client->nodegroup->nodes, i);
        if (!n) continue;
        if (((n->state & NODE_CONNECTED) != NODE_CONNECTED) || !n->version_handshake) continue;

        uint64_t dlen = (uint64_t)data_len;
        uint8_t vi[9];
        size_t vi_len = 0;

        if (dlen < 0xfdULL) {
            vi[0] = (uint8_t)dlen; vi_len = 1;
        } else if (dlen <= 0xffffULL) {
            vi[0] = 0xfd;
            vi[1] = (uint8_t)(dlen & 0xff);
            vi[2] = (uint8_t)((dlen >> 8) & 0xff);
            vi_len = 3;
        } else if (dlen <= 0xffffffffULL) {
            vi[0] = 0xfe;
            vi[1] = (uint8_t)(dlen & 0xff);
            vi[2] = (uint8_t)((dlen >> 8) & 0xff);
            vi[3] = (uint8_t)((dlen >> 16) & 0xff);
            vi[4] = (uint8_t)((dlen >> 24) & 0xff);
            vi_len = 5;
        } else {
            vi[0] = 0xff;
            vi[1] = (uint8_t)(dlen & 0xff);
            vi[2] = (uint8_t)((dlen >> 8) & 0xff);
            vi[3] = (uint8_t)((dlen >> 16) & 0xff);
            vi[4] = (uint8_t)((dlen >> 24) & 0xff);
            vi[5] = (uint8_t)((dlen >> 32) & 0xff);
            vi[6] = (uint8_t)((dlen >> 40) & 0xff);
            vi[7] = (uint8_t)((dlen >> 48) & 0xff);
            vi[8] = (uint8_t)((dlen >> 56) & 0xff);
            vi_len = 9;
        }

        size_t payload_len = vi_len + (size_t)data_len;
        uint8_t* payload = (uint8_t*)dogecoin_calloc(1, payload_len);
        if (!payload) continue;

        memcpy(payload, vi, vi_len);
        memcpy(payload + vi_len, data, data_len);

        cstring* msg = dogecoin_p2p_message_new(
            n->nodegroup->chainparams->netmagic,
            DOGECOIN_MSG_FILTERADD,
            payload,
            (uint32_t)payload_len
        );
        dogecoin_node_send(n, msg);
        cstr_free(msg, true);
        dogecoin_free(payload);
    }

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
