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
#include <pthread.h>
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

static const unsigned int HEADERS_MAX_RESPONSE_TIME = 120;
static const unsigned int MIN_TIME_DELTA_FOR_STATE_CHECK = 5;
static const unsigned int BLOCK_GAP_TO_DEDUCT_TO_START_SCAN_FROM = 5;
static const unsigned int BLOCKS_DELTA_IN_S = 60;
static const unsigned int COMPLETED_WHEN_NUM_NODES_AT_SAME_HEIGHT = 2;
#define MAX_HEADER_SYNC_CANDIDATES 64
/* Store a rolling lane cursor in node->hints low byte to diversify block locator trimming. */
#define HEADER_LANE_HINT_MASK 0xFFU
#define HEADER_INVALID_STREAK_SHIFT 8
#define HEADER_INVALID_STREAK_MASK (0xFFU << HEADER_INVALID_STREAK_SHIFT)
static const unsigned int MAX_INVALID_STREAK_VALUE = 0xFFU;
static const unsigned int INVALID_STREAK_SENTINEL = 0x100U;
static const unsigned int MAX_PARALLEL_HEADER_REQUESTS = 5;

static unsigned int spv_get_invalid_header_streak(const dogecoin_node* node)
{
    return (unsigned int)((node->hints & HEADER_INVALID_STREAK_MASK) >> HEADER_INVALID_STREAK_SHIFT);
}

static void spv_set_invalid_header_streak(dogecoin_node* node, unsigned int streak)
{
    if (streak > MAX_INVALID_STREAK_VALUE) streak = MAX_INVALID_STREAK_VALUE;
    node->hints = (node->hints & ~HEADER_INVALID_STREAK_MASK) | (streak << HEADER_INVALID_STREAK_SHIFT);
}

static void spv_reset_invalid_header_streak(dogecoin_node* node)
{
    spv_set_invalid_header_streak(node, 0);
}

static unsigned int spv_increment_invalid_header_streak(dogecoin_node* node)
{
    unsigned int streak = spv_get_invalid_header_streak(node);
    if (streak < MAX_INVALID_STREAK_VALUE) streak++;
    spv_set_invalid_header_streak(node, streak);
    return streak;
}

static dogecoin_bool dogecoin_net_spv_node_timer_callback(dogecoin_node *node, uint64_t *now);
void dogecoin_net_spv_post_cmd(dogecoin_node *node, dogecoin_p2p_msg_hdr *hdr, struct const_buffer *buf);
void dogecoin_net_spv_node_handshake_done(dogecoin_node *node);

typedef struct spv_header_parse_task_ {
    int nodeid;
    uint32_t amount_of_headers;
    const dogecoin_chainparams* chainparams;
    uint8_t* payload;
    size_t payload_len;
    struct spv_header_parse_task_* next;
} spv_header_parse_task;

typedef struct spv_header_parse_result_ {
    int nodeid;
    uint32_t amount_of_headers;
    uint8_t* payload;
    size_t payload_len;
    dogecoin_bool parse_ok;
    struct spv_header_parse_result_* next;
} spv_header_parse_result;

typedef struct spv_headers_pipeline_ctx_ spv_headers_pipeline_ctx;

/* Bounded master-writer staging for out-of-order header batches.
 * Workers never touch these slots. When the main thread receives a parsed batch whose first
 * header's prev_block does not match the current chaintip but is already known in headersdb,
 * the batch is staged here instead of being rejected. After every successful commit that
 * advances the tip, staged batches whose stored prev_block equals the new tip hash are re-applied.
 */
#define SPV_HEADERS_STAGE_CAPACITY 8

typedef struct spv_header_stage_slot_ {
    int in_use;
    int nodeid;
    uint32_t amount_of_headers;
    uint8_t* payload;       /* owned */
    size_t payload_len;
    uint8_t prev_block[32]; /* little-endian hash of the first header's prev_block */
} spv_header_stage_slot;

typedef struct spv_headers_stage_ctx_ {
    spv_header_stage_slot slots[SPV_HEADERS_STAGE_CAPACITY];
    size_t count;
    uint64_t staged_total;
    uint64_t drained_total;
    uint64_t dropped_total;
} spv_headers_stage_ctx;

static spv_headers_stage_ctx* spv_headers_stage_init(void)
{
    return (spv_headers_stage_ctx*)dogecoin_calloc(1, sizeof(spv_headers_stage_ctx));
}

static void spv_headers_stage_free(spv_headers_stage_ctx* stage)
{
    if (!stage) return;
    for (size_t i = 0; i < SPV_HEADERS_STAGE_CAPACITY; i++) {
        if (stage->slots[i].in_use && stage->slots[i].payload) {
            dogecoin_free(stage->slots[i].payload);
        }
    }
    dogecoin_free(stage);
}

static void spv_headers_stage_clear_slot(spv_header_stage_slot* slot)
{
    if (!slot) return;
    if (slot->payload) dogecoin_free(slot->payload);
    memset(slot, 0, sizeof(*slot));
}

static dogecoin_node* spv_find_node_by_id(dogecoin_spv_client* client, int nodeid)
{
    size_t i;
    for (i = 0; i < client->nodegroup->nodes->len; i++) {
        dogecoin_node* node = vector_idx(client->nodegroup->nodes, i);
        if (node && node->nodeid == nodeid) {
            return node;
        }
    }
    return NULL;
}

static dogecoin_bool spv_validate_headers_payload(uint32_t amount_of_headers, const uint8_t* payload, size_t payload_len, const dogecoin_chainparams* params)
{
    /* Worker stage keeps prevalidation lightweight; authoritative parsing/validation occurs on commit. */
    UNUSED(params);
    if (amount_of_headers == 0) return true;
    if (!payload) return false;
    if (payload_len == 0) return false;
    return (payload_len >= ((size_t)amount_of_headers * 81U));
}

#ifndef _WIN32
#define SPV_HEADERS_WORKER_COUNT 2
struct spv_headers_pipeline_ctx_ {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_t workers[SPV_HEADERS_WORKER_COUNT];
    dogecoin_bool running;
    dogecoin_bool started;
    spv_header_parse_task* task_head;
    spv_header_parse_task* task_tail;
    spv_header_parse_result* result_head;
    spv_header_parse_result* result_tail;
};

static void spv_free_header_parse_task(spv_header_parse_task* task)
{
    if (!task) return;
    dogecoin_free(task->payload);
    dogecoin_free(task);
}

static void spv_free_header_parse_result(spv_header_parse_result* result)
{
    if (!result) return;
    dogecoin_free(result->payload);
    dogecoin_free(result);
}

static void* spv_headers_pipeline_worker(void* arg)
{
    spv_headers_pipeline_ctx* ctx = (spv_headers_pipeline_ctx*)arg;
    while (true) {
        pthread_mutex_lock(&ctx->lock);
        while (ctx->running && !ctx->task_head) {
            pthread_cond_wait(&ctx->cond, &ctx->lock);
        }
        if (!ctx->running) {
            pthread_mutex_unlock(&ctx->lock);
            break;
        }

        spv_header_parse_task* task = ctx->task_head;
        ctx->task_head = task->next;
        if (!ctx->task_head) ctx->task_tail = NULL;
        pthread_mutex_unlock(&ctx->lock);

        spv_header_parse_result* result = dogecoin_calloc(1, sizeof(*result));
        if (result) {
            result->nodeid = task->nodeid;
            result->amount_of_headers = task->amount_of_headers;
            result->payload = task->payload;
            result->payload_len = task->payload_len;
            result->parse_ok = spv_validate_headers_payload(task->amount_of_headers, task->payload, task->payload_len, task->chainparams);
            result->next = NULL;
            task->payload = NULL;

            pthread_mutex_lock(&ctx->lock);
            if (ctx->result_tail) ctx->result_tail->next = result;
            else ctx->result_head = result;
            ctx->result_tail = result;
            pthread_mutex_unlock(&ctx->lock);
        }
        spv_free_header_parse_task(task);
    }
    return NULL;
}

static spv_headers_pipeline_ctx* spv_headers_pipeline_init(void)
{
    spv_headers_pipeline_ctx* ctx = dogecoin_calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    if (pthread_mutex_init(&ctx->lock, NULL) != 0) {
        dogecoin_free(ctx);
        return NULL;
    }
    if (pthread_cond_init(&ctx->cond, NULL) != 0) {
        pthread_mutex_destroy(&ctx->lock);
        dogecoin_free(ctx);
        return NULL;
    }

    ctx->running = true;
    ctx->started = true;
    for (size_t i = 0; i < SPV_HEADERS_WORKER_COUNT; i++) {
        if (pthread_create(&ctx->workers[i], NULL, spv_headers_pipeline_worker, ctx) != 0) {
            ctx->running = false;
            pthread_cond_broadcast(&ctx->cond);
            for (size_t j = 0; j < i; j++) pthread_join(ctx->workers[j], NULL);
            pthread_mutex_destroy(&ctx->lock);
            pthread_cond_destroy(&ctx->cond);
            dogecoin_free(ctx);
            return NULL;
        }
    }
    return ctx;
}

static void spv_headers_pipeline_free(spv_headers_pipeline_ctx* ctx)
{
    if (!ctx) return;
    if (ctx->started) {
        pthread_mutex_lock(&ctx->lock);
        ctx->running = false;
        pthread_cond_broadcast(&ctx->cond);
        pthread_mutex_unlock(&ctx->lock);
        for (size_t i = 0; i < SPV_HEADERS_WORKER_COUNT; i++) pthread_join(ctx->workers[i], NULL);
    }

    spv_header_parse_task* task = ctx->task_head;
    while (task) {
        spv_header_parse_task* next = task->next;
        spv_free_header_parse_task(task);
        task = next;
    }
    spv_header_parse_result* result = ctx->result_head;
    while (result) {
        spv_header_parse_result* next = result->next;
        spv_free_header_parse_result(result);
        result = next;
    }

    pthread_mutex_destroy(&ctx->lock);
    pthread_cond_destroy(&ctx->cond);
    dogecoin_free(ctx);
}
#else
static spv_headers_pipeline_ctx* spv_headers_pipeline_init(void) { return NULL; }
static void spv_headers_pipeline_free(spv_headers_pipeline_ctx* ctx) { UNUSED(ctx); }
#endif

/* Forward declaration so staging helpers can call the committer. */
static void spv_commit_parsed_headers_batch(dogecoin_spv_client* client, int nodeid, uint32_t amount_of_headers, const uint8_t* payload, size_t payload_len, dogecoin_bool parse_ok);

/* Read the first header's prev_block (32 bytes at offset 4 of the serialized header).
 * Returns true on success; false if payload is too short. */
static dogecoin_bool spv_batch_peek_prev_block(const uint8_t* payload, size_t payload_len, uint8_t out_prev_block[32])
{
    /* block header layout: 4 (version) + 32 (prev_block) + ... */
    if (!payload || payload_len < 36) return false;
    memcpy(out_prev_block, payload + 4, 32);
    return true;
}

static dogecoin_bool spv_stage_batch(dogecoin_spv_client* client, int nodeid, uint32_t amount_of_headers, const uint8_t* payload, size_t payload_len, const uint8_t prev_block[32])
{
    spv_headers_stage_ctx* stage = (spv_headers_stage_ctx*)client->headers_stage_ctx;
    if (!stage || !payload || payload_len == 0) return false;

    /* Allocate the new payload buffer up-front so we can bail out without disturbing
     * staging accounting (count/dropped_total) if the allocation fails. */
    uint8_t* copy = (uint8_t*)dogecoin_calloc(1, payload_len);
    if (!copy) return false;
    memcpy(copy, payload, payload_len);

    /* avoid duplicate staging for the same prev_block */
    for (size_t i = 0; i < SPV_HEADERS_STAGE_CAPACITY; i++) {
        if (stage->slots[i].in_use && memcmp(stage->slots[i].prev_block, prev_block, 32) == 0) {
            /* already staged for this prev; prefer the more recent payload */
            spv_headers_stage_clear_slot(&stage->slots[i]);
            stage->count--;
            break;
        }
    }

    size_t target = SPV_HEADERS_STAGE_CAPACITY;
    for (size_t i = 0; i < SPV_HEADERS_STAGE_CAPACITY; i++) {
        if (!stage->slots[i].in_use) { target = i; break; }
    }
    if (target == SPV_HEADERS_STAGE_CAPACITY) {
        /* capacity full; drop the oldest (index 0) to make room */
        spv_headers_stage_clear_slot(&stage->slots[0]);
        stage->count--;
        stage->dropped_total++;
        target = 0;
    }

    spv_header_stage_slot* slot = &stage->slots[target];
    slot->payload = copy;
    slot->payload_len = payload_len;
    slot->amount_of_headers = amount_of_headers;
    slot->nodeid = nodeid;
    memcpy(slot->prev_block, prev_block, 32);
    slot->in_use = 1;
    stage->count++;
    stage->staged_total++;

    if (client->nodegroup && client->nodegroup->log_write_cb) {
        client->nodegroup->log_write_cb("Staged out-of-order headers batch from node %d (count=%u, staged=%zu)\n", nodeid, amount_of_headers, stage->count);
    }
    return true;
}

static void spv_stage_drain_for_tip(dogecoin_spv_client* client)
{
    spv_headers_stage_ctx* stage = (spv_headers_stage_ctx*)client->headers_stage_ctx;
    if (!stage || stage->count == 0 || !client->headers_db) return;
    /* Drain as long as any staged slot's prev_block matches the current chaintip hash.
     * Committing can advance the tip further, enabling additional drains. */
    int made_progress = 1;
    while (made_progress) {
        made_progress = 0;
        dogecoin_blockindex* tip = client->headers_db->getchaintip(client->headers_db_ctx);
        if (!tip) break;
        for (size_t i = 0; i < SPV_HEADERS_STAGE_CAPACITY; i++) {
            spv_header_stage_slot* slot = &stage->slots[i];
            if (!slot->in_use) continue;
            if (memcmp(slot->prev_block, tip->hash, 32) != 0) continue;

            /* Take ownership locally so recursive commit doesn't see it in staging. */
            uint8_t* payload = slot->payload;
            size_t payload_len = slot->payload_len;
            uint32_t amount_of_headers = slot->amount_of_headers;
            int nodeid = slot->nodeid;
            slot->payload = NULL;
            slot->in_use = 0;
            slot->payload_len = 0;
            slot->amount_of_headers = 0;
            stage->count--;
            stage->drained_total++;

            if (client->nodegroup && client->nodegroup->log_write_cb) {
                client->nodegroup->log_write_cb("Draining staged headers batch from node %d (count=%u, remaining_staged=%zu)\n", nodeid, amount_of_headers, stage->count);
            }
            spv_commit_parsed_headers_batch(client, nodeid, amount_of_headers, payload, payload_len, true);
            dogecoin_free(payload);
            made_progress = 1;
            break; /* re-read chaintip before next slot scan */
        }
    }
}

void dogecoin_spv_client_enable_thread_safe_mode(dogecoin_spv_client* client)
{
    if (!client) return;
    if (client->thread_safe_mode) return;
    if (!client->headers_stage_ctx) {
        client->headers_stage_ctx = spv_headers_stage_init();
    }
    client->thread_safe_mode = true;
    if (client->nodegroup && client->nodegroup->log_write_cb) {
        client->nodegroup->log_write_cb("SPV thread-safe mode enabled: master-writer pipeline with %d out-of-order staging slots\n", SPV_HEADERS_STAGE_CAPACITY);
    }
}

static void spv_commit_parsed_headers_batch(dogecoin_spv_client* client, int nodeid, uint32_t amount_of_headers, const uint8_t* payload, size_t payload_len, dogecoin_bool parse_ok)
{
    dogecoin_node* node = spv_find_node_by_id(client, nodeid);
    if (!node) {
        client->nodegroup->log_write_cb("Skipping parsed headers for disconnected node %d\n", nodeid);
        return;
    }
    if (!parse_ok) {
        client->nodegroup->log_write_cb("Header payload parse failed from node %d\n", node->nodeid);
        return;
    }

    /* Out-of-order staging pre-check: if the batch's first header does not build on the current
     * chaintip but its prev_block is already in the headers DB, stage the batch for later drain
     * rather than rejecting it (and penalizing the peer with an invalid-sequence streak).
     * Only active when the staging ring has been provisioned (spv client thread-safe mode or
     * explicit init). Keeps legacy behavior unchanged for non-staged clients. */
    if (client->headers_stage_ctx && amount_of_headers > 0) {
        uint8_t prev_block[32];
        if (spv_batch_peek_prev_block(payload, payload_len, prev_block)) {
            dogecoin_blockindex* tip = client->headers_db ? client->headers_db->getchaintip(client->headers_db_ctx) : NULL;
            if (tip && memcmp(prev_block, tip->hash, 32) != 0) {
                dogecoin_blockindex* prev_block_index = dogecoin_headersdb_find((dogecoin_headers_db*)client->headers_db_ctx, prev_block);
                if (prev_block_index) {
                    if (spv_stage_batch(client, nodeid, amount_of_headers, payload, payload_len, prev_block)) {
                        return;
                    }
                    /* staging failed (e.g. alloc) -> fall through to legacy commit */
                }
            }
        }
    }

    unsigned int connected_headers = 0;
    unsigned int duplicate_headers = 0;
    unsigned int invalid_headers = 0;
    struct const_buffer workbuf = { payload, payload_len };
    for (uint32_t i = 0; i < amount_of_headers; i++) {
        dogecoin_bool connected = false;
        dogecoin_blockindex *pindex = client->headers_db->connect_hdr(client->headers_db_ctx, &workbuf, false, &connected);
        if (!pindex) {
            client->nodegroup->log_write_cb("Header deserialization failed (node %d)\n", node->nodeid);
            invalid_headers++;
            break;
        }
        uint32_t txcount = 0;
        if (!deser_varlen(&txcount, &workbuf)) {
            client->nodegroup->log_write_cb("Header txcount parse failed (node %d)\n", node->nodeid);
            invalid_headers++;
            break;
        }

        if (!connected) {
            dogecoin_bool header_exists_in_db = (dogecoin_headersdb_find((dogecoin_headers_db*)client->headers_db_ctx, pindex->hash) != NULL);
            if (header_exists_in_db) {
                duplicate_headers++;
                continue;
            }
            client->nodegroup->log_write_cb("Got invalid headers (not in sequence) from node %d\n", node->nodeid);
            invalid_headers++;
            node->state &= ~NODE_HEADERSYNC;
            unsigned int invalid_streak = spv_increment_invalid_header_streak(node);
            client->nodegroup->log_write_cb("Node %d invalid header streak %u\n", node->nodeid, invalid_streak);
            dogecoin_free(pindex);
            break;
        } else {
            spv_reset_invalid_header_streak(node);
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
    client->nodegroup->log_write_cb("Headers batch stats node %d: connected=%u duplicate=%u invalid=%u total=%u\n", node->nodeid, connected_headers, duplicate_headers, invalid_headers, amount_of_headers);
    client->nodegroup->log_write_cb("Chaintip at height %d\n", chaintip->height);

    /* If the tip advanced, try to drain any staged batches that now connect. */
    if (connected_headers > 0) {
        spv_stage_drain_for_tip(client);
        chaintip = client->headers_db->getchaintip(client->headers_db_ctx);
    }

    if (client->header_message_processed && client->header_message_processed(client, node, chaintip) == false)
        return;

    if (amount_of_headers == MAX_HEADERS_RESULTS && ((node->state & NODE_BLOCKSYNC) != NODE_BLOCKSYNC))
    {
        time_t lasttime = chaintip->header.timestamp;
        client->nodegroup->log_write_cb("chain size: %d, last time %s", chaintip->height, ctime(&lasttime));
        node->state &= ~NODE_HEADERSYNC;
        dogecoin_net_spv_request_headers(client);
    }
}

static dogecoin_bool spv_headers_pipeline_enqueue(dogecoin_spv_client* client, dogecoin_node* node, uint32_t amount_of_headers, const uint8_t* payload, size_t payload_len)
{
    spv_headers_pipeline_ctx* ctx = (spv_headers_pipeline_ctx*)client->headers_pipeline_ctx;
    if (!ctx || !payload) return false;

#ifndef _WIN32
    spv_header_parse_task* task = dogecoin_calloc(1, sizeof(*task));
    if (!task) return false;
    if (amount_of_headers == 0) {
        dogecoin_free(task);
        return false;
    }
    task->payload = dogecoin_calloc(1, payload_len);
    if (!task->payload) {
        dogecoin_free(task);
        return false;
    }
    memcpy(task->payload, payload, payload_len);
    task->payload_len = payload_len;
    task->amount_of_headers = amount_of_headers;
    task->chainparams = client->chainparams;
    task->nodeid = node->nodeid;
    task->next = NULL;

    pthread_mutex_lock(&ctx->lock);
    if (!ctx->running) {
        pthread_mutex_unlock(&ctx->lock);
        spv_free_header_parse_task(task);
        return false;
    }
    if (ctx->task_tail) ctx->task_tail->next = task;
    else ctx->task_head = task;
    ctx->task_tail = task;
    pthread_cond_signal(&ctx->cond);
    pthread_mutex_unlock(&ctx->lock);
    return true;
#else
    UNUSED(node); UNUSED(amount_of_headers); UNUSED(payload_len);
    return false;
#endif
}

static void spv_headers_pipeline_drain(dogecoin_spv_client* client)
{
    spv_headers_pipeline_ctx* ctx = (spv_headers_pipeline_ctx*)client->headers_pipeline_ctx;
    if (!ctx) return;

#ifndef _WIN32
    while (true) {
        pthread_mutex_lock(&ctx->lock);
        spv_header_parse_result* result = ctx->result_head;
        if (result) {
            ctx->result_head = result->next;
            if (!ctx->result_head) ctx->result_tail = NULL;
        }
        pthread_mutex_unlock(&ctx->lock);
        if (!result) break;

        spv_commit_parsed_headers_batch(client, result->nodeid, result->amount_of_headers, result->payload, result->payload_len, result->parse_ok);
        spv_free_header_parse_result(result);
    }
#endif
}

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
    client->headers_target_nodeid = -1;
    client->next_headers_peer_cursor = 0;
    client->header_no_progress_rounds = 0;
    client->last_tip_height_observed = 0;

    // SMPV default off
    client->smpv_ctx = NULL;
    client->smpv_enabled = false;
    client->headers_pipeline_ctx = spv_headers_pipeline_init();
    client->headers_stage_ctx = NULL;
    client->thread_safe_mode = false;

    return client;
}

void dogecoin_spv_set_headers_target_node(dogecoin_spv_client* client, int nodeid)
{
    if (!client) {
        return;
    }
    client->headers_target_nodeid = nodeid;
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

    if (client->headers_pipeline_ctx) {
        spv_headers_pipeline_free((spv_headers_pipeline_ctx*)client->headers_pipeline_ctx);
        client->headers_pipeline_ctx = NULL;
    }

    if (client->headers_stage_ctx) {
        spv_headers_stage_free((spv_headers_stage_ctx*)client->headers_stage_ctx);
        client->headers_stage_ctx = NULL;
    }

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

    /* Run scheduling from a single timer source to avoid duplicate fan-out from every connected node. */
    if (!node->nodegroup || !node->nodegroup->nodes || node->nodegroup->nodes->len == 0 || vector_idx(node->nodegroup->nodes, 0) != node) {
        return;
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
            for (i = length - 1; i >= 0; i--) {
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
    size_t lane_trim_offset = 0;
    if (!blocks) {
        lane_trim_offset = (size_t)(node->hints & HEADER_LANE_HINT_MASK);
    }

    dogecoin_net_spv_fill_block_locator((dogecoin_spv_client *)node->nodegroup->ctx, blocklocators);
    if (lane_trim_offset > 0 && blocklocators->len > 1) {
        size_t removable = blocklocators->len - 1;
        if (lane_trim_offset > removable) {
            lane_trim_offset = removable;
        }
        vector_remove_range(blocklocators, 0, lane_trim_offset);
    }
    if (!blocks && blocklocators->len > 0) {
        uint256_t* start_locator = vector_idx(blocklocators, 0);
        if (start_locator) {
            char locator_buf[DOGECOIN_HASH_LENGTH * 2 + 1];
            const char* locator_str = hash_to_string(*start_locator);
            memcpy_safe(locator_buf, locator_str, sizeof(locator_buf));
            node->nodegroup->log_write_cb("Header request node %d: lane_trim_offset=%zu locator_count=%zu start_locator=%s\n", node->nodeid, lane_trim_offset, blocklocators->len, locator_buf);
        }
    }

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
    int headers_target_nodeid = client->headers_target_nodeid;
    spv_headers_pipeline_drain(client);
    dogecoin_blockindex *chaintip = client->headers_db->getchaintip(client->headers_db_ctx);
    if (!chaintip) {
        return false;
    }
    unsigned int tip_height = chaintip->height;
    if (client->last_tip_height_observed == tip_height) {
        if (client->header_no_progress_rounds < 1024) {
            client->header_no_progress_rounds++;
        }
    } else {
        client->last_tip_height_observed = tip_height;
        client->header_no_progress_rounds = 0;
    }
    // If in header or block sync state, request headers or blocks from the node with the longest chain
    if ((client->stateflags & SPV_HEADER_SYNC_FLAG) == SPV_HEADER_SYNC_FLAG || (client->stateflags & SPV_FULLBLOCK_SYNC_FLAG) == SPV_FULLBLOCK_SYNC_FLAG)
    {
        unsigned int longest_chain_height = 0;
        unsigned int request_count = 0;
        size_t candidate_node_indices[MAX_HEADER_SYNC_CANDIDATES];
        size_t candidate_len = 0;
        dogecoin_bool candidate_overflow_logged = false;
        for(i = 0; i < client->nodegroup->nodes->len; ++i)
        {
            dogecoin_node *check_node = vector_idx(client->nodegroup->nodes, i);
            if (((check_node->state & NODE_CONNECTED) == NODE_CONNECTED) && check_node->version_handshake)
            {
                if (check_node->bestknownheight > longest_chain_height)
                {
                    longest_chain_height = check_node->bestknownheight;
                }
            }
        }

        // Request headers or blocks from nodes with the longest chain.
        if (longest_chain_height > tip_height) {
            dogecoin_bool request_blocks = (client->stateflags & SPV_FULLBLOCK_SYNC_FLAG) == SPV_FULLBLOCK_SYNC_FLAG;
            for(i = 0; i < client->nodegroup->nodes->len; ++i)
            {
                dogecoin_node *check_node = vector_idx(client->nodegroup->nodes, i);
                if (((check_node->state & NODE_CONNECTED) == NODE_CONNECTED) &&
                    check_node->version_handshake &&
                    (headers_target_nodeid < 0 || check_node->nodeid == headers_target_nodeid) &&
                    (check_node->state & NODE_HEADERSYNC) != NODE_HEADERSYNC &&
                    (check_node->state & NODE_BLOCKSYNC) != NODE_BLOCKSYNC &&
                    ((request_blocks && check_node->bestknownheight == longest_chain_height) ||
                     (!request_blocks && check_node->bestknownheight > tip_height)))
                {
                    if (request_blocks) {
                        dogecoin_net_spv_node_request_headers_or_blocks(check_node, true);
                        new_headers_available = true;
                        request_count++;
                    } else if (candidate_len < MAX_HEADER_SYNC_CANDIDATES) {
                        candidate_node_indices[candidate_len++] = i;
                    } else if (!candidate_overflow_logged) {
                        client->nodegroup->log_write_cb("Header peer candidate overflow (max %u), truncating list\n", MAX_HEADER_SYNC_CANDIDATES);
                        candidate_overflow_logged = true;
                    }
                }
            }
            if (!request_blocks && candidate_len > 0) {
                size_t max_parallel_cap = candidate_len < MAX_PARALLEL_HEADER_REQUESTS ? candidate_len : MAX_PARALLEL_HEADER_REQUESTS;
                size_t max_parallel = max_parallel_cap;
                for (size_t lane = 0; lane < max_parallel; lane++) {
                    size_t selected = candidate_node_indices[(client->next_headers_peer_cursor + lane) % candidate_len];
                    dogecoin_node *selected_node = vector_idx(client->nodegroup->nodes, selected);
                    uint32_t lane_hint = (uint32_t)((client->next_headers_peer_cursor + lane) % MAX_PARALLEL_HEADER_REQUESTS);
                    selected_node->hints = (selected_node->hints & ~HEADER_LANE_HINT_MASK) | lane_hint;
                    dogecoin_net_spv_node_request_headers_or_blocks(selected_node, false);
                    client->nodegroup->log_write_cb("Requested next headers chunk from node %d (lane=%zu/%zu, lane_trim_offset=%u, tip=%u)\n", selected_node->nodeid, lane + 1, max_parallel, lane_hint, tip_height);
                    new_headers_available = true;
                    request_count++;
                }
                client->next_headers_peer_cursor += (uint32_t)max_parallel;
            }
            if (request_count > 0) {
                client->nodegroup->log_write_cb("Requested headers/blocks from %u peer(s) at height %u (tip=%u)\n", request_count, longest_chain_height, tip_height);
            }
        }
    }

    // Fallback: original logic for handling cases where no suitable node was found
    unsigned int nodes_at_same_height = 0;
    if (!new_headers_available && client->headers_db->getchaintip(client->headers_db_ctx)->header.timestamp < client->oldest_item_of_interest - (BLOCK_GAP_TO_DEDUCT_TO_START_SCAN_FROM * BLOCKS_DELTA_IN_S) && client->stateflags == SPV_HEADER_SYNC_FLAG)
    {
        size_t candidate_node_indices[MAX_HEADER_SYNC_CANDIDATES];
        size_t candidate_len = 0;
        for(i = 0; i < client->nodegroup->nodes->len; i++)
        {
            dogecoin_node *check_node = vector_idx(client->nodegroup->nodes, i);
            if (((check_node->state & NODE_CONNECTED) == NODE_CONNECTED) && check_node->version_handshake)
            {
                if (headers_target_nodeid >= 0 && check_node->nodeid != headers_target_nodeid) {
                    continue;
                }
                if (check_node->bestknownheight > tip_height) {
                    if (candidate_len < MAX_HEADER_SYNC_CANDIDATES) {
                        candidate_node_indices[candidate_len++] = i;
                    }
                } else if (check_node->bestknownheight == tip_height) {
                    nodes_at_same_height++;
                }
            }
        }
        if (candidate_len > 0) {
            size_t max_parallel_cap = candidate_len < MAX_PARALLEL_HEADER_REQUESTS ? candidate_len : MAX_PARALLEL_HEADER_REQUESTS;
            size_t max_parallel = max_parallel_cap;
            for (size_t lane = 0; lane < max_parallel; lane++) {
                size_t selected = candidate_node_indices[(client->next_headers_peer_cursor + lane) % candidate_len];
                dogecoin_node *selected_node = vector_idx(client->nodegroup->nodes, selected);
                uint32_t lane_hint = (uint32_t)((client->next_headers_peer_cursor + lane) % MAX_PARALLEL_HEADER_REQUESTS);
                selected_node->hints = (selected_node->hints & ~HEADER_LANE_HINT_MASK) | lane_hint;
                dogecoin_net_spv_node_request_headers_or_blocks(selected_node, false);
                new_headers_available = true;
            }
            client->next_headers_peer_cursor += (uint32_t)max_parallel;
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
    /* Intentionally no immediate getheaders here; periodic scheduler batches peers into parallel lanes. */
    UNUSED(node);
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
    spv_headers_pipeline_drain(client);

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
            client->nodegroup->log_write_cb("Requesting %d blocks\n", varlen);
            cstring *p2p_msg = dogecoin_p2p_message_new(node->nodegroup->chainparams->netmagic, DOGECOIN_MSG_GETDATA, original_inv.p, original_inv.len);
            dogecoin_node_send(node, p2p_msg);
            cstr_free(p2p_msg, true);
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
        if (spv_headers_pipeline_enqueue(client, node, amount_of_headers, (const uint8_t*)buf->p, buf->len)) {
            spv_headers_pipeline_drain(client);
            return;
        }

        dogecoin_bool parse_ok = spv_validate_headers_payload(amount_of_headers, (const uint8_t*)buf->p, buf->len, client->chainparams);
        spv_commit_parsed_headers_batch(client, node->nodeid, amount_of_headers, (const uint8_t*)buf->p, buf->len, parse_ok);
    }

    if (strcmp(hdr->command, DOGECOIN_MSG_TX) == 0) {
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
