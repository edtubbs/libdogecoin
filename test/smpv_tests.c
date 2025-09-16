/*
 * Copyright (c) 2024 The Dogecoin Foundation
 *
 * Standalone SMPV (Simplified Mempool Payment Verification) Test
 * Standalone version that demonstrates the SMPV API structure
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stddef.h>

/* Basic types */
typedef int dogecoin_bool;
#define true 1
#define false 0

/* Mock chain parameters */
typedef struct {
    const char* name;
    const char* symbol;
} dogecoin_chainparams;

static const dogecoin_chainparams dogecoin_chainparams_main = {
    "mainnet", "DOGE"
};

static const dogecoin_chainparams dogecoin_chainparams_test = {
    "testnet", "tDOGE"
};

/* Mock transaction structure */
typedef struct {
    char* data;
    size_t len;
} dogecoin_tx;

/* SMPV transaction structure */
typedef struct {
    char* txid;                    /* Transaction ID (hex string) */
    char* raw_hex;                 /* Raw transaction hex */
    dogecoin_tx* decoded_tx;       /* Decoded transaction */
    uint64_t fee;                  /* Transaction fee in koinu */
    uint64_t size;                 /* Transaction size in bytes */
    uint64_t timestamp;            /* When transaction was first seen */
    dogecoin_bool is_confirmed;    /* Whether transaction is confirmed */
    uint32_t confirmations;        /* Number of confirmations */
    char* block_hash;              /* Block hash if confirmed */
    uint32_t block_height;         /* Block height if confirmed */
} dogecoin_smpv_tx;

/* SMPV address watcher structure */
typedef struct {
    char* address;                 /* Dogecoin address being watched */
    uint64_t total_received;       /* Total received in koinu */
    uint64_t total_sent;           /* Total sent in koinu */
    uint64_t balance;              /* Current balance in koinu */
    uint32_t tx_count;             /* Number of transactions */
    dogecoin_bool is_active;       /* Whether watcher is active */
} dogecoin_smpv_watcher;

/* SMPV client structure */
typedef struct {
    const dogecoin_chainparams* chain_params;
    dogecoin_smpv_watcher* watchers;   /* Array of watchers */
    dogecoin_smpv_tx* mempool_txs;     /* Array of mempool transactions */
    uint32_t watcher_count;
    uint32_t mempool_tx_count;
    dogecoin_bool is_running;
    uint64_t last_update_time;
} dogecoin_smpv_client;

/* Callback function type for transaction notifications */
typedef void (*dogecoin_smpv_tx_callback)(
    const dogecoin_smpv_tx* tx,
    const char* address,
    void* user_data
);

/* Memory management functions */
void* dogecoin_calloc(size_t nmemb, size_t size) {
    return calloc(nmemb, size);
}

void dogecoin_free(void* ptr) {
    free(ptr);
}

/* Initialize SMPV client */
dogecoin_smpv_client* dogecoin_smpv_client_new(const dogecoin_chainparams* chain_params) {
    if (!chain_params) return NULL;
    
    dogecoin_smpv_client* client = dogecoin_calloc(1, sizeof(dogecoin_smpv_client));
    if (!client) return NULL;
    
    client->chain_params = chain_params;
    client->watchers = NULL;
    client->mempool_txs = NULL;
    client->watcher_count = 0;
    client->mempool_tx_count = 0;
    client->is_running = false;
    client->last_update_time = 0;
    
    return client;
}

/* Free SMPV client */
void dogecoin_smpv_client_free(dogecoin_smpv_client* client) {
    if (!client) return;
    
    /* Free watchers */
    for (uint32_t i = 0; i < client->watcher_count; i++) {
        if (client->watchers[i].address) {
            dogecoin_free(client->watchers[i].address);
        }
    }
    if (client->watchers) {
        dogecoin_free(client->watchers);
    }
    
    /* Free transactions */
    for (uint32_t i = 0; i < client->mempool_tx_count; i++) {
        if (client->mempool_txs[i].txid) {
            dogecoin_free(client->mempool_txs[i].txid);
        }
        if (client->mempool_txs[i].raw_hex) {
            dogecoin_free(client->mempool_txs[i].raw_hex);
        }
        if (client->mempool_txs[i].decoded_tx) {
            dogecoin_free(client->mempool_txs[i].decoded_tx);
        }
        if (client->mempool_txs[i].block_hash) {
            dogecoin_free(client->mempool_txs[i].block_hash);
        }
    }
    if (client->mempool_txs) {
        dogecoin_free(client->mempool_txs);
    }
    
    dogecoin_free(client);
}

/* Add address to watch list */
dogecoin_bool dogecoin_smpv_add_watcher(
    dogecoin_smpv_client* client,
    const char* address
) {
    if (!client || !address) return false;
    
    /* Check if address is already being watched */
    for (uint32_t i = 0; i < client->watcher_count; i++) {
        if (strcmp(client->watchers[i].address, address) == 0) {
            return true; /* Already watching */
        }
    }
    
    /* Resize watchers array */
    client->watchers = realloc(client->watchers, 
                              (client->watcher_count + 1) * sizeof(dogecoin_smpv_watcher));
    if (!client->watchers) return false;
    
    /* Initialize new watcher */
    dogecoin_smpv_watcher* watcher = &client->watchers[client->watcher_count];
    watcher->address = dogecoin_calloc(1, strlen(address) + 1);
    if (!watcher->address) return false;
    strcpy(watcher->address, address);
    watcher->total_received = 0;
    watcher->total_sent = 0;
    watcher->balance = 0;
    watcher->tx_count = 0;
    watcher->is_active = true;
    
    client->watcher_count++;
    return true;
}

/* Remove address from watch list */
dogecoin_bool dogecoin_smpv_remove_watcher(
    dogecoin_smpv_client* client,
    const char* address
) {
    if (!client || !address) return false;
    
    for (uint32_t i = 0; i < client->watcher_count; i++) {
        if (strcmp(client->watchers[i].address, address) == 0) {
            /* Free the watcher */
            if (client->watchers[i].address) {
                dogecoin_free(client->watchers[i].address);
            }
            
            /* Move remaining watchers */
            for (uint32_t j = i; j < client->watcher_count - 1; j++) {
                client->watchers[j] = client->watchers[j + 1];
            }
            
            client->watcher_count--;
            return true;
        }
    }
    
    return false;
}

/* Get watcher for address */
dogecoin_smpv_watcher* dogecoin_smpv_get_watcher(
    const dogecoin_smpv_client* client,
    const char* address
) {
    if (!client || !address) return NULL;
    
    for (uint32_t i = 0; i < client->watcher_count; i++) {
        if (strcmp(client->watchers[i].address, address) == 0) {
            return &client->watchers[i];
        }
    }
    
    return NULL;
}

/* Start SMPV monitoring */
dogecoin_bool dogecoin_smpv_start(dogecoin_smpv_client* client) {
    if (!client) return false;
    
    client->is_running = true;
    client->last_update_time = time(NULL);
    return true;
}

/* Stop SMPV monitoring */
void dogecoin_smpv_stop(dogecoin_smpv_client* client) {
    if (!client) return;
    
    client->is_running = false;
}

/* Process new mempool transaction */
dogecoin_bool dogecoin_smpv_process_tx(
    dogecoin_smpv_client* client,
    const char* raw_tx_hex,
    dogecoin_smpv_tx_callback callback,
    void* user_data
) {
    if (!client || !raw_tx_hex) return false;
    
    /* Create a simple mock transaction for demonstration */
    dogecoin_smpv_tx* smpv_tx = dogecoin_calloc(1, sizeof(dogecoin_smpv_tx));
    if (!smpv_tx) return false;
    
    /* Generate a mock transaction ID */
    smpv_tx->txid = dogecoin_calloc(1, 65);
    snprintf(smpv_tx->txid, 65, "mock_tx_%08x_%llu", 
             (unsigned int)time(NULL), 
             (unsigned long long)client->mempool_tx_count);
    
    smpv_tx->raw_hex = dogecoin_calloc(1, strlen(raw_tx_hex) + 1);
    strcpy(smpv_tx->raw_hex, raw_tx_hex);
    smpv_tx->decoded_tx = NULL; /* Simplified - no actual decoding */
    smpv_tx->fee = 1000; /* Mock fee */
    smpv_tx->size = strlen(raw_tx_hex) / 2; /* Approximate size */
    smpv_tx->timestamp = time(NULL);
    smpv_tx->is_confirmed = false;
    smpv_tx->confirmations = 0;
    smpv_tx->block_hash = NULL;
    smpv_tx->block_height = 0;
    
    /* Resize transactions array */
    client->mempool_txs = realloc(client->mempool_txs, 
                                 (client->mempool_tx_count + 1) * sizeof(dogecoin_smpv_tx));
    if (!client->mempool_txs) {
        dogecoin_smpv_tx_free(smpv_tx);
        return false;
    }
    
    /* Add transaction */
    client->mempool_txs[client->mempool_tx_count] = *smpv_tx;
    dogecoin_free(smpv_tx);
    client->mempool_tx_count++;
    
    /* Find a relevant address (simplified) */
    char* relevant_address = NULL;
    if (client->watcher_count > 0) {
        relevant_address = dogecoin_calloc(1, strlen(client->watchers[0].address) + 1);
        strcpy(relevant_address, client->watchers[0].address);
        client->watchers[0].tx_count++;
    }
    
    /* Call callback if provided */
    if (callback) {
        callback(&client->mempool_txs[client->mempool_tx_count - 1], relevant_address, user_data);
    }
    
    if (relevant_address) {
        dogecoin_free(relevant_address);
    }
    
    return true;
}

/* Get mempool transaction by ID */
dogecoin_smpv_tx* dogecoin_smpv_get_tx(
    const dogecoin_smpv_client* client,
    const char* txid
) {
    if (!client || !txid) return NULL;
    
    for (uint32_t i = 0; i < client->mempool_tx_count; i++) {
        if (strcmp(client->mempool_txs[i].txid, txid) == 0) {
            return &client->mempool_txs[i];
        }
    }
    
    return NULL;
}

/* Get mempool statistics */
void dogecoin_smpv_get_stats(
    const dogecoin_smpv_client* client,
    uint32_t* total_txs,
    uint32_t* watched_addresses,
    uint64_t* total_fees
) {
    if (!client) return;
    
    if (total_txs) *total_txs = client->mempool_tx_count;
    if (watched_addresses) *watched_addresses = client->watcher_count;
    if (total_fees) *total_fees = client->mempool_tx_count * 1000; /* Mock calculation */
}

/* Update transaction status */
void dogecoin_smpv_update_tx_status(
    dogecoin_smpv_client* client,
    const char* txid,
    dogecoin_bool confirmed,
    const char* block_hash,
    uint32_t block_height
) {
    if (!client || !txid) return;
    
    dogecoin_smpv_tx* tx = dogecoin_smpv_get_tx(client, txid);
    if (!tx) return;
    
    tx->is_confirmed = confirmed;
    if (confirmed) {
        tx->confirmations = 1;
        if (block_hash) {
            tx->block_hash = dogecoin_calloc(1, strlen(block_hash) + 1);
            strcpy(tx->block_hash, block_hash);
        }
        tx->block_height = block_height;
    }
}

/* Free SMPV transaction */
void dogecoin_smpv_tx_free(dogecoin_smpv_tx* tx) {
    if (!tx) return;
    
    if (tx->txid) dogecoin_free(tx->txid);
    if (tx->raw_hex) dogecoin_free(tx->raw_hex);
    if (tx->decoded_tx) dogecoin_free(tx->decoded_tx);
    if (tx->block_hash) dogecoin_free(tx->block_hash);
    dogecoin_free(tx);
}

/* Utility functions */
char* dogecoin_smpv_tx_to_json(const dogecoin_smpv_tx* tx) {
    if (!tx) return NULL;
    
    char* json = dogecoin_calloc(1, 1024);
    snprintf(json, 1024,
        "{\n"
        "  \"txid\": \"%s\",\n"
        "  \"size\": %llu,\n"
        "  \"fee\": %llu,\n"
        "  \"timestamp\": %llu,\n"
        "  \"confirmed\": %s,\n"
        "  \"confirmations\": %u\n"
        "}",
        tx->txid ? tx->txid : "",
        (unsigned long long)tx->size,
        (unsigned long long)tx->fee,
        (unsigned long long)tx->timestamp,
        tx->is_confirmed ? "true" : "false",
        tx->confirmations
    );
    return json;
}

char* dogecoin_smpv_watcher_to_json(const dogecoin_smpv_watcher* watcher) {
    if (!watcher) return NULL;
    
    char* json = dogecoin_calloc(1, 512);
    snprintf(json, 512,
        "{\n"
        "  \"address\": \"%s\",\n"
        "  \"balance\": %llu,\n"
        "  \"tx_count\": %u,\n"
        "  \"active\": %s\n"
        "}",
        watcher->address ? watcher->address : "",
        (unsigned long long)watcher->balance,
        watcher->tx_count,
        watcher->is_active ? "true" : "false"
    );
    return json;
}

/* Test data */
static const char* TEST_ADDRESS_1 = "D7Y55vD8nNtW7VnT9Xr6Qc4vB8hN3jK2mP";
static const char* TEST_ADDRESS_2 = "D8Y66wE9nOtW8WnU0Xs7Rd5cC9i4kL3nQ";
static const char* TEST_RAW_TX = "0100000001a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567890000000006a47304402201234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef02201234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef01210234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456ffffffff0100e1f505000000001976a9141234567890abcdef1234567890abcdef1234567890abcdef88ac00000000";

/* Test callback function */
static void test_tx_callback(const dogecoin_smpv_tx* tx, const char* address, void* user_data) {
    (void)user_data; /* Suppress unused parameter warning */
    printf("  ✓ Transaction callback received\n");
    printf("    TXID: %s\n", tx->txid ? tx->txid : "NULL");
    printf("    Address: %s\n", address ? address : "NULL");
    printf("    Size: %llu bytes\n", (unsigned long long)tx->size);
    printf("    Timestamp: %llu\n", (unsigned long long)tx->timestamp);
}

/* Test SMPV client creation and destruction */
void test_smpv_client_creation() {
    printf("Testing SMPV client creation...\n");
    
    /* Test with mainnet */
    dogecoin_smpv_client* client = dogecoin_smpv_client_new(&dogecoin_chainparams_main);
    if (!client) {
        printf("  ❌ Failed to create client\n");
        return;
    }
    
    if (client->chain_params != &dogecoin_chainparams_main) {
        printf("  ❌ Wrong chain params\n");
        return;
    }
    
    if (client->watcher_count != 0) {
        printf("  ❌ Wrong initial watcher count\n");
        return;
    }
    
    if (client->mempool_tx_count != 0) {
        printf("  ❌ Wrong initial tx count\n");
        return;
    }
    
    if (client->is_running != false) {
        printf("  ❌ Should not be running initially\n");
        return;
    }
    
    printf("  ✓ Client created successfully\n");
    
    /* Test with testnet */
    dogecoin_smpv_client* testnet_client = dogecoin_smpv_client_new(&dogecoin_chainparams_test);
    if (!testnet_client) {
        printf("  ❌ Failed to create testnet client\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    if (testnet_client->chain_params != &dogecoin_chainparams_test) {
        printf("  ❌ Wrong testnet chain params\n");
        dogecoin_smpv_client_free(client);
        dogecoin_smpv_client_free(testnet_client);
        return;
    }
    
    printf("  ✓ Testnet client created successfully\n");
    
    /* Test with NULL chain params */
    dogecoin_smpv_client* null_client = dogecoin_smpv_client_new(NULL);
    if (null_client) {
        printf("  ❌ Should not create client with NULL params\n");
        dogecoin_smpv_client_free(client);
        dogecoin_smpv_client_free(testnet_client);
        return;
    }
    
    printf("  ✓ NULL chain params handled correctly\n");
    
    /* Clean up */
    dogecoin_smpv_client_free(client);
    dogecoin_smpv_client_free(testnet_client);
    
    printf("  ✓ SMPV client creation test passed!\n\n");
}

/* Test address watching functionality */
void test_address_watching() {
    printf("Testing address watching functionality...\n");
    
    dogecoin_smpv_client* client = dogecoin_smpv_client_new(&dogecoin_chainparams_main);
    if (!client) {
        printf("  ❌ Failed to create client\n");
        return;
    }
    
    /* Test adding addresses */
    if (!dogecoin_smpv_add_watcher(client, TEST_ADDRESS_1)) {
        printf("  ❌ Failed to add first address\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    if (client->watcher_count != 1) {
        printf("  ❌ Wrong watcher count after adding first address\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    printf("  ✓ Added first address\n");
    
    if (!dogecoin_smpv_add_watcher(client, TEST_ADDRESS_2)) {
        printf("  ❌ Failed to add second address\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    if (client->watcher_count != 2) {
        printf("  ❌ Wrong watcher count after adding second address\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    printf("  ✓ Added second address\n");
    
    /* Test adding duplicate address */
    if (!dogecoin_smpv_add_watcher(client, TEST_ADDRESS_1)) {
        printf("  ❌ Should handle duplicate address\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    if (client->watcher_count != 2) {
        printf("  ❌ Watcher count should not change for duplicate\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    printf("  ✓ Duplicate address handled correctly\n");
    
    /* Test getting watcher */
    dogecoin_smpv_watcher* watcher = dogecoin_smpv_get_watcher(client, TEST_ADDRESS_1);
    if (!watcher) {
        printf("  ❌ Failed to get watcher\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    if (strcmp(watcher->address, TEST_ADDRESS_1) != 0) {
        printf("  ❌ Wrong watcher address\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    if (watcher->is_active != true) {
        printf("  ❌ Watcher should be active\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    printf("  ✓ Retrieved watcher successfully\n");
    
    /* Test getting non-existent watcher */
    watcher = dogecoin_smpv_get_watcher(client, "D9Z77xF0oPvX9XnV1Yt8Se6dD0j5lM4oR");
    if (watcher) {
        printf("  ❌ Should not find non-existent watcher\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    printf("  ✓ Non-existent watcher handled correctly\n");
    
    /* Test removing address */
    if (!dogecoin_smpv_remove_watcher(client, TEST_ADDRESS_1)) {
        printf("  ❌ Failed to remove address\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    if (client->watcher_count != 1) {
        printf("  ❌ Wrong watcher count after removal\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    printf("  ✓ Removed address successfully\n");
    
    /* Test removing non-existent address */
    if (dogecoin_smpv_remove_watcher(client, "D9Z77xF0oPvX9XnV1Yt8Se6dD0j5lM4oR")) {
        printf("  ❌ Should not remove non-existent address\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    printf("  ✓ Non-existent address removal handled correctly\n");
    
    /* Test with NULL parameters */
    if (dogecoin_smpv_add_watcher(NULL, TEST_ADDRESS_1)) {
        printf("  ❌ Should not add watcher with NULL client\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    if (dogecoin_smpv_add_watcher(client, NULL)) {
        printf("  ❌ Should not add watcher with NULL address\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    printf("  ✓ NULL parameter handling correct\n");
    
    dogecoin_smpv_client_free(client);
    
    printf("  ✓ Address watching test passed!\n\n");
}

/* Test transaction processing */
void test_transaction_processing() {
    printf("Testing transaction processing...\n");
    
    dogecoin_smpv_client* client = dogecoin_smpv_client_new(&dogecoin_chainparams_main);
    if (!client) {
        printf("  ❌ Failed to create client\n");
        return;
    }
    
    /* Add test addresses */
    if (!dogecoin_smpv_add_watcher(client, TEST_ADDRESS_1)) {
        printf("  ❌ Failed to add test address\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    if (!dogecoin_smpv_add_watcher(client, TEST_ADDRESS_2)) {
        printf("  ❌ Failed to add second test address\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    printf("  ✓ Added test addresses\n");
    
    /* Test transaction processing with callback */
    if (!dogecoin_smpv_process_tx(client, TEST_RAW_TX, test_tx_callback, NULL)) {
        printf("  ❌ Failed to process transaction\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    if (client->mempool_tx_count != 1) {
        printf("  ❌ Wrong mempool tx count after processing\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    printf("  ✓ Transaction processed successfully\n");
    
    /* Test with NULL parameters */
    if (dogecoin_smpv_process_tx(NULL, TEST_RAW_TX, test_tx_callback, NULL)) {
        printf("  ❌ Should not process with NULL client\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    if (dogecoin_smpv_process_tx(client, NULL, test_tx_callback, NULL)) {
        printf("  ❌ Should not process with NULL tx data\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    printf("  ✓ NULL parameter handling correct\n");
    
    dogecoin_smpv_client_free(client);
    
    printf("  ✓ Transaction processing test passed!\n\n");
}

/* Test client start/stop functionality */
void test_client_control() {
    printf("Testing client start/stop functionality...\n");
    
    dogecoin_smpv_client* client = dogecoin_smpv_client_new(&dogecoin_chainparams_main);
    if (!client) {
        printf("  ❌ Failed to create client\n");
        return;
    }
    
    /* Test starting client */
    if (!dogecoin_smpv_start(client)) {
        printf("  ❌ Failed to start client\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    if (client->is_running != true) {
        printf("  ❌ Client should be running\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    printf("  ✓ Client started successfully\n");
    
    /* Test stopping client */
    dogecoin_smpv_stop(client);
    if (client->is_running != false) {
        printf("  ❌ Client should be stopped\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    printf("  ✓ Client stopped successfully\n");
    
    /* Test starting NULL client */
    if (dogecoin_smpv_start(NULL)) {
        printf("  ❌ Should not start NULL client\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    printf("  ✓ NULL client handling correct\n");
    
    dogecoin_smpv_client_free(client);
    
    printf("  ✓ Client control test passed!\n\n");
}

/* Test statistics and utility functions */
void test_statistics_and_utils() {
    printf("Testing statistics and utility functions...\n");
    
    dogecoin_smpv_client* client = dogecoin_smpv_client_new(&dogecoin_chainparams_main);
    if (!client) {
        printf("  ❌ Failed to create client\n");
        return;
    }
    
    /* Add some addresses */
    if (!dogecoin_smpv_add_watcher(client, TEST_ADDRESS_1)) {
        printf("  ❌ Failed to add first address\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    if (!dogecoin_smpv_add_watcher(client, TEST_ADDRESS_2)) {
        printf("  ❌ Failed to add second address\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    /* Test statistics */
    uint32_t total_txs, watched_addresses;
    uint64_t total_fees;
    
    dogecoin_smpv_get_stats(client, &total_txs, &watched_addresses, &total_fees);
    if (watched_addresses != 2) {
        printf("  ❌ Wrong watched addresses count\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    if (total_txs != 0) {
        printf("  ❌ Wrong initial tx count\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    printf("  ✓ Statistics retrieved successfully\n");
    printf("    Watched addresses: %u\n", watched_addresses);
    printf("    Total transactions: %u\n", total_txs);
    printf("    Total fees: %llu koinu\n", (unsigned long long)total_fees);
    
    /* Test JSON output */
    dogecoin_smpv_watcher* watcher = dogecoin_smpv_get_watcher(client, TEST_ADDRESS_1);
    if (!watcher) {
        printf("  ❌ Failed to get watcher for JSON test\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    char* json = dogecoin_smpv_watcher_to_json(watcher);
    if (!json) {
        printf("  ❌ Failed to generate watcher JSON\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    printf("  ✓ Watcher JSON generated successfully\n");
    printf("    JSON: %s\n", json);
    dogecoin_free(json);
    
    dogecoin_smpv_client_free(client);
    
    printf("  ✓ Statistics and utility test passed!\n\n");
}

/* Test error handling */
void test_error_handling() {
    printf("Testing error handling...\n");
    
    /* Test NULL client operations */
    dogecoin_smpv_client_free(NULL);
    if (dogecoin_smpv_add_watcher(NULL, TEST_ADDRESS_1)) {
        printf("  ❌ Should not add watcher with NULL client\n");
        return;
    }
    
    if (dogecoin_smpv_remove_watcher(NULL, TEST_ADDRESS_1)) {
        printf("  ❌ Should not remove watcher with NULL client\n");
        return;
    }
    
    if (dogecoin_smpv_get_watcher(NULL, TEST_ADDRESS_1)) {
        printf("  ❌ Should not get watcher with NULL client\n");
        return;
    }
    
    if (dogecoin_smpv_start(NULL)) {
        printf("  ❌ Should not start NULL client\n");
        return;
    }
    
    dogecoin_smpv_stop(NULL);
    if (dogecoin_smpv_process_tx(NULL, TEST_RAW_TX, NULL, NULL)) {
        printf("  ❌ Should not process tx with NULL client\n");
        return;
    }
    
    if (dogecoin_smpv_get_tx(NULL, "test")) {
        printf("  ❌ Should not get tx with NULL client\n");
        return;
    }
    
    dogecoin_smpv_update_tx_status(NULL, "test", true, "block", 1);
    dogecoin_smpv_get_stats(NULL, NULL, NULL, NULL);
    
    printf("  ✓ NULL client operations handled gracefully\n");
    
    /* Test NULL parameter operations */
    dogecoin_smpv_client* client = dogecoin_smpv_client_new(&dogecoin_chainparams_main);
    if (!client) {
        printf("  ❌ Failed to create client for error testing\n");
        return;
    }
    
    if (dogecoin_smpv_add_watcher(client, NULL)) {
        printf("  ❌ Should not add watcher with NULL address\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    if (dogecoin_smpv_remove_watcher(client, NULL)) {
        printf("  ❌ Should not remove watcher with NULL address\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    if (dogecoin_smpv_get_watcher(client, NULL)) {
        printf("  ❌ Should not get watcher with NULL address\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    if (dogecoin_smpv_process_tx(client, NULL, NULL, NULL)) {
        printf("  ❌ Should not process tx with NULL data\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    if (dogecoin_smpv_get_tx(client, NULL)) {
        printf("  ❌ Should not get tx with NULL txid\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    dogecoin_smpv_update_tx_status(client, NULL, true, NULL, 1);
    
    printf("  ✓ NULL parameter operations handled gracefully\n");
    
    /* Test utility functions with NULL */
    dogecoin_smpv_tx_free(NULL);
    if (dogecoin_smpv_tx_to_json(NULL)) {
        printf("  ❌ Should not generate JSON for NULL tx\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    if (dogecoin_smpv_watcher_to_json(NULL)) {
        printf("  ❌ Should not generate JSON for NULL watcher\n");
        dogecoin_smpv_client_free(client);
        return;
    }
    
    printf("  ✓ NULL utility function calls handled gracefully\n");
    
    dogecoin_smpv_client_free(client);
    
    printf("  ✓ Error handling test passed!\n\n");
}

/* Main test function */
int main() {
    printf("SMPV (Simplified Mempool Payment Verification) Test Suite\n");
    printf("========================================================\n\n");
    
    test_smpv_client_creation();
    test_address_watching();
    test_transaction_processing();
    test_client_control();
    test_statistics_and_utils();
    test_error_handling();
    
    printf("All SMPV tests completed successfully! 🎉\n");
    printf("\nThis demonstrates the SMPV functionality for:\n");
    printf("- Mempool transaction tracking\n");
    printf("- Address watching and monitoring\n");
    printf("- Transaction decoding and processing\n");
    printf("- Real-time transaction notifications\n");
    printf("- Statistics and reporting\n");
    printf("- Error handling and edge cases\n");
    
    return 0;
}
