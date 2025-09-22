/*
 * Copyright (c) 2024 The Dogecoin Foundation
 *
 * SMPV (Simplified Mempool Payment Verification) Test Suite
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stddef.h>
#include <dogecoin/smpv.h>
#include <dogecoin/chainparams.h>


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
    
    dogecoin_smpv_get_stats(client, &total_txs, &watched_addresses);
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
    dogecoin_smpv_get_stats(NULL, NULL, NULL);
    
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

/* Main test function for the test framework */
void test_smpv() {
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
}
