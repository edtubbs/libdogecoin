# SMPV (Simplified Mempool Payment Verification)

SMPV is a lightweight system for tracking mempool transactions for specific Dogecoin addresses, similar to how the [dogecoin-wallet](https://github.com/qlpqlp/dogecoin-wallet) detects mempool transactions.

## Overview

SMPV provides real-time monitoring of mempool transactions for watched addresses, allowing applications to:

- Track incoming and outgoing transactions
- Monitor transaction fees and sizes
- Receive real-time notifications
- Generate statistics and reports
- Handle both confirmed and unconfirmed transactions

## Features

### Core Functionality
- **Address Watching**: Add/remove addresses to monitor
- **Transaction Processing**: Process raw mempool transactions
- **Real-time Notifications**: Callback-based transaction alerts
- **Statistics**: Track transaction counts, fees, and balances
- **JSON Export**: Generate JSON reports for integration

### Key Benefits
- **Lightweight**: Minimal resource usage
- **Real-time**: Immediate transaction detection
- **Flexible**: Easy integration with existing applications
- **Reliable**: Robust error handling and memory management

## API Reference

### Client Management

#### `dogecoin_smpv_client_new()`
```c
dogecoin_smpv_client* dogecoin_smpv_client_new(const dogecoin_chainparams* chain_params);
```
Creates a new SMPV client for the specified chain parameters.

**Parameters:**
- `chain_params`: Chain parameters (mainnet/testnet)

**Returns:**
- New SMPV client on success
- `NULL` on failure

#### `dogecoin_smpv_client_free()`
```c
void dogecoin_smpv_client_free(dogecoin_smpv_client* client);
```
Frees an SMPV client and all associated resources.

### Address Watching

#### `dogecoin_smpv_add_watcher()`
```c
dogecoin_bool dogecoin_smpv_add_watcher(dogecoin_smpv_client* client, const char* address);
```
Adds an address to the watch list.

**Parameters:**
- `client`: SMPV client
- `address`: Dogecoin address to watch

**Returns:**
- `true` on success
- `false` on failure

#### `dogecoin_smpv_remove_watcher()`
```c
dogecoin_bool dogecoin_smpv_remove_watcher(dogecoin_smpv_client* client, const char* address);
```
Removes an address from the watch list.

#### `dogecoin_smpv_get_watcher()`
```c
dogecoin_smpv_watcher* dogecoin_smpv_get_watcher(const dogecoin_smpv_client* client, const char* address);
```
Gets watcher information for an address.

### Transaction Processing

#### `dogecoin_smpv_process_tx()`
```c
dogecoin_bool dogecoin_smpv_process_tx(
    dogecoin_smpv_client* client,
    const char* raw_tx_hex,
    dogecoin_smpv_tx_callback callback,
    void* user_data
);
```
Processes a raw mempool transaction.

**Parameters:**
- `client`: SMPV client
- `raw_tx_hex`: Raw transaction hex string
- `callback`: Callback function for notifications
- `user_data`: User data for callback

**Returns:**
- `true` if transaction was processed
- `false` if not relevant or error occurred

#### `dogecoin_smpv_get_tx()`
```c
dogecoin_smpv_tx* dogecoin_smpv_get_tx(const dogecoin_smpv_client* client, const char* txid);
```
Gets a transaction by its ID.

### Client Control

#### `dogecoin_smpv_start()`
```c
dogecoin_bool dogecoin_smpv_start(dogecoin_smpv_client* client);
```
Starts SMPV monitoring.

#### `dogecoin_smpv_stop()`
```c
void dogecoin_smpv_stop(dogecoin_smpv_client* client);
```
Stops SMPV monitoring.

### Statistics and Utilities

#### `dogecoin_smpv_get_stats()`
```c
void dogecoin_smpv_get_stats(
    const dogecoin_smpv_client* client,
    uint32_t* total_txs,
    uint32_t* watched_addresses,
    uint64_t* total_fees
);
```
Gets mempool statistics.

#### `dogecoin_smpv_tx_to_json()`
```c
char* dogecoin_smpv_tx_to_json(const dogecoin_smpv_tx* tx);
```
Converts a transaction to JSON format.

#### `dogecoin_smpv_watcher_to_json()`
```c
char* dogecoin_smpv_watcher_to_json(const dogecoin_smpv_watcher* watcher);
```
Converts a watcher to JSON format.

## Data Structures

### `dogecoin_smpv_client`
```c
typedef struct {
    const dogecoin_chainparams* chain_params;
    dogecoin_smpv_watcher* watchers;
    dogecoin_smpv_tx* mempool_txs;
    uint32_t watcher_count;
    uint32_t mempool_tx_count;
    dogecoin_bool is_running;
    uint64_t last_update_time;
} dogecoin_smpv_client;
```

### `dogecoin_smpv_tx`
```c
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
```

### `dogecoin_smpv_watcher`
```c
typedef struct {
    char* address;                 /* Dogecoin address being watched */
    uint64_t total_received;       /* Total received in koinu */
    uint64_t total_sent;           /* Total sent in koinu */
    uint64_t balance;              /* Current balance in koinu */
    uint32_t tx_count;             /* Number of transactions */
    dogecoin_bool is_active;       /* Whether watcher is active */
} dogecoin_smpv_watcher;
```

## Usage Example

```c
#include <dogecoin/smpv.h>
#include <dogecoin/chainparams.h>

/* Callback function for transaction notifications */
void tx_callback(const dogecoin_smpv_tx* tx, const char* address, void* user_data) {
    printf("New transaction for %s: %s\n", address, tx->txid);
    printf("Fee: %llu koinu\n", (unsigned long long)tx->fee);
    printf("Size: %llu bytes\n", (unsigned long long)tx->size);
}

int main() {
    /* Create SMPV client */
    dogecoin_smpv_client* client = dogecoin_smpv_client_new(&dogecoin_chainparams_main);
    if (!client) {
        printf("Failed to create SMPV client\n");
        return 1;
    }
    
    /* Add addresses to watch */
    dogecoin_smpv_add_watcher(client, "D7Y55vD8nNtW7VnT9Xr6Qc4vB8hN3jK2mP");
    dogecoin_smpv_add_watcher(client, "D8Y66wE9nOtW8WnU0Xs7Rd5cC9i4kL3nQ");
    
    /* Start monitoring */
    dogecoin_smpv_start(client);
    
    /* Process a transaction */
    const char* raw_tx = "0100000001..."; /* Raw transaction hex */
    dogecoin_smpv_process_tx(client, raw_tx, tx_callback, NULL);
    
    /* Get statistics */
    uint32_t total_txs, watched_addresses;
    uint64_t total_fees;
    dogecoin_smpv_get_stats(client, &total_txs, &watched_addresses, &total_fees);
    
    printf("Watched addresses: %u\n", watched_addresses);
    printf("Mempool transactions: %u\n", total_txs);
    printf("Total fees: %llu koinu\n", (unsigned long long)total_fees);
    
    /* Clean up */
    dogecoin_smpv_stop(client);
    dogecoin_smpv_client_free(client);
    
    return 0;
}
```

## Building and Testing

### Build Scripts
- `build_smpv_standalone.sh` - Linux/WSL build script
- `build_smpv_test.bat` - Windows build script

### Test Suite
- `test/smpv_standalone.c` - Comprehensive test suite
- `contrib/examples/smpv_example.c` - Usage example

### Running Tests
```bash
# Linux/WSL
chmod +x build_smpv_standalone.sh
./build_smpv_standalone.sh
./build/smpv_standalone

# Windows
build_smpv_test.bat
build\smpv_test.exe
```

## Integration with libdogecoin

SMPV is designed to work alongside libdogecoin's existing functionality:

- **Chain Parameters**: Uses libdogecoin's chain parameter system
- **Memory Management**: Follows libdogecoin's memory management patterns
- **Error Handling**: Consistent with libdogecoin's error handling approach
- **API Design**: Follows libdogecoin's API naming conventions

## Performance Considerations

- **Memory Usage**: Minimal memory footprint with efficient data structures
- **CPU Usage**: Low CPU overhead for transaction processing
- **Scalability**: Supports monitoring of multiple addresses simultaneously
- **Real-time**: Immediate transaction detection and notification

## Security Considerations

- **Input Validation**: All inputs are validated before processing
- **Memory Safety**: Proper memory allocation and deallocation
- **Error Handling**: Graceful handling of all error conditions
- **Data Integrity**: Transaction data is validated before processing

## Future Enhancements

- **Full Transaction Decoding**: Complete transaction parsing and validation
- **UTXO Tracking**: Track unspent transaction outputs
- **Fee Estimation**: Dynamic fee calculation based on network conditions
- **Blockchain Integration**: Integration with blockchain data for confirmation tracking
- **Network Monitoring**: Direct connection to mempool sources

## Contributing

SMPV follows libdogecoin's contribution guidelines:

1. Follow the existing code style
2. Add comprehensive tests
3. Update documentation
4. Ensure cross-platform compatibility
5. Maintain backward compatibility

## License

SMPV is part of libdogecoin and is licensed under the same terms as the main library.
