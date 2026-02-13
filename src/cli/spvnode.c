/*

 The MIT License (MIT)

 Copyright (c) 2017 Jonas Schnelli
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

#ifndef WIN32
#include <sys/stat.h>
#include <syslog.h>
#include <fcntl.h>
#include <assert.h>
#endif

#ifndef _MSC_VER
#include <getopt.h>
#include <unistd.h>
#else
#include <win/wingetopt.h>
#endif

#include <ctype.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <event2/buffer.h>
#include <event2/http.h>

#if defined(HAVE_CONFIG_H)
#include "libdogecoin-config.h"
#endif

#include <dogecoin/chainparams.h>
#include <dogecoin/constants.h>
#include <dogecoin/base58.h>
#include <dogecoin/bip39.h>
#include <dogecoin/ecc.h>
#include <dogecoin/headersdb_file.h>
#include <dogecoin/koinu.h>
#include <dogecoin/net.h>
#include <dogecoin/seal.h>
#include <dogecoin/spv.h>
#include <dogecoin/protocol.h>
#include <dogecoin/random.h>
#include <dogecoin/rest.h>
#include <dogecoin/serialize.h>
#include <dogecoin/tool.h>
#include <dogecoin/tx.h>
#include <dogecoin/utils.h>
#include <dogecoin/wallet.h>

#ifndef WIN32
#define BD_NO_CHDIR          01 /* Don't chdir ("/") */
#define BD_NO_CLOSE_FILES    02 /* Don't close all open files */
#define BD_NO_REOPEN_STD_FDS 04 /* Don't reopen stdin, stdout, and stderr
                                   to /dev/null */
#define BD_NO_UMASK0        010 /* Don't do a umask(0) */
#define BD_MAX_CLOSE       8192 /* Max file descriptors to close if
                                   sysconf(_SC_OPEN_MAX) is indeterminate */

int // returns 0 on success -1 on error
become_daemon(int flags)
{
  int maxfd, fd;

  /* The first fork will change our pid
   * but the sid and pgid will be the
   * calling process.
   */
  switch(fork())                    // become background process
  {
    case -1: return -1;
    case 0: break;                  // child falls through
    default: _exit(EXIT_SUCCESS);   // parent terminates
  }

  /*
   * Run the process in a new session without a controlling
   * terminal. The process group ID will be the process ID
   * and thus, the process will be the process group leader.
   * After this call the process will be in a new session,
   * and it will be the progress group leader in a new
   * process group.
   */
  if(setsid() == -1)                // become leader of new session
    return -1;

  /*
   * We will fork again, also known as a
   * double fork. This second fork will orphan
   * our process because the parent will exit.
   * When the parent process exits the child
   * process will be adopted by the init process
   * with process ID 1.
   * The result of this second fork is a process
   * with the parent as the init process with an ID
   * of 1. The process will be in it's own session
   * and process group and will have no controlling
   * terminal. Furthermore, the process will not
   * be the process group leader and thus, cannot
   * have the controlling terminal if there was one.
   */
  switch(fork())
  {
    case -1: return -1;
    case 0: break;                  // child breaks out of case
    default: _exit(EXIT_SUCCESS);   // parent process will exit
  }

  if(!(flags & BD_NO_UMASK0))
    umask(0);                       // clear file creation mode mask

//   if(!(flags & BD_NO_CHDIR))
//     chdir("/");                     // change to root directory

  if(!(flags & BD_NO_CLOSE_FILES))  // close all open files
  {
    maxfd = sysconf(_SC_OPEN_MAX);
    if(maxfd == -1)
      maxfd = BD_MAX_CLOSE;         // if we don't know then guess
    for(fd = 0; fd < maxfd; fd++)
      close(fd);
  }

  if(!(flags & BD_NO_REOPEN_STD_FDS))
  {
    /* now time to go "dark"!
     * we'll close stdin
     * then we'll point stdout and stderr
     * to /dev/null
     */
    close(STDIN_FILENO);

    fd = open("/dev/null", O_RDWR);
    if(fd != STDIN_FILENO)
      return -1;
    if(dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO)
      return -2;
    if(dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO)
      return -3;
  }

  return 0;
}
#endif

/* Minimal local bloom filter implementation - fixed size to avoid <math.h>/log() */
typedef struct {
    uint8_t* data;
    size_t data_len;     // bytes, fixed max 36000
    uint32_t n_hash_funcs; // fixed max 50
    uint32_t n_tweak;
    uint8_t n_flags;
} local_bloom_filter;

static uint32_t local_murmur3(const uint8_t* key, size_t len, uint32_t seed) {
    uint32_t h = seed;
    size_t i = 0;
    for (; i + 4 <= len; i += 4) {
        uint32_t k = key[i] | (key[i+1] << 8) | (key[i+2] << 16) | (key[i+3] << 24);
        k *= 0xcc9e2d51u;
        k = (k << 15) | (k >> 17);
        k *= 0x1b873593u;
        h ^= k;
        h = (h << 13) | (h >> 19);
        h = h * 5 + 0xe6546b64u;
    }
    uint32_t k = 0;
    switch (len - i) {
        case 3: k ^= key[i+2] << 16; break;
        case 2: k ^= key[i+1] << 8; break;
        case 1: k ^= key[i]; break;
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

static local_bloom_filter* local_bloom_new(uint32_t tweak, uint8_t flags) {
    local_bloom_filter* filter = dogecoin_calloc(1, sizeof(local_bloom_filter));
    filter->data_len = 36000; /* BIP37 max */
    filter->data = dogecoin_calloc(filter->data_len, 1);
    filter->n_hash_funcs = 50; /* BIP37 max */
    filter->n_tweak = tweak ? tweak : (uint32_t)rand();
    filter->n_flags = flags;
    return filter;
}

static void local_bloom_add(local_bloom_filter* filter, const uint8_t* data, size_t data_len) {
    for (uint32_t i = 0; i < filter->n_hash_funcs; i++) {
        uint32_t seed = i * 0xfba4c795u + filter->n_tweak;
        uint32_t idx = local_murmur3(data, data_len, seed) % (filter->data_len * 8);
        filter->data[idx / 8] |= (1 << (idx % 8));
    }
}

static void local_bloom_free(local_bloom_filter* filter) {
    if (!filter) return;
    if (filter->data) dogecoin_free(filter->data);
    dogecoin_free(filter);
}

/* End of local bloom implementation */

/* This is a list of all the options that can be used with the program. */
static struct option long_options[] = {
        {"testnet", no_argument, NULL, 't'},
        {"regtest", no_argument, NULL, 'r'},
        {"ips", no_argument, NULL, 'i'},
        {"debug", no_argument, NULL, 'd'},
        {"maxnodes", no_argument, NULL, 'm'},
        {"mnemonic", no_argument, NULL, 'n'},
        {"pass_phrase", no_argument, NULL, 's'},
        {"dbfile", no_argument, NULL, 'f'},
        {"continuous", no_argument, NULL, 'c'},
        {"address", no_argument, NULL, 'a'},
        {"full_sync", no_argument, NULL, 'b'},
        {"checkpoint", no_argument, NULL, 'p'},
        {"wallet_file", required_argument, NULL, 'w'},
        {"headers_file", required_argument, NULL, 'h'},
        {"no_prompt", no_argument, NULL, 'l'},
        {"encrypted_file", required_argument, NULL, 'y'},
        {"use_tpm", no_argument, NULL, 'j'},
        {"master_key", no_argument, NULL, 'k'},
        {"http_server", required_argument, NULL, 'u'},
        {"smpv", no_argument, NULL, 'x'},
        {"daemon", no_argument, NULL, 'z'},
        {NULL, 0, NULL, 0} };

/**
 * Print_version() prints the version of the program
 */
static void print_version() {
    printf("Version: %s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
    }

/**
 * This function prints the usage of the spvnode command
 */
static void print_usage() {
    print_version();
    printf("Usage: spvnode (-c|continuous) (-i|--ips <ip,ip,...>) (-m[--maxpeers] <int>) (-f <headersfile|0 for in mem only>) \
(-a|--address <address>) (-n|--mnemonic <seed_phrase>) (-s|[--pass_phrase]) (-y|--encrypted_file <file_num 0-999>) \
(-w|--wallet_file <filename>) (-h|--headers_file <filename>) (-l|[--no_prompt]) (-b[--full_sync]) (-p[--checkpoint]) (-k[--master_key]) (-j[--use_tpm]) \
(-u|--http_server <ip:port>) (-x|--smpv) (-t|--testnet) (-r|--regtest) (-d|--debug) <command>\n");
    printf("Supported commands:\n");
    printf("        scan      (scan blocks up to the tip, creates header.db file)\n");
    printf("\nExamples: \n");
    printf("Sync up to the chain tip and stores all headers in headers.db (quit once synced):\n");
    printf("> ./spvnode scan\n\n");
    printf("Sync up to the chain tip and give some debug output during that process:\n");
    printf("> ./spvnode -d scan\n\n");
    printf("Sync up, show debug info, don't store headers in file (only in memory), wait for new blocks:\n");
    printf("> ./spvnode -d -f 0 -c -b scan\n\n");
    printf("Sync up, with an address, show debug info, don't store headers in file, wait for new blocks:\n");
    printf("> ./spvnode -d -f 0 -c -a \"DSVw8wkkTXccdq78etZ3UwELrmpfvAiVt1\" -b scan\n\n");
    printf("Sync up, with a wallet file \"main_wallet.db\", show debug info, don't store headers in file, wait for new blocks:\n");
    printf("> ./spvnode -d -f 0 -c -w \"./main_wallet.db\" -b scan\n\n");
    printf("Sync up, with a wallet file \"main_wallet.db\", show debug info, with a headers file \"main_headers.db\", wait for new blocks:\n");
    printf("> ./spvnode -d -c -w \"./main_wallet.db\" -h \"./main_headers.db\" -b scan\n\n");
    printf("Sync up, with a wallet file \"main_wallet.db\", with an address, show debug info, with a headers file, with a headers file \"main_headers.db\", wait for new blocks:\n");
    printf("> ./spvnode -d -c -a \"DSVw8wkkTXccdq78etZ3UwELrmpfvAiVt1\" -w \"./main_wallet.db\" -h \"./main_headers.db\" -b scan\n\n");
    printf("Sync up, with encrypted mnemonic 0, show debug info, don't store headers in file, wait for new blocks:\n");
    printf("> ./spvnode -d -f 0 -c -y 0 -b scan\n\n");
    printf("Sync up, with encrypted mnemonic 0, BIP39 passphrase, show debug info, don't store headers in file, wait for new blocks:\n");
    printf("> ./spvnode -d -f 0 -c -y 0 -s -b scan\n\n");
    printf("Sync up, with encrypted mnemonic 0, BIP39 passphrase, show debug info, don't store headers in file, wait for new blocks, use TPM:\n");
    printf("> ./spvnode -d -f 0 -c -y 0 -s -j -b scan\n\n");
    printf("Sync up, with encrypted key 0, show debug info, don't store headers in file, wait for new blocks, use master key:\n");
    printf("> ./spvnode -d -f 0 -c -y 0 -k -b scan\n\n");
    printf("Sync up, with encrypted key 0, show debug info, don't store headers in file, wait for new blocks, use master key, use TPM:\n");
    printf("> ./spvnode -d -f 0 -c -y 0 -k -j -b scan\n\n");
    printf("Sync up, with mnemonic \"test\", BIP39 passphrase, show debug info, don't store headers in file, wait for new blocks:\n");
    printf("> ./spvnode -d -f 0 -c -n \"test\" -s -b scan\n\n");
    printf("Sync up, with a wallet file \"main_wallet.db\", with encrypted mnemonic 0, show debug info, don't store headers in file, wait for new blocks:\n");
    printf("> ./spvnode -d -f 0 -c -w \"./main_wallet.db\" -y 0 -b scan\n\n");
    printf("Sync up, with a wallet file \"main_wallet.db\", with encrypted mnemonic 0, show debug info, with a headers file \"main_headers.db\", wait for new blocks:\n");
    printf("> ./spvnode -d -c -w \"./main_wallet.db\" -h \"./main_headers.db\" -y 0 -b scan\n\n");
    printf("Sync up, with a wallet file \"main_wallet.db\", with encrypted mnemonic 0, show debug info, with a headers file \"main_headers.db\", wait for new blocks, use TPM:\n");
    printf("> ./spvnode -d -c -w \"./main_wallet.db\" -h \"./main_headers.db\" -y 0 -j -b scan\n\n");
    printf("Sync up, with a wallet file \"main_wallet.db\", with encrypted mnemonic 0, show debug info, with a headers file \"main_headers.db\", wait for new blocks, use master key:\n");
    printf("> ./spvnode -d -c -w \"./main_wallet.db\" -h \"./main_headers.db\" -y 0 -k -b scan\n\n");
    printf("Sync up, with a wallet file \"main_wallet.db\", with encrypted mnemonic 0, show debug info, with a headers file \"main_headers.db\", wait for new blocks, use master key, use TPM:\n");
    printf("> ./spvnode -d -c -w \"./main_wallet.db\" -h \"./main_headers.db\" -y 0 -k -j -b scan\n\n");
    printf("Sync up, with a wallet file \"main_wallet.db\", show debug info, wait for new blocks, enable http server:\n");
    printf("> ./spvnode -d -c -w \"./main_wallet.db\" -u \"0.0.0.0:8080\" -b scan\n\n");
    }


/**
 * When a new block is added to the blockchain, this function is called
 *
 * @param client The client object.
 * @param node The node that sent the message.
 * @param newtip The new tip of the headers chain.
 *
 * @return A boolean value.
 */
dogecoin_bool spv_header_message_processed(struct dogecoin_spv_client_* client, dogecoin_node* node, dogecoin_blockindex* newtip) {
    UNUSED(node);
    if (newtip) {
        time_t timestamp = client->headers_db->getchaintip(client->headers_db_ctx)->header.timestamp;
        printf("New headers tip height %d from %s\n", newtip->height, ctime(&timestamp));
        }
    return true;
    }

static dogecoin_bool quit_when_synced = true;
/**
 * When the sync is complete, print a message and either exit or wait for new blocks or relevant
 * transactions
 *
 * @param client The client object.
 */
void spv_sync_completed(dogecoin_spv_client* client) {
    printf("Sync completed, at height %d\n", client->headers_db->getchaintip(client->headers_db_ctx)->height);

    /* If a bloom filter is active, request filtered blocks from the last
       checkpoint to tip to discover UTXOs. Per BIP37, the peer responds
       with a merkleblock for every requested block — blocks with matching
       transactions include the matched TXs, while non-matching blocks
       come back with 0 matched transactions. */
    if (client->bloom_filter && client->bloom_filter_len > 0) {
        printf("[spv] Requesting historical filtered blocks for UTXO discovery (checkpoint to tip)...\n");
        dogecoin_net_spv_request_filtered_history(client, 0); /* 0 = scan all available blocks back to checkpoint */
    }

    if (quit_when_synced) {
        dogecoin_node_group_shutdown(client->nodegroup);
    } else {
        printf("Waiting for new blocks or relevant transactions...\n");
    }
}

// Signal handler for SIGINT
void handle_sigint() {
    // Reset standard input back to blocking mode
#ifndef _WIN32
    int stdin_flags = fcntl(STDIN_FILENO, F_GETFL);
    fcntl(STDIN_FILENO, F_SETFL, stdin_flags & ~O_NONBLOCK);
#endif
    exit(0);
}

int main(int argc, char* argv[]) {
    int ret = 0;
    int long_index = 0;
    int opt = 0;
    char* data = 0;
    char* ips = 0;
    dogecoin_bool debug = false;
    int maxnodes = 10;
    char* dbfile = 0;
    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;
    char* address = NULL;
    dogecoin_bool use_checkpoint = false;
    char* pass = 0;
    char* mnemonic_in = 0;
    char* name = 0;
    char* headers_name = 0;
    dogecoin_bool full_sync = false;
    dogecoin_bool have_decl_daemon = false;
    dogecoin_bool prompt = true;
    dogecoin_bool encrypted = false;
    dogecoin_bool master_key = false;
    dogecoin_bool tpm = false;
    char* http_server = NULL;
    int file_num = NO_FILE;
    dogecoin_bool smpv_cli_enable = false;

    if (argc <= 1 || strlen(argv[argc - 1]) == 0 || argv[argc - 1][0] == '-') {
        /* exit if no command was provided */
        print_usage();
        exit(EXIT_FAILURE);
        }
    data = argv[argc - 1];

    /* get arguments */
    while ((opt = getopt_long_only(argc, argv, "i:ctrdsm:n:f:y:u:w:h:a:lbpzkj:x", long_options, &long_index)) != -1) {
        switch (opt) {
                case 'c':
                    quit_when_synced = false;
                    break;
                case 't':
                    chain = &dogecoin_chainparams_test;
                    break;
                case 'r':
                    chain = &dogecoin_chainparams_regtest;
                    break;
                case 'd':
                    debug = true;
                    break;
                case 'i':
                    ips = optarg;
                    break;
                case 's':
                    pass = getpass("BIP39 passphrase: \n");
                    break;
                case 'm':
                    maxnodes = (int)strtol(optarg, (char**)NULL, 10);
                    break;
                case 'n':
                    mnemonic_in = optarg;
                    break;
                case 'f':
                    dbfile = optarg;
                    break;
                case 'a':
                    address = optarg;
                    break;
                case 'b':
                    full_sync = true;
                    break;
                case 'p':
                    use_checkpoint = true;
                    break;
                case 'h':
                    headers_name = optarg;
                    break;
                case 'l':
                    prompt = false;
                    break;
                case 'y':
                    encrypted = true;
                    file_num = (int)strtol(optarg, (char**)NULL, 10);
                    break;
                case 'k':
                    master_key = true;
                    break;
                case 'j':
                    tpm = true;
                    break;
                case 'w':
                    name = optarg;
                    break;
                case 'u':
                    http_server = optarg;
                    if (!isdigit(http_server[0])) {
                        printf("Please add the ip and port after -u and try again. e.g. '-u 0.0.0.0:8080'\n");
                        exit(EXIT_FAILURE);
                    }
                    break;
                case 'z':
                    have_decl_daemon = true;
                    break;
                case 'v':
                    print_version();
                    exit(EXIT_SUCCESS);
                    break;
                case 'x':
                    smpv_cli_enable = true;
                    break;
                default:
                    print_usage();
                    exit(EXIT_FAILURE);
            }
        }

    if (strcmp(data, "scan") == 0) {
        dogecoin_ecc_start();
        dogecoin_spv_client* client = dogecoin_spv_client_new(chain, debug, (dbfile && (dbfile[0] == '0' || (strlen(dbfile) > 1 && dbfile[0] == 'n' && dbfile[0] == 'o'))) ? true : false, use_checkpoint, full_sync, maxnodes, http_server);

        /* Keep all headers in memory so historical filtered block scan can walk
           the full prev chain from checkpoint to tip for UTXO discovery. */
        ((dogecoin_headers_db*)client->headers_db_ctx)->max_hdr_in_mem = 0;

        if (http_server) {
            evhttp_set_gencb(client->nodegroup->http_server, dogecoin_http_request_cb, client);
        }
        if (smpv_cli_enable) {
            dogecoin_spv_enable_smpv(client, true);
            printf("[smpv] enabled via CLI flag\n");
        }
        client->header_message_processed = spv_header_message_processed;
        client->sync_completed = spv_sync_completed;
        signal(SIGINT, handle_sigint);

#if WITH_WALLET
        dogecoin_wallet_opts wopts = {
            .mnemonic_in = mnemonic_in,
            .pass = pass,
            .encrypted = encrypted,
            .tpm = tpm,
            .file_num = file_num,
            .master_key = master_key,
            .prompt = prompt
        };
        dogecoin_wallet* wallet = dogecoin_wallet_init(
            chain,
            address,
            name,
            &wopts);
        if (!wallet) {
            printf("Could not initialize wallet...\n");
            // clear and free the passphrase
            if (pass) {
                dogecoin_mem_zero (pass, strlen(pass));
                dogecoin_free(pass);
                }
            dogecoin_spv_client_free(client);
            dogecoin_ecc_stop();
            return EXIT_FAILURE;
        }
        // clear and free the passphrase
        if (pass) {
            dogecoin_mem_zero (pass, strlen(pass));
            dogecoin_free(pass);
            }
        print_utxos(wallet);

        /* Initial BIP37 filter setup using filterload with fixed-size bloom */
        if (wallet->waddr_vector->len > 0 || HASH_COUNT(wallet->utxos) > 0) {
            local_bloom_filter* filter = local_bloom_new(0, 1); /* random tweak, UPDATE_ALL */

            unsigned int i;
            for (i = 0; i < wallet->waddr_vector->len; i++) {
                dogecoin_wallet_addr* waddr = vector_idx(wallet->waddr_vector, i);
                if (waddr->ignore) continue;
                local_bloom_add(filter, waddr->pubkeyhash, sizeof(uint160_t));
            }

            dogecoin_utxo* utxo;
            dogecoin_utxo* tmp;
            HASH_ITER(hh, wallet->utxos, utxo, tmp) {
                uint8_t outpoint[36];
                memcpy(outpoint, utxo->txid, 32);
                uint32_t vout_le = htole32(utxo->vout);
                memcpy(outpoint + 32, &vout_le, 4);
                local_bloom_add(filter, outpoint, 36);
            }

            dogecoin_bool loaded = dogecoin_spv_client_filterload(client,
                                                                 filter->data,
                                                                 filter->data_len,
                                                                 filter->n_hash_funcs,
                                                                 filter->n_tweak,
                                                                 filter->n_flags);
            if (loaded) {
                printf("[spv] Initial filterload sent (fixed max size, %u hash funcs)\n", filter->n_hash_funcs);
            } else {
                printf("[spv] Failed to send initial filterload\n");
            }
            local_bloom_free(filter);
        } else {
            printf("[spv] Empty wallet - no BIP37 filter set\n");
        }

        client->sync_transaction = dogecoin_wallet_check_transaction;
        client->sync_transaction_ctx = wallet;
#endif
        char* header_suffix = "_headers.db";
        char* header_prefix = (char*)chain->chainname;
        char* headersfile = NULL;
        dogecoin_bool response = false;
        if (mnemonic_in) {
            // mnemonic was provided, so store headers in separate file
            char* wallet_type = "_mnemonic";
            char* header_type_prefix = concat(header_prefix, wallet_type);
            headersfile = concat(header_type_prefix, header_suffix);
            dogecoin_free(header_type_prefix);
            if (headers_name) {
                // Load headers file name with headers name:
                response = dogecoin_spv_client_load(client, (dbfile ? dbfile : headers_name), prompt);
            } else {
                // Otherwise, use default headers file name:
                response = dogecoin_spv_client_load(client, (dbfile ? dbfile : headersfile), prompt);
            }
        }
        else if (headers_name) {
            // Load headers file name with headers name:
            response = dogecoin_spv_client_load(client, (dbfile ? dbfile : headers_name), prompt);
        } else {
            // Otherwise, use default headers file name:
            headersfile = concat(header_prefix, header_suffix);
            response = dogecoin_spv_client_load(client, (dbfile ? dbfile : headersfile), prompt);
        }

        dogecoin_free(headersfile);
        if (!response) {
            printf("Could not load or create headers database...aborting\n");
            ret = EXIT_FAILURE;
        } else {
            if (have_decl_daemon) {
#if defined(HAVE_DECL_DAEMON) && !defined(WIN32)
                const char *LOGNAME = "libdogecoin-spvnode";

                // turn this process into a daemon
                ret = become_daemon(0);
                if(ret)
                {
                    syslog(LOG_USER | LOG_ERR, "error starting");
                    closelog();
                    return EXIT_FAILURE;
                }

                // we are now a daemon!
                // printf now will go to /dev/null

                // open up the system log
                openlog(LOGNAME, LOG_PID, LOG_USER);
                syslog(LOG_USER | LOG_INFO, "starting");

                // run forever in the background
                while(1)
                {
                    sleep(60);
                    syslog(LOG_USER | LOG_INFO, "running");
                }
#else
            fprintf(stderr, "Error: -z | --daemon is not supported on this operating system\n");
            return false;
#endif
            }
            printf("done\n");
            printf("Discover peers...\n");
            dogecoin_spv_client_discover_peers(client, ips);

            printf("Connecting to the p2p network...\n");
            dogecoin_spv_client_runloop(client);
            dogecoin_spv_client_free(client);
            printf("done\n");
            ret = EXIT_SUCCESS;
#if WITH_WALLET
            dogecoin_wallet_free(wallet);
#endif
            }
        dogecoin_ecc_stop();
    } else if (strcmp(data, "sanity") == 0) {
#if WITH_WALLET
    dogecoin_ecc_start();
    if (address != NULL) {
        char delim[] = " ";
        // copy address into a new string, strtok modifies the string
        char* address_copy = strdup(address);

        // backup existing default wallet file prior to radio doge functions test
        const dogecoin_chainparams *params = chain_from_b58_prefix(address_copy);
        dogecoin_wallet *tmp = dogecoin_wallet_new(params);
        int result;
        FILE *file;
        if ((file = fopen(tmp->filename, "r")))
        {
            fclose(file);
#ifdef WIN32
            #include <winbase.h>
            result = CopyFile((char*)tmp->filename, "tmp.bin", true);
            if (result == 1) result = 0;
#else
            result = file_copy((char *)tmp->filename, "tmp.bin");
#endif
            if (result != 0) {
                printf( "could not copy '%s' %d\n", tmp->filename, result );
            } else {
                printf( "File '%s' copied to 'tmp.bin'\n", tmp->filename);
            }
        }

        char *ptr;
        char* temp_address_copy = address_copy;

        while((ptr = strtok_r(temp_address_copy, delim, &temp_address_copy))) {
            int res = dogecoin_register_watch_address_with_node(ptr);
            printf("registered:     %d %s\n", res, ptr);
            uint64_t amount = dogecoin_get_balance(ptr);
            if (amount > 0) {
                char* amount_str = dogecoin_get_balance_str(ptr);
                printf("total:          %s\n", amount_str);
                unsigned int utxo_count = dogecoin_get_utxos_length(ptr);
                if (utxo_count) {
                    printf("utxo count:     %d\n", utxo_count);
                    unsigned int i = 1;
                    for (; i <= utxo_count; i++) {
                        printf("txid:           %s\n", dogecoin_get_utxo_txid_str(ptr, i));
                        printf("vout:           %d\n", dogecoin_get_utxo_vout(ptr, i));
                        char* utxo_amount_str = dogecoin_get_utxo_amount(ptr, i);
                        printf("amount:         %s\n", utxo_amount_str);
                        dogecoin_free(utxo_amount_str);
                    }
                }
                dogecoin_free(amount_str);
            }
            res = dogecoin_unregister_watch_address_with_node(ptr);
            printf("unregistered:   %s\n", res ? "true" : "false");
        }

        if ((file = fopen("tmp.bin", "r"))) {
            fclose(file);
#ifdef WIN32
            #include <winbase.h>
            char *tmp_filename = _strdup((char *)tmp->filename);
            char *filename = _strdup((char *)tmp->filename);
            replace_last_after_delim(filename, "\\", "tmp.bin");
            LPVOID message;
            result = DeleteFile(tmp->filename);
            if (!result) {
                FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&message, 0, NULL);
                printf("ERROR: %s\n", (char *)message);
            }
            result = rename(filename, tmp->filename);
            dogecoin_free(filename);
            dogecoin_free(tmp_filename);
#else
            result = rename("tmp.bin", tmp->filename);
#endif
            if( result != 0 ) {
                printf( "could not copy 'tmp.bin' %d\n", result );
            } else {
                printf( "File 'tmp.bin' copied to '%s'\n", tmp->filename);
            }
        }
        dogecoin_wallet_free(tmp);
        dogecoin_free(address_copy);
    }

    dogecoin_ecc_stop();
#endif
    } else {
        printf("Invalid command (use -?)\n");
        ret = EXIT_FAILURE;
        }
    return ret;
    }