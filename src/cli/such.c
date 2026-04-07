/*

 The MIT License (MIT)

 Copyright (c) 2016 Jonas Schnelli
 Copyright (c) 2023 bluezr
 Copyright (c) 2023 edtubbs
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

#include <assert.h>
#include <ctype.h>
#ifndef _MSC_VER
#include <getopt.h>
#include <unistd.h>
#else
#include <win/wingetopt.h>
#include <win/winunistd.h>
#endif

#ifdef HAVE_CONFIG_H
#  include "libdogecoin-config.h"
#endif
#include <stdbool.h>
#include <stdio.h>   /* printf */
#include <stdlib.h>  /* atoi, malloc */
#include <string.h>  /* strcpy */

#include <dogecoin/uthash.h>

#include <dogecoin/address.h>
#include <dogecoin/bip32.h>
#include <dogecoin/bip39.h>
#include <dogecoin/bip44.h>
#include <dogecoin/cstr.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/ecc.h>
#include <dogecoin/eckey.h>
#include <dogecoin/koinu.h>
#include <dogecoin/seal.h>
#include <dogecoin/serialize.h>
#include <dogecoin/sign.h>
#include <dogecoin/tool.h>
#include <dogecoin/transaction.h>
#include <dogecoin/tx.h>
#include <dogecoin/utils.h>
#include <dogecoin/wow.h>
#include <dogecoin/pqc_dilithium.h>
#include <dogecoin/pqc_falcon.h>
#include <dogecoin/pqc_raccoon.h>

// ******************************** SUCH -C TRANSACTION MENU ********************************
#ifdef WITH_NET
#include <dogecoin/net.h>
void broadcasting_menu(int txindex, int is_testnet) {
    int running = 1;
    int selected = -1;
    const dogecoin_chainparams* chain = is_testnet ? &dogecoin_chainparams_test : &dogecoin_chainparams_main;
    working_transaction* tx = find_transaction(txindex);
    char* raw_hexadecimal_tx = get_raw_transaction(txindex);
    int length = HASH_COUNT(transactions);
    while (running) {
        printf("length: %d\n", length);
        for (int i = 0; i <= length; i++) {
            printf("\n--------------------------------\n");
            printf("transaction to broadcast: %s\n", raw_hexadecimal_tx);
            selected == i ? printf("confirm:         [X]\n") : 0;

            if (selected == i) {
                printf("\n\n");
                printf("please confirm this is the transaction you want to send:\n");
                printf("1. yes\n");
                printf("2. no\n");
                switch (atoi(getl("\ncommand"))) {
                        case 1:
                            /* The above code is checking if the data is NULL, empty or larger than the maximum
                            size of a p2p message. */
                            if (raw_hexadecimal_tx == NULL || strlen(raw_hexadecimal_tx) == 0 || strlen(raw_hexadecimal_tx) > DOGECOIN_MAX_P2P_MSG_SIZE) {
                                printf("Transaction in invalid or to large.\n");
                                }
                            uint8_t* data_bin = dogecoin_malloc(strlen(raw_hexadecimal_tx) / 2 + 1);
                            size_t outlen = 0;
                            utils_hex_to_bin(raw_hexadecimal_tx, data_bin, strlen(raw_hexadecimal_tx), &outlen);

                            /* Deserializing the transaction and broadcasting it to the network. */
                            if (dogecoin_tx_deserialize(data_bin, outlen, tx->transaction, NULL)) {
                                broadcast_tx(chain, tx->transaction, 0, 10, 15, 0);
                                }
                            else {
                                printf("Transaction is invalid\n");
                                }
                            dogecoin_free(data_bin);
                            selected = -1; // set selected to number out of bounds for i
                            i = length; // reset loop to start
                            break;
                        case 2:
                            selected = -1; // set selected to number out of bounds for i
                            i = length; // reset loop to start
                            break;
                    }
                }
            // if on last iteration, jump into switch case pausing loop
            // execution so user has ability to reset loop index in order
            // to target desired input to edit. otherwise set loop index to
            // length thus finishing final iteration and set running to 0 to
            // escape encompassing while loop so we return to previous menu
            if (i == length) {
                printf("\n\n");
                printf("1. broadcast transaction\n");
                printf("2. main menu\n");
                switch (atoi(getl("\ncommand"))) {
                        case 1:
                            // tx_input submenu

                            selected = i;
                            i = i - i - 1;
                            break;
                        case 2:
                            i = length;
                            running = 0;
                            break;
                    }
                }
            }
        }
    }
#endif

// keeping is_testnet for integration with validation functions
// can remove #pragma once that's completed
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
void signing_menu(int txindex, int is_testnet) {
#pragma GCC diagnostic pop
    int running = 1;
    int input_to_sign;
    char* raw_hexadecimal_tx;
    char* script_pubkey;
    char* private_key_wif;
    while (running) {
        printf("\n 1. sign input (from current working transaction)\n");
        printf(" 2. sign input (raw hexadecimal transaction)\n");
        printf(" 3. print signed transaction\n");
        printf(" 4. go back\n\n");
        switch (atoi(getl("command"))) {
                case 1:
                    input_to_sign = atoi(getl("input to sign")); // 0
                    private_key_wif = (char*)get_private_key("private_key"); // ci5prbqz7jXyFPVWKkHhPq4a9N8Dag3TpeRfuqqC2Nfr7gSqx1fy
                    script_pubkey = dogecoin_private_key_wif_to_pubkey_hash(private_key_wif);
                    // 76a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac
                    raw_hexadecimal_tx = get_raw_transaction(txindex);
                    // 76a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac
                    if (!sign_indexed_raw_transaction(txindex, input_to_sign, raw_hexadecimal_tx, script_pubkey, 1, private_key_wif)) {
                        printf("signing indexed raw transaction failed!\n");
                        }
                    else printf("transaction input successfully signed!\n");
                    break;
                case 2:
                    input_to_sign = atoi(getl("input to sign")); // 0
                    private_key_wif = (char*)get_private_key("private_key"); // ci5prbqz7jXyFPVWKkHhPq4a9N8Dag3TpeRfuqqC2Nfr7gSqx1fy
                    script_pubkey = dogecoin_private_key_wif_to_pubkey_hash(private_key_wif);
                    raw_hexadecimal_tx = (char*)get_raw_tx("raw transaction");
                    // 76a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac
                    debug_print("input_to_sign: %d\n", input_to_sign);
                    debug_print("raw_hexadecimal_transaction: %s\n", raw_hexadecimal_tx);
                    debug_print("script_pubkey: %s\n", script_pubkey);
                    debug_print("input_to_sign: %d\n", input_to_sign);
                    debug_print("private_key: %s\n", private_key_wif);
                    if (!sign_indexed_raw_transaction(txindex, input_to_sign, raw_hexadecimal_tx, script_pubkey, 1, private_key_wif)) {
                        printf("signing indexed raw transaction failed!\n");
                        }
                    else printf("transaction input successfully signed!\n");
                    break;
                case 3:
                    printf("raw_tx: %s\n", get_raw_transaction(txindex));
                    break;
                case 4:
                    running = 0;
                    break;
            }
        }
    }

void sub_menu(int txindex, int is_testnet) {
    int running = 1;
    int temp_vout_index;
    char* temp_hex_utxo_txid;
    const char* temp_ext_p2pkh;
    char* temp_amt;
    char* output_address;
    char* desired_fee;
    char* total_amount_for_verification;
    char* public_key;
    char* raw_hexadecimal_transaction;
    while (running) {
        printf("\n 1. add input\n");
        printf(" 2. add output\n");
        printf(" 3. finalize transaction\n");
        printf(" 4. sign transaction\n");
#ifdef WITH_NET
        printf(" 5. broadcast transaction\n");
#endif
        printf(" 8. print transaction\n");
        printf(" 9. main menu\n\n");
        switch (atoi(getl("command"))) {
                case 1:
                    printf("raw_tx: %s\n", get_raw_transaction(txindex));
                    temp_vout_index = atoi(getl("vout index")); // 1
                    temp_hex_utxo_txid = (char*)getl("txid"); // b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074 & 42113bdc65fc2943cf0359ea1a24ced0b6b0b5290db4c63a3329c6601c4616e2
                    add_utxo(txindex, temp_hex_utxo_txid, temp_vout_index);
                    printf("raw_tx: %s\n", get_raw_transaction(txindex));
                    break;
                case 2:
                    temp_amt = (char*)getl("amount to send to destination address"); // 5
                    temp_ext_p2pkh = getl("destination address"); // nbGfXLskPh7eM1iG5zz5EfDkkNTo9TRmde
                    printf("destination: %s\n", temp_ext_p2pkh);
                    printf("addout success: %d\n", add_output(txindex, (char*)temp_ext_p2pkh, temp_amt));
                    char* str = get_raw_transaction(txindex);
                    printf("raw_tx: %s\n", str);
                    break;
                case 3:
                    output_address = (char*)getl("re-enter destination address for verification"); // nbGfXLskPh7eM1iG5zz5EfDkkNTo9TRmde
                    desired_fee = (char*)getl("desired fee"); // .00226
                    total_amount_for_verification = (char*)getl("total amount for verification"); // 12
                    public_key = (char*)getl("senders address");
                    // noxKJyGPugPRN4wqvrwsrtYXuQCk7yQEsy
                    raw_hexadecimal_transaction = finalize_transaction(txindex, output_address, desired_fee, total_amount_for_verification, public_key);
                    printf("raw_tx: %s\n", raw_hexadecimal_transaction);
                    break;
                case 4:
                    signing_menu(txindex, is_testnet);
                    break;
#ifdef WITH_NET
                case 5:
                    broadcasting_menu(txindex, is_testnet);
                    break;
#endif
                case 8:
                    printf("raw_tx: %s\n", get_raw_transaction(txindex));
                    break;
                case 9:
                    running = 0;
                    break;
            }
        }
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
void transaction_input_menu(int txindex, int is_testnet) {
#pragma GCC diagnostic pop
    int running_transaction_input_menu = 1;
    working_transaction* tx = find_transaction(txindex);
    while (running_transaction_input_menu) {
        int length = tx->transaction->vin->len;
        int selected = -1;
        char* hex_utxo_txid;
        int vout;
        char* raw_hexadecimal_tx;
        char* script_pubkey;
        int input_to_sign;
        char* private_key_wif;
        for (int i = 0; i < length; i++) {
            printf("\n--------------------------------\n");
            printf("input index:      %d\n", i);
            dogecoin_tx_in* tx_in = vector_idx(tx->transaction->vin, i);
            vout = tx_in->prevout.n;
            printf("prevout.n:        %d\n", vout);
            hex_utxo_txid = utils_uint8_to_hex(tx_in->prevout.hash, sizeof tx_in->prevout.hash);
            printf("txid:             %s\n", hex_utxo_txid);
            printf("script signature: %s\n", utils_uint8_to_hex((const uint8_t*)tx_in->script_sig->str, tx_in->script_sig->len));
            printf("tx_in->sequence:  %x\n", tx_in->sequence);
            selected == i ? printf("selected:         [X]\n") : 0;

            if (selected == i) {
                printf("\n\n");
                printf("1. select field to edit\n");
                printf("2. finish editing\n");
                switch (atoi(getl("\ncommand"))) {
                        case 1:
                            // tx_input submenu
                            printf("1. prevout.n\n");
                            printf("2. txid\n");
                            printf("3. script signature\n");
                            switch (atoi(getl("field to edit"))) {
                                    case 1:
                                        printf("prevout.n\n");
                                        vout = atoi(getl("new input index"));
                                        tx_in->prevout.n = vout;
                                        break;
                                    case 2:
                                        hex_utxo_txid = (char*)get_raw_tx("new txid");
                                        utils_uint256_sethex((char*)hex_utxo_txid, (uint8_t*)tx_in->prevout.hash);
                                        tx_in->prevout.n = vout;
                                        break;
                                    case 3:
                                        printf("\nediting script signature:\n\n");
                                        input_to_sign = i;
                                        private_key_wif = (char*)get_private_key("private_key"); // ci5prbqz7jXyFPVWKkHhPq4a9N8Dag3TpeRfuqqC2Nfr7gSqx1fy
                                        script_pubkey = dogecoin_private_key_wif_to_pubkey_hash(private_key_wif);
                                        cstr_erase(tx_in->script_sig, 0, tx_in->script_sig->len);
                                        // 76a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac
                                        raw_hexadecimal_tx = get_raw_transaction(txindex);
                                        printf("raw_hexadecimal_transaction: %s\n", raw_hexadecimal_tx);
                                        // 76a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac
                                        if (!sign_indexed_raw_transaction(txindex, input_to_sign, raw_hexadecimal_tx, script_pubkey, 1, private_key_wif)) {
                                            printf("signing indexed raw transaction failed!\n");
                                            }
                                        else printf("transaction input successfully signed!\n");
                                        dogecoin_free(script_pubkey);
                                        break;
                                }
                            i = i - i - 1; // reset loop to start
                            break;
                        case 2:
                            selected = -1; // set selected to number out of bounds for i
                            i = i - i - 1; // reset loop to start
                            break;
                    }
                }
            // if on last iteration, jump into switch case pausing loop
            // execution so user has ability to reset loop index in order
            // to target desired input to edit. otherwise set loop index to
            // length thus finishing final iteration and set running to 0 to
            // escape encompassing while loop so we return to previous menu
            if (i == length - 1) {
                printf("\n\n");
                printf("1. select input to edit\n");
                printf("2. main menu\n");
                switch (atoi(getl("\ncommand"))) {
                        case 1:
                            // tx_input submenu
                            selected = atoi(getl("vin index"));
                            i = i - i - 1;
                            break;
                        case 2:
                            i = length;
                            running_transaction_input_menu = 0;
                            break;
                    }
                }
            }
        }
    }

void transaction_output_menu(int txindex, int is_testnet) {
    int running_transaction_output_menu = 1;
    while (running_transaction_output_menu) {
        char* destinationaddress;
        char* coin_amount[21];
        dogecoin_mem_zero(coin_amount, 21);
        uint64_t koinu_amount;
        uint64_t tx_out_total = 0;
        const dogecoin_chainparams* chain = is_testnet ? &dogecoin_chainparams_test : &dogecoin_chainparams_main;
        working_transaction* tx = find_transaction(txindex);
        int length = tx->transaction->vout->len;
        int selected = -1;
        printf("length: %d\n", length);
        for (int i = 0; i < length; i++) {
            dogecoin_tx_out* tx_out = vector_idx(tx->transaction->vout, i);
            tx_out_total += tx_out->value;
            printf("\n--------------------------------\n");
            printf("output index:       %d\n", i);
            printf("script public key:  %s\n", utils_uint8_to_hex((const uint8_t*)tx_out->script_pubkey->str, tx_out->script_pubkey->len));
            koinu_to_coins_str(tx_out->value, (char*)coin_amount);
            printf("amount:             %s\n", (char*)coin_amount);
            // selected should only equal anything other than -1 upon setting
            // loop index in conditional targetting last iteration:
            selected == i ? printf("selected:           [X]\n") : 0;
            if (selected == i) {
                printf("\n\n");
                printf("1. select field to edit\n");
                printf("2. finish editing\n");
                switch (atoi(getl("\ncommand"))) {
                        case 1:
                            // tx_input submenu
                            printf("1. script public key\n");
                            printf("2. amount\n");
                            switch (atoi(getl("field to edit"))) {
                                    case 1:
                                        destinationaddress = (char*)getl("new destination address");
                                        if (!verifyP2pkhAddress(destinationaddress, strlen(destinationaddress))) {
                                            printf("\ninvalid destination address!\n");
                                            break;
                                            }
                                        else {
                                            koinu_amount = coins_to_koinu_str((char*)coin_amount);
                                            vector_remove_idx(tx->transaction->vout, i);
                                            dogecoin_tx_add_address_out(tx->transaction, chain, koinu_amount, destinationaddress);
                                            }
                                        break;
                                    case 2:
                                        memcpy_safe(coin_amount, (char*)getl("new amount"), 21);
                                        koinu_amount = coins_to_koinu_str((char*)coin_amount);
                                        if (!koinu_amount) {
                                            printf("number is invalid or set to 0\n");
                                        } else tx_out->value = koinu_amount;
                                        break;
                                }
                            tx_out_total = 0;
                            i = i - i - 1; // reset loop to start
                            break;
                        case 2:
                            selected = -1; // set selected to number out of bounds for i
                            tx_out_total = 0;
                            i = i - i - 1; // reset loop to start
                            break;
                    }
                }
            // if on last iteration, jump into switch case pausing loop
            // execution so user has ability to reset loop index in order
            // to target desired input to edit. otherwise set loop index to
            // length thus finishing final iteration and set running to 0 to
            // escape encompassing while loop so we return to previous menu
            if (i == length - 1) {
                printf("\n\n");
                char* subtotal[21];
                dogecoin_mem_zero(subtotal, 21);
                koinu_to_coins_str(tx_out_total, (char*)subtotal);
                printf("subtotal - desired fee: %s\n", (char*)subtotal);
                printf("\n");
                printf("1. select output to edit\n");
                printf("2. main menu\n");
                switch (atoi(getl("\ncommand"))) {
                        case 1:
                            // tx_input submenu
                            selected = atoi(getl("vout index"));
                            tx_out_total = 0;
                            i = i - i - 1;
                            break;
                        case 2:
                            i = length;
                            running_transaction_output_menu = 0;
                            break;
                    }
                }
            }
        }
    }

void edit_menu(int txindex, int is_testnet) {
    int running_edit_menu = 1;
    while (running_edit_menu) {
        printf("\n");
        printf("1. edit input\n");
        printf("2. edit output\n");
        printf("3. main menu\n");
        switch (atoi(getl("\ncommand"))) {
                case 1:
                    transaction_input_menu(txindex, is_testnet);
                    break;
                case 2:
                    transaction_output_menu(txindex, is_testnet);
                    break;
                case 3:
                    running_edit_menu = 0;
                    break;
            }
        }
    }

int chainparams_menu(int is_testnet) {
    printf("\n1. mainnet\n");
    printf("2. testnet\n\n");
    switch (atoi(getl("command"))) {
            case 1:
                is_testnet = false;
                break;
            case 2:
                is_testnet = true;
                break;
        }
    return is_testnet;
    }

int is_testnet = true;

void main_menu() {
    int running = 1;
    struct working_transaction* s;
    int temp, txindex;
    wow();

    // load existing testnet transaction into memory for demonstration purposes.
    save_raw_transaction(start_transaction(), "0100000002746007aed61e8531faba1af6610f10a5422c70a2a7eb6ffb51cb7a7b7b5e45b40100000000ffffffffe216461c60c629333ac6b40d29b5b0b6d0ce241aea5903cf4329fc65dc3b11420100000000ffffffff020065cd1d000000001976a9144da2f8202789567d402f7f717c01d98837e4325488ac30b4b529000000001976a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac00000000");
    while (running) {
        printf("\nsuch transaction: \n\n");
        printf(" 1. add transaction\n");
        printf(" 2. edit transaction by id\n");
        printf(" 3. find transaction\n");
        printf(" 4. sign transaction\n");
        printf(" 5. delete transaction\n");
        printf(" 6. delete all transactions\n");
        printf(" 7. print transactions\n");
        printf(" 8. import raw transaction (memory)\n");
#ifdef WITH_NET
        printf(" 9. broadcast transaction\n");
        printf(" 10. change network (current: %s)\n", is_testnet ? "testnet" : "mainnet");
        printf(" 11. quit\n");
#else
        printf(" 9. change network (current: %s)\n", is_testnet ? "testnet" : "mainnet");
        printf(" 10. quit\n");
#endif
        switch (atoi(getl("\ncommand"))) {
                case 1:
                    sub_menu(start_transaction(), is_testnet);
                    break;
                case 2:
                    temp = atoi(getl("ID of transaction to edit"));
                    s = find_transaction(temp);
                    if (s) {
                        edit_menu(temp, is_testnet);
                        }
                    else {
                        printf("\nno transaction found with that id. please try again!\n");
                        }
                    break;
                case 3:
                    s = find_transaction(atoi(getl("ID to find")));
                    s ? printf("transaction: %s\n", get_raw_transaction(s->idx)) : printf("\nno transaction found with that id. please try again!\n");
                    break;
                case 4:
                    temp = atoi(getl("ID of transaction to sign"));
                    s = find_transaction(temp);
                    if (s) {
                        signing_menu(temp, is_testnet);
                        }
                    else {
                        printf("\nno transaction found with that id. please try again!\n");
                        }
                    break;
                case 5:
                    s = find_transaction(atoi(getl("ID to delete")));
                    if (s) {
                        remove_transaction(s);
                        }
                    else {
                        printf("\nno transaction found with that id. please try again!\n");
                        }
                    break;
                case 6:
                    remove_all();
                    break;
                case 7:
                    count_transactions();
                    print_transactions();
                    break;
                case 8:
                    txindex = start_transaction();
                    int res = save_raw_transaction(txindex, get_raw_tx("raw transaction"));
                    if (!res) {
                        printf("error saving transaction!\n");
                        clear_transaction(txindex);
                        }
                    else {
                        printf("successfully saved raw transaction to memory for the session!\n");
                        printf("working transaction id is: %d\n", txindex);
                        }
                    break;
#ifdef WITH_NET
                case 9:
                    temp = atoi(getl("ID of transaction to edit"));
                    s = find_transaction(temp);
                    if (s) {
                        broadcasting_menu(temp, is_testnet);
                        }
                    else {
                        printf("\nno transaction found with that id. please try again!\n");
                        }
                    break;
                case 10:
                    is_testnet = chainparams_menu(is_testnet);
                    break;
                case 11:
                    running = 0;
                    break;
#else
                case 9:
                    is_testnet = chainparams_menu(is_testnet);
                    break;
                case 10:
                    running = 0;
                    break;
#endif
            }
        }
    remove_all();
    }

// ******************************** END TRANSACTION MENU ********************************

// ******************************** CLI INTERFACE ********************************
static struct option long_options[] =
    {
        {"privkey", required_argument, NULL, 'p'},
        {"pubkey", required_argument, NULL, 'k'},
        {"derived_path", required_argument, NULL, 'm'},
        {"chunks", required_argument, NULL, 'm'},
        {"sighash", required_argument, NULL, 'h'},
        {"script", required_argument, NULL, 's'},
        {"input_index", required_argument, NULL, 'i'},
        {"raw_tx", required_argument, NULL, 'x'},
        {"entropy", required_argument, NULL, 'e'},
        {"entropy_size", required_argument, NULL, 'z'},
        {"mnemonic", required_argument, NULL, 'n'},
        {"pass_phrase", no_argument, NULL, 'a'},
        {"account_int", required_argument, NULL, 'o'},
        {"change_level", required_argument, NULL, 'g'},
        {"address_index", required_argument, NULL, 'i'},
        {"encrypted_file", required_argument, NULL, 'y'},
        {"use_tpm", no_argument, NULL, 'j'},
        {"command", required_argument, NULL, 'c'},
        {"silent", no_argument, NULL, 'b'},
        {"overwrite", no_argument, NULL, 'w'},
        {"testnet", no_argument, NULL, 't'},
        {"regtest", no_argument, NULL, 'r'},
        {"version", no_argument, NULL, 'v'},
        {NULL, 0, NULL, 0} };

static void print_version()
    {
    printf("Version: %s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
    }

static void print_usage()
    {
    print_version();
    printf("Usage: such -c <cmd> (-m|-derived_path <bip_derived_path>) (-k|-pubkey <publickey>) (-p|-privkey <privatekey>) (-h|-sighash <sighash type>) \
(-s|-script <script pubkey>) (-i|-input_index <input index>) (-x|-raw_tx <raw hex tx>) (-o|-account_int <account_int>) (-g|-change_level <change_level>) \
(-e|-entropy <hex_entropy>) (-n|-mnemonic <seed_phrase>) (-a|-pass_phrase) (-y|-encrypted_file <file_num 0-999>) (-w[--overwrite]) (-b[--silent]) \
(-z|-entropy_size <bit_size>) (-j[--use_tpm]) (-t[--testnet]) (-r[--regtest])\n");
    printf("Available commands:\n");
    printf("generate_public_key (requires -p <wif>),\n");
    printf("p2pkh (requires -k <public key hex>),\n");
    printf("generate_private_key,\n");
    printf("bip32_extended_master_key (-y <file_num>, -j (use_tpm), -w (overwrite) and -b (silent), all optional),\n");
    printf("generate_mnemonic (-e <hex_entropy> or -y <file_num>, -z <bit_size>, -j (use_tpm), -w (overwrite) and -b (silent), all optional),\n");
    printf("list_encryption_keys_in_tpm,\n");
    printf("decrypt_master_key (requires -y <file_num>, -j (use_tpm) optional),\n");
    printf("decrypt_mnemonic (requires -y <file_num>, -j (use_tpm) optional),\n");
    printf("seed_to_master_key (-y <file_num>, -j (use_tpm) optional),\n");
    printf("mnemonic_to_key (requires -n <seed_phrase> or -y <file_num>, -j (use_tpm), -o <account_int>, -g <change_level>, -i <address_index> and -a, all optional),\n");
    printf("mnemonic_to_addresses (requires -n <seed_phrase> or -y <file_num>, -j (use_tpm), -o <account_int>, -g <change_level>, -i <address_index> and -a, all optional),\n");
    printf("print_keys (requires -p <private key hex>),\n");
    printf("derive_child_keys (requires -m <custom path> -p <public or private key>),\n");
    printf("sign (-x <raw hex tx> -s <script pubkey> -i <input index> -h <sighash type> -p <private key>),\n");
        printf("addpqcdatawitness (-x <raw hex tx> -i <input index> -k <pqc_pubkey_hex> -s <pqc_signature_hex> [-h <max_chunk_bytes, default 400>]),\n");
        printf("addscriptsigpqc (-x <raw hex tx> -i <input index> -k <pqc_pubkey_hex> -s <pqc_signature_hex>) [deprecated, regtest-only test helper],\n");
        printf("printscriptsigpqc (-x <raw hex tx>) [deprecated scriptSig inspector],\n");
        printf("addwitness (-x <raw hex tx> -i <input index> -s <witness item hex>),\n");
        printf("printwitness (-x <raw hex tx>),\n");
        printf("p2sh_p2wsh_datacarrier_scriptpubkey (-s <witness_script_hex>),\n");
        printf("p2sh_p2wsh_datacarrier_witness_script (-i <chunk_count>),\n");
        printf("pqc_chunk_hex (-x <hex_payload> [-h <max_chunk_bytes, default 520>]),\n");
        printf("apply_p2sh_p2wsh_redeemscript_and_witness (-x <raw hex tx> -i <input index> -s <redeemscript_hex> -k <witness_script_hex> -m <chunk_hex_csv>),\n");
#ifdef USE_LIBOQS
    printf("tx_sighash32 (-x <raw hex tx> -s <script pubkey> -i <input index> -h <sighash type>),\n");
#endif
    printf("comp2der (-s <compact signature>),\n");
    printf("bip32maintotest (-p <extended hd master key>),\n");
    printf("signmessage (-x '<message>' -p <private key>),\n");
    printf("verifymessage (-x '<message>' -s <signature (base64 encoded)> -k <address>),\n");
    printf("transaction,\n");
#ifdef USE_LIBOQS
    printf("falcon_keygen (generates Falcon-512 keypair),\n");
    printf("falcon_sign (requires -p <falcon_secret_key_hex> -x <message_hex|tx_sighash_hex>),\n");
    printf("falcon_verify (requires -k <falcon_public_key_hex> -x <message_hex|tx_sighash_hex> -s <signature_hex>),\n");
    printf("falcon_commit (requires -k <falcon_public_key_hex> -s <signature_hex>),\n");
    printf("dilithium2_keygen (generates Dilithium2 keypair),\n");
    printf("dilithium2_sign (requires -p <dilithium2_secret_key_hex> -x <message_hex|tx_sighash_hex>),\n");
    printf("dilithium2_verify (requires -k <dilithium2_public_key_hex> -x <message_hex|tx_sighash_hex> -s <signature_hex>),\n");
    printf("dilithium2_commit (requires -k <dilithium2_public_key_hex> -s <signature_hex>),\n");
    printf("raccoong_keygen (generates Raccoon-G-44 keypair),\n");
    printf("raccoong_sign (requires -p <raccoong_secret_key_hex> -x <message_hex|tx_sighash_hex>),\n");
    printf("raccoong_verify (requires -k <raccoong_public_key_hex> -x <message_hex|tx_sighash_hex> -s <signature_hex>),\n");
    printf("raccoong_commit (requires -k <raccoong_public_key_hex> -s <signature_hex>),\n");
    printf("raccoong_hd_derive (requires -p <raccoong_secret_key_hex> -s <chaincode_hex> -i <child_index>, optional -g <0|1 hardened>),\n");
    printf("raccoong_hd_derive_pub (requires -k <raccoong_public_key_hex> -s <chaincode_hex> -i <child_index>),\n");
    printf("falcon_add_commit_tx (requires -x <raw_tx_hex> -s <falcon_commitment_hex>),\n");
    printf("dilithium2_add_commit_tx (requires -x <raw_tx_hex> -s <dilithium2_commitment_hex>),\n");
    printf("raccoong_add_commit_tx (requires -x <raw_tx_hex> -s <raccoong_commitment_hex>),\n");
#endif
    printf("\nExamples: \n");
    printf("Generate a testnet private ec keypair wif/hex:\n");
    printf("> such -c generate_private_key\n\n");
    printf("> such -c generate_public_key -p QRYZwxVxBFKgKP4bWPEwWBJpN3C3cTN6fads8SgJTgaPTJhEWgLH\n\n");
    }

static bool showError(const char* er)
    {
    printf("Error: %s\n", er);
    dogecoin_ecc_stop();
    return 1;
    }

static void such_witness_item_free_cb(void* data)
{
    cstr_free((cstring*)data, true);
}

static void such_reset_witness_stack(dogecoin_tx_in* tx_in)
{
    if (!tx_in) {
        return;
    }
    if (tx_in->witness_stack) {
        vector_free(tx_in->witness_stack, true);
    }
    tx_in->witness_stack = vector_new(1, such_witness_item_free_cb);
}

static dogecoin_bool such_witness_push_hex(vector_t* witness_stack, const char* hex, const char* what)
{
    if (!witness_stack || !hex) {
        return false;
    }
    size_t hex_len = strlen(hex);
    if ((hex_len % 2) != 0) {
        printf("Error: Invalid %s hex length\n", what);
        return false;
    }

    size_t outlen = 0;
    uint8_t* data = dogecoin_malloc(hex_len / 2 + 1);
    if (!data) {
        printf("Error: Failed to allocate %s buffer\n", what);
        return false;
    }
    utils_hex_to_bin(hex, data, hex_len, &outlen);

    cstring* item = cstr_new_buf(data, outlen);
    dogecoin_free(data);
    if (!item) {
        printf("Error: Failed to allocate %s witness item\n", what);
        return false;
    }
    if (!vector_add(witness_stack, item)) {
        cstr_free(item, true);
        printf("Error: Failed to append %s witness item\n", what);
        return false;
    }
    return true;
}

static void such_append_witness_drop_script(cstring* witness_script, size_t drops)
{
    for (size_t i = 0; i < drops; i++) {
        dogecoin_script_append_op(witness_script, OP_DROP);
    }
    dogecoin_script_append_op(witness_script, OP_1);
}

static dogecoin_bool such_hex_payload_chunks(const char* payload_hex, size_t max_chunk_bytes, vector_t* chunks_out)
{
    if (!payload_hex || !chunks_out) {
        return false;
    }
    size_t payload_hex_len = strlen(payload_hex);
    if ((payload_hex_len % 2) != 0) {
        return false;
    }
    if (max_chunk_bytes == 0) {
        return false;
    }
    size_t chunk_hex_len = max_chunk_bytes * 2;
    if (chunk_hex_len == 0) {
        return false;
    }
    if (payload_hex_len == 0) {
        return true;
    }

    for (size_t off = 0; off < payload_hex_len; off += chunk_hex_len) {
        size_t take = payload_hex_len - off;
        if (take > chunk_hex_len) {
            take = chunk_hex_len;
        }
        cstring* chunk = cstr_new_sz(take + 1);
        if (!chunk) {
            return false;
        }
        cstr_append_buf(chunk, payload_hex + off, take);
        if (!vector_add(chunks_out, chunk)) {
            cstr_free(chunk, true);
            return false;
        }
    }
    return true;
}

static dogecoin_bool such_witness_script_is_dropn_true(const uint8_t* script, size_t script_len, size_t expected_drops)
{
    if (!script || script_len == 0) {
        return false;
    }
    if (script_len != expected_drops + 1) {
        return false;
    }
    for (size_t i = 0; i < expected_drops; i++) {
        if (script[i] != OP_DROP) {
            return false;
        }
    }
    return script[script_len - 1] == OP_1;
}

static dogecoin_bool such_scriptsig_is_push_only_p2sh_p2wsh_redeemscript(const cstring* script_sig)
{
    if (!script_sig || !script_sig->str || script_sig->len != 35) {
        return false;
    }
    const uint8_t* s = (const uint8_t*)script_sig->str;
    return (s[0] == 0x22 && s[1] == OP_0 && s[2] == 0x20);
}

static void print_tx_witness_stack(const dogecoin_tx* tx)
{
    if (!tx) {
        return;
    }

    for (size_t vin_index = 0; vin_index < tx->vin->len; vin_index++) {
        dogecoin_tx_in* tx_in = vector_idx(tx->vin, vin_index);
        size_t witness_items = (tx_in && tx_in->witness_stack) ? tx_in->witness_stack->len : 0;
        printf("input[%zu] witness items: %zu\n", vin_index, witness_items);
        for (size_t wit_index = 0; wit_index < witness_items; wit_index++) {
            cstring* witness_item = vector_idx(tx_in->witness_stack, wit_index);
            char* witness_hex = utils_uint8_to_hex((const uint8_t*)witness_item->str, witness_item->len);
            printf("  witness[%zu]: %s\n", wit_index, witness_hex ? witness_hex : "");
        }
    }
}

static dogecoin_bool extract_scriptsig_pqc_items(const cstring* script_sig,
                                                 const uint8_t** out_pk, size_t* out_pk_len,
                                                 const uint8_t** out_sig, size_t* out_sig_len)
{
    if (!script_sig || !out_pk || !out_pk_len || !out_sig || !out_sig_len || script_sig->len == 0) {
        return false;
    }
    const uint8_t* s = (const uint8_t*)script_sig->str;
    size_t slen = script_sig->len;
    size_t off = 0;
    const uint8_t* item0 = NULL;
    const uint8_t* item1 = NULL;
    size_t item0_len = 0;
    size_t item1_len = 0;
    for (int item = 0; item < 2; item++) {
        if (off >= slen) {
            break;
        }
        uint8_t op = s[off++];
        size_t push_len = 0;
        if (op > 0 && op < OP_PUSHDATA1) {
            push_len = op;
        } else if (op == OP_PUSHDATA1) {
            if (off + 1 > slen) break;
            push_len = s[off++];
        } else if (op == OP_PUSHDATA2) {
            if (off + 2 > slen) break;
            push_len = (size_t)s[off] | ((size_t)s[off + 1] << 8);
            off += 2;
        } else if (op == OP_PUSHDATA4) {
            if (off + 4 > slen) break;
            push_len = (size_t)s[off] |
                       ((size_t)s[off + 1] << 8) |
                       ((size_t)s[off + 2] << 16) |
                       ((size_t)s[off + 3] << 24);
            off += 4;
        } else {
            break;
        }
        if (push_len == 0 || off + push_len > slen) {
            break;
        }
        if (item == 0) {
            item0 = s + off;
            item0_len = push_len;
        } else {
            item1 = s + off;
            item1_len = push_len;
        }
        off += push_len;
    }
            if (!item0 || !item1) {
                return false;
            }
            *out_pk = item0;
            *out_pk_len = item0_len;
            *out_sig = item1;
            *out_sig_len = item1_len;
            return true;
}

static dogecoin_bool such_apply_legacy_scriptsig_pqc(dogecoin_tx_in* tx_in, const char* pqc_pubkey_hex, const char* pqc_sig_hex)
{
    if (!tx_in || !tx_in->script_sig || !pqc_pubkey_hex || !pqc_sig_hex) {
        return false;
    }
    if ((strlen(pqc_pubkey_hex) % 2) != 0 || (strlen(pqc_sig_hex) % 2) != 0) {
        printf("Error: Invalid PQC pubkey/signature hex\n");
        return false;
    }

    size_t pk_len = strlen(pqc_pubkey_hex) / 2;
    size_t sig_len = strlen(pqc_sig_hex) / 2;
    uint8_t* pk_data = dogecoin_malloc(pk_len);
    uint8_t* sig_data = dogecoin_malloc(sig_len);
    if (!pk_data || !sig_data) {
        if (pk_data) dogecoin_free(pk_data);
        if (sig_data) dogecoin_free(sig_data);
        printf("Error: Failed to allocate pqc payload buffers\n");
        return false;
    }

    size_t pk_outlen = 0;
    size_t sig_outlen = 0;
    utils_hex_to_bin(pqc_pubkey_hex, pk_data, strlen(pqc_pubkey_hex), &pk_outlen);
    utils_hex_to_bin(pqc_sig_hex, sig_data, strlen(pqc_sig_hex), &sig_outlen);
    if (pk_outlen == 0 || sig_outlen == 0) {
        dogecoin_free(pk_data);
        dogecoin_free(sig_data);
        printf("Error: Failed to decode pqc payload hex\n");
        return false;
    }

    dogecoin_script_append_pushdata(tx_in->script_sig, pk_data, pk_outlen);
    dogecoin_script_append_pushdata(tx_in->script_sig, sig_data, sig_outlen);
    dogecoin_free(pk_data);
    dogecoin_free(sig_data);
    return true;
}

static void such_select_pqc_full_tag(size_t pubkey_len, char out_tag[9])
{
    if (!out_tag) {
        return;
    }
    if (pubkey_len == 897) {
        memcpy(out_tag, "FLC1FULL", 8);
    } else if (pubkey_len == 1312) {
        memcpy(out_tag, "DIL2FULL", 8);
    } else {
        memcpy(out_tag, "RCG4FULL", 8);
    }
    out_tag[8] = '\0';
}

static dogecoin_bool such_script_append_hex_chunks(cstring* script, const char* hex_payload, size_t max_chunk_bytes, size_t* chunk_count_out)
{
    if (!script || !hex_payload || !chunk_count_out) {
        return false;
    }
    if (max_chunk_bytes == 0 || max_chunk_bytes > 520) {
        return false;
    }
    size_t hex_len = strlen(hex_payload);
    if ((hex_len % 2) != 0) {
        return false;
    }

    size_t chunks = 0;
    size_t chunk_hex_len = max_chunk_bytes * 2;
    for (size_t off = 0; off < hex_len; off += chunk_hex_len) {
        size_t take = hex_len - off;
        if (take > chunk_hex_len) {
            take = chunk_hex_len;
        }
        size_t chunk_bin_len = take / 2;
        uint8_t* chunk_bin = dogecoin_malloc(chunk_bin_len + 1);
        if (!chunk_bin) {
            return false;
        }
        size_t outlen = 0;
        utils_hex_to_bin(hex_payload + off, chunk_bin, take, &outlen);
        if (outlen == 0) {
            dogecoin_free(chunk_bin);
            return false;
        }
        dogecoin_script_append_pushdata(script, chunk_bin, outlen);
        dogecoin_free(chunk_bin);
        chunks++;
    }

    *chunk_count_out = chunks;
    return true;
}

static dogecoin_bool such_apply_pqc_p2sh_datacarrier(dogecoin_tx_in* tx_in,
                                                      const char* pqc_pubkey_hex,
                                                      const char* pqc_sig_hex,
                                                      size_t max_chunk_bytes,
                                                      cstring** out_redeem_script,
                                                      cstring** out_script_pubkey,
                                                      char out_tag[9],
                                                      size_t* out_pub_chunks,
                                                      size_t* out_sig_chunks)
{
    if (!tx_in || !tx_in->script_sig || !pqc_pubkey_hex || !pqc_sig_hex || !out_pub_chunks || !out_sig_chunks) {
        return false;
    }
    if ((strlen(pqc_pubkey_hex) % 2) != 0 || (strlen(pqc_sig_hex) % 2) != 0) {
        printf("Error: Invalid PQC pubkey/signature hex\n");
        return false;
    }
    if (max_chunk_bytes == 0 || max_chunk_bytes > 520) {
        printf("Error: max_chunk_bytes must be in range 1..520\n");
        return false;
    }

    uint16_t pk_len = (uint16_t)(strlen(pqc_pubkey_hex) / 2);
    uint16_t sig_len = (uint16_t)(strlen(pqc_sig_hex) / 2);
    if ((size_t)pk_len * 2 != strlen(pqc_pubkey_hex) || (size_t)sig_len * 2 != strlen(pqc_sig_hex)) {
        printf("Error: PQC payload too large\n");
        return false;
    }

    char tag[9];
    such_select_pqc_full_tag((size_t)pk_len, tag);
    if (out_tag) {
        memcpy(out_tag, tag, 9);
    }

    cstring* redeem_script = cstr_new_sz((size_t)pk_len + (size_t)sig_len + 256);
    if (!redeem_script) {
        printf("Error: Failed to allocate redeem script\n");
        return false;
    }

    dogecoin_script_append_pushdata(redeem_script, (const uint8_t*)tag, 8);
    uint8_t pk_len_le[2] = { (uint8_t)(pk_len & 0xff), (uint8_t)((pk_len >> 8) & 0xff) };
    uint8_t sig_len_le[2] = { (uint8_t)(sig_len & 0xff), (uint8_t)((sig_len >> 8) & 0xff) };
    dogecoin_script_append_pushdata(redeem_script, pk_len_le, sizeof(pk_len_le));

    size_t pub_chunks = 0;
    size_t sig_chunks = 0;
    if (!such_script_append_hex_chunks(redeem_script, pqc_pubkey_hex, max_chunk_bytes, &pub_chunks)) {
        cstr_free(redeem_script, true);
        printf("Error: Failed to append pubkey chunks\n");
        return false;
    }

    dogecoin_script_append_pushdata(redeem_script, sig_len_le, sizeof(sig_len_le));
    if (!such_script_append_hex_chunks(redeem_script, pqc_sig_hex, max_chunk_bytes, &sig_chunks)) {
        cstr_free(redeem_script, true);
        printf("Error: Failed to append signature chunks\n");
        return false;
    }

    size_t push_items = 1 + 1 + pub_chunks + 1 + sig_chunks;
    for (size_t i = 0; i < push_items; i++) {
        dogecoin_script_append_op(redeem_script, OP_DROP);
    }
    dogecoin_script_append_op(redeem_script, OP_1);

    cstr_resize(tx_in->script_sig, 0);
    dogecoin_script_append_pushdata(tx_in->script_sig, (const uint8_t*)redeem_script->str, redeem_script->len);
    such_reset_witness_stack(tx_in);

    uint160_t redeem_hash160;
    dogecoin_script_get_scripthash(redeem_script, redeem_hash160);
    cstring* script_pubkey = cstr_new_sz(64);
    if (!script_pubkey) {
        cstr_free(redeem_script, true);
        return false;
    }
    dogecoin_script_build_p2sh(script_pubkey, redeem_hash160);

    *out_pub_chunks = pub_chunks;
    *out_sig_chunks = sig_chunks;

    if (out_redeem_script) {
        *out_redeem_script = redeem_script;
    } else {
        cstr_free(redeem_script, true);
    }
    if (out_script_pubkey) {
        *out_script_pubkey = script_pubkey;
    } else {
        cstr_free(script_pubkey, true);
    }
    return true;
}

int main(int argc, char* argv[])
    {
    int long_index = 0;
    int opt = 0;
    char* pkey = 0;
    char* pubkey = 0;
    char* cmd = 0;
    char* derived_path = 0;
    uint32_t account = BIP44_FIRST_ACCOUNT_NODE;   /* default account (BIP44_FIRST_ACCOUNT_NODE) */
    char* change_level = BIP44_CHANGE_EXTERNAL;    /* default external (BIP44_CHANGE_EXTERNAL) */
    char* mnemonic_in = 0;
    char* pass = 0;
    char* entropy = 0;
    char* entropy_size = "256";
    MNEMONIC mnemonic = {0};
    SEED seed = {0};
    dogecoin_bool tpm = false;
    dogecoin_bool encrypted = false;
    dogecoin_bool overwrite = false;
    dogecoin_bool silent = false;
    int file_num = NO_FILE;

    char* txhex = 0;
    char* scripthex = 0;
    uint32_t inputindex = 0;
    int sighashtype = 1;
    dogecoin_mem_zero(&pkey, sizeof(pkey));
    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    /* get arguments */
    while ((opt = getopt_long_only(argc, argv, "h:i:s:x:p:k:m:o:g:e:n:y:c:z:atrvbwj", long_options, &long_index)) != -1) {
        switch (opt) {
                case 'p':
                    pkey = optarg;
                    if (strlen(pkey) < 50)
                        return showError("Private key must be WIF encoded");
                    break;
                case 'c':
                    cmd = optarg;
                    break;
                case 'm':
                    derived_path = optarg;
                    break;
                case 'o':
                    account = (int)strtol(optarg, (char**)NULL, 10);
                    break;
                case 'g':
                    change_level = optarg;
                    break;
                case 'e':
                    if (encrypted)
                        return showError("Parameter -e cannot be used with -y");
                    entropy = optarg;
                    if (entropy != NULL){
                        sprintf(entropy_size, "%zu", strlen(entropy) / HEX_CHARS_PER_BYTE * 8);
                    }

                    break;
                case 'z':
                    entropy_size = optarg;
                    break;
                case 'n':
                    mnemonic_in = optarg;
                    break;
                case 'a':
                    pass = getpass("BIP39 passphrase: \n");
                    break;
                case 'k':
                    pubkey = optarg;
                    break;
                case 't':
                    chain = &dogecoin_chainparams_test;
                    break;
                case 'r':
                    chain = &dogecoin_chainparams_regtest;
                    break;
                case 'v':
                    print_version();
                    exit(EXIT_SUCCESS);
                    break;
                case 'w':
                    if (!encrypted)
                        return showError("Overwrite can only be used with encrypted files");
                    overwrite = true;
                    break;
                case 'b':
                    if (!encrypted)
                        return showError("Silent can only be used with encrypted files");
                    silent = true;
                    break;
                case 'y':
                    if (entropy)
                        return showError("Parameter -y cannot be used with -e");
                    encrypted = true;
                    file_num = (int)strtol(optarg, (char**)NULL, 10);
                    break;
                case 'j':
                    if (!encrypted)
                        return showError("TPM can only be used with encrypted files");
                    tpm = true;
                    break;
                case 'x':
                    txhex = optarg;
                    break;
                case 's':
                    scripthex = optarg;
                    break;
                case 'i':
                    inputindex = (int)strtol(optarg, (char**)NULL, 10);
                    break;
                case 'h':
                    sighashtype = (int)strtol(optarg, (char**)NULL, 10);
                    break;
                default:
                    print_usage();
                    exit(EXIT_FAILURE);
            }
        }

    if (!cmd) {
        /* exit if no command was provided */
        print_usage();
        exit(EXIT_FAILURE);
        }

    /* start ECC context */
    dogecoin_ecc_start();

    const char* pkey_error = "missing extended key (use -p)";

    if (strcmp(cmd, "generate_public_key") == 0) {
        /* output compressed hex pubkey from hex privkey */

        char pubkey_hex[PUBKEYHEXLEN];
        size_t sizeout = sizeof(pubkey_hex);

        if (!pkey)
            return showError(pkey_error);
        if (!pubkey_from_privatekey(chain, pkey, pubkey_hex, &sizeout))
            return showError("attempt to generate pubkey from privatekey failed");

        /* erase previous private key */
        dogecoin_mem_zero(pkey, strlen(pkey));

        /* generate public key hex from private key hex */
        printf("public key hex: %s\n", pubkey_hex);

        /* give out p2pkh address */
        char* address_p2pkh = dogecoin_char_vla(sizeout);
        addresses_from_pubkey(chain, pubkey_hex, address_p2pkh);
        printf("p2pkh address: %s\n", address_p2pkh);

        /* clean memory */
        dogecoin_mem_zero(pubkey_hex, strlen(pubkey_hex));
        dogecoin_mem_zero(address_p2pkh, strlen(address_p2pkh));
        free(address_p2pkh);
        /* Creating a new address from a public key. */
        }
    else if (strcmp(cmd, "p2pkh") == 0) {
        char address_p2pkh[P2PKHLEN];
        if (!pubkey)
            return showError("Missing public key (use -k)");
        if (!addresses_from_pubkey(chain, pubkey, address_p2pkh))
            return showError("Operation failed, invalid pubkey");
        printf("p2pkh address: %s\n", address_p2pkh);

        dogecoin_mem_zero(pubkey, strlen(pubkey));
        dogecoin_mem_zero(address_p2pkh, strlen(address_p2pkh));
        /* Generating a new private key and printing it out. */
        }
    else if (strcmp(cmd, "generate_private_key") == 0) {
        char newprivkey_wif[PRIVKEYWIFLEN];
        char newprivkey_hex[PRIVKEYHEXLEN];

        /* generate a new private key */
        gen_privatekey(chain, newprivkey_wif, sizeof(newprivkey_wif), newprivkey_hex);
        printf("private key wif: %s\n", newprivkey_wif);
        printf("private key hex: %s\n", newprivkey_hex);
        dogecoin_mem_zero(newprivkey_wif, strlen(newprivkey_wif));
        dogecoin_mem_zero(newprivkey_hex, strlen(newprivkey_hex));
        /* Generating a new master key. */
        }
    else if (strcmp(cmd, "bip32_extended_master_key") == 0) {
        char masterkey[HDKEYLEN];

        /* if tpm is enabled, use it to generate a new master key */
        if (encrypted) {

            /* if overwrite is enabled, ask for confirmation */
            if (overwrite) {
                printf("Overwrite? Y/N\n");

                char buffer[MAX_LEN];
                /* get user input */
                if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
                    if (buffer[0] != 'Y' && buffer[0] != 'y') {

                        /* if not confirmed, abort */
                        printf("aborted\n");
                        dogecoin_ecc_stop();
                        return 1;
                        }
                    }
                }

            /* generate a new master key and encrypt it */
            dogecoin_hdnode node;

            if (tpm) {
                /* generate and encrypt a new hd master key with TPM 2.0 */
                if (!dogecoin_generate_hdnode_encrypt_with_tpm(&node, file_num, overwrite)) {
                    printf("bip32_extended_master_key (-y <file_num>, -j (use_tpm) and -w (overwrite), all optional),\n");
                    return showError("Failed to generate/encrypt master key in TPM\n");
                    }
                }

            else {
                /* generate and encrypt a new hd master key with software */
                if (!dogecoin_generate_hdnode_encrypt_with_sw(&node, file_num, overwrite, NULL, NULL, NULL)) {
                    printf("bip32_extended_master_key (-y <file_num>, -j (use_tpm) and -w (overwrite), all optional),\n");
                    return showError("Failed to generate master key in sofware");
                    }
                }

            /* serialize the master key */
            dogecoin_hdnode_serialize_private (&node, chain, masterkey, sizeof(masterkey));
            }

        /* otherwise, generate a new master key from entropy */
        else {
            /* generate a new hd master key */
            hd_gen_master(chain, masterkey, sizeof(masterkey));
            }

        /* if silent is enabled, don't print the master key */
        if (!silent) {
            printf("bip32 extended master key: %s\n", masterkey);
            }

        dogecoin_mem_zero(masterkey, strlen(masterkey));
        }
    else if (strcmp(cmd, "print_keys") == 0) {
        if (!pkey)
            return showError("no extended key (-p)");
        if (!hd_print_node(chain, pkey))
            return showError("invalid extended key\n");
        }
    else if (strcmp(cmd, "derive_child_keys") == 0) {
        if (!pkey)
            return showError("no extended key (-p)");
        if (!derived_path)
            return showError("no derivation path (-m)");
        char newextkey[HDKEYLEN];

        //check if we derive a range of keys
        unsigned int maxlen = 1024;
        int posanum = -1;
        int posbnum = -1;
        int end = -1;
        uint64_t from = 0;
        uint64_t to = 0;

        static char digits[] = "0123456789";
        unsigned int i;
        for (i = 0; i < strlen(derived_path); i++) {
            if (i > maxlen) {
                break;
                }
            if (posanum > -1 && posbnum == -1) {
                if (derived_path[i] == '-') {
                    if (i - posanum >= 9) {
                        break;
                        }
                    posbnum = i + 1;
                    char buf[9] = { 0 };
                    memcpy_safe(buf, &derived_path[posanum], i - posanum);
                    from = strtoull(buf, NULL, 10);
                    }
                else if (!strchr(digits, derived_path[i])) {
                    posanum = -1;
                    break;
                    }
                }
            else if (posanum > -1 && posbnum > -1) {
                if (derived_path[i] == ']' || derived_path[i] == ')') {
                    if (i - posbnum >= 9) {
                        break;
                        }
                    char buf[9] = { 0 };
                    memcpy_safe(buf, &derived_path[posbnum], i - posbnum);
                    to = strtoull(buf, NULL, 10);
                    end = i + 1;
                    break;
                    }
                else if (!strchr(digits, derived_path[i])) {
                    // posbnum = -1; // value stored is never read
                    break;
                    }
                }
            if (derived_path[i] == '[' || derived_path[i] == '(') {
                posanum = i + 1;
                }
            }

        if (end > -1 && from <= to) {
            for (i = from; i <= to; i++) {
                char* keypathnew = dogecoin_char_vla(strlen(derived_path) + 16);
                memcpy_safe(keypathnew, derived_path, posanum - 1);
                char index[11] = { 0 };
                sprintf(index, "%lld", (long long)i);
                memcpy_safe(keypathnew + posanum - 1, index, strlen(index));
                memcpy_safe(keypathnew + posanum - 1 + strlen(index), &derived_path[end], strlen(derived_path) - end);

                if (!hd_derive(chain, pkey, keypathnew, newextkey, sizeof(newextkey)))
                    {
                    free(keypathnew);
                    return showError("Deriving child key failed\n");
                    }
                else
                    {
                    free(keypathnew);
                    hd_print_node(chain, newextkey);
                    }
                }
            }
        else {
            if (!hd_derive(chain, pkey, derived_path, newextkey, sizeof(newextkey)))
                return showError("Deriving child key failed\n");
            else
                hd_print_node(chain, newextkey);
            }
        }
    else if (strcmp(cmd, "sign") == 0) {
        // ./such -c sign -x <raw hex tx> -s <script pubkey> -i <input index> -h <sighash type> -p <private key>
        if (!txhex || !scripthex) {
            return showError("Missing tx-hex or script-hex (use -x, -s)\n");
            }

        if (strlen(txhex) > 1024 * 100) { //don't accept tx larger then 100kb
            return showError("tx too large (max 100kb)\n");
            }

        //deserialize transaction
        dogecoin_tx* tx = dogecoin_tx_new();
        uint8_t* data_bin = dogecoin_malloc(strlen(txhex) / 2 + 1);
        size_t outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!dogecoin_tx_deserialize(data_bin, outlen, tx, NULL)) {
            dogecoin_free(data_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex");
            }

        dogecoin_free(data_bin);

        if ((size_t)inputindex >= tx->vin->len) {
            dogecoin_tx_free(tx);
            return showError("Inputindex out of range");
            }

        uint8_t* script_data = dogecoin_uint8_vla(strlen(scripthex) / 2 + 1);
        utils_hex_to_bin(scripthex, script_data, strlen(scripthex), &outlen);
        cstring* script = cstr_new_buf(script_data, outlen);
        free(script_data);

        uint256_t sighash;
        dogecoin_mem_zero(sighash, sizeof(sighash));
        dogecoin_tx_sighash(tx, script, inputindex, sighashtype, sighash);

        char* hex = utils_uint8_to_hex(sighash, 32);
        utils_reverse_hex(hex, 64);

        enum dogecoin_tx_out_type type = dogecoin_script_classify(script, NULL);
        printf("script: %s\n", scripthex);
        printf("script-type: %s\n", dogecoin_tx_out_type_to_str(type));
        printf("inputindex: %d\n", inputindex);
        printf("sighashtype: %d\n", sighashtype);
        printf("hash: %s\n", hex);

        // sign
        dogecoin_bool sign = false;
        dogecoin_key key;
        dogecoin_privkey_init(&key);
        if (dogecoin_privkey_decode_wif(pkey, chain, &key)) {
            sign = true;
            }
        else {
            if (pkey) {
                if (strlen(pkey) > 50) {
                    dogecoin_tx_free(tx);
                    cstr_free(script, true);
                    return showError("Invalid wif privkey\n");
                    }
                }
            else {
                printf("No private key provided, signing will not happen\n");
                }
            }
        if (sign) {
            uint8_t sigcompact[64] = { 0 };
            size_t sigderlen = 74 + 1; //&hashtype
            uint8_t sigder_plus_hashtype[75] = { 0 };
            enum dogecoin_tx_sign_result res = dogecoin_tx_sign_input(tx, script, &key, inputindex, sighashtype, sigcompact, sigder_plus_hashtype, &sigderlen);
            cstr_free(script, true);

            if (res != DOGECOIN_SIGN_OK) {
                printf("!!!Sign error:%s\n", dogecoin_tx_sign_result_to_str(res));
                }

            char sigcompacthex[64 * 2 + 1] = { 0 };
            utils_bin_to_hex((unsigned char*)sigcompact, 64, sigcompacthex);

            char sigderhex[74 * 2 + 2 + 1]; //74 der, 2 hashtype, 1 nullbyte
            dogecoin_mem_zero(sigderhex, sizeof(sigderhex));
            utils_bin_to_hex((unsigned char*)sigder_plus_hashtype, sigderlen, sigderhex);

            printf("\nSignature created:\n");
            printf("signature compact: %s\n", sigcompacthex);
            printf("signature DER (+hashtype): %s\n", sigderhex);

            cstring* signed_tx = cstr_new_sz(1024);
            dogecoin_tx_serialize(signed_tx, tx);

            char* signed_tx_hex = dogecoin_char_vla(signed_tx->len * 2 + 1);
            utils_bin_to_hex((unsigned char*)signed_tx->str, signed_tx->len, signed_tx_hex);
            printf("signed TX: %s\n", signed_tx_hex);
            cstr_free(signed_tx, true);
            free(signed_tx_hex);
            }
        dogecoin_tx_free(tx);
        }
    else if (strcmp(cmd, "addpqcdatawitness") == 0) {
        if (!txhex || !pubkey || !scripthex) {
            return showError("Missing tx-hex, pqc-pubkey-hex, or pqc-signature-hex (use -x, -k, -s)\n");
        }
        if (strlen(txhex) > 1024 * 100) {
            return showError("tx too large (max 100kb)\n");
        }

        dogecoin_tx* tx = dogecoin_tx_new();
        uint8_t* data_bin = dogecoin_malloc(strlen(txhex) / 2 + 1);
        size_t outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!dogecoin_tx_deserialize(data_bin, outlen, tx, NULL)) {
            dogecoin_free(data_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex");
        }
        dogecoin_free(data_bin);

        if ((size_t)inputindex >= tx->vin->len) {
            dogecoin_tx_free(tx);
            return showError("Inputindex out of range");
        }
        size_t max_chunk_bytes = sighashtype > 0 ? (size_t)sighashtype : 400;
        if (max_chunk_bytes == 0 || max_chunk_bytes > 520) {
            dogecoin_tx_free(tx);
            return showError("max_chunk_bytes must be in range 1..520 (use -h)");
        }

        dogecoin_tx_in* tx_in = vector_idx(tx->vin, inputindex);
        cstring* redeem_script = NULL;
        cstring* script_pubkey = NULL;
        char full_tag[9];
        size_t pub_chunks = 0;
        size_t sig_chunks = 0;
        if (!such_apply_pqc_p2sh_datacarrier(tx_in, pubkey, scripthex, max_chunk_bytes, &redeem_script, &script_pubkey, full_tag, &pub_chunks, &sig_chunks)) {
            if (redeem_script) cstr_free(redeem_script, true);
            if (script_pubkey) cstr_free(script_pubkey, true);
            dogecoin_tx_free(tx);
            return showError("Failed to apply PQC P2SH data carrier");
        }

        char* redeem_hex_tmp = utils_uint8_to_hex((const uint8_t*)redeem_script->str, redeem_script->len);
        char* script_pubkey_hex_tmp = utils_uint8_to_hex((const uint8_t*)script_pubkey->str, script_pubkey->len);
        char* redeem_hex = redeem_hex_tmp ? strdup(redeem_hex_tmp) : NULL;
        char* script_pubkey_hex = script_pubkey_hex_tmp ? strdup(script_pubkey_hex_tmp) : NULL;

        cstring* out_tx = cstr_new_sz(1024);
        dogecoin_tx_serialize(out_tx, tx);
        char* out_tx_hex = dogecoin_char_vla(out_tx->len * 2 + 1);
        utils_bin_to_hex((unsigned char*)out_tx->str, out_tx->len, out_tx_hex);
        printf("tx with pqc p2sh carrier: %s\n", out_tx_hex);
        printf("carrier_tag: %s\n", full_tag);
        printf("pubkey_chunks: %zu\n", pub_chunks);
        printf("signature_chunks: %zu\n", sig_chunks);
        printf("redeemscript: %s\n", redeem_hex ? redeem_hex : "");
        printf("scriptpubkey: %s\n", script_pubkey_hex ? script_pubkey_hex : "");
        if (redeem_hex) dogecoin_free(redeem_hex);
        if (script_pubkey_hex) dogecoin_free(script_pubkey_hex);
        cstr_free(script_pubkey, true);
        cstr_free(redeem_script, true);
        cstr_free(out_tx, true);
        free(out_tx_hex);
        dogecoin_tx_free(tx);
    }
    else if (strcmp(cmd, "addscriptsigpqc") == 0) {
        if (!txhex || !pubkey || !scripthex) {
            return showError("Missing tx-hex, pqc-pubkey-hex, or pqc-signature-hex (use -x, -k, -s)\n");
        }
        if (chain != &dogecoin_chainparams_regtest) {
            return showError("addscriptsigpqc is deprecated for relay flows; use addpqcdatawitness (Doginals-style P2SH carrier)");
        }

        if (strlen(txhex) > 1024 * 100) {
            return showError("tx too large (max 100kb)\n");
        }
        dogecoin_tx* tx = dogecoin_tx_new();
        uint8_t* data_bin = dogecoin_malloc(strlen(txhex) / 2 + 1);
        size_t outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!dogecoin_tx_deserialize(data_bin, outlen, tx, NULL)) {
            dogecoin_free(data_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex");
        }
        dogecoin_free(data_bin);
        if ((size_t)inputindex >= tx->vin->len) {
            dogecoin_tx_free(tx);
            return showError("Inputindex out of range");
        }

        dogecoin_tx_in* tx_in = vector_idx(tx->vin, inputindex);
        if (!such_apply_legacy_scriptsig_pqc(tx_in, pubkey, scripthex)) {
            dogecoin_tx_free(tx);
            return showError("Failed to append non-standard scriptSig PQC payload");
        }

        cstring* out_tx = cstr_new_sz(1024);
        dogecoin_tx_serialize(out_tx, tx);
        char* out_tx_hex = dogecoin_char_vla(out_tx->len * 2 + 1);
        utils_bin_to_hex((unsigned char*)out_tx->str, out_tx->len, out_tx_hex);
        printf("tx with scriptsig pqc (deprecated/regtest helper): %s\n", out_tx_hex);
        cstr_free(out_tx, true);
        free(out_tx_hex);
        dogecoin_tx_free(tx);
    }
    else if (strcmp(cmd, "printscriptsigpqc") == 0) {
        if (!txhex) {
            return showError("Missing tx-hex (use -x)\n");
        }
        if (strlen(txhex) > 1024 * 100) {
            return showError("tx too large (max 100kb)\n");
        }

        dogecoin_tx* tx = dogecoin_tx_new();
        uint8_t* data_bin = dogecoin_malloc(strlen(txhex) / 2 + 1);
        size_t outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!dogecoin_tx_deserialize(data_bin, outlen, tx, NULL)) {
            dogecoin_free(data_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex");
        }
        dogecoin_free(data_bin);
        printf("warning: printscriptsigpqc inspects deprecated direct scriptSig payloads; canonical flow is addpqcdatawitness\n");

        for (size_t vin_index = 0; vin_index < tx->vin->len; vin_index++) {
            dogecoin_tx_in* tx_in = vector_idx(tx->vin, vin_index);
            const uint8_t* pqc_pk = NULL;
            const uint8_t* pqc_sig = NULL;
            size_t pqc_pk_len = 0;
            size_t pqc_sig_len = 0;
            printf("input[%zu]\n", vin_index);
            if (!tx_in || !extract_scriptsig_pqc_items(tx_in->script_sig, &pqc_pk, &pqc_pk_len, &pqc_sig, &pqc_sig_len)) {
                printf("  scriptsig_pqc: none\n");
                continue;
            }
            char* pk_hex_tmp = utils_uint8_to_hex(pqc_pk, pqc_pk_len);
            char* pk_hex = pk_hex_tmp ? strdup(pk_hex_tmp) : NULL;
            char* sig_hex_tmp = utils_uint8_to_hex(pqc_sig, pqc_sig_len);
            char* sig_hex = sig_hex_tmp ? strdup(sig_hex_tmp) : NULL;
            printf("  scriptsig_pqc_pubkey: %s\n", pk_hex ? pk_hex : "");
            printf("  scriptsig_pqc_signature: %s\n", sig_hex ? sig_hex : "");
            if (pk_hex) dogecoin_free(pk_hex);
            if (sig_hex) dogecoin_free(sig_hex);
        }
        dogecoin_tx_free(tx);
    }
    else if (strcmp(cmd, "addwitness") == 0) {
        if (!txhex || !scripthex) {
            return showError("Missing tx-hex or witness-hex (use -x, -s)\n");
        }
        if (strlen(txhex) > 1024 * 100) {
            return showError("tx too large (max 100kb)\n");
        }
        if ((strlen(scripthex) % 2) != 0) {
            return showError("Invalid witness item hex\n");
        }

        dogecoin_tx* tx = dogecoin_tx_new();
        uint8_t* data_bin = dogecoin_malloc(strlen(txhex) / 2 + 1);
        size_t outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!dogecoin_tx_deserialize(data_bin, outlen, tx, NULL)) {
            dogecoin_free(data_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex");
        }
        dogecoin_free(data_bin);

        if ((size_t)inputindex >= tx->vin->len) {
            dogecoin_tx_free(tx);
            return showError("Inputindex out of range");
        }

        dogecoin_tx_in* tx_in = vector_idx(tx->vin, inputindex);
        if (!such_scriptsig_is_push_only_p2sh_p2wsh_redeemscript(tx_in->script_sig)) {
            dogecoin_tx_free(tx);
            return showError("addwitness policy: only P2SH-P2WSH spends are accepted; use apply_p2sh_p2wsh_redeemscript_and_witness\n");
        }
        if (!tx_in->witness_stack) {
            tx_in->witness_stack = vector_new(1, such_witness_item_free_cb);
            if (!tx_in->witness_stack) {
                dogecoin_tx_free(tx);
                return showError("Failed to allocate witness stack");
            }
        }

        uint8_t* witness_data = dogecoin_malloc(strlen(scripthex) / 2 + 1);
        utils_hex_to_bin(scripthex, witness_data, strlen(scripthex), &outlen);
        cstring* witness_item = cstr_new_buf(witness_data, outlen);
        dogecoin_free(witness_data);
        if (!witness_item || !vector_add(tx_in->witness_stack, witness_item)) {
            if (witness_item) {
                cstr_free(witness_item, true);
            }
            dogecoin_tx_free(tx);
            return showError("Failed to append witness item");
        }

        cstring* with_witness_tx = cstr_new_sz(1024);
        dogecoin_tx_serialize(with_witness_tx, tx);
        char* with_witness_tx_hex = dogecoin_char_vla(with_witness_tx->len * 2 + 1);
        utils_bin_to_hex((unsigned char*)with_witness_tx->str, with_witness_tx->len, with_witness_tx_hex);
        printf("tx with witness: %s\n", with_witness_tx_hex);
        print_tx_witness_stack(tx);

        cstr_free(with_witness_tx, true);
        free(with_witness_tx_hex);
        dogecoin_tx_free(tx);
    }
    else if (strcmp(cmd, "printwitness") == 0) {
        if (!txhex) {
            return showError("Missing tx-hex (use -x)\n");
        }
        if (strlen(txhex) > 1024 * 100) {
            return showError("tx too large (max 100kb)\n");
        }

        dogecoin_tx* tx = dogecoin_tx_new();
        uint8_t* data_bin = dogecoin_malloc(strlen(txhex) / 2 + 1);
        size_t outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!dogecoin_tx_deserialize(data_bin, outlen, tx, NULL)) {
            dogecoin_free(data_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex");
        }
        dogecoin_free(data_bin);

        print_tx_witness_stack(tx);
        dogecoin_tx_free(tx);
    }
    else if (strcmp(cmd, "p2sh_p2wsh_datacarrier_scriptpubkey") == 0) {
        if (!scripthex) {
            return showError("Missing witness_script_hex (use -s)\n");
        }
        if ((strlen(scripthex) % 2) != 0) {
            return showError("Invalid witness_script_hex\n");
        }

        size_t witness_script_len = strlen(scripthex) / 2;
        uint8_t* witness_script_bytes = dogecoin_malloc(witness_script_len + 1);
        if (!witness_script_bytes) {
            return showError("Failed to allocate witness script buffer");
        }
        size_t witness_script_outlen = 0;
        utils_hex_to_bin(scripthex, witness_script_bytes, strlen(scripthex), &witness_script_outlen);
        if (witness_script_outlen == 0) {
            dogecoin_free(witness_script_bytes);
            return showError("Failed to decode witness_script_hex");
        }

        uint8_t witness_script_sha[32];
        dogecoin_hash_sngl_sha256(witness_script_bytes, witness_script_outlen, witness_script_sha);
        dogecoin_free(witness_script_bytes);

        cstring* redeem_script = cstr_new_sz(64);
        dogecoin_script_append_op(redeem_script, OP_0);
        dogecoin_script_append_pushdata(redeem_script, witness_script_sha, sizeof(witness_script_sha));

        uint160_t redeem_hash160;
        dogecoin_script_get_scripthash(redeem_script, redeem_hash160);

        cstring* script_pubkey = cstr_new_sz(64);
        dogecoin_script_build_p2sh(script_pubkey, redeem_hash160);

        char* redeem_hex_tmp = utils_uint8_to_hex((const uint8_t*)redeem_script->str, redeem_script->len);
        char* script_pubkey_hex_tmp = utils_uint8_to_hex((const uint8_t*)script_pubkey->str, script_pubkey->len);
        char* redeem_hex = redeem_hex_tmp ? strdup(redeem_hex_tmp) : NULL;
        char* script_pubkey_hex = script_pubkey_hex_tmp ? strdup(script_pubkey_hex_tmp) : NULL;
        printf("redeemscript: %s\n", redeem_hex ? redeem_hex : "");
        printf("scriptpubkey: %s\n", script_pubkey_hex ? script_pubkey_hex : "");
        if (redeem_hex) dogecoin_free(redeem_hex);
        if (script_pubkey_hex) dogecoin_free(script_pubkey_hex);

        cstr_free(script_pubkey, true);
        cstr_free(redeem_script, true);
    }
    else if (strcmp(cmd, "p2sh_p2wsh_datacarrier_witness_script") == 0) {
        size_t chunk_count = (size_t)inputindex;
        cstring* witness_script = cstr_new_sz(chunk_count + 8);
        such_append_witness_drop_script(witness_script, chunk_count);
        char* witness_script_hex = utils_uint8_to_hex((const uint8_t*)witness_script->str, witness_script->len);
        printf("witness_script: %s\n", witness_script_hex ? witness_script_hex : "");
        cstr_free(witness_script, true);
    }
    else if (strcmp(cmd, "pqc_chunk_hex") == 0) {
        if (!txhex) {
            return showError("Missing payload hex (use -x)\n");
        }
        size_t max_chunk_bytes = sighashtype > 0 ? (size_t)sighashtype : 520;
        if (max_chunk_bytes == 0 || max_chunk_bytes > 520) {
            return showError("max_chunk_bytes must be in range 1..520 (use -h)");
        }

        vector_t* chunks = vector_new(8, such_witness_item_free_cb);
        if (!such_hex_payload_chunks(txhex, max_chunk_bytes, chunks)) {
            vector_free(chunks, true);
            return showError("Failed to chunk payload hex");
        }
        printf("chunks: %zu\n", chunks->len);
        for (size_t i = 0; i < chunks->len; i++) {
            cstring* chunk = vector_idx(chunks, i);
            printf("chunk[%zu]: %s\n", i, chunk ? chunk->str : "");
        }
        vector_free(chunks, true);
    }
    else if (strcmp(cmd, "apply_p2sh_p2wsh_redeemscript_and_witness") == 0) {
        if (!txhex || !scripthex || !pubkey || !derived_path) {
            return showError("Missing tx/redeemscript/witness_script/chunks (use -x -s -k -m)\n");
        }
        if ((strlen(scripthex) % 2) != 0 || (strlen(pubkey) % 2) != 0) {
            return showError("Invalid redeemscript_hex or witness_script_hex\n");
        }

        dogecoin_tx* tx = dogecoin_tx_new();
        uint8_t* data_bin = dogecoin_malloc(strlen(txhex) / 2 + 1);
        size_t outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!dogecoin_tx_deserialize(data_bin, outlen, tx, NULL)) {
            dogecoin_free(data_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex");
        }
        dogecoin_free(data_bin);

        if ((size_t)inputindex >= tx->vin->len) {
            dogecoin_tx_free(tx);
            return showError("Inputindex out of range");
        }
        dogecoin_tx_in* tx_in = vector_idx(tx->vin, inputindex);
        if (!tx_in->script_sig) {
            tx_in->script_sig = cstr_new_sz(32);
            if (!tx_in->script_sig) {
                dogecoin_tx_free(tx);
                return showError("Failed to allocate scriptSig buffer");
            }
        }

        size_t redeem_outlen = 0;
        uint8_t* redeem_bytes = dogecoin_malloc(strlen(scripthex) / 2 + 1);
        if (!redeem_bytes) {
            dogecoin_tx_free(tx);
            return showError("Failed to allocate redeem script");
        }
        utils_hex_to_bin(scripthex, redeem_bytes, strlen(scripthex), &redeem_outlen);
        cstr_resize(tx_in->script_sig, 0);
        dogecoin_script_append_pushdata(tx_in->script_sig, redeem_bytes, redeem_outlen);
        dogecoin_free(redeem_bytes);

        such_reset_witness_stack(tx_in);
        if (!tx_in->witness_stack) {
            dogecoin_tx_free(tx);
            return showError("Failed to allocate witness stack");
        }

        char* chunks_csv = strdup(derived_path);
        if (!chunks_csv) {
            dogecoin_tx_free(tx);
            return showError("Failed to allocate chunks csv");
        }
        char* tok = strtok(chunks_csv, ",");
        while (tok) {
            while (*tok == ' ' || *tok == '\t') tok++;
            if (*tok != '\0') {
                if ((strlen(tok) / 2) > 520) {
                    free(chunks_csv);
                    dogecoin_tx_free(tx);
                    return showError("Witness chunk exceeds 520-byte policy limit");
                }
                if (!such_witness_push_hex(tx_in->witness_stack, tok, "chunk")) {
                    free(chunks_csv);
                    dogecoin_tx_free(tx);
                    return showError("Failed to append witness chunk");
                }
            }
            tok = strtok(NULL, ",");
        }
        free(chunks_csv);

        size_t witness_script_len = strlen(pubkey) / 2;
        uint8_t* witness_script_bytes = dogecoin_malloc(witness_script_len + 1);
        if (!witness_script_bytes) {
            dogecoin_tx_free(tx);
            return showError("Failed to allocate witness script decode buffer");
        }
        size_t witness_script_outlen = 0;
        utils_hex_to_bin(pubkey, witness_script_bytes, strlen(pubkey), &witness_script_outlen);
        size_t chunk_items = tx_in->witness_stack->len;
        if (!such_witness_script_is_dropn_true(witness_script_bytes, witness_script_outlen, chunk_items)) {
            dogecoin_free(witness_script_bytes);
            dogecoin_tx_free(tx);
            return showError("witness_script must be OP_DROP xN then OP_1, where N == chunk count");
        }
        dogecoin_free(witness_script_bytes);

        if (!such_witness_push_hex(tx_in->witness_stack, pubkey, "witness_script")) {
            dogecoin_tx_free(tx);
            return showError("Failed to append witness script");
        }

        cstring* with_witness_tx = cstr_new_sz(1024);
        dogecoin_tx_serialize(with_witness_tx, tx);
        char* with_witness_tx_hex = dogecoin_char_vla(with_witness_tx->len * 2 + 1);
        utils_bin_to_hex((unsigned char*)with_witness_tx->str, with_witness_tx->len, with_witness_tx_hex);
        printf("tx with witness: %s\n", with_witness_tx_hex);
        print_tx_witness_stack(tx);

        cstr_free(with_witness_tx, true);
        free(with_witness_tx_hex);
        dogecoin_tx_free(tx);
    }
#ifdef USE_LIBOQS
    else if (strcmp(cmd, "tx_sighash32") == 0) {
        // ./such -c tx_sighash32 -x <raw hex tx> -s <script pubkey> -i <input index> -h <sighash type>
        if (!txhex || !scripthex) {
            return showError("Missing tx-hex or script-hex (use -x, -s)\n");
        }

        if (strlen(txhex) > 1024 * 100) { // don't accept tx larger than 100kb
            return showError("tx too large (max 100kb)\n");
        }

        dogecoin_tx* tx = dogecoin_tx_new();
        uint8_t* data_bin = dogecoin_malloc(strlen(txhex) / 2 + 1);
        size_t outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!dogecoin_tx_deserialize(data_bin, outlen, tx, NULL)) {
            dogecoin_free(data_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex");
        }
        dogecoin_free(data_bin);

        if ((size_t)inputindex >= tx->vin->len) {
            dogecoin_tx_free(tx);
            return showError("Inputindex out of range");
        }

        uint8_t* script_data = dogecoin_uint8_vla(strlen(scripthex) / 2 + 1);
        utils_hex_to_bin(scripthex, script_data, strlen(scripthex), &outlen);
        cstring* script = cstr_new_buf(script_data, outlen);
        free(script_data);

        uint8_t sighash32[32];
        dogecoin_mem_zero(sighash32, sizeof(sighash32));
        if (!dogecoin_tx_sighash32(tx, script, inputindex, sighashtype, sighash32)) {
            cstr_free(script, true);
            dogecoin_tx_free(tx);
            return showError("Failed to compute tx sighash");
        }

        char* sighash_hex = utils_uint8_to_hex(sighash32, sizeof(sighash32));
        printf("tx_sighash32: %s\n", sighash_hex);
        cstr_free(script, true);
        dogecoin_tx_free(tx);
    }
#endif
    else if (strcmp(cmd, "comp2der") == 0) {
        // ./such -c comp2der -s <compact signature>
        if (!scripthex || strlen(scripthex) != 128) {
            return showError("Missing signature or invalid length (use hex, 128 chars == 64 bytes)\n");
            }

        size_t outlen = 0;
        uint8_t sig_comp[65];
        printf("%s\n", scripthex);
        utils_hex_to_bin(scripthex, sig_comp, 128, &outlen);

        unsigned char sigder[74];
        size_t sigderlen = sizeof(sigder);

        dogecoin_ecc_compact_to_der_normalized(sig_comp, sigder, &sigderlen);
        char* hexbuf = dogecoin_char_vla(sigderlen * 2 + 1);
        utils_bin_to_hex(sigder, sigderlen, hexbuf);
        printf("DER: %s\n", hexbuf);
        free(hexbuf);
        }
    else if (strcmp(cmd, "bip32maintotest") == 0) { /* Creating a bip32 master key from a private key. */
        dogecoin_hdnode node;
        if (!dogecoin_hdnode_deserialize(pkey, chain, &node)) {
            return showError("dogecoin_hd_deserialize failed!\n");
            }
        char masterkeyhex[HDKEYLEN];
        int strsize = HDKEYLEN;
        dogecoin_hdnode_serialize_private(&node, &dogecoin_chainparams_test, masterkeyhex, strsize);
        printf("xpriv: %s\n", masterkeyhex);
        dogecoin_hdnode_serialize_public(&node, &dogecoin_chainparams_test, masterkeyhex, strsize);
        printf("xpub: %s\n", masterkeyhex);
        }
    else if (strcmp(cmd, "generate_mnemonic") == 0) { /* Creating a bip32 master key from a mnemonic. */

        /* if tpm is enabled, generate mnemonic with tpm */
        if (encrypted) {

            /* if overwrite is enabled, ask for confirmation */
            if (overwrite) {
                printf("Overwrite? Y/N\n");

                char buffer[MAX_LEN];
                /* get user input */
                if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
                    if (buffer[0] != 'Y' && buffer[0] != 'y') {

                        /* if not confirmed, abort */
                        printf("aborted\n");
                        dogecoin_ecc_stop();
                        return 1;
                        }
                    }
                }

            if (tpm) {
                /* Try to generate mnemonic with TPM first */
                if (!generateRandomEnglishMnemonicTPM(mnemonic, file_num, overwrite)) {
                    printf("generate_mnemonic -y <file_num>, -j (use_tpm), -w (overwrite), -b (silent),\n");
                    return showError("Failed to generate/encrypt mnemonic in TPM\n");
                    }
                }

            else {
                /* generate mnemonic with software */
                if (generateRandomEnglishMnemonicSW(mnemonic, file_num, overwrite, NULL, NULL) == false) {
                    printf("generate_mnemonic -y <file_num>, -j (use_tpm), -w (overwrite), -b (silent),\n");
                    return showError("Failed to generate/encrypt mnemonic in software");
                    }
                }
            }

        /* else generate mnemonic with ecc */
        else if (generateEnglishMnemonic(entropy, entropy_size, mnemonic) == -1) {
            printf("generate_mnemonic (-e <hex_entropy>, optional),\n");
            return showError("Failed to generate mnemonic\n");
            }

        /* if not silent, display mnemonic */
        if (!silent) {
            printf("%s\n", mnemonic);
            }
        }
    else if (strcmp(cmd, "list_encryption_keys_in_tpm") == 0) {

        /* list encryption keys in TPM */
        wchar_t *names[MAX_FILES] = {0};
        size_t count = 0;

        if (dogecoin_list_encryption_keys_in_tpm(names, &count) == false) {
            return showError("failed to list encryption keys in TPM\n");
            }

#if defined (_WIN64) && !defined(__MINGW64__)
        /* display encryption key names */
        for (size_t i = 0; i < count; i++) {
            wprintf(L"%ls\n", names[i]);
            }
#endif
        /* free memory */
        for (size_t i = 0; i < count; i++) {
            dogecoin_free(names[i]);
            }
        }
    else if (strcmp(cmd, "decrypt_master_key") == 0) {

        /* if tpm is enabled, decrypt master key from tpm */
        if (encrypted) {
            printf("Decrypt master key? Y/N\n");

            char buffer[MAX_LEN];
            /* get user input */
            if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
                if (buffer[0] != 'Y' && buffer[0] != 'y') {

                    /* if not confirmed, abort */
                    printf("aborted\n");
                    dogecoin_ecc_stop();
                    return 1;
                    }
                }

            dogecoin_hdnode node;

            if (tpm) {
                /* decrypt master key from tpm */
                if (!dogecoin_decrypt_hdnode_with_tpm (&node, file_num)) {
                    printf("decrypt_master_key (requires -y <file_num>, -j (use_tpm) optional),\n");
                    return showError("Failed to decrypt master key in TPM\n");
                    }
                }

            else {
                /* decrypt master key from software */
                if (dogecoin_decrypt_hdnode_with_sw (&node, file_num, NULL, NULL) == false) {
                    printf("decrypt_master_key (requires -y <file_num>, -j (use_tpm) optional),\n");
                    return showError("failed to decrypt master key with software\n");
                    }
                }

            /* serialize the master key */
            char masterkey[HDKEYLEN];
            dogecoin_hdnode_serialize_private (&node, chain, masterkey, sizeof(masterkey));

            /* display the master key */
            printf("bip32 extended master key: %s\n", masterkey);
            dogecoin_mem_zero(masterkey, strlen(masterkey));
            }

        /* else display usage */
        else {
            return showError("decrypt_master_key (requires -y <file_num>, -j (use_tpm) optional\n");
            }
        }
    else if (strcmp(cmd, "decrypt_mnemonic") == 0) {

        /* if tpm is enabled, decrypt mnemonic from tpm */
        if (encrypted) {
            printf("Decrypt mnemonic? Y/N\n");

            char buffer[MAX_LEN];
            /* get user input */
            if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
                if (buffer[0] != 'Y' && buffer[0] != 'y') {

                    /* if not confirmed, abort */
                    printf("aborted\n");
                    dogecoin_ecc_stop();
                    return 1;
                    }
                }

            if (tpm) {
                /* decrypt mnemonic from tpm */
                if (!dogecoin_decrypt_mnemonic_with_tpm (mnemonic, file_num)) {
                    printf("decrypt_mnemonic (requires -y <file_num>, -j (use_tpm) optional),\n");
                    return showError("failed to decrypt mnemonic with tpm\n");
                    }
                }

            else {
                /* decrypt mnemonic from software */
                if (dogecoin_decrypt_mnemonic_with_sw (mnemonic, file_num, NULL, NULL) == false) {
                    printf("decrypt_mnemonic (requires -y <file_num>, -j (use_tpm) optional),\n");
                    return showError("failed to decrypt mnemonic with software\n");
                    }
                }

            /* display mnemonic */
            printf("%s\n", mnemonic);
            }

        /* else display usage */
        else {
            return showError("decrypt_mnemonic (requires -y <file_num>, -j (use_tpm) optional\n");
            }
        }
    else if (strcmp(cmd, "seed_to_master_key") == 0) { /* Creating a bip32 master key from a seed. */

        /* if tpm is enabled, get seed from tpm */
        if (encrypted) {
            printf("Decrypt seed for master key? Y/N\n");

            char buffer[MAX_LEN];
            /* get user input */
            if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
                if (buffer[0] != 'Y' && buffer[0] != 'y') {

                    /* if not confirmed, abort */
                    printf("aborted\n");
                    dogecoin_ecc_stop();
                    return 1;
                    }
                }

            if (tpm) {
                /* get seed from tpm */
                if (!dogecoin_decrypt_seed_with_tpm (seed, file_num)) {
                    printf("seed_to_master_key (requires -y <file_num>, -j (use_tpm) optional),\n");
                    return showError("failed to decrypt seed with tpm\n");
                    }
                }

            else {
                /* get seed from software */
                if (dogecoin_decrypt_seed_with_sw (seed, file_num, NULL, NULL) == false) {
                    printf("seed_to_master_key (requires -y <file_num>, -j (use_tpm) optional),\n");
                    return showError("failed to decrypt seed with software\n");
                    }
                }
            }

            /* print master key from seed */
            dogecoin_hdnode node;
            char masterkey[HDKEYLEN];
            dogecoin_hdnode_from_seed(seed, sizeof(seed), &node);
            dogecoin_hdnode_serialize_private(&node, chain, masterkey, sizeof(masterkey));
            printf("bip32 extended master key: %s\n", masterkey);
            dogecoin_mem_zero(masterkey, strlen(masterkey));
            dogecoin_mem_zero(seed, sizeof(seed));
        }
    else if (strcmp(cmd, "mnemonic_to_key") == 0) { /* Creating a bip32 master key from a mnemonic. */

        /* if tpm is enabled, get mnemonic from tpm */
        if (encrypted) {
            printf("Decrypt mnemonic for master key? Y/N\n");

            /* get user input */
            char c = getchar();
            if (c != 'Y' && c != 'y') {

                /* if not confirmed, abort */
                printf("aborted\n");
                dogecoin_ecc_stop();
                return 1;
                }

            if (tpm) {
                /* get mnemonic from tpm */
                if (!dogecoin_decrypt_mnemonic_with_tpm (mnemonic, file_num)) {
                    printf("mnemonic_to_key (requires -y <file_num>, -j (use_tpm) optional),\n");
                    return showError("failed to decrypt mnemonic with tpm\n");
                    }
                }

            else {
                /* get mnemonic from software */
                if (dogecoin_decrypt_mnemonic_with_sw (mnemonic, file_num, NULL, NULL) == false) {
                    printf("mnemonic_to_key (requires -y <file_num>, -j (use_tpm) optional),\n");
                    return showError("failed to decrypt mnemonic with software\n");
                    }
                }
            }
        /* else display usage */
        else if (!mnemonic_in) {
            return showError("mnemonic_to_key (-n <seed_phrase> or requires -y <file_num>, -j (use_tpm) optional\n");
            }

        /* generate private key from mnemonic */
        dogecoin_hdnode node;
        dogecoin_hdnode extended_key;
        SEED seed;
        KEY_PATH keypath;
        char wifstr[PRIVKEYWIFLEN];
        size_t wiflen = sizeof(wifstr);

        /* generate seed from mnemonic */
        if (dogecoin_seed_from_mnemonic(encrypted ? mnemonic : mnemonic_in, pass, seed) == -1) {
            printf("mnemonic_to_key (-n <seed_phrase> or requires -y <file_num>, -j (use_tpm) optional),\n");

            /* clear and free passphrase */
            if (pass) {
                dogecoin_mem_zero(pass, strlen(pass));
                dogecoin_free(pass);
                }
            return showError("failed to generate seed from mnemonic\n");
            }

        /* clear and free passphrase */
        if (pass) {
            dogecoin_mem_zero(pass, strlen(pass));
            dogecoin_free(pass);
            }

        /* generate master key from seed */
        dogecoin_hdnode_from_seed(seed, sizeof(seed), &node);

        /* derive bip44 extended key from master key */
        derive_bip44_extended_key(&node, &account, &inputindex, change_level, NULL, (chain == &dogecoin_chainparams_test), keypath, &extended_key);
        printf("keypath: %s\n", keypath);

        /* encode private key to wif */
        dogecoin_privkey_encode_wif((dogecoin_key*) extended_key.private_key, chain, wifstr, &wiflen);
        printf("private key (wif): %s\n", wifstr);

        }
    else if (strcmp(cmd, "mnemonic_to_addresses") == 0) { /* Creating wif addresses from a mnemonic via slip44. */

        char hd_pubkey_address[P2PKHLEN];

        /* if tpm is enabled, get mnemonic from tpm */
        if (encrypted) {
            printf("Decrypt mnemonic for addresses? Y/N\n");

            char buffer[MAX_LEN];
            /* get user input */
            if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
                if (buffer[0] != 'Y' && buffer[0] != 'y') {

                    /* if not confirmed, abort */
                    printf("aborted\n");
                    dogecoin_ecc_stop();
                    return 1;
                    }
                }

            if (tpm) {
                /* get mnemonic from tpm */
                if (!dogecoin_decrypt_mnemonic_with_tpm (mnemonic, file_num)) {
                    printf("mnemonic_to_addresses (requires -y <file_num>, -j (use_tpm), -o <account_int>, -g <change_level>, -i <address_index> and -a, all optional),\n");
                    return showError("failed to decrypt mnemonic with tpm\n");
                    }
                }

            else {
                /* get mnemonic from software */
                if (dogecoin_decrypt_mnemonic_with_sw (mnemonic, file_num, NULL, NULL) == false) {
                    printf("mnemonic_to_addresses (requires -y <file_num>, -j (use_tpm), -o <account_int>, -g <change_level>, -i <address_index> and -a, all optional),\n");
                    return showError("failed to decrypt mnemonic with software\n");
                    }
                }
            }

        /* else display usage */
        else if (!mnemonic_in) {
            return showError("mnemonic_to_addresses (requires -n <seed_phrase> or -y <file_num>, -j (use_tpm), -o <account_int>, -g <change_level>, -i <address_index> and -a (all optional))\n");
            }

        /* generate wif address for slip44 account, index, and change_level, from bip39 mnemonic and password (optional) */
        if (inputindex == 0) {

            /* Generate all addresses for the account. */
            for (int i = 0; i < 20; i++) {
                if (getDerivedHDAddressFromMnemonic(account, i, change_level, encrypted ? mnemonic : mnemonic_in, pass, hd_pubkey_address, (chain == &dogecoin_chainparams_test)) == -1) {

                    /* clear and free passphrase */
                    if (pass) {
                        dogecoin_mem_zero(pass, strlen(pass));
                        dogecoin_free(pass);
                        }
                    return showError("Failed to generate wif address from mnemonic\n");
                    }
                printf("Address %d: %s\n", i, hd_pubkey_address);
                }
            }
        else {

            /* Generate a single address for the account. */
            if (getDerivedHDAddressFromMnemonic(account, inputindex, change_level, encrypted ? mnemonic : mnemonic_in, pass, hd_pubkey_address, (chain == &dogecoin_chainparams_test)) == -1) {
                printf("mnemonic_to_addresses (requires -n <seed_phrase> or -y <file_num>, -j (use_tpm), -o <account_int>, -g <change_level>, -i <address_index> and -a, all optional),\n");

                /* clear and free passphrase */
                if (pass) {
                    dogecoin_mem_zero(pass, strlen(pass));
                    dogecoin_free(pass);
                    }
                return showError("Failed to generate wif address from mnemonic\n");
                }

            printf("Address %d: %s\n", inputindex, hd_pubkey_address);
            }

        /* clear and free passphrase */
        if (pass) {
            dogecoin_mem_zero(pass, strlen(pass));
            dogecoin_free(pass);
            }
        }
    else if (strcmp(cmd, "signmessage") == 0) {
        // ./such -c signmessage -x "<message>" -p <private key>
        if (!txhex) {
            return showError("Missing message (use -x)\n");
            }

        if (strlen(txhex) > 1024 * 100) { //don't accept tx larger then 100kb
            return showError("tx too large (max 100kb)\n");
            }

        eckey* key = new_eckey_from_privkey(pkey);
        char* sig = sign_message(key->private_key_wif, txhex);
        printf("message: %s\n", txhex);
        printf("content: %s\n", sig);
        printf("address: %s\n", key->address);
        dogecoin_free(key);
        dogecoin_free(sig);
        }
    else if (strcmp(cmd, "verifymessage") == 0) {
        // ./such -c verifymessage -x "<message>" -s <signature> -k <address>
        if (!txhex || !scripthex || !pubkey) {
            return showError("Missing message or signature or address (use -x, -s, -k)\n");
            }

        if (strlen(txhex) > 1024 * 100) { //don't accept tx larger then 100kb
            return showError("tx too large (max 100kb)\n");
            }

        if (verify_message(scripthex, txhex, pubkey)) {
            printf("Message is verified!\n");
        } else {
            printf("Message is not valid!\n");
        }
        }
    else if (strcmp(cmd, "transaction") == 0) {
        main_menu();
        }
#ifdef USE_LIBOQS
    else if (strcmp(cmd, "falcon_keygen") == 0) {
        // ./such -c falcon_keygen
        uint8_t *pk = NULL, *sk = NULL;
        size_t pk_len = 0, sk_len = 0;
        
        printf("Generating Falcon-512 keypair...\n");
        
        if (!dogecoin_falcon512_keypair(&pk, &pk_len, &sk, &sk_len)) {
            return showError("Failed to generate Falcon-512 keypair\n");
        }
        
        char* pk_hex = dogecoin_malloc(pk_len * 2 + 1);
        char* sk_hex = dogecoin_malloc(sk_len * 2 + 1);
        if (!pk_hex || !sk_hex) {
            if (pk_hex) dogecoin_free(pk_hex);
            if (sk_hex) dogecoin_free(sk_hex);
            dogecoin_free(pk);
            dogecoin_free(sk);
            return showError("Failed to allocate Falcon key hex buffers\n");
        }
        utils_bin_to_hex(pk, pk_len, pk_hex);
        utils_bin_to_hex(sk, sk_len, sk_hex);
        
        printf("\n=== Falcon-512 Keypair Generated ===\n");
        printf("public key:  %s\n", pk_hex);
        printf("secret key:  %s\n", sk_hex);
        printf("pk length:   %zu bytes\n", pk_len);
        printf("sk length:   %zu bytes\n", sk_len);
        printf("\n⚠️  Keep your secret key safe! Anyone with it can sign messages.\n");
        
        dogecoin_free(pk_hex);
        dogecoin_free(sk_hex);
        dogecoin_free(pk);
        dogecoin_free(sk);
        }
    else if (strcmp(cmd, "falcon_sign") == 0) {
        // ./such -c falcon_sign -p <secret_key_hex> -x <message_hex>
        if (!pkey) {
            return showError("Missing secret key (use -p)\n");
        }
        if (!txhex) {
            return showError("Missing message (use -x)\n");
        }
        
        printf("Signing message with Falcon-512...\n");
        
        if ((strlen(pkey) % 2) != 0) {
            return showError("Invalid secret key hex\n");
        }
        size_t sk_len = strlen(pkey) / 2;
        uint8_t* sk = dogecoin_malloc(sk_len);
        size_t sk_outlen = 0;
        utils_hex_to_bin(pkey, sk, strlen(pkey), &sk_outlen);
        if (sk_outlen != sk_len) {
            dogecoin_free(sk);
            return showError("Invalid secret key hex\n");
        }
        
        if ((strlen(txhex) % 2) != 0) {
            dogecoin_free(sk);
            return showError("Invalid message hex\n");
        }
        size_t msg_len = strlen(txhex) / 2;
        uint8_t* msg = dogecoin_malloc(msg_len);
        size_t msg_outlen = 0;
        utils_hex_to_bin(txhex, msg, strlen(txhex), &msg_outlen);
        if (msg_outlen != msg_len) {
            dogecoin_free(sk);
            dogecoin_free(msg);
            return showError("Invalid message hex\n");
        }
        
        // Sign (allocates new buffer that must be freed)
        uint8_t* sig = NULL;
        size_t sig_len = 0;
        
        if (!dogecoin_falcon512_sign(sk, sk_len, msg, msg_len, &sig, &sig_len)) {
            dogecoin_free(sk);
            dogecoin_free(msg);
            return showError("Failed to sign message with Falcon-512\n");
        }
        
        // utils_uint8_to_hex returns static buffer, don't free
        char* sig_hex = utils_uint8_to_hex(sig, sig_len);
        
        printf("\n=== Falcon-512 Signature Generated ===\n");
        printf("signature:   %s\n", sig_hex);
        printf("sig length:  %zu bytes\n", sig_len);
        printf("msg length:  %zu bytes\n", msg_len);
        
        dogecoin_free(sk);
        dogecoin_free(msg);
        dogecoin_free(sig);
        }
    else if (strcmp(cmd, "falcon_verify") == 0) {
        // ./such -c falcon_verify -k <public_key_hex> -x <message_hex> -s <signature_hex>
        if (!pubkey) {
            return showError("Missing public key (use -k)\n");
        }
        if (!txhex) {
            return showError("Missing message (use -x)\n");
        }
        if (!scripthex) {
            return showError("Missing signature (use -s)\n");
        }
        
        printf("Verifying Falcon-512 signature...\n");
        
        if ((strlen(pubkey) % 2) != 0) {
            return showError("Invalid public key hex\n");
        }
        size_t pk_len = strlen(pubkey) / 2;
        uint8_t* pk = dogecoin_malloc(pk_len);
        size_t pk_outlen = 0;
        utils_hex_to_bin(pubkey, pk, strlen(pubkey), &pk_outlen);
        if (pk_outlen != pk_len) {
            dogecoin_free(pk);
            return showError("Invalid public key hex\n");
        }
        
        if ((strlen(txhex) % 2) != 0) {
            dogecoin_free(pk);
            return showError("Invalid message hex\n");
        }
        size_t msg_len = strlen(txhex) / 2;
        uint8_t* msg = dogecoin_malloc(msg_len);
        size_t msg_outlen = 0;
        utils_hex_to_bin(txhex, msg, strlen(txhex), &msg_outlen);
        if (msg_outlen != msg_len) {
            dogecoin_free(pk);
            dogecoin_free(msg);
            return showError("Invalid message hex\n");
        }
        
        if ((strlen(scripthex) % 2) != 0) {
            dogecoin_free(pk);
            dogecoin_free(msg);
            return showError("Invalid signature hex\n");
        }
        size_t sig_len = strlen(scripthex) / 2;
        uint8_t* sig = dogecoin_malloc(sig_len);
        size_t sig_outlen = 0;
        utils_hex_to_bin(scripthex, sig, strlen(scripthex), &sig_outlen);
        if (sig_outlen != sig_len) {
            dogecoin_free(pk);
            dogecoin_free(msg);
            dogecoin_free(sig);
            return showError("Invalid signature hex\n");
        }
        
        // Verify
        dogecoin_bool verified = dogecoin_falcon512_verify(pk, pk_len, msg, msg_len, sig, sig_len);
        
        printf("\n=== Falcon-512 Verification Result ===\n");
        if (verified) {
            printf("✓ VERIFIED: Signature is valid!\n");
            printf("The signature is authentic for this message and public key.\n");
        } else {
            printf("✗ FAILED: Signature is invalid!\n");
            printf("The signature does NOT match the message/public key.\n");
        }
        
        if (!verified) {
            dogecoin_free(pk);
            dogecoin_free(msg);
            dogecoin_free(sig);
            dogecoin_ecc_stop();
            return 1;
        }
        dogecoin_free(pk);
        dogecoin_free(msg);
        dogecoin_free(sig);
        }
    else if (strcmp(cmd, "falcon_commit") == 0) {
        // ./such -c falcon_commit -k <public_key_hex> -s <signature_hex>
        if (!pubkey) {
            return showError("Missing public key (use -k)\n");
        }
        if (!scripthex) {
            return showError("Missing signature (use -s)\n");
        }
        
        printf("Generating Falcon-512 commitment...\n");
        
        if ((strlen(pubkey) % 2) != 0) {
            return showError("Invalid public key hex\n");
        }
        size_t pk_len = strlen(pubkey) / 2;
        uint8_t* pk = dogecoin_malloc(pk_len);
        size_t pk_outlen = 0;
        utils_hex_to_bin(pubkey, pk, strlen(pubkey), &pk_outlen);
        if (pk_outlen != pk_len) {
            dogecoin_free(pk);
            return showError("Invalid public key hex\n");
        }
        
        if ((strlen(scripthex) % 2) != 0) {
            dogecoin_free(pk);
            return showError("Invalid signature hex\n");
        }
        size_t sig_len = strlen(scripthex) / 2;
        uint8_t* sig = dogecoin_malloc(sig_len);
        size_t sig_outlen = 0;
        utils_hex_to_bin(scripthex, sig, strlen(scripthex), &sig_outlen);
        if (sig_outlen != sig_len) {
            dogecoin_free(pk);
            dogecoin_free(sig);
            return showError("Invalid signature hex\n");
        }
        
        // Generate commitment
        uint8_t commit[32];
        if (!dogecoin_falcon512_commit_bytes(pk, pk_len, sig, sig_len, commit)) {
            dogecoin_free(pk);
            dogecoin_free(sig);
            return showError("Failed to generate Falcon-512 commitment\n");
        }
        
        char commit_hex[65];
        utils_bin_to_hex(commit, 32, commit_hex);
        
        printf("\n=== Falcon-512 Commitment Generated ===\n");
        printf("commitment:  %s\n", commit_hex);
        printf("length:      32 bytes\n");
        printf("\nThis commitment can be included in an OP_RETURN output:\n");
        printf("OP_RETURN script: 6a24464c4331%s\n", commit_hex);
        printf("\nTo verify off-chain:\n");
        printf("1. Get the full signature from the signer\n");
        printf("2. Recompute: commit = SHA256(public_key || signature)\n");
        printf("3. Compare with this on-chain commitment\n");
        dogecoin_free(pk);
        dogecoin_free(sig);
        }
    else if (strcmp(cmd, "dilithium2_keygen") == 0) {
        uint8_t *pk = NULL, *sk = NULL;
        size_t pk_len = 0, sk_len = 0;
        printf("Generating Dilithium2 keypair...\n");
        if (!dogecoin_dilithium2_keypair(&pk, &pk_len, &sk, &sk_len)) {
            return showError("Failed to generate Dilithium2 keypair\n");
        }
        char* pk_hex = dogecoin_malloc(pk_len * 2 + 1);
        char* sk_hex = dogecoin_malloc(sk_len * 2 + 1);
        if (!pk_hex || !sk_hex) {
            if (pk_hex) dogecoin_free(pk_hex);
            if (sk_hex) dogecoin_free(sk_hex);
            dogecoin_free(pk);
            dogecoin_free(sk);
            return showError("Failed to allocate Dilithium2 key hex buffers\n");
        }
        utils_bin_to_hex(pk, pk_len, pk_hex);
        utils_bin_to_hex(sk, sk_len, sk_hex);
        printf("\n=== Dilithium2 Keypair Generated ===\n");
        printf("public key:  %s\n", pk_hex);
        printf("secret key:  %s\n", sk_hex);
        printf("pk length:   %zu bytes\n", pk_len);
        printf("sk length:   %zu bytes\n", sk_len);
        dogecoin_free(pk_hex);
        dogecoin_free(sk_hex);
        dogecoin_free(pk);
        dogecoin_free(sk);
    }
    else if (strcmp(cmd, "dilithium2_sign") == 0) {
        if (!pkey) return showError("Missing secret key (use -p)\n");
        if (!txhex) return showError("Missing message (use -x)\n");
        if ((strlen(pkey) % 2) != 0) return showError("Invalid secret key hex\n");
        size_t sk_len = strlen(pkey) / 2;
        uint8_t* sk = dogecoin_malloc(sk_len);
        size_t sk_outlen = 0;
        utils_hex_to_bin(pkey, sk, strlen(pkey), &sk_outlen);
        if (sk_outlen != sk_len) { dogecoin_free(sk); return showError("Invalid secret key hex\n"); }
        if ((strlen(txhex) % 2) != 0) { dogecoin_free(sk); return showError("Invalid message hex\n"); }
        size_t msg_len = strlen(txhex) / 2;
        uint8_t* msg = dogecoin_malloc(msg_len);
        size_t msg_outlen = 0;
        utils_hex_to_bin(txhex, msg, strlen(txhex), &msg_outlen);
        if (msg_outlen != msg_len) { dogecoin_free(sk); dogecoin_free(msg); return showError("Invalid message hex\n"); }
        uint8_t* sig = NULL; size_t sig_len = 0;
        if (!dogecoin_dilithium2_sign(sk, sk_len, msg, msg_len, &sig, &sig_len)) {
            dogecoin_free(sk); dogecoin_free(msg);
            return showError("Failed to sign message with Dilithium2\n");
        }
        char* sig_hex = utils_uint8_to_hex(sig, sig_len);
        printf("\n=== Dilithium2 Signature Generated ===\n");
        printf("signature:   %s\n", sig_hex);
        printf("sig length:  %zu bytes\n", sig_len);
        printf("msg length:  %zu bytes\n", msg_len);
        dogecoin_free(sk); dogecoin_free(msg); dogecoin_free(sig);
    }
    else if (strcmp(cmd, "dilithium2_verify") == 0) {
        if (!pubkey) return showError("Missing public key (use -k)\n");
        if (!txhex) return showError("Missing message (use -x)\n");
        if (!scripthex) return showError("Missing signature (use -s)\n");
        if ((strlen(pubkey) % 2) != 0) return showError("Invalid public key hex\n");
        size_t pk_len = strlen(pubkey) / 2;
        uint8_t* pk = dogecoin_malloc(pk_len);
        size_t pk_outlen = 0;
        utils_hex_to_bin(pubkey, pk, strlen(pubkey), &pk_outlen);
        if (pk_outlen != pk_len) { dogecoin_free(pk); return showError("Invalid public key hex\n"); }
        if ((strlen(txhex) % 2) != 0) { dogecoin_free(pk); return showError("Invalid message hex\n"); }
        size_t msg_len = strlen(txhex) / 2;
        uint8_t* msg = dogecoin_malloc(msg_len);
        size_t msg_outlen = 0;
        utils_hex_to_bin(txhex, msg, strlen(txhex), &msg_outlen);
        if (msg_outlen != msg_len) { dogecoin_free(pk); dogecoin_free(msg); return showError("Invalid message hex\n"); }
        if ((strlen(scripthex) % 2) != 0) { dogecoin_free(pk); dogecoin_free(msg); return showError("Invalid signature hex\n"); }
        size_t sig_len = strlen(scripthex) / 2;
        uint8_t* sig = dogecoin_malloc(sig_len);
        size_t sig_outlen = 0;
        utils_hex_to_bin(scripthex, sig, strlen(scripthex), &sig_outlen);
        if (sig_outlen != sig_len) { dogecoin_free(pk); dogecoin_free(msg); dogecoin_free(sig); return showError("Invalid signature hex\n"); }
        dogecoin_bool verified = dogecoin_dilithium2_verify(pk, pk_len, msg, msg_len, sig, sig_len);
        printf("\n=== Dilithium2 Verification Result ===\n");
        printf("%s\n", verified ? "✓ VERIFIED: Signature is valid!" : "✗ FAILED: Signature is invalid!");
        dogecoin_free(pk); dogecoin_free(msg); dogecoin_free(sig);
        if (!verified) { dogecoin_ecc_stop(); return 1; }
    }
    else if (strcmp(cmd, "dilithium2_commit") == 0) {
        if (!pubkey) return showError("Missing public key (use -k)\n");
        if (!scripthex) return showError("Missing signature (use -s)\n");
        if ((strlen(pubkey) % 2) != 0) return showError("Invalid public key hex\n");
        size_t pk_len = strlen(pubkey) / 2;
        uint8_t* pk = dogecoin_malloc(pk_len);
        size_t pk_outlen = 0;
        utils_hex_to_bin(pubkey, pk, strlen(pubkey), &pk_outlen);
        if (pk_outlen != pk_len) { dogecoin_free(pk); return showError("Invalid public key hex\n"); }
        if ((strlen(scripthex) % 2) != 0) { dogecoin_free(pk); return showError("Invalid signature hex\n"); }
        size_t sig_len = strlen(scripthex) / 2;
        uint8_t* sig = dogecoin_malloc(sig_len);
        size_t sig_outlen = 0;
        utils_hex_to_bin(scripthex, sig, strlen(scripthex), &sig_outlen);
        if (sig_outlen != sig_len) { dogecoin_free(pk); dogecoin_free(sig); return showError("Invalid signature hex\n"); }
        uint8_t commit[32];
        if (!dogecoin_dilithium2_commit_bytes(pk, pk_len, sig, sig_len, commit)) {
            dogecoin_free(pk); dogecoin_free(sig); return showError("Failed to generate Dilithium2 commitment\n");
        }
        char commit_hex[65];
        utils_bin_to_hex(commit, 32, commit_hex);
        printf("\n=== Dilithium2 Commitment Generated ===\n");
        printf("commitment:  %s\n", commit_hex);
        printf("length:      32 bytes\n");
        printf("\nThis commitment can be included in an OP_RETURN output:\n");
        printf("OP_RETURN script (prefix 6a24 + tag 44494c32='DIL2'): 6a2444494c32%s\n", commit_hex);
        dogecoin_free(pk); dogecoin_free(sig);
    }
    else if (strcmp(cmd, "raccoong_keygen") == 0) {
        uint8_t *pk = NULL, *sk = NULL;
        size_t pk_len = 0, sk_len = 0;
        printf("Generating Raccoon-G-44 keypair...\n");
        if (!dogecoin_raccoong44_keypair(&pk, &pk_len, &sk, &sk_len)) {
            return showError("Failed to generate Raccoon-G-44 keypair\n");
        }
        char* pk_hex = dogecoin_malloc(pk_len * 2 + 1);
        char* sk_hex = dogecoin_malloc(sk_len * 2 + 1);
        if (!pk_hex || !sk_hex) {
            if (pk_hex) dogecoin_free(pk_hex);
            if (sk_hex) dogecoin_free(sk_hex);
            dogecoin_free(pk);
            dogecoin_free(sk);
            return showError("Failed to allocate Raccoon-G key hex buffers\n");
        }
        utils_bin_to_hex(pk, pk_len, pk_hex);
        utils_bin_to_hex(sk, sk_len, sk_hex);
        printf("\n=== Raccoon-G-44 Keypair Generated ===\n");
        printf("public key:  %s\n", pk_hex);
        printf("secret key:  %s\n", sk_hex);
        printf("pk length:   %zu bytes\n", pk_len);
        printf("sk length:   %zu bytes\n", sk_len);
        dogecoin_free(pk_hex);
        dogecoin_free(sk_hex);
        dogecoin_free(pk);
        dogecoin_free(sk);
    }
    else if (strcmp(cmd, "raccoong_sign") == 0) {
        if (!pkey) return showError("Missing secret key (use -p)\n");
        if (!txhex) return showError("Missing message (use -x)\n");
        if ((strlen(pkey) % 2) != 0) return showError("Invalid secret key hex\n");
        size_t sk_len = strlen(pkey) / 2;
        uint8_t* sk = dogecoin_malloc(sk_len);
        size_t sk_outlen = 0;
        utils_hex_to_bin(pkey, sk, strlen(pkey), &sk_outlen);
        if (sk_outlen != sk_len) { dogecoin_free(sk); return showError("Invalid secret key hex\n"); }
        if ((strlen(txhex) % 2) != 0) { dogecoin_free(sk); return showError("Invalid message hex\n"); }
        size_t msg_len = strlen(txhex) / 2;
        uint8_t* msg = dogecoin_malloc(msg_len);
        size_t msg_outlen = 0;
        utils_hex_to_bin(txhex, msg, strlen(txhex), &msg_outlen);
        if (msg_outlen != msg_len) { dogecoin_free(sk); dogecoin_free(msg); return showError("Invalid message hex\n"); }
        uint8_t* sig = NULL; size_t sig_len = 0;
        if (!dogecoin_raccoong44_sign(sk, sk_len, msg, msg_len, &sig, &sig_len)) {
            dogecoin_free(sk); dogecoin_free(msg);
            return showError("Failed to sign message with Raccoon-G-44\n");
        }
        char* sig_hex = utils_uint8_to_hex(sig, sig_len);
        printf("\n=== Raccoon-G-44 Signature Generated ===\n");
        printf("signature:   %s\n", sig_hex);
        printf("sig length:  %zu bytes\n", sig_len);
        printf("msg length:  %zu bytes\n", msg_len);
        dogecoin_free(sk); dogecoin_free(msg); dogecoin_free(sig);
    }
    else if (strcmp(cmd, "raccoong_verify") == 0) {
        if (!pubkey) return showError("Missing public key (use -k)\n");
        if (!txhex) return showError("Missing message (use -x)\n");
        if (!scripthex) return showError("Missing signature (use -s)\n");
        if ((strlen(pubkey) % 2) != 0) return showError("Invalid public key hex\n");
        size_t pk_len = strlen(pubkey) / 2;
        uint8_t* pk = dogecoin_malloc(pk_len);
        size_t pk_outlen = 0;
        utils_hex_to_bin(pubkey, pk, strlen(pubkey), &pk_outlen);
        if (pk_outlen != pk_len) { dogecoin_free(pk); return showError("Invalid public key hex\n"); }
        if ((strlen(txhex) % 2) != 0) { dogecoin_free(pk); return showError("Invalid message hex\n"); }
        size_t msg_len = strlen(txhex) / 2;
        uint8_t* msg = dogecoin_malloc(msg_len);
        size_t msg_outlen = 0;
        utils_hex_to_bin(txhex, msg, strlen(txhex), &msg_outlen);
        if (msg_outlen != msg_len) { dogecoin_free(pk); dogecoin_free(msg); return showError("Invalid message hex\n"); }
        if ((strlen(scripthex) % 2) != 0) { dogecoin_free(pk); dogecoin_free(msg); return showError("Invalid signature hex\n"); }
        size_t sig_len = strlen(scripthex) / 2;
        uint8_t* sig = dogecoin_malloc(sig_len);
        size_t sig_outlen = 0;
        utils_hex_to_bin(scripthex, sig, strlen(scripthex), &sig_outlen);
        if (sig_outlen != sig_len) { dogecoin_free(pk); dogecoin_free(msg); dogecoin_free(sig); return showError("Invalid signature hex\n"); }
        dogecoin_bool verified = dogecoin_raccoong44_verify(pk, pk_len, msg, msg_len, sig, sig_len);
        printf("\n=== Raccoon-G-44 Verification Result ===\n");
        printf("%s\n", verified ? "✓ VERIFIED: Signature is valid!" : "✗ FAILED: Signature is invalid!");
        dogecoin_free(pk); dogecoin_free(msg); dogecoin_free(sig);
        if (!verified) { dogecoin_ecc_stop(); return 1; }
    }
    else if (strcmp(cmd, "raccoong_commit") == 0) {
        if (!pubkey) return showError("Missing public key (use -k)\n");
        if (!scripthex) return showError("Missing signature (use -s)\n");
        if ((strlen(pubkey) % 2) != 0) return showError("Invalid public key hex\n");
        size_t pk_len = strlen(pubkey) / 2;
        uint8_t* pk = dogecoin_malloc(pk_len);
        size_t pk_outlen = 0;
        utils_hex_to_bin(pubkey, pk, strlen(pubkey), &pk_outlen);
        if (pk_outlen != pk_len) { dogecoin_free(pk); return showError("Invalid public key hex\n"); }
        if ((strlen(scripthex) % 2) != 0) { dogecoin_free(pk); return showError("Invalid signature hex\n"); }
        size_t sig_len = strlen(scripthex) / 2;
        uint8_t* sig = dogecoin_malloc(sig_len);
        size_t sig_outlen = 0;
        utils_hex_to_bin(scripthex, sig, strlen(scripthex), &sig_outlen);
        if (sig_outlen != sig_len) { dogecoin_free(pk); dogecoin_free(sig); return showError("Invalid signature hex\n"); }
        uint8_t commit[32];
        if (!dogecoin_raccoong44_commit_bytes(pk, pk_len, sig, sig_len, commit)) {
            dogecoin_free(pk); dogecoin_free(sig); return showError("Failed to generate Raccoon-G-44 commitment\n");
        }
        char commit_hex[65];
        utils_bin_to_hex(commit, 32, commit_hex);
        printf("\n=== Raccoon-G-44 Commitment Generated ===\n");
        printf("commitment:  %s\n", commit_hex);
        printf("length:      32 bytes\n");
        printf("\nThis commitment can be included in an OP_RETURN output:\n");
        printf("OP_RETURN script (prefix 6a24 + tag 52434734='RCG4'): 6a2452434734%s\n", commit_hex);
        dogecoin_free(pk); dogecoin_free(sig);
    }
    else if (strcmp(cmd, "raccoong_hd_derive") == 0) {
        if (!pkey) return showError("Missing parent secret key (use -p)\n");
        if (!scripthex) return showError("Missing chaincode hex (use -s)\n");
        if ((strlen(scripthex) % 2) != 0 || strlen(scripthex) != 64) return showError("Chaincode must be 32 bytes (64 hex)\n");
        if ((strlen(pkey) % 2) != 0) return showError("Invalid parent secret key hex\n");
        size_t psk_len = strlen(pkey) / 2;
        uint8_t* psk = dogecoin_malloc(psk_len);
        size_t psk_outlen = 0;
        utils_hex_to_bin(pkey, psk, strlen(pkey), &psk_outlen);
        if (psk_outlen != psk_len) { dogecoin_free(psk); return showError("Invalid parent secret key hex\n"); }
        uint8_t chaincode[DOGECOIN_PQC_RACCOON_CHAINCODE_LEN];
        size_t cc_outlen = 0;
        utils_hex_to_bin(scripthex, chaincode, strlen(scripthex), &cc_outlen);
        if (cc_outlen != DOGECOIN_PQC_RACCOON_CHAINCODE_LEN) { dogecoin_free(psk); return showError("Invalid chaincode hex\n"); }
        uint8_t* child_pk = NULL; uint8_t* child_sk = NULL;
        size_t child_pk_len = 0; size_t child_sk_len = 0;
        int hardened = 0;
        if (change_level) {
            hardened = atoi(change_level) ? 1 : 0;
        }
        if (!dogecoin_raccoong44_hd_derive_priv(psk, psk_len, chaincode, inputindex, hardened, &child_sk, &child_sk_len, &child_pk, &child_pk_len)) {
            dogecoin_free(psk);
            return showError("Raccoon-G-44 private child derivation failed\n");
        }
        char* child_pk_hex = dogecoin_malloc(child_pk_len * 2 + 1);
        char* child_sk_hex = dogecoin_malloc(child_sk_len * 2 + 1);
        if (!child_pk_hex || !child_sk_hex) {
            if (child_pk_hex) dogecoin_free(child_pk_hex);
            if (child_sk_hex) dogecoin_free(child_sk_hex);
            dogecoin_free(psk);
            dogecoin_free(child_pk);
            dogecoin_free(child_sk);
            return showError("Failed to allocate child key hex buffers\n");
        }
        utils_bin_to_hex(child_pk, child_pk_len, child_pk_hex);
        utils_bin_to_hex(child_sk, child_sk_len, child_sk_hex);
        printf("\n=== Raccoon-G-44 HD Child Key (Private Derivation) ===\n");
        printf("child index: %u%s\n", inputindex, hardened ? " (hardened)" : "");
        printf("child public key:  %s\n", child_pk_hex);
        printf("child secret key:  %s\n", child_sk_hex);
        dogecoin_free(psk);
        dogecoin_free(child_pk);
        dogecoin_free(child_sk);
        dogecoin_free(child_pk_hex);
        dogecoin_free(child_sk_hex);
    }
    else if (strcmp(cmd, "raccoong_hd_derive_pub") == 0) {
        if (!pubkey) return showError("Missing parent public key (use -k)\n");
        if (!scripthex) return showError("Missing chaincode hex (use -s)\n");
        if ((strlen(scripthex) % 2) != 0 || strlen(scripthex) != 64) return showError("Chaincode must be 32 bytes (64 hex)\n");
        if ((strlen(pubkey) % 2) != 0) return showError("Invalid parent public key hex\n");
        size_t ppk_len = strlen(pubkey) / 2;
        uint8_t* ppk = dogecoin_malloc(ppk_len);
        size_t ppk_outlen = 0;
        utils_hex_to_bin(pubkey, ppk, strlen(pubkey), &ppk_outlen);
        if (ppk_outlen != ppk_len) { dogecoin_free(ppk); return showError("Invalid parent public key hex\n"); }
        uint8_t chaincode[DOGECOIN_PQC_RACCOON_CHAINCODE_LEN];
        size_t cc_outlen = 0;
        utils_hex_to_bin(scripthex, chaincode, strlen(scripthex), &cc_outlen);
        if (cc_outlen != DOGECOIN_PQC_RACCOON_CHAINCODE_LEN) { dogecoin_free(ppk); return showError("Invalid chaincode hex\n"); }
        if (inputindex & 0x80000000U) {
            dogecoin_free(ppk);
            return showError("raccoong_hd_derive_pub does not support hardened indices\n");
        }
        uint8_t* child_pk = NULL;
        size_t child_pk_len = 0;
        if (!dogecoin_raccoong44_hd_derive_pub(ppk, ppk_len, chaincode, inputindex, &child_pk, &child_pk_len)) {
            dogecoin_free(ppk);
            return showError("Raccoon-G-44 public child derivation failed\n");
        }
        char* child_pk_hex = dogecoin_malloc(child_pk_len * 2 + 1);
        if (!child_pk_hex) {
            dogecoin_free(ppk);
            dogecoin_free(child_pk);
            return showError("Failed to allocate child public key hex buffer\n");
        }
        utils_bin_to_hex(child_pk, child_pk_len, child_pk_hex);
        printf("\n=== Raccoon-G-44 HD Child Key (Public Derivation) ===\n");
        printf("child index: %u\n", inputindex);
        printf("child public key:  %s\n", child_pk_hex);
        dogecoin_free(ppk);
        dogecoin_free(child_pk);
        dogecoin_free(child_pk_hex);
    }
    #endif
#ifdef USE_LIBOQS
    else if (strcmp(cmd, "falcon_add_commit_tx") == 0) {
        // ./such -c falcon_add_commit_tx -x <raw_tx_hex> -s <falcon_commitment_hex>
        if (!txhex || !scripthex) {
            return showError("Missing tx hex or commitment hex (use -x, -s)\n");
        }
        if ((strlen(txhex) % 2) != 0) {
            return showError("Raw transaction hex length must be even\n");
        }
        if (strlen(scripthex) != 64) {
            return showError("Commitment must be exactly 32 bytes (64 hex characters)\n");
        }
        for (size_t i = 0; i < strlen(scripthex); i++) {
            if (!isxdigit((unsigned char)scripthex[i])) {
                return showError("Commitment must be hex encoded\n");
            }
        }

        dogecoin_tx* tx = dogecoin_tx_new();
        uint8_t* data_bin = dogecoin_malloc(strlen(txhex) / 2 + 1);
        size_t outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!dogecoin_tx_deserialize(data_bin, outlen, tx, NULL)) {
            dogecoin_free(data_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex\n");
        }
        dogecoin_free(data_bin);

        uint8_t commit32[32];
        size_t commit_len = 0;
        utils_hex_to_bin(scripthex, commit32, strlen(scripthex), &commit_len);
        if (commit_len != sizeof(commit32)) {
            dogecoin_tx_free(tx);
            return showError("Failed to decode commitment\n");
        }

        if (!dogecoin_tx_add_falcon512_commit(tx, commit32)) {
            dogecoin_tx_free(tx);
            return showError("Failed to append Falcon commitment output\n");
        }

        cstring* tx_with_commit = cstr_new_sz(1024);
        dogecoin_tx_serialize(tx_with_commit, tx);
        char* tx_with_commit_hex = dogecoin_malloc(tx_with_commit->len * 2 + 1);
        if (!tx_with_commit_hex) {
            cstr_free(tx_with_commit, true);
            dogecoin_tx_free(tx);
            return showError("Failed to allocate memory for tx hex\n");
        }
        utils_bin_to_hex((unsigned char*)tx_with_commit->str, tx_with_commit->len, tx_with_commit_hex);

        printf("tx with commitment: %s\n", tx_with_commit_hex);

        cstr_free(tx_with_commit, true);
        dogecoin_free(tx_with_commit_hex);
        dogecoin_tx_free(tx);
    }
    else if (strcmp(cmd, "dilithium2_add_commit_tx") == 0) {
        if (!txhex || !scripthex) {
            return showError("Missing tx hex or commitment hex (use -x, -s)\n");
        }
        if ((strlen(txhex) % 2) != 0) {
            return showError("Raw transaction hex length must be even\n");
        }
        if (strlen(scripthex) != 64) {
            return showError("Commitment must be exactly 32 bytes (64 hex characters)\n");
        }
        for (size_t i = 0; i < strlen(scripthex); i++) {
            if (!isxdigit((unsigned char)scripthex[i])) {
                return showError("Commitment must be hex encoded\n");
            }
        }

        dogecoin_tx* tx = dogecoin_tx_new();
        uint8_t* data_bin = dogecoin_malloc(strlen(txhex) / 2 + 1);
        size_t outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!dogecoin_tx_deserialize(data_bin, outlen, tx, NULL)) {
            dogecoin_free(data_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex\n");
        }
        dogecoin_free(data_bin);

        uint8_t commit32[32];
        size_t commit_len = 0;
        utils_hex_to_bin(scripthex, commit32, strlen(scripthex), &commit_len);
        if (commit_len != sizeof(commit32)) {
            dogecoin_tx_free(tx);
            return showError("Failed to decode commitment\n");
        }

        if (!dogecoin_tx_add_dilithium2_commit(tx, commit32)) {
            dogecoin_tx_free(tx);
            return showError("Failed to append Dilithium2 commitment output\n");
        }

        cstring* tx_with_commit = cstr_new_sz(1024);
        dogecoin_tx_serialize(tx_with_commit, tx);
        char* tx_with_commit_hex = dogecoin_malloc(tx_with_commit->len * 2 + 1);
        if (!tx_with_commit_hex) {
            cstr_free(tx_with_commit, true);
            dogecoin_tx_free(tx);
            return showError("Failed to allocate memory for tx hex\n");
        }
        utils_bin_to_hex((unsigned char*)tx_with_commit->str, tx_with_commit->len, tx_with_commit_hex);
        printf("tx with commitment: %s\n", tx_with_commit_hex);
        cstr_free(tx_with_commit, true);
        dogecoin_free(tx_with_commit_hex);
        dogecoin_tx_free(tx);
    }
    else if (strcmp(cmd, "raccoong_add_commit_tx") == 0) {
        if (!txhex || !scripthex) {
            return showError("Missing tx hex or commitment hex (use -x, -s)\n");
        }
        if ((strlen(txhex) % 2) != 0) {
            return showError("Raw transaction hex length must be even\n");
        }
        if (strlen(scripthex) != 64) {
            return showError("Commitment must be exactly 32 bytes (64 hex characters)\n");
        }
        for (size_t i = 0; i < strlen(scripthex); i++) {
            if (!isxdigit((unsigned char)scripthex[i])) {
                return showError("Commitment must be hex encoded\n");
            }
        }

        dogecoin_tx* tx = dogecoin_tx_new();
        uint8_t* data_bin = dogecoin_malloc(strlen(txhex) / 2 + 1);
        size_t outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!dogecoin_tx_deserialize(data_bin, outlen, tx, NULL)) {
            dogecoin_free(data_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex\n");
        }
        dogecoin_free(data_bin);

        uint8_t commit32[32];
        size_t commit_len = 0;
        utils_hex_to_bin(scripthex, commit32, strlen(scripthex), &commit_len);
        if (commit_len != sizeof(commit32)) {
            dogecoin_tx_free(tx);
            return showError("Failed to decode commitment\n");
        }

        if (!dogecoin_tx_add_raccoong44_commit(tx, commit32)) {
            dogecoin_tx_free(tx);
            return showError("Failed to append Raccoon-G-44 commitment output\n");
        }

        cstring* tx_with_commit = cstr_new_sz(1024);
        dogecoin_tx_serialize(tx_with_commit, tx);
        char* tx_with_commit_hex = dogecoin_malloc(tx_with_commit->len * 2 + 1);
        if (!tx_with_commit_hex) {
            cstr_free(tx_with_commit, true);
            dogecoin_tx_free(tx);
            return showError("Failed to allocate memory for tx hex\n");
        }
        utils_bin_to_hex((unsigned char*)tx_with_commit->str, tx_with_commit->len, tx_with_commit_hex);
        printf("tx with commitment: %s\n", tx_with_commit_hex);
        cstr_free(tx_with_commit, true);
        dogecoin_free(tx_with_commit_hex);
        dogecoin_tx_free(tx);
    }
#endif
    else {
        print_usage();
        return showError("Unknown command\n");
    }

    dogecoin_ecc_stop();

    return 0;
    }
