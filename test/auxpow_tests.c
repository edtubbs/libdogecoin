/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli
 * Copyright (c) 2024 edtubbs
 * Copyright (c) 2022-2024 The Dogecoin Foundation
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <dogecoin/auxpow.h>
#include <dogecoin/mem.h>
#include <dogecoin/serialize.h>
#include <dogecoin/utils.h>
#include <dogecoin/validation.h>
#include <dogecoin/protocol.h>
#include <dogecoin/chainparams.h>

void tamper_with_hash(uint256* hash)
{
    for (size_t i = 0; i < sizeof(uint256); i++)
    {
        (*hash)[i] ^= 0xFF; // Simple bit flip to change the hash
    }
}

static inline void set_correct_chain_id(dogecoin_block_header* header)
{
    // Set a correct chain ID from dogecoin_chainparams_main
    int32_t chain_id = dogecoin_chainparams_main.chain_id;
    int32_t base_version = 2; // Usually base version 2 for AuxPoW
    header->version = (base_version & 0xFFFF) | (chain_id << 16);
}

/* Existing tests retained as-is */

void test_auxpow_block()
{
    dogecoin_auxpow_block* auxpow_block = dogecoin_auxpow_block_new();

    // Set correct chain ID for a test expecting successful deserialization
    set_correct_chain_id(auxpow_block->header);

    struct const_buffer buf;
    uint256 chainwork = {0};

    const char* auxpow_hex = "03016200c96fd9d1b98330440082bcc1e58a39fe5a522f42defc501bff9b68f7b67ed99e1144e430166c54e9b911d8e059c03d0f972e7ab971c51f5505ff0bb21fee6fb1d88a9d5be132051a00000000";
    unsigned char auxpow_bin[1024];
    size_t outlen = 0;
    utils_hex_to_bin(auxpow_hex, auxpow_bin, strlen(auxpow_hex), &outlen);

    buf.p = auxpow_bin;
    buf.len = outlen;

    int deserialization_result = dogecoin_block_header_deserialize(auxpow_block->header, &buf, (dogecoin_chainparams*)&dogecoin_chainparams_main, &chainwork);
    assert(deserialization_result == 1 && "Deserialization failed for AuxPoW block header");

    cstring* serialized_header = cstr_new_sz(80);
    dogecoin_block_header_serialize(serialized_header, auxpow_block->header);
    cstr_free(serialized_header, true);

    dogecoin_auxpow_block_free(auxpow_block);
}

void test_auxpow_no_inputs_in_parent_coinbase()
{
    dogecoin_auxpow_block* auxpow_block = dogecoin_auxpow_block_new();
    // Set correct chain ID so failure is only due to no inputs
    set_correct_chain_id(auxpow_block->header);

    dogecoin_tx* parent_coinbase = dogecoin_tx_new();
    parent_coinbase->vin = vector_new(0, NULL);
    auxpow_block->parent_coinbase = parent_coinbase;

    uint256 chainwork = {0};
    int validation_result = check_auxpow(auxpow_block, (dogecoin_chainparams*)&dogecoin_chainparams_main, &chainwork);
    assert(validation_result == 0 && "AuxPoW with no inputs in parent coinbase should be invalid");

    dogecoin_auxpow_block_free(auxpow_block);
}

void test_auxpow_invalid_merkle_root()
{
    dogecoin_auxpow_block* auxpow_block = dogecoin_auxpow_block_new();
    // Set correct chain ID so failure is due to invalid merkle root only
    set_correct_chain_id(auxpow_block->header);

    dogecoin_block_header* parent_header = dogecoin_block_header_new();
    memcpy(parent_header->merkle_root, "00000000000000000000000000000000", DOGECOIN_HASH_LENGTH);
    auxpow_block->parent_header = parent_header;

    uint256 incorrect_merkle_root;
    memcpy(incorrect_merkle_root, "11111111111111111111111111111111", DOGECOIN_HASH_LENGTH);
    memcpy(auxpow_block->parent_header->merkle_root, incorrect_merkle_root, DOGECOIN_HASH_LENGTH);

    uint256 chainwork = {0};
    int validation_result = check_auxpow(auxpow_block, (dogecoin_chainparams*)&dogecoin_chainparams_main, &chainwork);
    assert(validation_result == 0 && "AuxPoW with invalid Merkle root should be invalid");

    dogecoin_auxpow_block_free(auxpow_block);
}

void test_auxpow_tampered_chain_id()
{
    // This test specifically checks chain ID tampering, so do NOT set correct chain ID
    dogecoin_auxpow_block* auxpow_block = dogecoin_auxpow_block_new();
    auxpow_block->parent_header = dogecoin_block_header_new();
    auxpow_block->parent_header->version = 100; // Incorrect chain ID

    tamper_with_hash(&auxpow_block->parent_header->merkle_root);

    uint256 chainwork = {0};
    int validation_result = check_auxpow(auxpow_block, (dogecoin_chainparams*)&dogecoin_chainparams_main, &chainwork);
    assert(validation_result == 0 && "AuxPoW with tampered chain ID should be invalid");

    dogecoin_auxpow_block_free(auxpow_block);
}

void test_auxpow_large_merkle_branch()
{
    dogecoin_auxpow_block* auxpow_block = dogecoin_auxpow_block_new();
    // Correct chain ID so it fails only due to large merkle branch
    set_correct_chain_id(auxpow_block->header);

    auxpow_block->aux_merkle_count = 100; // Too large
    uint256 chainwork = {0};
    int validation_result = check_auxpow(auxpow_block, (dogecoin_chainparams*)&dogecoin_chainparams_main, &chainwork);
    assert(validation_result == 0 && "AuxPoW with large Merkle branch should be invalid");
    dogecoin_auxpow_block_free(auxpow_block);
}

void test_auxpow_modified_aux_hash()
{
    dogecoin_auxpow_block* auxpow_block = dogecoin_auxpow_block_new();
    // Correct chain ID to isolate failure reason
    set_correct_chain_id(auxpow_block->header);

    // Tamper with aux hash (merkle_root as a stand-in for demonstration)
    tamper_with_hash(&auxpow_block->header->merkle_root);

    uint256 chainwork = {0};
    int validation_result = check_auxpow(auxpow_block, (dogecoin_chainparams*)&dogecoin_chainparams_main, &chainwork);
    assert(validation_result == 0 && "AuxPoW with modified aux hash should be invalid");

    dogecoin_auxpow_block_free(auxpow_block);
}

void test_auxpow_non_coinbase_parent()
{
    dogecoin_auxpow_block* auxpow_block = dogecoin_auxpow_block_new();
    // Correct chain ID to isolate reason (non-coinbase parent)
    set_correct_chain_id(auxpow_block->header);

    dogecoin_tx* non_coinbase = dogecoin_tx_new();
    non_coinbase->vin = vector_new(1, NULL);
    dogecoin_tx_in* tx_in = dogecoin_calloc(1, sizeof(dogecoin_tx_in));
    memset(&tx_in->prevout.hash, 0x01, 32);
    tx_in->prevout.n = 1;
    vector_add(non_coinbase->vin, tx_in);

    auxpow_block->parent_coinbase = non_coinbase;

    uint256 chainwork = {0};
    int validation_result = check_auxpow(auxpow_block, (dogecoin_chainparams*)&dogecoin_chainparams_main, &chainwork);
    assert(validation_result == 0 && "AuxPoW with non-coinbase parent tx should be invalid");

    dogecoin_auxpow_block_free(auxpow_block);
}

void test_auxpow_double_roots_in_coinbase()
{
    dogecoin_auxpow_block* auxpow_block = dogecoin_auxpow_block_new();
    // Correct chain ID to isolate failure reason
    set_correct_chain_id(auxpow_block->header);

    dogecoin_tx* parent_coinbase = dogecoin_tx_new();
    parent_coinbase->vin = vector_new(1, NULL);

    dogecoin_tx_in* tx_in = dogecoin_calloc(1, sizeof(dogecoin_tx_in));
    tx_in->script_sig = cstr_new_sz(100);
    cstr_append_buf(tx_in->script_sig, "root1", 5);
    cstr_append_buf(tx_in->script_sig, "root2", 5);
    vector_add(parent_coinbase->vin, tx_in);

    auxpow_block->parent_coinbase = parent_coinbase;

    uint256 chainwork = {0};
    int validation_result = check_auxpow(auxpow_block, (dogecoin_chainparams*)&dogecoin_chainparams_main, &chainwork);
    assert(validation_result == 0 && "AuxPoW with multiple roots in coinbase should be invalid");

    dogecoin_auxpow_block_free(auxpow_block);
}

void test_auxpow_legacy_format()
{
    dogecoin_auxpow_block* auxpow_block = dogecoin_auxpow_block_new();
    // If the legacy format was intended to be valid, set correct chain ID
    // If not, set it anyway to isolate reason (legacy format unsupported)
    set_correct_chain_id(auxpow_block->header);

    dogecoin_tx* parent_coinbase = dogecoin_tx_new();
    parent_coinbase->vin = vector_new(1, NULL);
    dogecoin_tx_in* tx_in = dogecoin_calloc(1, sizeof(dogecoin_tx_in));
    tx_in->script_sig = cstr_new("auxrootwithoutheader");
    vector_add(parent_coinbase->vin, tx_in);
    auxpow_block->parent_coinbase = parent_coinbase;

    uint256 chainwork = {0};
    int validation_result = check_auxpow(auxpow_block, (dogecoin_chainparams*)&dogecoin_chainparams_main, &chainwork);
    // As per the note, currently expecting invalid due to legacy format not supported
    assert(validation_result == 0 && "Legacy AuxPoW format test (if supported by logic)");

    dogecoin_auxpow_block_free(auxpow_block);
}

void test_auxpow_nonce_size_mismatch()
{
    dogecoin_auxpow_block* auxpow_block = dogecoin_auxpow_block_new();
    // Correct chain ID to isolate nonce/size mismatch reason
    set_correct_chain_id(auxpow_block->header);

    dogecoin_tx* parent_coinbase = dogecoin_tx_new();
    parent_coinbase->vin = vector_new(1, NULL);
    dogecoin_tx_in* tx_in = dogecoin_calloc(1, sizeof(dogecoin_tx_in));
    tx_in->script_sig = cstr_new_sz(100);

    cstr_append_buf(tx_in->script_sig, "auxroot", 7);
    unsigned char wrong_data[8] = {0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00};
    cstr_append_buf(tx_in->script_sig, wrong_data, 8);

    vector_add(parent_coinbase->vin, tx_in);
    auxpow_block->parent_coinbase = parent_coinbase;

    uint256 chainwork = {0};
    int validation_result = check_auxpow(auxpow_block, (dogecoin_chainparams*)&dogecoin_chainparams_main, &chainwork);
    assert(validation_result == 0 && "AuxPoW with incorrect nonce/size in coinbase should be invalid");

    dogecoin_auxpow_block_free(auxpow_block);
}

void test_auxpow_invalid_aux_hash_position()
{
    dogecoin_auxpow_block* auxpow_block = dogecoin_auxpow_block_new();
    // Correct chain ID to isolate invalid aux hash position reason
    set_correct_chain_id(auxpow_block->header);

    auxpow_block->parent_coinbase = dogecoin_tx_new();
    auxpow_block->aux_merkle_count = 1;
    auxpow_block->aux_merkle_index = 99; // Out-of-range index
    auxpow_block->aux_merkle_branch = dogecoin_calloc(1, sizeof(uint256));
    memset(auxpow_block->aux_merkle_branch[0], 0xAB, DOGECOIN_HASH_LENGTH);

    uint256 chainwork = {0};
    int validation_result = check_auxpow(auxpow_block, (dogecoin_chainparams*)&dogecoin_chainparams_main, &chainwork);
    assert(validation_result == 0 && "AuxPoW with invalid aux hash position should be invalid");

    dogecoin_auxpow_block_free(auxpow_block);
}

void test_auxpow_tampered_parent_merkle_root()
{
    dogecoin_auxpow_block* auxpow_block = dogecoin_auxpow_block_new();
    // Correct chain ID so we fail only due to tampered parent merkle root
    set_correct_chain_id(auxpow_block->header);

    auxpow_block->parent_header = dogecoin_block_header_new();
    memset(auxpow_block->parent_header->merkle_root, 0x00, DOGECOIN_HASH_LENGTH);

    tamper_with_hash(&auxpow_block->parent_header->merkle_root);

    uint256 chainwork = {0};
    int validation_result = check_auxpow(auxpow_block, (dogecoin_chainparams*)&dogecoin_chainparams_main, &chainwork);
    assert(validation_result == 0 && "AuxPoW with tampered parent Merkle root should be invalid");

    dogecoin_auxpow_block_free(auxpow_block);
}

void test_auxpow()
{
    test_auxpow_block();
    test_auxpow_no_inputs_in_parent_coinbase();
    test_auxpow_invalid_merkle_root();
    test_auxpow_tampered_chain_id();
    test_auxpow_large_merkle_branch();
    test_auxpow_modified_aux_hash();
    test_auxpow_non_coinbase_parent();
    test_auxpow_double_roots_in_coinbase();
    test_auxpow_legacy_format();
    test_auxpow_nonce_size_mismatch();
    test_auxpow_invalid_aux_hash_position();
    test_auxpow_tampered_parent_merkle_root();
}
