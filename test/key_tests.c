/*
 The MIT License (MIT)

 Copyright (c) 2015 Jonas Schnelli
 Copyright (c) 2022 bluezr
 Copyright (c) 2022-2023 The Dogecoin Foundation

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <test/utest.h>

#include <dogecoin/key.h>
#include <dogecoin/utils.h>
#include <dogecoin/bip39.h>
#include <dogecoin/bip32.h>
#include <dogecoin/address.h>
#include <dogecoin/chainparams.h>

void test_key()
{
    dogecoin_key key;
    dogecoin_privkey_init(&key);
    assert(dogecoin_privkey_is_valid(&key) == 0);
    dogecoin_privkey_gen(&key);
    assert(dogecoin_privkey_is_valid(&key) == 1);
    dogecoin_pubkey pubkey;
    dogecoin_pubkey_init(&pubkey);
    assert(dogecoin_pubkey_is_valid(&pubkey) == 0);
    dogecoin_pubkey_from_key(&key, &pubkey);
    assert(dogecoin_pubkey_is_valid(&pubkey) == 1);
    assert(dogecoin_privkey_verify_pubkey(&key, &pubkey) == 1);
    unsigned int i;
    for (i = 33; i < DOGECOIN_ECKEY_UNCOMPRESSED_LENGTH; ++i)
        assert(pubkey.pubkey[i] == 0);
    uint8_t* hash = utils_hex_to_uint8((const char*)"26db47a48a10b9b0b697b793f5c0231aa35fe192c9d063d7b03a55e3c302850a");
    unsigned char sig[74];
    size_t outlen = 74;
    dogecoin_key_sign_hash(&key, hash, sig, &outlen);
    unsigned char sigcmp[64];
    size_t outlencmp = 64;
    dogecoin_key_sign_hash_compact(&key, hash, sigcmp, &outlencmp);
    unsigned char sigcmp_rec[64];
    size_t outlencmp_rec = 64;
    int recid;
    dogecoin_pubkey pubkey_rec;
    dogecoin_pubkey_init(&pubkey_rec);
    dogecoin_key_sign_hash_compact_recoverable(&key, hash, sigcmp_rec, &outlencmp_rec, &recid);
    dogecoin_key_sign_recover_pubkey(sigcmp_rec, hash, recid, &pubkey_rec);
    u_assert_int_eq(dogecoin_pubkey_verify_sig(&pubkey, hash, sig, outlen), true);
    u_assert_mem_eq(pubkey.pubkey, pubkey_rec.pubkey, sizeof(pubkey.pubkey));
    char str[66 + 1];
    size_t size = sizeof(str);
    int r = dogecoin_pubkey_get_hex(&pubkey, str, &size);
    u_assert_int_eq(r, true);
    u_assert_uint32_eq(size, 66);
    size = 50;
    r = dogecoin_pubkey_get_hex(&pubkey, str, &size);
    u_assert_int_eq(r, false);
    dogecoin_privkey_cleanse(&key);
    dogecoin_pubkey_cleanse(&pubkey);
    dogecoin_key key_wif;
    dogecoin_privkey_init(&key_wif);
    assert(dogecoin_privkey_is_valid(&key_wif) == 0);
    dogecoin_privkey_gen(&key_wif);
    assert(dogecoin_privkey_is_valid(&key_wif) == 1);
    char wifstr[PRIVKEYWIFLEN];
    size_t wiflen = PRIVKEYWIFLEN;
    dogecoin_privkey_encode_wif(&key_wif, &dogecoin_chainparams_main, wifstr, &wiflen);
    wiflen = PRIVKEYWIFLEN;
    dogecoin_key key_wif_decode;
    dogecoin_privkey_decode_wif(wifstr, &dogecoin_chainparams_main, &key_wif_decode);
    u_assert_mem_eq(key_wif_decode.privkey, key_wif.privkey, sizeof(key_wif_decode.privkey));
    getWifEncodedPrivKey(key_wif.privkey, false, wifstr, &wiflen);
    getDecodedPrivKeyWif(wifstr, false, key_wif_decode.privkey);
    u_assert_mem_eq(key_wif_decode.privkey, key_wif.privkey, sizeof(key_wif_decode.privkey));
}

void test_electrum_v1_mnemonic_to_master_key()
{
    /*
     * Electrum v1 mnemonic to BIP32 master key test
     * 
     * Reference: Electrum v1 (pre-2.0) non-standard seed derivation
     * Source: https://electrum.readthedocs.io/en/latest/seedphrase.html
     * 
     * Electrum v1 algorithm (non-standard, not BIP39):
     * - 1626-word dictionary (wordlist_electrum in include/bip39/electrum.h)
     * - Base-1626 encoding to 16 bytes (for proper v1 mnemonics)
     * - Fallback: SHA256(mnemonic + optional_passphrase)
     * - SHA256 stretching: repeat 100,000 times: stretched = SHA256(stretched + seed)
     * - Results in 32-byte seed (padded to 64 bytes for BIP32)
     * 
     * This test verifies the complete flow for the 'such' CLI tool:
     *   Electrum v1 mnemonic → stretched seed → BIP32 master key
     * 
     * VERIFICATION METHOD - Python command to verify seed derivation:
     *   python3 -c "import hashlib; s=hashlib.sha256(b'alpha bravo').digest(); st=s; exec('st=hashlib.sha256(st+s).digest();'*100000); print(st.hex())"
     * 
     * Test vectors verified using Python's standard hashlib.sha256
     * which implements SHA-256 per FIPS 180-4, making them independently verifiable
     */
    
    SEED buffer_for_seed;
    dogecoin_hdnode root_node;
    
    /* Electrum v1 two-word test case */
    const char* v1_mnemonic = "alpha bravo";
    const char* empty_pass = "";
    
    memset(buffer_for_seed, 0, MAX_SEED_SIZE);
    memset(&root_node, 0, sizeof(root_node));
    
    /* Step 1: Convert Electrum v1 mnemonic to seed */
    int seed_result = dogecoin_seed_from_electrum_v1_mnemonic(v1_mnemonic, empty_pass, buffer_for_seed);
    u_assert_int_eq(seed_result, 0);
    
    /* Verify seed output (first 32 bytes, remaining 32 are zero)
     * Expected value verified with Python hashlib.sha256 stretching
     * Verification command:
     *   python3 -c "import hashlib; s=hashlib.sha256(b'alpha bravo').digest(); st=s; exec('st=hashlib.sha256(st+s).digest();'*100000); print(st.hex())"
     * Expected output: d46b151636c4b8dfe628364198808d25e83c0ba21bc0bab094357094ef0b537d
     */
    char* seed_as_hex = utils_uint8_to_hex(buffer_for_seed, 32);
    const char* ref_seed_hex = "d46b151636c4b8dfe628364198808d25e83c0ba21bc0bab094357094ef0b537d";
    u_assert_str_eq(seed_as_hex, ref_seed_hex);
    debug_print("Electrum v1 seed (32 bytes): %s\n", seed_as_hex);
    
    /* Step 2: Derive BIP32 master node from seed */
    dogecoin_bool node_result = dogecoin_hdnode_from_seed(buffer_for_seed, MAX_SEED_SIZE, &root_node);
    u_assert_int_eq(node_result, true);
    
    /* Verify chain code was generated */
    char* chain_hex = utils_uint8_to_hex(root_node.chain_code, 32);
    debug_print("Chain code: %s\n", chain_hex);
    u_assert_int_eq(strlen(chain_hex), 64); /* 32 bytes = 64 hex chars */
    
    /* Verify private key was generated */
    char* privkey_hex = utils_uint8_to_hex(root_node.private_key, 32);
    debug_print("Private key: %s\n", privkey_hex);
    u_assert_int_eq(strlen(privkey_hex), 64); /* 32 bytes = 64 hex chars */
    
    /* Test with passphrase 
     * Verification command:
     *   python3 -c "import hashlib; s=hashlib.sha256(b'alpha bravo testpass').digest(); st=s; exec('st=hashlib.sha256(st+s).digest();'*100000); print(st.hex())"
     */
    const char* with_pass = "testpass";
    memset(buffer_for_seed, 0, MAX_SEED_SIZE);
    
    seed_result = dogecoin_seed_from_electrum_v1_mnemonic(v1_mnemonic, with_pass, buffer_for_seed);
    u_assert_int_eq(seed_result, 0);
    
    /* Expected value verified with Python hashlib.sha256 - independently verifiable */
    char* seed_pass_hex = utils_uint8_to_hex(buffer_for_seed, 32);
    const char* ref_seed_pass_hex = "d51554cccc286493f510b8c2a4104e4132562518a5db4ec5e8a3325dff8234ee";
    u_assert_str_eq(seed_pass_hex, ref_seed_pass_hex);
    debug_print("Electrum v1 seed with passphrase: %s\n", seed_pass_hex);
    
    utils_clear_buffers();

    /*
     * Electrum v1 proper 12-word mnemonic test with key derivation
     *
     * Test vector from Electrum's test suite:
     *   seed_hex = '8edad31a95e7d59f8837667510d75a4d'
     *   mnemonic = 'hardly point goal hallway patience key stone difference ready caught listen fact'
     *   mn_encode(seed_hex) == mnemonic.split()
     *   mn_decode(mnemonic.split()) == seed_hex
     *
     * Stretched seed verified with Python:
     *   python3 -c "s=b'8edad31a95e7d59f8837667510d75a4d'; x=s; exec('import hashlib\\nx=hashlib.sha256(x+s).digest();'*100000); print(x.hex())"
     *   => 64ea202eb1941a971e8a9af7b4caae1cbde9890103092ac57ce68ec5d9314213
     *
     * Key derivation (n=0, for_change=0) verified with Python ecdsa:
     *   tweak = double_SHA256("0:0:" + mpk_raw_64_bytes)
     *   derived = (master_secret + tweak) mod curve_order
     *   => 490aa18749841c21f4ece6da50898645578736ce0e38cd67568c14e3c47c9d95
     */
    const char* v1_12_mn = "hardly point goal hallway patience key stone difference ready caught listen fact";
    const char* v1_12_pass = "";

    memset(buffer_for_seed, 0, MAX_SEED_SIZE);
    memset(&root_node, 0, sizeof(root_node));

    seed_result = dogecoin_seed_from_electrum_v1_mnemonic(v1_12_mn, v1_12_pass, buffer_for_seed);
    u_assert_int_eq(seed_result, 0);

    char* seed_12_hex = utils_uint8_to_hex(buffer_for_seed, 32);
    const char* ref_seed_12_hex = "64ea202eb1941a971e8a9af7b4caae1cbde9890103092ac57ce68ec5d9314213";
    u_assert_str_eq(seed_12_hex, ref_seed_12_hex);
    debug_print("Electrum v1 12-word seed: %s\n", seed_12_hex);

    /* Verify Electrum v1 key derivation (n=0, for_change=0) */
    uint8_t priv32[32];
    dogecoin_mem_zero(priv32, sizeof(priv32));
    u_assert_int_eq(electrum_v1_derive_privkey32((const uint8_t*)buffer_for_seed, 0, 0, priv32), 1);

    char* derived_hex = utils_uint8_to_hex(priv32, 32);
    const char* ref_derived_hex = "490aa18749841c21f4ece6da50898645578736ce0e38cd67568c14e3c47c9d95";
    u_assert_str_eq(derived_hex, ref_derived_hex);
    debug_print("Electrum v1 derived key (0:0:): %s\n", derived_hex);

    utils_clear_buffers();
}
