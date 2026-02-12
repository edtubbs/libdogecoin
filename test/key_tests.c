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
     * Electrum v1 mnemonic to private key derivation test
     * 
     * Reference: Electrum v1 (pre-2.0) non-standard seed derivation
     * Source: https://electrum.readthedocs.io/en/latest/seedphrase.html
     * 
     * Electrum v1 algorithm (non-standard, not BIP32/BIP39):
     * - 1626-word dictionary (wordlist_electrum in include/bip39/electrum.h)
     * - Base-1626 encoding to 16 bytes (for proper v1 mnemonics)
     * - Fallback: SHA256(mnemonic + optional_passphrase)
     * - SHA256 stretching: repeat 100,000 times: stretched = SHA256(stretched + seed)
     * - Results in 32-byte seed (NOT used with BIP32)
     * 
     * Electrum v1 key derivation (NOT BIP32):
     * - Derives keys using: privkey = master_secret + SHA256(n:for_change:mpk) mod n
     * - Where mpk is the uncompressed public key from master_secret
     * - This is completely different from BIP32 hierarchical deterministic derivation
     * 
     * This test verifies the complete Electrum v1 flow:
     *   Electrum v1 mnemonic → stretched seed → electrum_v1_derive_privkey32()
     * 
     * VERIFICATION METHOD - Python command to verify seed derivation:
     *   python3 -c "import hashlib; s=hashlib.sha256(b'alpha bravo').digest(); st=s; exec('st=hashlib.sha256(st+s).digest();'*100000); print(st.hex())"
     * 
     * Test vectors verified using Python's standard hashlib.sha256
     * which implements SHA-256 per FIPS 180-4, making them independently verifiable
     */
    
    SEED buffer_for_seed;
    
    /* Electrum v1 two-word test case */
    const char* v1_mnemonic = "alpha bravo";
    const char* empty_pass = "";
    
    memset(buffer_for_seed, 0, MAX_SEED_SIZE);
    
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
    
    /* Step 2: Derive private key using Electrum v1 custom derivation (NOT BIP32)
     * Electrum v1 derivation: privkey = master_secret + SHA256(n:for_change:mpk) mod n
     * where mpk is the uncompressed public key derived from master_secret
     * This is different from BIP32 hierarchical deterministic derivation
     */
    uint8_t priv32_receiving[32];
    dogecoin_mem_zero(priv32_receiving, sizeof(priv32_receiving));
    
    /* Derive key at index 0, for_change=0 (receiving address) */
    int derive_result = electrum_v1_derive_privkey32((const uint8_t*)buffer_for_seed, 0, 0, priv32_receiving);
    u_assert_int_eq(derive_result, 1); /* returns 1 on success */
    
    /* Verify derived private key is valid */
    dogecoin_key receiving_key;
    dogecoin_privkey_init(&receiving_key);
    memcpy(receiving_key.privkey, priv32_receiving, 32);
    u_assert_int_eq(dogecoin_privkey_is_valid(&receiving_key), 1);
    
    char* privkey_hex = utils_uint8_to_hex(priv32_receiving, 32);
    debug_print("Electrum v1 derived privkey (index=0, change=0): %s\n", privkey_hex);
    
    /* Also test change address derivation (for_change=1) */
    uint8_t priv32_change[32];
    dogecoin_mem_zero(priv32_change, sizeof(priv32_change));
    
    derive_result = electrum_v1_derive_privkey32((const uint8_t*)buffer_for_seed, 0, 1, priv32_change);
    u_assert_int_eq(derive_result, 1);
    
    dogecoin_key change_key;
    dogecoin_privkey_init(&change_key);
    memcpy(change_key.privkey, priv32_change, 32);
    u_assert_int_eq(dogecoin_privkey_is_valid(&change_key), 1);
    
    char* change_privkey_hex = utils_uint8_to_hex(priv32_change, 32);
    debug_print("Electrum v1 derived privkey (index=0, change=1): %s\n", change_privkey_hex);
    
    /* Verify receiving and change keys are different */
    int keys_differ = (memcmp(priv32_receiving, priv32_change, 32) != 0);
    u_assert_int_eq(keys_differ, 1);
    
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
}
