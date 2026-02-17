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
#include <dogecoin/ecc.h>
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
     * Electrum v1 key derivation test
     *
     * Tests electrum_v1_derive_privkey32() which takes a raw 16-byte seed
     * and derives child private keys. Seed decoding is tested in bip39_tests.
     *
     * Test vectors verified with bip-utils (pip install bip-utils):
     *   from bip_utils import *
     *   seed = ElectrumV1SeedGenerator("hardly point goal ...").Generate()
     *   e = ElectrumV1.FromSeed(seed)
     *   e.GetPrivateKey(0, 0).Raw().ToHex()  # child key
     *   P2PKHAddr.EncodeKey(e.GetPublicKey(0, 0),
     *       net_ver=CoinsConf.DogecoinMainNet.ParamByKey("p2pkh_net_ver"),
     *       pub_key_mode=P2PKHPubKeyModes.UNCOMPRESSED)  # address
     */

    SEED buffer_for_seed;

    /*
     * "hardly point goal hallway patience key stone difference ready caught listen fact"
     * Key derivation (n=0, for_change=0):
     *   master_secret = stretch_key('8edad31a95e7d59f8837667510d75a4d')
     *   tweak = double_SHA256("0:0:" + mpk_raw_64_bytes)
     *   derived = (master_secret + tweak) mod curve_order
     *   => 490aa18749841c21f4ece6da50898645578736ce0e38cd67568c14e3c47c9d95
     */
    const char* v1_12_mn = "hardly point goal hallway patience key stone difference ready caught listen fact";

    memset(buffer_for_seed, 0, MAX_SEED_SIZE);
    u_assert_int_eq(dogecoin_seed_from_electrum_v1_mnemonic(v1_12_mn, "", buffer_for_seed), 0);

    /* Verify Electrum v1 key derivation (n=0, for_change=0) */
    uint8_t priv32[32];
    dogecoin_mem_zero(priv32, sizeof(priv32));
    u_assert_int_eq(electrum_v1_derive_privkey32((const uint8_t*)buffer_for_seed, 0, 0, priv32), 1);

    char* derived_hex = utils_uint8_to_hex(priv32, 32);
    u_assert_str_eq(derived_hex, "490aa18749841c21f4ece6da50898645578736ce0e38cd67568c14e3c47c9d95");

    /* Verify uncompressed address matches bip-utils reference */
    {
        uint8_t pubser[65];
        size_t publen = sizeof(pubser);
        dogecoin_ecc_get_pubkey(priv32, pubser, &publen, false);
        u_assert_int_eq(publen, 65);
        u_assert_int_eq(pubser[0], 0x04);

        dogecoin_pubkey pubkey;
        dogecoin_pubkey_init(&pubkey);
        memcpy(pubkey.pubkey, pubser, 65);
        pubkey.compressed = false;

        char addr[P2PKHLEN];
        dogecoin_mem_zero(addr, sizeof(addr));
        dogecoin_pubkey_getaddr_p2pkh(&pubkey, &dogecoin_chainparams_main, addr);
        u_assert_str_eq(addr, "D5H1b4AHaZEVJeWTKn2M6SVyxc4DzQeefQ");
    }

    /* Verify child key at (n=1, for_change=0) matches bip-utils */
    {
        uint8_t priv32_1[32];
        dogecoin_mem_zero(priv32_1, sizeof(priv32_1));
        u_assert_int_eq(electrum_v1_derive_privkey32((const uint8_t*)buffer_for_seed, 1, 0, priv32_1), 1);

        char* derived_hex_1 = utils_uint8_to_hex(priv32_1, 32);
        u_assert_str_eq(derived_hex_1, "95de25eca551ebdb2b542371a375e9a9e6b7dcfdf8c978f22a29d70c3ff0c961");

        uint8_t pubser[65];
        size_t publen = sizeof(pubser);
        dogecoin_ecc_get_pubkey(priv32_1, pubser, &publen, false);

        dogecoin_pubkey pubkey;
        dogecoin_pubkey_init(&pubkey);
        memcpy(pubkey.pubkey, pubser, 65);
        pubkey.compressed = false;

        char addr[P2PKHLEN];
        dogecoin_mem_zero(addr, sizeof(addr));
        dogecoin_pubkey_getaddr_p2pkh(&pubkey, &dogecoin_chainparams_main, addr);
        u_assert_str_eq(addr, "DFMtzW5hhucXAnZW4emfEAHwZrRUi3EQZG");
    }

    /* "like just love..." mnemonic — key derivation + address at (n=0, for_change=0) */
    {
        const char* v1_ljl_mn = "like just love know never want time out there make look eye";
        memset(buffer_for_seed, 0, MAX_SEED_SIZE);
        u_assert_int_eq(dogecoin_seed_from_electrum_v1_mnemonic(v1_ljl_mn, "", buffer_for_seed), 0);

        uint8_t ljl_priv32[32];
        dogecoin_mem_zero(ljl_priv32, sizeof(ljl_priv32));
        u_assert_int_eq(electrum_v1_derive_privkey32((const uint8_t*)buffer_for_seed, 0, 0, ljl_priv32), 1);

        char* ljl_derived = utils_uint8_to_hex(ljl_priv32, 32);
        u_assert_str_eq(ljl_derived, "b9a83170bfc2a80219d3d4b789acf145792a3470c440e767741de054e3484bb2");

        uint8_t ljl_pub[65];
        size_t ljl_publen = sizeof(ljl_pub);
        dogecoin_ecc_get_pubkey(ljl_priv32, ljl_pub, &ljl_publen, false);

        dogecoin_pubkey ljl_pubkey;
        dogecoin_pubkey_init(&ljl_pubkey);
        memcpy(ljl_pubkey.pubkey, ljl_pub, 65);
        ljl_pubkey.compressed = false;

        char ljl_addr[P2PKHLEN];
        dogecoin_mem_zero(ljl_addr, sizeof(ljl_addr));
        dogecoin_pubkey_getaddr_p2pkh(&ljl_pubkey, &dogecoin_chainparams_main, ljl_addr);
        u_assert_str_eq(ljl_addr, "DJqkqMLLkio821TrxpZxUDhVFaSDR7VeWz");
    }

    utils_clear_buffers();
}
