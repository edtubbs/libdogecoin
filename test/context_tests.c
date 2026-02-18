/*
 The MIT License (MIT)
*/

#include <string.h>

#include <test/utest.h>
#include <dogecoin/libdogecoin.h>

void test_context_keypair_ex()
{
    dogecoin_context* ctx = dogecoin_context_new(false, false);
    u_assert_true(ctx != NULL);

    size_t wif_size = 0;
    size_t addr_size = 0;
    u_assert_true(dogecoin_generate_keypair_ex(ctx, NULL, &wif_size, NULL, &addr_size));
    u_assert_true(wif_size > 1);
    u_assert_true(addr_size > 1);

    char wif[PRIVKEYWIFLEN] = {0};
    char addr[P2PKHLEN] = {0};
    size_t wif_cap = sizeof(wif);
    size_t addr_cap = sizeof(addr);
    u_assert_true(dogecoin_generate_keypair_ex(ctx, wif, &wif_cap, addr, &addr_cap));
    u_assert_true(strlen(wif) > 0);
    u_assert_true(strlen(addr) > 0);
    u_assert_int_eq(dogecoin_context_get_error_code(ctx), 0);

    char tiny_wif[1] = {0};
    char tiny_addr[1] = {0};
    size_t tiny_wif_cap = sizeof(tiny_wif);
    size_t tiny_addr_cap = sizeof(tiny_addr);
    u_assert_true(!dogecoin_generate_keypair_ex(ctx, tiny_wif, &tiny_wif_cap, tiny_addr, &tiny_addr_cap));
    u_assert_true(dogecoin_context_get_error_code(ctx) != 0);
    u_assert_true(strlen(dogecoin_context_get_error(ctx)) > 0);

    dogecoin_context_release(ctx);
}
