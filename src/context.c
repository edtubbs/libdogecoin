/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2024-2026 The Dogecoin Foundation
 */

#include <dogecoin/libdogecoin.h>
#include <dogecoin/mem.h>

static void dogecoin_context_zero_error(dogecoin_context* ctx)
{
    if (!ctx) return;
    ctx->error_code = 0;
    ctx->last_error[0] = '\0';
}

dogecoin_context* dogecoin_context_new(dogecoin_bool testnet, dogecoin_bool enable_net)
{
    dogecoin_context* ctx = (dogecoin_context*)dogecoin_calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    ctx->chain_params = testnet ? &dogecoin_chainparams_test : &dogecoin_chainparams_main;
    ctx->enable_net = enable_net ? 1 : 0;
    ctx->refcount = 1;
    ctx->tx_ctx = NULL;
    ctx->key_ctx = NULL;
    dogecoin_context_zero_error(ctx);
    return ctx;
}

void dogecoin_context_acquire(dogecoin_context* ctx)
{
    if (!ctx) return;
    ctx->refcount++;
}

void dogecoin_context_release(dogecoin_context* ctx)
{
    if (!ctx) return;
    if (ctx->refcount > 1) {
        ctx->refcount--;
        return;
    }
    dogecoin_free(ctx);
}

const dogecoin_chainparams* dogecoin_context_get_chainparams(const dogecoin_context* ctx)
{
    return ctx ? ctx->chain_params : NULL;
}

struct dogecoin_transaction_context* dogecoin_context_get_transaction_context(dogecoin_context* ctx)
{
    return ctx ? ctx->tx_ctx : NULL;
}

struct dogecoin_eckey_context* dogecoin_context_get_eckey_context(dogecoin_context* ctx)
{
    return ctx ? ctx->key_ctx : NULL;
}

void dogecoin_context_set_error(dogecoin_context* ctx, int code, const char* msg)
{
    if (!ctx) return;
    ctx->error_code = code;
    if (!msg) {
        ctx->last_error[0] = '\0';
        return;
    }
    strncpy(ctx->last_error, msg, sizeof(ctx->last_error) - 1);
    ctx->last_error[sizeof(ctx->last_error) - 1] = '\0';
}

int dogecoin_context_get_error_code(const dogecoin_context* ctx)
{
    return ctx ? ctx->error_code : 0;
}

const char* dogecoin_context_get_error(const dogecoin_context* ctx)
{
    if (!ctx) return "";
    return ctx->last_error;
}

int dogecoin_generate_keypair_ex(dogecoin_context* ctx, char* wif, size_t* wif_size, char* addr, size_t* addr_size)
{
    if (!ctx || !wif_size || !addr_size) {
        dogecoin_context_set_error(ctx, -1, "invalid arguments");
        return false;
    }

    const dogecoin_bool is_testnet = (ctx->chain_params != &dogecoin_chainparams_main);
    char tmp_wif[PRIVKEYWIFLEN] = {0};
    char tmp_addr[P2PKHLEN] = {0};
    if (!generatePrivPubKeypair(tmp_wif, tmp_addr, is_testnet)) {
        dogecoin_context_set_error(ctx, -2, "key generation failed");
        return false;
    }

    size_t wif_need = strlen(tmp_wif) + 1;
    size_t addr_need = strlen(tmp_addr) + 1;
    dogecoin_context_zero_error(ctx);
    if (!wif || !addr) {
        *wif_size = wif_need;
        *addr_size = addr_need;
        return true;
    }
    if (*wif_size < wif_need || *addr_size < addr_need) {
        *wif_size = wif_need;
        *addr_size = addr_need;
        dogecoin_context_set_error(ctx, -3, "output buffer too small");
        return false;
    }

    memcpy(wif, tmp_wif, wif_need);
    memcpy(addr, tmp_addr, addr_need);
    *wif_size = wif_need;
    *addr_size = addr_need;
    return true;
}
