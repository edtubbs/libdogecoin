/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2024-2026 The Dogecoin Foundation
 */

#include <dogecoin/libdogecoin.h>
#include <dogecoin/mem.h>
#include <dogecoin/random.h>

#include "secp256k1/include/secp256k1.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

struct dogecoin_transaction_context* dogecoin_transaction_context_new(void);
void dogecoin_transaction_context_free(struct dogecoin_transaction_context* ctx);
struct dogecoin_eckey_context* dogecoin_eckey_context_new(void);
void dogecoin_eckey_context_free(struct dogecoin_eckey_context* ctx);

static size_t dogecoin_refcount_lock_size(void)
{
#ifdef _WIN32
    return sizeof(CRITICAL_SECTION);
#else
    return sizeof(pthread_mutex_t);
#endif
}

static void dogecoin_context_cleanup(dogecoin_context* ctx)
{
    if (!ctx) return;
    if (ctx->tx_ctx) dogecoin_transaction_context_free(ctx->tx_ctx);
    if (ctx->key_ctx) dogecoin_eckey_context_free(ctx->key_ctx);
    if (ctx->rng_state) free_fast_random_context((struct fast_random_context*)ctx->rng_state);
    if (ctx->ecc_ctx) secp256k1_context_destroy((secp256k1_context*)ctx->ecc_ctx);
    if (ctx->refcount_lock) {
#ifdef _WIN32
        DeleteCriticalSection((CRITICAL_SECTION*)ctx->refcount_lock);
#else
        pthread_mutex_destroy((pthread_mutex_t*)ctx->refcount_lock);
#endif
        dogecoin_free(ctx->refcount_lock);
    }
    ctx->tx_ctx = NULL;
    ctx->key_ctx = NULL;
    ctx->rng_state = NULL;
    ctx->ecc_ctx = NULL;
    ctx->refcount_lock = NULL;
}

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
    ctx->refcount_lock = dogecoin_calloc(1, dogecoin_refcount_lock_size());
    if (!ctx->refcount_lock) {
        dogecoin_free(ctx);
        return NULL;
    }
#ifdef _WIN32
    InitializeCriticalSection((CRITICAL_SECTION*)ctx->refcount_lock);
#else
    if (pthread_mutex_init((pthread_mutex_t*)ctx->refcount_lock, NULL) != 0) {
        dogecoin_free(ctx->refcount_lock);
        ctx->refcount_lock = NULL;
        dogecoin_free(ctx);
        return NULL;
    }
#endif
    ctx->ecc_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx->ecc_ctx) {
        dogecoin_context_cleanup(ctx);
        dogecoin_free(ctx);
        return NULL;
    }
    union {
        uint256_t u256;
        uint8_t bytes[32];
    } randomization_seed;
    if (!dogecoin_random_bytes(randomization_seed.bytes, sizeof(randomization_seed.bytes), 0) ||
        !secp256k1_context_randomize((secp256k1_context*)ctx->ecc_ctx, randomization_seed.bytes)) {
        dogecoin_mem_zero(randomization_seed.bytes, sizeof(randomization_seed.bytes));
        dogecoin_context_cleanup(ctx);
        dogecoin_free(ctx);
        return NULL;
    }
    const uint256_t* rng_init_seed = (const uint256_t*)&randomization_seed.u256;
    ctx->rng_state = init_fast_random_context(false, rng_init_seed);
    dogecoin_mem_zero(randomization_seed.bytes, sizeof(randomization_seed.bytes));
    ctx->tx_ctx = dogecoin_transaction_context_new();
    ctx->key_ctx = dogecoin_eckey_context_new();
    if (!ctx->rng_state || !ctx->tx_ctx || !ctx->key_ctx) {
        dogecoin_context_cleanup(ctx);
        dogecoin_free(ctx);
        return NULL;
    }
    dogecoin_context_zero_error(ctx);
    return ctx;
}

void dogecoin_context_acquire(dogecoin_context* ctx)
{
    if (!ctx) return;
    if (!ctx->refcount_lock) return;
#ifdef _WIN32
    EnterCriticalSection((CRITICAL_SECTION*)ctx->refcount_lock);
#else
    pthread_mutex_lock((pthread_mutex_t*)ctx->refcount_lock);
#endif
    ctx->refcount++;
#ifdef _WIN32
    LeaveCriticalSection((CRITICAL_SECTION*)ctx->refcount_lock);
#else
    pthread_mutex_unlock((pthread_mutex_t*)ctx->refcount_lock);
#endif
}

void dogecoin_context_release(dogecoin_context* ctx)
{
    dogecoin_bool should_free = false;
    if (!ctx) return;
    if (!ctx->refcount_lock) return;
#ifdef _WIN32
    EnterCriticalSection((CRITICAL_SECTION*)ctx->refcount_lock);
#else
    pthread_mutex_lock((pthread_mutex_t*)ctx->refcount_lock);
#endif
    if (ctx->refcount > 0) ctx->refcount--;
    if (ctx->refcount == 0) should_free = true;
#ifdef _WIN32
    LeaveCriticalSection((CRITICAL_SECTION*)ctx->refcount_lock);
#else
    pthread_mutex_unlock((pthread_mutex_t*)ctx->refcount_lock);
#endif
    if (!should_free) return;
    dogecoin_context_cleanup(ctx);
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

void* dogecoin_context_get_ecc_context(dogecoin_context* ctx)
{
    return ctx ? ctx->ecc_ctx : NULL;
}

void* dogecoin_context_get_rng_state(dogecoin_context* ctx)
{
    return ctx ? ctx->rng_state : NULL;
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

/* ---------------------------------------------------------------------------
 * Short-form alias API: dogecoin_ctx_*
 *
 * These are thin aliases over dogecoin_context_* that match the API surface
 * documented in doc/thread_safety.md. dogecoin_ctx_new_ts() additionally
 * marks the context as thread-safe so dependent subsystems can opt into
 * per-object locking when wired through the context.
 * --------------------------------------------------------------------------- */

dogecoin_ctx* dogecoin_ctx_new(dogecoin_bool testnet, dogecoin_bool enable_net)
{
    dogecoin_ctx* ctx = dogecoin_context_new(testnet, enable_net);
    if (ctx) ctx->thread_safe = 0;
    return ctx;
}

dogecoin_ctx* dogecoin_ctx_new_ts(dogecoin_bool testnet, dogecoin_bool enable_net)
{
    dogecoin_ctx* ctx = dogecoin_context_new(testnet, enable_net);
    if (ctx) ctx->thread_safe = 1;
    return ctx;
}

void dogecoin_ctx_acquire(dogecoin_ctx* ctx)
{
    dogecoin_context_acquire(ctx);
}

void dogecoin_ctx_release(dogecoin_ctx* ctx)
{
    dogecoin_context_release(ctx);
}

int dogecoin_ctx_is_thread_safe(const dogecoin_ctx* ctx)
{
    return ctx ? ctx->thread_safe : 0;
}
