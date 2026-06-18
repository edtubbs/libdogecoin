/*

 The MIT License (MIT)

 Copyright (c) 2024-2026 The Dogecoin Foundation

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

/*
 * Thread-safe routing helpers shared by the libdogecoin CLI tools.
 *
 * The CLI sources are compiled twice: once into the legacy binaries
 * (`such`, `sendtx`, `spvnode`) and once into thread-safe binaries
 * (`such_ts`, `sendtx_ts`, `spvnode_ts`) compiled with `-DDOGECOIN_TS=1`.
 *
 * Rather than invisibly redefining public API names, this header exposes a
 * small set of explicit, greppable wrappers. In the `-DDOGECOIN_TS` build each
 * wrapper routes through the matching `_ts` library API so the resulting
 * binary exercises the thread-safe contexts and per-object mutexes documented
 * in doc/thread_safety.md; otherwise it calls the plain API. The two builds are
 * otherwise identical.
 */

#ifndef __LIBDOGECOIN_THREADSAFE_H__
#define __LIBDOGECOIN_THREADSAFE_H__

#include <stdio.h>

#include <dogecoin/dogecoin.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/eckey.h>
#include <dogecoin/transaction.h>
#include <dogecoin/tx.h>
#include <dogecoin/wallet.h>

#ifdef DOGECOIN_TS
#define DOGECOIN_CLI_TS_LABEL "thread-safe"
#else
#define DOGECOIN_CLI_TS_LABEL "single-threaded"
#endif

/* --------------------------------------------------------------------------
 * Thread-safe context lifecycle
 *
 * In the `_ts` build this creates a thread-safe libdogecoin context (a
 * refcount-mutex guarded object), announces the mode and returns the held
 * context for the tool to thread through `_ts` object constructors. The
 * matching finish call releases it. In the legacy build both are no-ops.
 * -------------------------------------------------------------------------- */
static inline dogecoin_ctx* cli_ts_context_start(const char* tool, dogecoin_bool testnet)
{
#ifdef DOGECOIN_TS
    dogecoin_ctx* ctx = dogecoin_ctx_new_ts(testnet, false);
    printf("%s: thread-safe mode %s\n", tool,
           dogecoin_ctx_is_thread_safe(ctx) ? "enabled" : "unavailable");
    return ctx;
#else
    (void)tool;
    (void)testnet;
    return NULL;
#endif
}

static inline void cli_ts_context_finish(dogecoin_ctx* ctx)
{
#ifdef DOGECOIN_TS
    dogecoin_ctx_release(ctx);
#else
    (void)ctx;
#endif
}

/* --------------------------------------------------------------------------
 * Transaction builder
 * -------------------------------------------------------------------------- */
static inline dogecoin_tx* cli_tx_new(void)
{
#ifdef DOGECOIN_TS
    return dogecoin_tx_new_ts();
#else
    return dogecoin_tx_new();
#endif
}

static inline void cli_tx_free(dogecoin_tx* tx)
{
#ifdef DOGECOIN_TS
    dogecoin_tx_free_ts(tx);
#else
    dogecoin_tx_free(tx);
#endif
}

/* --------------------------------------------------------------------------
 * Transaction registry
 *
 * The CLI builds transactions through the index-based transaction API, which
 * operates on the per-thread default transaction context. The `_ts` wrappers
 * below therefore target that same default context so registry lookups stay
 * consistent with the rest of the index-based API.
 * -------------------------------------------------------------------------- */
static inline int cli_start_transaction(void)
{
#ifdef DOGECOIN_TS
    return start_transaction_ts(dogecoin_transaction_context_default());
#else
    return start_transaction();
#endif
}

static inline working_transaction* cli_find_transaction(int idx)
{
#ifdef DOGECOIN_TS
    return find_transaction_ts(dogecoin_transaction_context_default(), idx);
#else
    return find_transaction(idx);
#endif
}

static inline void cli_remove_transaction(working_transaction* working_tx)
{
#ifdef DOGECOIN_TS
    remove_transaction_ts(dogecoin_transaction_context_default(), working_tx);
#else
    remove_transaction(working_tx);
#endif
}

static inline void cli_remove_all(void)
{
#ifdef DOGECOIN_TS
    remove_all_ts(dogecoin_transaction_context_default());
#else
    remove_all();
#endif
}

static inline int cli_get_transaction_count(void)
{
#ifdef DOGECOIN_TS
    return get_transaction_count_ts(dogecoin_transaction_context_default());
#else
    return get_transaction_count();
#endif
}

/* --------------------------------------------------------------------------
 * Index-based transaction mutation/serialization
 *
 * The CLI mutates and serializes working transactions through the index-based
 * API. In the `_ts` build the working transaction is mutex-bearing (created
 * via dogecoin_tx_new_ts() inside new_transaction_ts), so these wrappers
 * acquire the matching per-transaction lock around each operation. The base
 * index functions never re-enter these wrappers, so the lock is taken at most
 * once per call. In the legacy build the lock is absent (thread_safe == 0) and
 * the wrappers reduce to a direct call.
 * -------------------------------------------------------------------------- */
#ifdef DOGECOIN_TS
static inline dogecoin_mutex_t* cli_tx_lock_for(int txindex)
{
    working_transaction* wtx = find_transaction_ts(dogecoin_transaction_context_default(), txindex);
    if (wtx && wtx->transaction && wtx->transaction->thread_safe) {
        return &wtx->transaction->lock;
    }
    return NULL;
}
#endif

static inline int cli_save_raw_transaction(int txindex, const char* hexadecimal_transaction)
{
#ifdef DOGECOIN_TS
    dogecoin_mutex_t* lk = cli_tx_lock_for(txindex);
    if (lk) dogecoin_mutex_lock(lk);
    int r = save_raw_transaction(txindex, hexadecimal_transaction);
    if (lk) dogecoin_mutex_unlock(lk);
    return r;
#else
    return save_raw_transaction(txindex, hexadecimal_transaction);
#endif
}

static inline int cli_add_utxo(int txindex, char* hex_utxo_txid, int vout)
{
#ifdef DOGECOIN_TS
    dogecoin_mutex_t* lk = cli_tx_lock_for(txindex);
    if (lk) dogecoin_mutex_lock(lk);
    int r = add_utxo(txindex, hex_utxo_txid, vout);
    if (lk) dogecoin_mutex_unlock(lk);
    return r;
#else
    return add_utxo(txindex, hex_utxo_txid, vout);
#endif
}

static inline int cli_add_output(int txindex, char* destinationaddress, char* amount)
{
#ifdef DOGECOIN_TS
    dogecoin_mutex_t* lk = cli_tx_lock_for(txindex);
    if (lk) dogecoin_mutex_lock(lk);
    int r = add_output(txindex, destinationaddress, amount);
    if (lk) dogecoin_mutex_unlock(lk);
    return r;
#else
    return add_output(txindex, destinationaddress, amount);
#endif
}

static inline char* cli_finalize_transaction(int txindex, char* destinationaddress, char* subtractedfee,
                                             char* out_dogeamount_for_verification, char* changeaddress)
{
#ifdef DOGECOIN_TS
    dogecoin_mutex_t* lk = cli_tx_lock_for(txindex);
    if (lk) dogecoin_mutex_lock(lk);
    char* r = finalize_transaction(txindex, destinationaddress, subtractedfee,
                                   out_dogeamount_for_verification, changeaddress);
    if (lk) dogecoin_mutex_unlock(lk);
    return r;
#else
    return finalize_transaction(txindex, destinationaddress, subtractedfee,
                                out_dogeamount_for_verification, changeaddress);
#endif
}

static inline char* cli_get_raw_transaction(int txindex)
{
#ifdef DOGECOIN_TS
    dogecoin_mutex_t* lk = cli_tx_lock_for(txindex);
    if (lk) dogecoin_mutex_lock(lk);
    char* r = get_raw_transaction(txindex);
    if (lk) dogecoin_mutex_unlock(lk);
    return r;
#else
    return get_raw_transaction(txindex);
#endif
}

/* clear_transaction removes (and frees) the working transaction, so it is
   routed through the thread-safe registry rather than holding the per-object
   lock it is about to destroy. */
static inline void cli_clear_transaction(int txindex)
{
#ifdef DOGECOIN_TS
    dogecoin_transaction_context* ctx = dogecoin_transaction_context_default();
    remove_transaction_ts(ctx, find_transaction_ts(ctx, txindex));
#else
    clear_transaction(txindex);
#endif
}

/* --------------------------------------------------------------------------
 * eckey
 *
 * The key is a standalone object (never added to a registry), so the `_ts`
 * build exercises the eckey context lifecycle with a throwaway context.
 * -------------------------------------------------------------------------- */
static inline eckey* cli_eckey_from_privkey(char* private_key)
{
#ifdef DOGECOIN_TS
    dogecoin_eckey_context* kctx = dogecoin_eckey_context_new();
    eckey* key = new_eckey_from_privkey_ts(kctx, private_key);
    dogecoin_eckey_context_free(kctx);
    return key;
#else
    return new_eckey_from_privkey(private_key);
#endif
}

/* --------------------------------------------------------------------------
 * Wallet
 * -------------------------------------------------------------------------- */
static inline dogecoin_wallet* cli_wallet_init(dogecoin_ctx* ctx, const dogecoin_chainparams* chain,
                                               const char* address, const char* name,
                                               const dogecoin_wallet_opts* opts)
{
#ifdef DOGECOIN_TS
    return dogecoin_wallet_init_ts(ctx, chain, address, name, opts);
#else
    (void)ctx;
    return dogecoin_wallet_init(chain, address, name, opts);
#endif
}

static inline dogecoin_wallet* cli_wallet_new(dogecoin_ctx* ctx, const dogecoin_chainparams* params)
{
    dogecoin_wallet* wallet = dogecoin_wallet_new(params);
#ifdef DOGECOIN_TS
    if (wallet) dogecoin_wallet_enable_thread_safe(wallet, ctx);
#else
    (void)ctx;
#endif
    return wallet;
}

static inline void cli_wallet_free(dogecoin_wallet* wallet)
{
#ifdef DOGECOIN_TS
    dogecoin_wallet_free_ts(wallet);
#else
    dogecoin_wallet_free(wallet);
#endif
}

#endif /* __LIBDOGECOIN_THREADSAFE_H__ */
