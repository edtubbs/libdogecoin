# Thread safety model (libdogecoin)

This document describes which libdogecoin APIs are safe to call from multiple
threads and the concurrency mechanisms the library provides.

> Thread-safe (`_ts`) library APIs provide per-object or per-context mutex
> protection. The CLI tools ship in two flavours: the legacy single-threaded
> binaries (`such`, `sendtx`, `spvnode`) and thread-safe variants
> (`such_ts`, `sendtx_ts`, `spvnode_ts`) compiled with `-DDOGECOIN_TS=1` that
> route through the `_ts` APIs.

## Overview of the concurrency model

libdogecoin uses two complementary strategies:

1. **Thread-local state for legacy globals.** Several internal registries that
   were historically process-global are declared `DOGECOIN_THREAD_LOCAL`, so
   each thread gets its own independent copy and no locking is required:
   * the hash/map registries (`hashes`, `maps` in `include/dogecoin/map.h`),
   * the wallet UTXO list (`utxos` in `include/dogecoin/wallet.h`),
   * the default transaction context (`src/transaction.c`),
   * the hex conversion scratch buffers (`src/utils.c`),
   * the RNG function pointers / mapper (`src/random.c`).

   `DOGECOIN_THREAD_LOCAL` expands to `_Thread_local`, `__thread`, or
   `__declspec(thread)` depending on the toolchain (`include/dogecoin/dogecoin.h`).

2. **Explicit contexts and per-object mutexes for shared, mutable state.** When
   an object genuinely needs to be shared between threads, the library provides
   `_ts` constructors/operations that embed and take a `dogecoin_mutex_t`. These
   are the context objects (`dogecoin_context`, `dogecoin_eckey_context`,
   `dogecoin_transaction_context`) and the per-object `_ts` wrappers for the
   transaction builder and the wallet.

The SPV client itself runs its message loop on the single libevent IO thread;
there is no internal worker pool. Apps that want concurrency drive their own
threads and share only the `_ts`-protected objects described below.

## Mutex helpers

`include/dogecoin/dogecoin.h` provides a tiny portable mutex wrapper used by all
`_ts` objects:

* `dogecoin_mutex_init` / `dogecoin_mutex_lock` / `dogecoin_mutex_unlock` /
  `dogecoin_mutex_destroy` — inline wrappers over `pthread_mutex_*` (POSIX) or
  `CRITICAL_SECTION` (Windows). Each is a no-op when threads are unavailable or
  the mutex was never initialized, so the same code compiles cleanly with or
  without threading support.

## Context API

The context object is reference counted; the refcount is guarded by a
process-wide mutex (`src/context.c`):

* `dogecoin_context_new` / `dogecoin_ctx_new` — create a context (the `ctx`
  spelling is a short alias of the `context` spelling).
* `dogecoin_ctx_new_ts` — like `dogecoin_ctx_new` but tags the context as
  thread-safe so dependent code can branch on `dogecoin_ctx_is_thread_safe(ctx)`.
* `dogecoin_ctx_acquire` — increment the refcount before handing the context to
  another thread.
* `dogecoin_ctx_release` — decrement the refcount; the final release frees it.
* `dogecoin_ctx_is_thread_safe` — query the thread-safe flag.

## API thread-safety summary

### Safe to call from multiple threads

* The context refcount APIs above (`dogecoin_ctx_new`/`_ts`/`acquire`/`release`/
  `is_thread_safe`) — the refcount is mutex-guarded.
* `dogecoin_ecc_start` / `dogecoin_ecc_stop` — process-wide singletons, refcounted.
* Read access to chain parameters (`&dogecoin_chainparams_main`, etc.) — they
  are immutable after process start.
* Anything backed by `DOGECOIN_THREAD_LOCAL` state (hex helpers, per-thread
  hash/map registries, per-thread UTXO list) — each thread is fully isolated.

### Safe to share across threads via `_ts` variants

* eckey context (`dogecoin_eckey_context_new`/`_free`, `new_eckey_ts`,
  `new_eckey_from_privkey_ts`, `add_eckey_ts`, `find_eckey_ts`,
  `remove_eckey_ts`, `start_key_ts`).
* transaction context (`dogecoin_transaction_context_new`/`_free`,
  `new_transaction_ts`, `add_transaction_ts`, `find_transaction_ts`,
  `remove_transaction_ts`, `remove_all_ts`, `get_transaction_count_ts`,
  `start_transaction_ts`).
* transaction builder (`dogecoin_tx_new_ts`, `dogecoin_tx_add_input_ts`,
  `dogecoin_tx_add_output_ts`, `dogecoin_tx_sign_ts`,
  `dogecoin_tx_finalize_ts`, `dogecoin_tx_free_ts`).
* wallet (`dogecoin_wallet_new_ts`, `dogecoin_wallet_load_ts`,
  `dogecoin_wallet_add_hd_account_ts`, `dogecoin_wallet_get_address_ts`,
  `dogecoin_wallet_save_ts`, `dogecoin_wallet_free_ts`).

### Not thread-safe (must be single-threaded)

* `dogecoin_hdnode_*` mutation APIs.
* The non-`_ts` `working_transaction` / `eckey` slab APIs — use the `_ts`
  variants with an explicit context if you need sharing.
* SPV client objects and their per-node counters — driven on the libevent IO
  thread only.

Callers that need to mix non-TS APIs with concurrent work should keep each
non-TS object on a single owning thread.

## Code examples

### Single-threaded (legacy) usage

```c
#include <dogecoin/libdogecoin.h>

dogecoin_context* ctx = dogecoin_context_new(false, false);
if (!ctx) { /* handle error */ }
char wif[PRIVKEYWIFLEN]  = {0};
char addr[P2PKHLEN]      = {0};
size_t wif_n = sizeof(wif), addr_n = sizeof(addr);
dogecoin_generate_keypair_ex(ctx, wif, &wif_n, addr, &addr_n);
dogecoin_context_release(ctx);
```

### Multi-threaded (`_ts`) usage

```c
#include <dogecoin/libdogecoin.h>

/* One context shared between threads. The refcount is mutex-guarded. */
dogecoin_ctx* ctx = dogecoin_ctx_new_ts(false, false);

/* Each thread acquires before use and releases when it is done. */
dogecoin_ctx_acquire(ctx);
/* ... do work, e.g. call dogecoin_generate_keypair_ex(ctx, ...) ... */
dogecoin_ctx_release(ctx);

/* Final release frees the context. */
dogecoin_ctx_release(ctx);
```

### Recommended usage patterns

* Use `dogecoin_ctx_new_ts()` for concurrent apps and keep object ownership
  explicit.
* Prefer **one mutable wallet/transaction object per worker thread** whenever
  possible to minimize lock contention.
* If sharing a wallet object across threads, use only the `_ts` wallet
  functions (`dogecoin_wallet_*_ts`) and avoid mixing direct non-`_ts` wallet
  mutation in parallel.
* For signing, `dogecoin_tx_sign_ts()` acquires locks in a fixed order
  (`tx->lock` then `wallet->lock`) to avoid inversion.

### Wallet `_ts` usage example

```c
dogecoin_ctx* ctx = dogecoin_ctx_new_ts(false, false);
dogecoin_wallet* wallet = dogecoin_wallet_load_ts(ctx, "main_wallet.db");
char addr[P2PKHLEN] = {0};

dogecoin_wallet_add_hd_account_ts(wallet, 0);
dogecoin_wallet_get_address_ts(wallet, addr, sizeof(addr), 0, 0, false);
dogecoin_wallet_save_ts(wallet);
dogecoin_wallet_free_ts(wallet);
dogecoin_ctx_release(ctx);
```

### Transaction `_ts` usage example

```c
dogecoin_tx* tx = dogecoin_tx_new_ts();
dogecoin_tx_in* in = dogecoin_tx_in_new();
dogecoin_tx_out* out = dogecoin_tx_out_new();
/* initialize prevout/script/value fields before add_*_ts calls */
dogecoin_tx_add_input_ts(tx, in);
dogecoin_tx_add_output_ts(tx, out);
dogecoin_tx_in_free(in);
dogecoin_tx_out_free(out);
dogecoin_tx_sign_ts(tx, wallet, NULL);
dogecoin_tx_finalize_ts(tx);
dogecoin_tx_free_ts(tx);
```

## Thread-safe CLI variants

The build produces a thread-safe variant of each CLI alongside the legacy
binary:

| legacy        | thread-safe      |
|---------------|------------------|
| `such`        | `such_ts`        |
| `sendtx`      | `sendtx_ts`      |
| `spvnode`     | `spvnode_ts`     |

The `_ts` binaries are the same sources compiled with `-DDOGECOIN_TS=1`
(`src/cli/cli_ts.h`). In that mode the transaction-builder entry points
(`dogecoin_tx_new` / `dogecoin_tx_free`) are routed to their `_ts` variants and
the tool creates a thread-safe context at startup, printing for example:

```
such: thread-safe mode enabled
```

The legacy binaries are unaffected and print nothing extra.

## Verifying with sanitizers

```sh
# ThreadSanitizer build (autotools)
CFLAGS="-fsanitize=thread -O1 -g" \
LDFLAGS="-fsanitize=thread" \
./configure --with-net --with-tools --enable-test-passwd
make -j$(nproc)
LIBDOGECOIN_TEST_PASSWD=testpass ./tests
```

```sh
# Valgrind (helgrind) for lock-order auditing
valgrind --tool=helgrind ./tests
```

## Roadmap for `_ts` API surface

The following modules still require single-thread ownership; `_ts` variants
remain tracked here for a future pass:

* HD derivation (`dogecoin_hdnode_*`) — derivation is functional; the
  `_ts` variants should protect cached child key tables when caches exist.
* SPV client — the runloop is single-threaded on the libevent IO thread; a
  future pass could parallelize header/block validation behind an opt-in `_ts`
  entry point.

