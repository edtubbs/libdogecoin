# Thread safety model (libdogecoin)

This document describes which libdogecoin APIs are safe to call from multiple
threads and the internal concurrency design used by the SPV client. It also
describes the **thread-safe (`_ts`) build variants** of the CLI tools and the
compile-time `DOGECOIN_THREAD_SAFE` macro they are built with.

> The intent is to provide safer binaries without disturbing legacy APIs. When
> in doubt, use the `_ts` variants for concurrent or long-running processes.

## Build variants

For every CLI tool shipped by libdogecoin there is a parallel thread-safe
binary that is compiled with `DOGECOIN_THREAD_SAFE=1`:

| Legacy tool | Thread-safe tool |
|-------------|------------------|
| `such`      | `such_ts`        |
| `sendtx`    | `sendtx_ts`      |
| `spvnode`   | `spvnode_ts`     |

Both variants link the same `libdogecoin` shared library. The `_ts` variants:

* Define `DOGECOIN_THREAD_SAFE=1` at compile time so TS-only code paths in the
  CLI can be conditionally compiled.
* Call `dogecoin_spv_client_enable_thread_safe_mode()` immediately after
  constructing the SPV client. This enables the master-writer pipeline
  (documented below) and the bounded out-of-order header-batch staging ring.
* Do **not** change the on-disk format of `headers.db` or any other
  persisted state. You can alternate between the legacy and `_ts` binaries
  against the same chainstate.

To produce the `_ts` binaries alongside the legacy ones:

* Autotools: `./configure --with-net --with-tools && make`
* CMake: `cmake -B build -DWITH_NET=ON -DWITH_TOOLS=ON && cmake --build build`

## Concurrency model in the SPV client

The SPV client uses a **single master writer** combined with a small pool of
**worker producers** for header batches. Only the master thread ever writes to
the headers DB (`.headers.db`) or to the in-memory block index; workers never
touch the headers DB, the wallet, or the chain tip.

```
            ┌──────────┐           per-node parsed batches
 libevent ──▶  master  ──────────▶   ┌──────────────────┐
 IO thread  │  (main)  │             │  MPSC result ring │
            └────┬─────┘             └────────┬─────────┘
                 │                            ▲
                 ▼ commit to headers.db       │ worker produces
         ┌────────────────┐              ┌────┴────────┐
         │ out-of-order   │              │ worker pool  │
         │ staging ring   │              │  (2 threads) │
         │ (bounded, 8)   │              └──────────────┘
         └────────────────┘
```

* **Master thread.** Drains parsed results from the MPSC ring produced by the
  worker pool, calls `headers_db->connect_hdr()` to commit each header, and on
  every tip advance attempts to drain any batches that had been staged for
  out-of-order delivery. This is the *only* thread that writes the headers DB.
* **Worker pool.** Runs lightweight payload prevalidation (framing/size
  checks) and copies the parsed batch into an owned buffer that is handed to
  the master. Workers never touch `headers_db`, the wallet, or the chain
  state. See `src/spv.c::spv_headers_pipeline_worker`.
* **Out-of-order staging.** A bounded ring of up to
  `SPV_HEADERS_STAGE_CAPACITY` (8) batches keyed by the first header's
  `prev_block`. When a batch arrives whose `prev_block` is known in the DB
  but is not the current tip (typical for peers that announce ahead of the
  current chain), the batch is buffered instead of being rejected with an
  `invalid (not in sequence)` streak. After every successful tip advance the
  master drains any staged batch whose `prev_block` matches the new tip,
  recursively. See `src/spv.c::spv_stage_batch` and
  `src/spv.c::spv_stage_drain_for_tip`.

This preserves the existing btree-based reorg semantics: genuine reorgs are
still handled by the normal `connect_hdr`/disconnect-tip path; the staging
ring only addresses innocuous gap-fill caused by concurrent peers.

### What the master-writer model implies

* **No headers DB lock is needed — headersdb is single-writer by contract.**
  The SPV master thread is the only writer, and legacy tools (`spvnode`,
  `such`, `sendtx`) are single-threaded, so the previous `sync_lock` has
  been removed from `src/headersdb_file.c`. The `sync_lock` field is kept
  as a reserved `void*` to preserve ABI for callers that embed
  `dogecoin_headers_db` in their own structures; the field is never
  dereferenced. If a future caller needs to share a single
  `dogecoin_headers_db` across threads, provide a `*_ts` wrapper that
  wraps your own mutex around the call site rather than re-adding a lock
  inside the DB.
* **Workers do not see partially-written DB state.** They only produce parsed
  batches; they cannot race with the master.
* **No mid-batch staging.** If a batch fails structurally mid-way (bad PoW,
  truncation, etc.), it is still rejected and the peer gets a streak. Only
  whole-batch staging based on the first-header `prev_block` is attempted.

## API thread-safety summary

### Safe to call from multiple threads

* `dogecoin_ctx_new` / `dogecoin_ctx_new_ts` / `dogecoin_ctx_acquire` /
  `dogecoin_ctx_release` — short-form aliases over `dogecoin_context_*`. The
  refcount is guarded by a process-wide mutex (`src/context.c`).
  `dogecoin_ctx_new_ts()` additionally tags the context as thread-safe so
  dependent subsystems can branch on `dogecoin_ctx_is_thread_safe(ctx)` to
  select per-object locking when needed.
* `dogecoin_headersdb_*` read APIs (`find`, `getchaintip`,
  `fill_blocklocator_tip`) on a DB owned by one writer — the DB itself is
  single-writer; concurrent reads from other threads are safe only while
  the writer is not committing. If you need true multi-reader safety,
  serialize calls externally (e.g. with your own `rwlock`).
* `dogecoin_ecc_start` / `dogecoin_ecc_stop` — process-wide singletons,
  refcounted.
* Read access to chain parameters (`&dogecoin_chainparams_main`, etc.) — they
  are immutable at process start.

### Safe only in the `_ts` binaries (or after opt-in at runtime)

* `dogecoin_spv_client_runloop` combined with out-of-order batch delivery —
  call `dogecoin_spv_client_enable_thread_safe_mode(client)` right after
  `dogecoin_spv_client_new()` to activate the staging ring.

### Not thread-safe (must be single-threaded)

* `dogecoin_hdnode_*` mutation APIs.
* `working_transaction` / `eckey` slab APIs unless used via their `*_ts`
  variants that take an explicit context (`new_transaction_ts`,
  `new_eckey_ts`, etc.).
* Per-node SPV counters (`hints`, `invalid_header_streak`) — accessed on the
  libevent IO thread only.

Callers that need to mix these APIs with concurrent work should keep each
non-TS object on a single owning thread.

## Enabling thread-safe mode at runtime from the library

If you link `libdogecoin` into your own program you can enable the TS behavior
without recompiling:

```c
#include <dogecoin/spv.h>

dogecoin_spv_client* client = dogecoin_spv_client_new(...);
dogecoin_spv_client_enable_thread_safe_mode(client);
```

This is what `spvnode_ts` does on startup.

## Verifying the pipeline

`spvnode_ts` (run with `-d`) logs lines such as:

```
SPV thread-safe mode enabled: master-writer pipeline with 8 out-of-order staging slots
Staged out-of-order headers batch from node 17 (count=2000, staged=1)
Draining staged headers batch from node 17 (count=2000, remaining_staged=0)
Chaintip at height ...
```

An example capture is kept under
`doc/verification/spvnode_ts_phase2_thread_safe_sample.txt`.

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

/* One context shared between threads. The refcount is atomic; per-object
 * subsystems can be added under the same TS umbrella as they grow _ts
 * variants. */
dogecoin_ctx* ctx = dogecoin_ctx_new_ts(false, false);

/* Each thread acquires before use and releases when it is done. */
dogecoin_ctx_acquire(ctx);
/* ... do work, e.g. call dogecoin_generate_keypair_ex(ctx, ...) ... */
dogecoin_ctx_release(ctx);

/* Final release frees the context. */
dogecoin_ctx_release(ctx);
```

`dogecoin_ctx_new_ts()` returns the same `dogecoin_context` type as
`dogecoin_context_new()`; the only behavioural difference today is the
`thread_safe` flag, which dependent subsystems can branch on as their `_ts`
variants land. The non-`_ts` constructor remains thread-compatible (any
single owning thread may use it) and the refcount itself is always atomic.

## Roadmap for `_ts` API surface

The following modules still require single-thread ownership; `_ts` variants
remain tracked here for a future pass:

* HD derivation (`dogecoin_hdnode_*`) — derivation is functional; the
  `_ts` variants should protect cached child key tables when caches exist.

## Wallet and transaction `_ts` wrappers

The wallet and transaction builder now expose explicit `_ts` variants that add
internal per-object mutex protection in `DOGECOIN_THREAD_SAFE` builds:

* Wallet: `dogecoin_wallet_new_ts`, `dogecoin_wallet_load_ts`,
  `dogecoin_wallet_add_hd_account_ts`, `dogecoin_wallet_get_address_ts`,
  `dogecoin_wallet_save_ts`, `dogecoin_wallet_free_ts`.
* Transaction builder: `dogecoin_tx_new_ts`, `dogecoin_tx_add_input_ts`,
  `dogecoin_tx_add_output_ts`, `dogecoin_tx_sign_ts`,
  `dogecoin_tx_finalize_ts`, `dogecoin_tx_free_ts`.

Legacy non-`_ts` APIs remain unchanged for backwards compatibility.

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

## Verifying with sanitizers

Recommended local invocations once the full `_ts` surface lands:

```sh
# ThreadSanitizer build (autotools)
CFLAGS="-fsanitize=thread -O1 -g" \
LDFLAGS="-fsanitize=thread" \
./configure --with-net --with-tools --enable-test-passwd
make -j$(nproc)
LIBDOGECOIN_TEST_PASSWD=testpass ./test/tests
```

```sh
# Valgrind (helgrind) for lock-order auditing
valgrind --tool=helgrind ./tests
```
