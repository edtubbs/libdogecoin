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
 * Shared compile-time switch for the thread-safe (`_ts`) CLI variants.
 *
 * The same CLI sources are compiled twice: once into the legacy binary
 * (`such`, `sendtx`, `spvnode`) and once into a thread-safe binary
 * (`such_ts`, `sendtx_ts`, `spvnode_ts`) that defines DOGECOIN_TS. When
 * DOGECOIN_TS is set the directly substitutable transaction-builder entry
 * points are routed to their `_ts` variants, which take a per-object mutex
 * (see doc/thread_safety.md). The non-`_ts` build is unaffected.
 */

#ifndef __LIBDOGECOIN_CLI_TS_H__
#define __LIBDOGECOIN_CLI_TS_H__

#include <dogecoin/dogecoin.h>

#ifdef DOGECOIN_TS

/* Transaction builder: same signatures, mutex-protected variants. */
#define dogecoin_tx_new        dogecoin_tx_new_ts
#define dogecoin_tx_free       dogecoin_tx_free_ts

#define DOGECOIN_CLI_TS_ENABLED 1
#define DOGECOIN_CLI_TS_LABEL   "thread-safe"

/* Initialize and tear down a thread-safe libdogecoin context at startup so the
 * `_ts` binaries exercise the thread-safe context API (dogecoin_ctx_new_ts /
 * dogecoin_ctx_is_thread_safe / dogecoin_ctx_release) and announce the mode. */
#define DOGECOIN_CLI_TS_ANNOUNCE(tool)                                              \
    do {                                                                            \
        dogecoin_ctx* _ts_ctx = dogecoin_ctx_new_ts(false, false);                  \
        printf("%s: thread-safe mode %s\n", (tool),                                 \
               dogecoin_ctx_is_thread_safe(_ts_ctx) ? "enabled" : "unavailable");   \
        dogecoin_ctx_release(_ts_ctx);                                              \
    } while (0)

#else

#define DOGECOIN_CLI_TS_ENABLED 0
#define DOGECOIN_CLI_TS_LABEL   "single-threaded"
#define DOGECOIN_CLI_TS_ANNOUNCE(tool) do { (void)(tool); } while (0)

#endif /* DOGECOIN_TS */

#endif /* __LIBDOGECOIN_CLI_TS_H__ */
