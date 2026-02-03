/**
 * Copyright (c) 2015-2016 The Bitcoin Core developers
 * Copyright (c) 2024-2026 edtubbs
 * Copyright (c) 2024-2026 The Dogecoin Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <float.h>

#ifndef _WIN32
#include <sys/time.h>
#endif

#ifdef _WIN32
#include <windows.h>
#elif defined(__arm__) || defined(__aarch64__)
#include <time.h>
#else
#include <x86intrin.h>
#endif

/* libdogecoin */
#include <dogecoin/dogecoin.h>    /* brings public API, incl. ECC */
#include <dogecoin/sha2.h>
#include <dogecoin/scrypt.h>
#include <dogecoin/tx.h>
#include <dogecoin/mem.h>
#include <dogecoin/random.h>
#include <dogecoin/utils.h>
#include <dogecoin/pqc_falcon.h>
#include <dogecoin/ecc.h>

#define BUFFER_SIZE (1000 * 1000)
#define HASH_SIZE 32

typedef struct {
    double start, end, minTime, maxTime, totalTime;
    uint64_t startCycles, endCycles, minCycles, maxCycles, totalCycles, count;
    uint8_t *input;
    uint8_t *output;
} benchmark_context;

/* ---- timing helpers ---- */
static double gettimedouble(void) {
#ifdef _WIN32
    return (double)GetTickCount64() / 1000.0;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_usec * 0.000001 + tv.tv_sec;
#endif
}

static uint64_t perf_cpucycles(void) {
#ifdef _WIN32
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return (uint64_t)li.QuadPart;
#elif defined(__arm__) || defined(__aarch64__)
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)(ts.tv_sec * 1000000000ULL + ts.tv_nsec);
#else
    return (uint64_t)__rdtsc();
#endif
}

/* ---- harness ---- */
typedef void (*bench_fn)(benchmark_context *);

static void run_benchmark(bench_fn fn, const char *name) {
    benchmark_context ctx;
    ctx.input = (uint8_t*)calloc(BUFFER_SIZE, sizeof(uint8_t));
    ctx.output = (uint8_t*)malloc(HASH_SIZE);
    ctx.minTime = DBL_MAX;
    ctx.maxTime = DBL_MIN;
    ctx.minCycles = UINT64_MAX;
    ctx.maxCycles = 0;
    ctx.totalTime = 0.0;
    ctx.totalCycles = 0;
    ctx.count = 0;

    ctx.start = gettimedouble();
    ctx.startCycles = perf_cpucycles();

    while (1) {
        fn(&ctx);

        double time = ctx.end - ctx.start;
        uint64_t cycles = ctx.endCycles - ctx.startCycles;

        ctx.count++;
        if (time   < ctx.minTime)   ctx.minTime   = time;
        if (time   > ctx.maxTime)   ctx.maxTime   = time;
        if (cycles < ctx.minCycles) ctx.minCycles = cycles;
        if (cycles > ctx.maxCycles) ctx.maxCycles = cycles;

        if (ctx.totalTime > 3.0) break;

        ctx.start = ctx.end;
        ctx.startCycles = ctx.endCycles;
    }

    printf("%-12s %-8lu %-10.6f %-10.6f %-10.6f %-12lu %-12lu %-12lu\n",
           name,
           (unsigned long)ctx.count,
           ctx.minTime,
           ctx.maxTime,
           (ctx.count ? ctx.totalTime / (double)ctx.count : 0.0),
           ctx.minCycles,
           ctx.maxCycles,
           (ctx.count ? ctx.totalCycles / ctx.count : 0ULL));

    free(ctx.input);
    free(ctx.output);
}

/* ---- baselines ---- */

static void sha256_bench(benchmark_context *ctx) {
    sha256_raw(ctx->input, BUFFER_SIZE, ctx->output);
    ctx->end = gettimedouble();
    ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start;
    ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void scrypt_bench(benchmark_context *ctx) {
    scrypt_1024_1_1_256((char *)ctx->input, (char *)ctx->output);
    ctx->end = gettimedouble();
    ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start;
    ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

/* ---- OP_RETURN commit (32 bytes) using tx helpers ---- */

static void opret_commit_bench(benchmark_context *ctx) {
    uint8_t commit[32];
    for (int i = 0; i < 32; ++i) commit[i] = (uint8_t)i;

    dogecoin_tx* tx = dogecoin_tx_new();
    dogecoin_tx_add_falcon512_commit(tx, commit);

    uint8_t out[32];
    (void)dogecoin_tx_extract_falcon512_commit(tx, out);
    dogecoin_tx_free(tx);

    ctx->end = gettimedouble();
    ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start;
    ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

/* ---- Falcon (requires --enable-liboqs) ---- */
#ifdef USE_LIBOQS
static void falcon_keypair_bench(benchmark_context *ctx) {
    uint8_t *pk = NULL, *sk = NULL; size_t pk_len = 0, sk_len = 0;
    (void)dogecoin_falcon512_keypair(&pk, &pk_len, &sk, &sk_len);
    if (pk) dogecoin_free(pk);
    if (sk) dogecoin_free(sk);
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void falcon_sign_bench(benchmark_context *ctx) {
    static uint8_t *pk = NULL, *sk = NULL; static size_t pk_len = 0, sk_len = 0;
    if (!pk || !sk) (void)dogecoin_falcon512_keypair(&pk, &pk_len, &sk, &sk_len);
    uint8_t *sig = NULL; size_t sig_len = 0;
    (void)dogecoin_falcon512_sign(sk, sk_len, ctx->input, 32, &sig, &sig_len);
    if (sig) dogecoin_free(sig);
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void falcon_verify_bench(benchmark_context *ctx) {
    static uint8_t *pk = NULL, *sk = NULL, *sig = NULL;
    static size_t pk_len = 0, sk_len = 0, sig_len = 0;
    static int primed = 0;
    if (!primed) {
        (void)dogecoin_falcon512_keypair(&pk, &pk_len, &sk, &sk_len);
        (void)dogecoin_falcon512_sign(sk, sk_len, ctx->input, 32, &sig, &sig_len);
        primed = 1;
    }
    (void)dogecoin_falcon512_verify(pk, pk_len, ctx->input, 32, sig, sig_len);
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void falcon_commit_bytes_bench(benchmark_context *ctx) {
    static uint8_t *pk = NULL, *sk = NULL, *sig = NULL;
    static size_t pk_len = 0, sk_len = 0, sig_len = 0;
    static int primed = 0;
    if (!primed) {
        (void)dogecoin_falcon512_keypair(&pk, &pk_len, &sk, &sk_len);
        (void)dogecoin_falcon512_sign(sk, sk_len, ctx->input, 32, &sig, &sig_len);
        primed = 1;
    }
    uint8_t commit32[32];
    (void)dogecoin_falcon512_commit_bytes(pk, pk_len, sig, sig_len, commit32);
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}
#endif /* USE_LIBOQS */

/* ---- secp256k1 via ECC module (no direct secp includes) ---- */

static void make_valid_privkey(uint8_t sk[32]) {
    /* try random bytes until valid */
    while (1) {
        dogecoin_random_bytes(sk, 32, 0);
        if (dogecoin_ecc_verify_privatekey(sk)) return;
        sk[0] ^= 0x01; /* nudge */
        if (dogecoin_ecc_verify_privatekey(sk)) return;
    }
}

static void make_msg32(const uint8_t *src, uint8_t out32[32]) {
    sha256_raw(src, 64, out32);
}

static void secp_keypair_bench(benchmark_context *ctx) {
    /* keypair = generate priv + derive compressed pub */
    uint8_t sk[32]; make_valid_privkey(sk);
    uint8_t pk[33]; size_t pklen = 33;
    dogecoin_ecc_get_pubkey(sk, pk, &pklen, true);
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void secp_sign_bench(benchmark_context *ctx) {
    /* reuse one key for stable sign throughput */
    static int primed = 0;
    static uint8_t sk[32];
    if (!primed) { make_valid_privkey(sk); primed = 1; }

    uint8_t msg32[32]; make_msg32(ctx->input, msg32);
    unsigned char sigder[80]; size_t siglen = sizeof(sigder);
    (void)dogecoin_ecc_sign(sk, msg32, sigder, &siglen);
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void secp_verify_bench(benchmark_context *ctx) {
    /* prime msg/pair/sig once, then verify repeatedly */
    static int primed = 0;
    static uint8_t pk[33]; static size_t pklen = 33;
    static uint8_t msg32[32];
    static unsigned char sigder[80]; static size_t siglen = 0;

    if (!primed) {
        uint8_t sk[32]; make_valid_privkey(sk);
        pklen = 33; dogecoin_ecc_get_pubkey(sk, pk, &pklen, true);
        make_msg32(ctx->input, msg32);
        siglen = sizeof(sigder);
        (void)dogecoin_ecc_sign(sk, msg32, sigder, &siglen);
        primed = 1;
    }

    (void)dogecoin_ecc_verify_sig(pk, true, msg32, sigder, siglen);
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

/* ---- main ---- */

int main(void) {
    /* init ECC once for secp benches */
    (void)dogecoin_ecc_start();

    printf("%-12s %-8s %-10s %-10s %-10s %-12s %-12s %-12s\n",
           "#Benchmark", "Count", "Min Time", "Max Time", "Avg Time",
           "Min Cycles", "Max Cycles", "Avg Cycles");

    /* baselines */
    run_benchmark(sha256_bench,       "SHA256");
    run_benchmark(scrypt_bench,       "Scrypt");

    /* commit embed/extract */
    run_benchmark(opret_commit_bench, "OPRET-32");

#ifdef USE_LIBOQS
    run_benchmark(falcon_keypair_bench,      "Falcon-kp");
    run_benchmark(falcon_sign_bench,         "Falcon-sig");
    run_benchmark(falcon_verify_bench,       "Falcon-ver");
    run_benchmark(falcon_commit_bytes_bench, "Falcon-cmt");
#else
    printf("%-12s %s\n", "Falcon-kp",  "skipped (liboqs disabled)");
    printf("%-12s %s\n", "Falcon-sig", "skipped (liboqs disabled)");
    printf("%-12s %s\n", "Falcon-ver", "skipped (liboqs disabled)");
    printf("%-12s %s\n", "Falcon-cmt", "skipped (liboqs disabled)");
#endif

    /* secp256k1 via ECC module */
    run_benchmark(secp_keypair_bench, "secp-kp");
    run_benchmark(secp_sign_bench,    "secp-sig");
    run_benchmark(secp_verify_bench,  "secp-ver");

    printf("\nOptions:\n");
#if defined(__AVX2__) && USE_AVX2
    printf("AVX2 SHA256\n");
#endif
#if defined(__SSE2__) && USE_SSE
    printf("SSE SHA256\n");
#endif
#if defined(__SSE2__) && USE_SSE2
    printf("SSE2 Scrypt\n");
#endif
#ifdef USE_LIBOQS
    printf("liboqs Falcon-512\n");
#endif
    printf("secp256k1 via ECC module\n");

    dogecoin_ecc_stop();
    return 0;
}
