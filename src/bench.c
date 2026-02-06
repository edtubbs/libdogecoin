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

    printf("%-16s %-8lu %-10.6f %-10.6f %-10.6f %-12lu %-12lu %-12llu\n",
           name,
           (unsigned long)ctx.count,
           ctx.minTime,
           ctx.maxTime,
           (ctx.count ? ctx.totalTime / (double)ctx.count : 0.0),
           (unsigned long)ctx.minCycles,
           (unsigned long)ctx.maxCycles,
           (unsigned long long)(ctx.count ? ctx.totalCycles / ctx.count : 0ULL));

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
static void falcon512_keypair_bench(benchmark_context *ctx) {
    uint8_t *pk = NULL, *sk = NULL; size_t pk_len = 0, sk_len = 0;
    (void)dogecoin_falcon512_keypair(&pk, &pk_len, &sk, &sk_len);
    if (pk) dogecoin_free(pk);
    if (sk) dogecoin_free(sk);
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void falcon512_sign_bench(benchmark_context *ctx) {
    static uint8_t *pk = NULL, *sk = NULL; static size_t pk_len = 0, sk_len = 0;
    if (!pk || !sk) (void)dogecoin_falcon512_keypair(&pk, &pk_len, &sk, &sk_len);
    uint8_t *sig = NULL; size_t sig_len = 0;
    (void)dogecoin_falcon512_sign(sk, sk_len, ctx->input, 32, &sig, &sig_len);
    if (sig) dogecoin_free(sig);
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void falcon512_verify_bench(benchmark_context *ctx) {
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

static void falcon512_commit_bytes_bench(benchmark_context *ctx) {
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

/* ---- Other PQC Algorithms (Dilithium, SPHINCS+) ---- */
#include <oqs/oqs.h>

/* Generic PQC benchmark helper */
typedef struct {
    const char *alg_name;
    OQS_SIG *alg;
    uint8_t *pk;
    uint8_t *sk;
    uint8_t *sig;
    size_t pk_len;
    size_t sk_len;
    size_t sig_len;
    int primed;
} pqc_bench_state;

static pqc_bench_state dilithium2_state = {0};
static pqc_bench_state dilithium3_state = {0};
static pqc_bench_state dilithium5_state = {0};
static pqc_bench_state sphincs_shake_128s_state = {0};
static pqc_bench_state sphincs_shake_128f_state = {0};

/* Helper to check if a PQC algorithm is available by name */
static dogecoin_bool pqc_alg_is_available(const char *alg_name) {
    OQS_SIG *alg = OQS_SIG_new(alg_name);
    if (alg) {
        OQS_SIG_free(alg);
        return true;
    }
    return false;
}

static void pqc_init_state(pqc_bench_state *state, const char *alg_name) {
    if (state->primed) return;
    state->alg_name = alg_name;
    state->alg = OQS_SIG_new(alg_name);
    if (!state->alg) return;
    
    state->pk = (uint8_t*)dogecoin_malloc(state->alg->length_public_key);
    state->sk = (uint8_t*)dogecoin_malloc(state->alg->length_secret_key);
    state->sig = (uint8_t*)dogecoin_malloc(state->alg->length_signature);
    
    if (!state->pk || !state->sk || !state->sig) {
        if (state->pk) dogecoin_free(state->pk);
        if (state->sk) dogecoin_free(state->sk);
        if (state->sig) dogecoin_free(state->sig);
        OQS_SIG_free(state->alg);
        state->alg = NULL;
        return;
    }
    
    OQS_STATUS st = OQS_SIG_keypair(state->alg, state->pk, state->sk);
    if (st != OQS_SUCCESS) {
        dogecoin_free(state->pk);
        dogecoin_free(state->sk);
        dogecoin_free(state->sig);
        OQS_SIG_free(state->alg);
        state->alg = NULL;
        return;
    }
    
    state->primed = 1;
}

static void pqc_keypair_bench_generic(benchmark_context *ctx, const char *alg_name) {
    OQS_SIG* alg = OQS_SIG_new(alg_name);
    if (!alg) return;
    
    uint8_t *pk = (uint8_t*)dogecoin_malloc(alg->length_public_key);
    uint8_t *sk = (uint8_t*)dogecoin_malloc(alg->length_secret_key);
    
    if (pk && sk) {
        OQS_SIG_keypair(alg, pk, sk);
        dogecoin_free(pk);
        dogecoin_free(sk);
    }
    
    OQS_SIG_free(alg);
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void pqc_sign_bench_generic(benchmark_context *ctx, pqc_bench_state *state, const char *alg_name) {
    if (!state->primed) pqc_init_state(state, alg_name);
    if (!state->alg) return;
    
    size_t sig_len = 0;
    OQS_SIG_sign(state->alg, state->sig, &sig_len, ctx->input, 32, state->sk);
    
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void pqc_verify_bench_generic(benchmark_context *ctx, pqc_bench_state *state, const char *alg_name) {
    if (!state->primed) {
        pqc_init_state(state, alg_name);
        if (state->alg) {
            size_t sig_len = 0;
            OQS_SIG_sign(state->alg, state->sig, &sig_len, ctx->input, 32, state->sk);
        }
    }
    if (!state->alg) return;
    
    OQS_SIG_verify(state->alg, ctx->input, 32, state->sig, state->alg->length_signature, state->pk);
    
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void pqc_commit_bench_generic(benchmark_context *ctx, pqc_bench_state *state, const char *alg_name) {
    if (!state->primed) {
        pqc_init_state(state, alg_name);
        if (state->alg) {
            size_t sig_len = 0;
            OQS_SIG_sign(state->alg, state->sig, &sig_len, ctx->input, 32, state->sk);
        }
    }
    if (!state->alg) return;
    
    uint8_t commit32[32];
    sha256_context sha_ctx;
    sha256_init(&sha_ctx);
    sha256_write(&sha_ctx, state->pk, state->alg->length_public_key);
    sha256_write(&sha_ctx, state->sig, state->alg->length_signature);
    sha256_finalize(&sha_ctx, commit32);
    
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

/* Dilithium2 benchmarks - use string names for compatibility */
static void dilithium2_keypair_bench(benchmark_context *ctx) {
    pqc_keypair_bench_generic(ctx, "Dilithium2");
}
static void dilithium2_sign_bench(benchmark_context *ctx) {
    pqc_sign_bench_generic(ctx, &dilithium2_state, "Dilithium2");
}
static void dilithium2_verify_bench(benchmark_context *ctx) {
    pqc_verify_bench_generic(ctx, &dilithium2_state, "Dilithium2");
}
static void dilithium2_commit_bench(benchmark_context *ctx) {
    pqc_commit_bench_generic(ctx, &dilithium2_state, "Dilithium2");
}

/* Dilithium3 benchmarks - use string names for compatibility */
static void dilithium3_keypair_bench(benchmark_context *ctx) {
    pqc_keypair_bench_generic(ctx, "Dilithium3");
}
static void dilithium3_sign_bench(benchmark_context *ctx) {
    pqc_sign_bench_generic(ctx, &dilithium3_state, "Dilithium3");
}
static void dilithium3_verify_bench(benchmark_context *ctx) {
    pqc_verify_bench_generic(ctx, &dilithium3_state, "Dilithium3");
}
static void dilithium3_commit_bench(benchmark_context *ctx) {
    pqc_commit_bench_generic(ctx, &dilithium3_state, "Dilithium3");
}

/* Dilithium5 benchmarks - use string names for compatibility */
static void dilithium5_keypair_bench(benchmark_context *ctx) {
    pqc_keypair_bench_generic(ctx, "Dilithium5");
}
static void dilithium5_sign_bench(benchmark_context *ctx) {
    pqc_sign_bench_generic(ctx, &dilithium5_state, "Dilithium5");
}
static void dilithium5_verify_bench(benchmark_context *ctx) {
    pqc_verify_bench_generic(ctx, &dilithium5_state, "Dilithium5");
}
static void dilithium5_commit_bench(benchmark_context *ctx) {
    pqc_commit_bench_generic(ctx, &dilithium5_state, "Dilithium5");
}

/* SPHINCS+ SHAKE-128s benchmarks - use string names for compatibility */
static void sphincs_shake_128s_keypair_bench(benchmark_context *ctx) {
    pqc_keypair_bench_generic(ctx, "SPHINCS+-SHAKE-128s-simple");
}
static void sphincs_shake_128s_sign_bench(benchmark_context *ctx) {
    pqc_sign_bench_generic(ctx, &sphincs_shake_128s_state, "SPHINCS+-SHAKE-128s-simple");
}
static void sphincs_shake_128s_verify_bench(benchmark_context *ctx) {
    pqc_verify_bench_generic(ctx, &sphincs_shake_128s_state, "SPHINCS+-SHAKE-128s-simple");
}
static void sphincs_shake_128s_commit_bench(benchmark_context *ctx) {
    pqc_commit_bench_generic(ctx, &sphincs_shake_128s_state, "SPHINCS+-SHAKE-128s-simple");
}

/* SPHINCS+ SHAKE-128f benchmarks - use string names for compatibility */
static void sphincs_shake_128f_keypair_bench(benchmark_context *ctx) {
    pqc_keypair_bench_generic(ctx, "SPHINCS+-SHAKE-128f-simple");
}
static void sphincs_shake_128f_sign_bench(benchmark_context *ctx) {
    pqc_sign_bench_generic(ctx, &sphincs_shake_128f_state, "SPHINCS+-SHAKE-128f-simple");
}
static void sphincs_shake_128f_verify_bench(benchmark_context *ctx) {
    pqc_verify_bench_generic(ctx, &sphincs_shake_128f_state, "SPHINCS+-SHAKE-128f-simple");
}
static void sphincs_shake_128f_commit_bench(benchmark_context *ctx) {
    pqc_commit_bench_generic(ctx, &sphincs_shake_128f_state, "SPHINCS+-SHAKE-128f-simple");
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

    printf("%-16s %-8s %-10s %-10s %-10s %-12s %-12s %-12s\n",
           "#Benchmark", "Count", "Min Time", "Max Time", "Avg Time",
           "Min Cycles", "Max Cycles", "Avg Cycles");
    printf("================================================================================================================================\n");

    /* baselines */
    printf("\n--- Classical Baselines ---\n");
    run_benchmark(sha256_bench,       "SHA256");
    run_benchmark(scrypt_bench,       "Scrypt");

    /* commit embed/extract */
    printf("\n--- OP_RETURN Commit (for off-chain SPV verification) ---\n");
    run_benchmark(opret_commit_bench, "OPRET-32");

    /* secp256k1 via ECC module - classical baseline for comparison */
    printf("\n--- secp256k1 (Classical ECC Baseline) ---\n");
    run_benchmark(secp_keypair_bench, "secp-kp");
    run_benchmark(secp_sign_bench,    "secp-sig");
    run_benchmark(secp_verify_bench,  "secp-ver");

#ifdef USE_LIBOQS
    /* Falcon-512 - primary PQC baseline */
    printf("\n--- Falcon-512 (Primary PQC Baseline) ---\n");
    run_benchmark(falcon512_keypair_bench,      "Falcon512-kp");
    run_benchmark(falcon512_sign_bench,         "Falcon512-sig");
    run_benchmark(falcon512_verify_bench,       "Falcon512-ver");
    run_benchmark(falcon512_commit_bytes_bench, "Falcon512-cmt");

    /* Dilithium variants - compare against Falcon */
    printf("\n--- Dilithium (NIST PQC Standard) - Compare vs Falcon ---\n");
    if (pqc_alg_is_available("Dilithium2")) {
        run_benchmark(dilithium2_keypair_bench, "Dilith2-kp");
        run_benchmark(dilithium2_sign_bench,    "Dilith2-sig");
        run_benchmark(dilithium2_verify_bench,  "Dilith2-ver");
        run_benchmark(dilithium2_commit_bench,  "Dilith2-cmt");
    } else {
        printf("%-16s %s\n", "Dilithium2", "not available");
    }
    
    if (pqc_alg_is_available("Dilithium3")) {
        run_benchmark(dilithium3_keypair_bench, "Dilith3-kp");
        run_benchmark(dilithium3_sign_bench,    "Dilith3-sig");
        run_benchmark(dilithium3_verify_bench,  "Dilith3-ver");
        run_benchmark(dilithium3_commit_bench,  "Dilith3-cmt");
    } else {
        printf("%-16s %s\n", "Dilithium3", "not available");
    }
    
    if (pqc_alg_is_available("Dilithium5")) {
        run_benchmark(dilithium5_keypair_bench, "Dilith5-kp");
        run_benchmark(dilithium5_sign_bench,    "Dilith5-sig");
        run_benchmark(dilithium5_verify_bench,  "Dilith5-ver");
        run_benchmark(dilithium5_commit_bench,  "Dilith5-cmt");
    } else {
        printf("%-16s %s\n", "Dilithium5", "not available");
    }

    /* SPHINCS+ variants - compare against Falcon */
    printf("\n--- SPHINCS+ (Hash-based) - Compare vs Falcon ---\n");
    if (pqc_alg_is_available("SPHINCS+-SHAKE-128s-simple")) {
        run_benchmark(sphincs_shake_128s_keypair_bench, "SPHNCS128s-kp");
        run_benchmark(sphincs_shake_128s_sign_bench,    "SPHNCS128s-sig");
        run_benchmark(sphincs_shake_128s_verify_bench,  "SPHNCS128s-ver");
        run_benchmark(sphincs_shake_128s_commit_bench,  "SPHNCS128s-cmt");
    } else {
        printf("%-16s %s\n", "SPHINCS128s", "not available");
    }
    
    if (pqc_alg_is_available("SPHINCS+-SHAKE-128f-simple")) {
        run_benchmark(sphincs_shake_128f_keypair_bench, "SPHNCS128f-kp");
        run_benchmark(sphincs_shake_128f_sign_bench,    "SPHNCS128f-sig");
        run_benchmark(sphincs_shake_128f_verify_bench,  "SPHNCS128f-ver");
        run_benchmark(sphincs_shake_128f_commit_bench,  "SPHNCS128f-cmt");
    } else {
        printf("%-16s %s\n", "SPHINCS128f", "not available");
    }
#else
    printf("\n--- PQC Algorithms (liboqs disabled) ---\n");
    printf("%-16s %s\n", "Falcon512",    "skipped (liboqs disabled)");
    printf("%-16s %s\n", "Dilithium",    "skipped (liboqs disabled)");
    printf("%-16s %s\n", "SPHINCS+",     "skipped (liboqs disabled)");
#endif

    printf("\n================================================================================================================================\n");
    printf("\nBuild Options:\n");
#if defined(__AVX2__) && USE_AVX2
    printf("  AVX2 SHA256\n");
#endif
#if defined(__SSE2__) && USE_SSE
    printf("  SSE SHA256\n");
#endif
#if defined(__SSE2__) && USE_SSE2
    printf("  SSE2 Scrypt\n");
#endif
#ifdef USE_LIBOQS
    printf("  liboqs enabled:\n");
    printf("    - Falcon-512 (primary PQC baseline)\n");
    printf("    - Dilithium-2/3/5 (NIST standard, lattice-based)\n");
    printf("    - SPHINCS+ (hash-based, conservative security)\n");
#endif
    printf("  secp256k1 (classical ECC baseline)\n");
    printf("\nNote: All PQC algorithms use OP_RETURN commits for off-chain SPV verification\n");

    dogecoin_ecc_stop();
    return 0;
}
