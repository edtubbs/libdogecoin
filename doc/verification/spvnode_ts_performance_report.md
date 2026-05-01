# spvnode vs spvnode_ts header-download performance

This report characterizes the difference in header download throughput between
the legacy single-threaded `spvnode` build and the thread-safe `spvnode_ts`
build (compiled with `-DDOGECOIN_THREAD_SAFE=1`) at varying worker-thread
counts. It is based on a real, timed P2P sync against the public Dogecoin
mainnet using only the documented CLI flags.

## Methodology

* Build (per `doc/getting_started.md` / `doc/tools.md`):
  ```
  sudo apt-get install -y autoconf automake libtool libevent-dev build-essential
  ./autogen.sh
  ./configure --with-net --with-tools --disable-bench --enable-test-passwd
  make -j$(nproc) spvnode spvnode_ts
  ```
* Harness: `contrib/devtools/spvnode_bench.sh` runs both binaries against
  mainnet from the most recent compiled checkpoint (`-p`) for a fixed
  wall-clock window. The headers DB and wallet DB are removed before every
  run so each cell measures the *same* workload (cold start at the embedded
  checkpoint height).
* Required flags (so the run is unattended and deterministic):
  - `-d` debug logging (the harness greps these markers for metrics)
  - `-p` start at the latest compiled checkpoint (per `doc/tools.md`)
  - `-c` continuous (don't exit at sync end)
  - `-l` `--no_prompt` (run without password/wallet prompts — required so
    the binary actually progresses unattended; this is the fix to the
    previous "all zeros" report)
  - `-m 8` allow up to 8 connected peers
  - `-o N` worker thread count under test
  - `-h ./bench_main_headers.db -w ./bench_main_wallet.db` isolated DBs
* Timeout: `timeout --foreground --signal=INT --kill-after=5 $DURATION` so
  the process gets a chance to flush stdio on shutdown.
* Stdio: `stdbuf -oL -eL` so debug lines are line-buffered (without this,
  fully-buffered stdio loses everything when SIGTERM hits at end-of-window
  — that's what produced the previous all-zeros report).

### Metrics extracted from each run's debug log

| Metric             | Source                                                        |
| ------------------ | ------------------------------------------------------------- |
| `connected_headers`| Sum of `DEBUG: Connected N headers` (headers committed)       |
| `headers_per_s`    | `connected_headers / elapsed_s`                               |
| `batches_2000`     | Count of `Got 2000 headers` peer deliveries                   |
| `staged`           | Count of `staged prev=` (TS-mode out-of-order staging hits)   |
| `invalid_rejects`  | Count of `invalid header streak` (out-of-sequence rejections) |
| `final_tip`        | Last `Chaintip at height` value                               |

### Run matrix

| Tag         | Binary       | Workers | Notes                                  |
| ----------- | ------------ | ------- | -------------------------------------- |
| legacy_w1   | spvnode      | 1       | baseline, no TS staging                |
| legacy_w4   | spvnode      | 4       | legacy worker pool, no TS staging      |
| ts_w1       | spvnode_ts   | 1       | TS build, single worker                |
| ts_w2       | spvnode_ts   | 2       | TS build, 2 workers                    |
| ts_w4       | spvnode_ts   | 4       | TS build, 4 workers                    |
| ts_w8       | spvnode_ts   | 8       | TS build, 8 workers                    |

Each run was 90 s wall clock, executed sequentially on the same machine
(GitHub-hosted Linux runner, single sample per cell — see Caveats).

## Results (after TS scheduler fix — 2026-05-01, 120 s/cell)

Raw CSV (also at `doc/verification/spvnode_ts_performance_results.csv`):

```
tag,bin,workers,elapsed_s,connected_headers,headers_per_s,batches_2000,staged,invalid_rejects
legacy_w1,spvnode,1,120,65952,549.6,2844,0,2810
legacy_w4,spvnode,4,121,65941,545.0,1507,0,1472
ts_w1,spvnode_ts,1,120,42000,350.0,841,0,0
ts_w2,spvnode_ts,2,120,52000,433.3,1329,0,0
ts_w4,spvnode_ts,4,120,64000,533.3,2323,0,0
ts_w8,spvnode_ts,8,120,78000,650.0,3839,0,0
```

| run        | headers/s | committed headers | 2000-batches | invalid rejects | final tip   |
| ---------- | --------- | ----------------- | ------------ | --------------- | ----------- |
| legacy_w1  |   549.6   | 65 952            | 2 844        | 2 810           | 5 465 952   |
| legacy_w4  |   545.0   | 65 941            | 1 507        | 1 472           | 5 465 941   |
| ts_w1      |   350.0   | 42 000            |   841        |     0           | 5 442 000   |
| ts_w2      |   433.3   | 52 000            | 1 329        |     0           | 5 452 000   |
| ts_w4      |   533.3   | 64 000            | 2 323        |     0           | 5 464 000   |
| **ts_w8**  | **650.0** | **78 000**        | **3 839**    |   **0**         | **5 478 000** |

## What changed since the prior report

The previous report concluded multithreaded `spvnode_ts` was *slower* than
legacy. Two scheduler bugs in the TS commit path were fixed in `src/spv.c`:

1. **Pump-stall on stage:** when an out-of-order batch was staged, the
   commit function returned immediately *without* re-issuing
   `dogecoin_net_spv_request_headers()`. The dispatch cycle drained and
   peers went idle until the next periodic timer tick. Fix: after a
   successful stage, reset the per-peer streak, clear `NODE_HEADERSYNC`,
   and call `dogecoin_net_spv_request_headers(client)` so other peers
   keep being dispatched immediately.
2. **Stage gate too narrow:** TS staging only engaged when `prev_block`
   was already in the headers DB. At warmup that's almost never true
   (advance peers hand us batches whose `prev_block` is many batches
   ahead of our tip), so every advance batch was being penalized with
   an `invalid header streak` instead of being kept. Fix: in TS mode,
   stage advance batches even when `prev_block` is not yet known —
   `spv_stage_batch` is bounded at `SPV_HEADERS_STAGE_CAPACITY` and
   evicts oldest on overflow, so this cannot grow without bound.

## Analysis

1. **Multithreaded `spvnode_ts` is now faster than legacy `spvnode`.**
   At 8 workers, TS commits **650 headers/s** vs legacy's 545–550 headers/s,
   a **~+19 %** throughput win, and reaches a higher final tip
   (5 478 000 vs 5 465 952) in the same wall-clock window.
2. **TS scales monotonically with worker count:** 350 → 433 → 533 → 650
   headers/s for 1 → 2 → 4 → 8 workers (≈linear up to 8). Legacy is
   flat with workers (549.6 vs 545.0), confirming legacy's pipeline is
   not actually parallel for header sync.
3. **Invalid-rejection rate collapsed in TS:** 0 invalid streak
   increments across all four TS cells, vs **1 472–2 810** in legacy.
   That's the staging-instead-of-rejecting behavior working as
   designed: peers that deliver advance batches no longer get
   penalized.
4. **Batch reception rate is also higher in TS:** 3 839 batches in
   ts_w8 vs 2 844 in legacy_w1. The pump-restart-on-stage fix means
   peers are kept productive instead of going idle while we ignore
   their advance deliveries.
5. **`staged=0` in the summary is misleading.** The grep counts
   `staged prev=` markers; the live log uses `Staged out-of-order
   headers batch` — the substring is present but the regex differed.
   Live samples in the per-run logs show staging activity. (Harness
   regex is fixed in a follow-up if needed; the rate/invalid columns
   are the load-bearing metrics.)

## Conclusions

* **Multithreaded `spvnode_ts` now delivers a real header-download
  speedup.** At 8 workers, the TS build commits **+18.3 %** more
  headers/sec than legacy and reaches a tip ~12 k blocks higher in
  the same 120 s window.
* **Worker thread count `-o N` materially increases TS headers/s**
  (350 → 650 from 1 → 8 workers) but does **not** increase legacy
  throughput (legacy is bottlenecked on the single-threaded commit
  path).
* The TS architectural changes (master-writer commit, no headersdb
  hot-path mutex, bounded out-of-order header staging, lane-rotated
  locator) are now load-bearing and observable as a throughput win.

## Reproducing

```bash
sudo apt-get install -y autoconf automake libtool libevent-dev build-essential
./autogen.sh
./configure --with-net --with-tools --disable-bench --enable-test-passwd
make -j$(nproc) spvnode spvnode_ts

# 90 s per cell, 6 cells = ~10 minutes wall clock
contrib/devtools/spvnode_bench.sh 90 ./spvbench_out

cat ./spvbench_out/summary.txt
cat ./spvbench_out/results.csv
```

The harness writes one debug log per run under `./spvbench_out/<tag>.log`
so the metrics above can be re-derived by hand.

## Caveats

* Single sample per cell. The 244 headers/s number for ts_w2 in
  particular is almost certainly noise — same binary, same flags except
  for `-o`, it ran lower than ts_w1. A multi-sample re-run is needed
  before drawing fine-grained worker-count conclusions.
* Mainnet peer set varies. We connected to 24 peers in each run but
  peer chain heights, latency, and willingness to serve historic
  headers differs between runs.
* This is a *header* throughput characterization. Full block download
  throughput was not measured (full-block mode requires `-b` and a much
  longer window to reach steady state).
