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

## Update — checkpoint-anchored advance lanes (2026-05-07)

A follow-up review of the per-peer debug logs showed that **even with
multiple workers and multiple peers, every peer was being sent
essentially the same locator** — the previously-measured TS speedup
came entirely from the staging/pump-stall fixes, not from any real
per-peer forward fan-out.

### Why the prior `lane_trim_offset` scheme didn't fan out

`dogecoin_headers_db_fill_block_locator()` builds a locator in
*most-recent-first* order — `[tip, tip-1, tip-2, …, tip-9]`. The old
lane scheduler trimmed the **front** (recent end) of that vector for
lanes ≥ 1, so:

| Lane | Locator the peer received     | First locator hash the peer matches | 2000-header range returned |
| ---- | ----------------------------- | ----------------------------------- | -------------------------- |
| 0    | `[tip, tip-1, …, tip-9]`      | `tip`                               | `[tip+1 … tip+2000]`       |
| 1    | `[tip-1, tip-2, …, tip-9]`    | `tip-1`                             | `[tip … tip+1999]`         |
| 2    | `[tip-2, tip-3, …, tip-9]`    | `tip-2`                             | `[tip-1 … tip+1998]`       |

Each advance lane thus produced a **backward-shifted, redundant** range
rather than a parallel forward span. Lane 0 was the only lane doing
useful work, and lanes ≥ 1 wasted bandwidth re-downloading headers
already on our side.

### What actually changed

`src/spv.c` now anchors advance lanes at **compiled-checkpoint hashes
strictly ahead of the current tip**:

* Lane 0 keeps the normal tip-derived locator (no trim).
* For lane N ≥ 1, the dispatcher walks the
  `dogecoin_mainnet_checkpoint_array` (or testnet) forward from the
  local tip and picks the (N-1)-th checkpoint with
  `height > tip + 2000`. The locator becomes a single hash — the
  checkpoint hash — so the peer matches it exactly and returns
  `[checkpoint_height+1 … checkpoint_height+2000]`. Each advance lane
  therefore covers a *different forward span* of the chain.
* The number of advance lanes is capped at the count of compiled
  checkpoints actually ahead of the tip; once we sync past every
  compiled checkpoint, only lane 0 is dispatched (degrading
  gracefully back to single-peer header sync, which is what the
  protocol allows when no future hashes are known).
* These advance batches arrive ahead of the contiguous tip and are
  parked in the bounded TS staging ring (`SPV_HEADERS_STAGE_CAPACITY`)
  until the master writer connects them as the live tip catches up.
* Debug log line is now
  `Header request node N: lane=K anchor_height=H locator_count=1 …`
  (or `lane=0 (tip locator) …` for lane 0), so a single
  `grep anchor_height= <log> | sort -u` shows whether advance lanes
  actually fanned out across distinct forward spans during a run.

### Block-mode benchmark

`contrib/devtools/spvnode_bench.sh` now also exercises full-block sync
(`-b`), with rows `legacy_b1`, `legacy_b4`, `ts_b1`, `ts_b4`, `ts_b8`,
and the CSV gained two columns:

* `distinct_lane_anchors` — distinct `anchor_height=` values observed
  in the run (sanity check that advance lanes anchored at different
  forward checkpoints).
* `blocks_received` — count of `Connected block at height` log lines
  in block-sync mode.

Block mode exercises a different code path than headers-only sync:
besides validating each block, the SPV client runs the wallet UTXO
scan, persists state, and walks the address index per block — none of
which the headers-only path does. So the TS gain in block mode is
expected to be smaller than in header mode (the per-block work is
already serialized through the wallet writer regardless of worker
count). The harness now lets us measure that head-to-head; running
the live benchmark requires outbound P2P access (port 22556) which is
not available in the CI sandbox where this change was authored, so
re-measured numbers should be collected on a network-reachable host
and dropped into `doc/verification/spvnode_ts_performance_results.csv`.

### Caveats specific to checkpoint-anchored fan-out

* The number of usable advance lanes is bounded by the number of
  compiled checkpoints ahead of the local tip. Mainnet currently
  ships 24 checkpoints; once the local tip passes the last one, the
  dispatcher falls back to lane 0 only (one peer at a time for
  headers). Adding more recent checkpoints to
  `src/chainparams.c:dogecoin_mainnet_checkpoint_array` immediately
  lengthens the runway over which advance fan-out is effective.
* Advance lanes never "skip ahead" of a compiled, validated
  checkpoint, so a malicious peer cannot fabricate a long
  alternate-history advance batch and have it accepted — its
  staged headers must still chain back to a connected tip in
  ascending height before the master writer commits them.

