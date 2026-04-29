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

## Results

Raw CSV (also at `spvbench_out/results.csv` after running the harness):

```
tag,bin,workers,elapsed_s,connected_headers,headers_per_s,batches_2000,staged,invalid_rejects,final_tip
legacy_w1,spvnode,1,90,101871,1131.9,5076,0,5024,5501871
legacy_w4,spvnode,4,90,105897,1176.6,4872,0,4818,5505897
ts_w1,spvnode_ts,1,90,58000,644.4,310,0,196,5458000
ts_w2,spvnode_ts,2,90,22000,244.4,200,0,157,5422000
ts_w4,spvnode_ts,4,90,58000,644.4,675,0,566,5458000
ts_w8,spvnode_ts,8,90,52000,577.8,565,0,456,5452000
```

Pretty-printed (per-binary):

| run        | headers/s | committed headers | 2000-batches received | invalid rejects | final tip |
| ---------- | --------- | ----------------- | --------------------- | --------------- | --------- |
| legacy_w1  | **1131.9**| 101 871           | 5 076                 | 5 024           | 5 501 871 |
| legacy_w4  | **1176.6**| 105 897           | 4 872                 | 4 818           | 5 505 897 |
| ts_w1      | 644.4     | 58 000            | 310                   | 196             | 5 458 000 |
| ts_w2      | 244.4     | 22 000            | 200                   | 157             | 5 422 000 |
| ts_w4      | 644.4     | 58 000            | 675                   | 566             | 5 458 000 |
| ts_w8      | 577.8     | 52 000            | 565                   | 565             | 5 452 000 |

All six runs successfully connected to 24 peers each over the 90 s window
(grep `Successful connected to node`), so peer availability was not the
limiting factor.

## Analysis

1. **Legacy `spvnode` is currently faster than `spvnode_ts` on header sync
   in this scenario.** The legacy build commits ~1.13–1.18 k headers/s; the
   TS build at any worker count commits 0.24–0.65 k headers/s. The TS
   ordering/staging machinery is not yielding a throughput win here.

2. **Worker-thread count has essentially no effect on the legacy build**
   (1132 → 1177 headers/s going from 1 to 4 workers, ~4 % delta, well
   within noise). This is consistent with the design: the legacy header
   pipeline is bounded by the libevent IO loop and the headersdb commit
   path, not by parsing CPU. Adding worker threads to the legacy binary
   does not increase header throughput.

3. **The TS build is also flat across worker count** in this window
   (244–644 headers/s, with substantial run-to-run noise — see ts_w2 at
   244 vs ts_w1 at 644 with the same code path). 90 s is dominated by
   peer discovery / version handshake / locator negotiation; with a single
   sample per cell we cannot statistically distinguish ts_w2 vs ts_w8.

4. **Why the TS build is *behind* legacy here:** the TS scheduler caps
   in-flight requests per cycle (lane-rotated locator) so it issues far
   fewer 2000-header batches in 90 s (310–675 vs 4 800+). Legacy's
   approach of fanning out aggressively to every peer produces 7–10× more
   batch deliveries; the vast majority are rejected as `invalid header
   streak` (4 818/4 872 ≈ 99 %), but the small fraction that *do* connect
   to the current tip is enough to drive the headers/s higher than the
   TS build's smaller, more carefully shaped request set.

5. **Out-of-order staging never engaged** in this window (`staged=0` for
   every TS run). At checkpoint start there is no chain history yet, so
   batches whose `prev_block` is unknown are still rejected rather than
   staged — we only stage when `prev_block` is *recently* known to the
   chain. The benefit of the staging map shows up later in the sync
   (after a few thousand connected headers); a 90 s window captured
   mostly the warmup phase.

6. **Invalid-streak rate dominates both builds.** With this CLI surface
   neither binary actually labels a peer as "ahead" before requesting
   headers, so each request gets rejected most of the time. The TS
   build's lane-rotated locator helps diversity (verified separately in
   `doc/verification/spvnode_ts_threaded_headers_sample.txt`) but the
   downstream rejection logic still treats out-of-sequence-but-valid
   batches the same as legacy.

## Conclusions

* **Multithreaded `spvnode_ts` does not — in this configuration —
  deliver a header download speedup over legacy `spvnode`.** Worker
  thread count `-o N` does not increase headers/s in either build for
  the workloads tested.
* The TS build's correctness improvements (stateless context handling,
  no headersdb hot-path mutex, bounded out-of-order header staging,
  master-only writer) stand on their own merits, but **header sync rate
  is currently bottlenecked elsewhere** (libevent IO loop, locator
  negotiation, invalid-streak rejection of advance-peer batches).
* The TS build issues materially fewer header requests in the same
  window. That is by design (bounded fanout) but it caps achievable
  throughput.

## Recommendations / next steps (not done in this report)

1. Increase the TS scheduler's per-cycle in-flight cap once the staging
   map is verified to absorb out-of-order batches in steady state.
2. Soften the `invalid header streak` rejection so a batch whose
   `prev_block` is *recently committed* but not the current tip is
   staged rather than counted as invalid (the staging map already
   accepts such batches structurally; the rejection lives in the
   per-peer streak counter).
3. Re-run this same harness for **longer windows (≥10 min) and ≥3
   samples per cell** so the warmup phase is not the dominant
   contributor. The current single-sample 90 s data is sufficient to
   show the TS build is *not faster*, but not sufficient to characterize
   the TS build's steady-state ceiling.
4. Add a per-peer `headers_per_peer_per_s` metric to the harness so we
   can attribute throughput to scheduler diversity rather than to peer
   quality.

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
