# SPV Header Download Performance: `spvnode` vs `spvnode_ts`

## Goal

Characterize whether the thread-safe (`_ts`) build of `spvnode` actually
increases header (and block) download throughput relative to the legacy build,
across a range of worker-thread counts.

## Methodology

### Binaries under test

* `spvnode` — legacy build (no `-DDOGECOIN_THREAD_SAFE`). Uses a single
  serialized commit path on the network thread; out-of-order header deliveries
  from peers that are ahead of the local tip are rejected with
  `Got invalid headers (not in sequence)` and increment the per-peer
  `invalid_header_streak` counter.
* `spvnode_ts` — built with `-DDOGECOIN_THREAD_SAFE=1` (see `Makefile.am` and
  `CMakeLists.txt` `_ts` targets). At startup it calls
  `dogecoin_spv_client_enable_thread_safe_mode()` which activates the bounded
  out-of-order header-batch staging map (8 slots) added in `src/spv.c`
  (`spv_stage_batch` / `spv_stage_drain_for_tip`).

Both binaries share the same SPV scheduler with rotating `lane_trim_offset`
so locator vectors differ across peers in the same dispatch cycle.

### Workload

Each run starts from a recent compiled-in checkpoint (`-p`) on Dogecoin
mainnet, at most 8 connected peers (`-m 8`), in continuous mode (`-c`),
writes to a fresh `bench_main_headers.db` (deleted between runs), and is
terminated by `timeout` after a fixed wall-clock budget (default 120 s).

Worker counts under test:

| Binary        | Worker counts      |
|---------------|--------------------|
| `spvnode`     | 1, 4               |
| `spvnode_ts`  | 1, 2, 4, 8         |

Legacy at `w>1` is included as a control: the worker pool exists but the
legacy commit path is unchanged, so additional workers do not raise the
effective per-cycle dispatch fan-out beyond the existing scheduler bounds.

### Metrics (per run)

Computed from the debug log written by `-d`:

* `connected_headers` — sum of `Connected N headers` deliveries.
* `headers_per_s` — `connected_headers / elapsed_s`.
* `batches_2000` — count of `Got 2000 headers` lines (raw batch arrivals).
* `staged` — count of `staged prev=...` events (TS only; out-of-order
  acceptances that legacy would have dropped).
* `invalid_rejects` — count of `invalid header streak` increments.
* `final_tip` — last `Chaintip at height N` value.

Run via:

```bash
contrib/devtools/spvnode_bench.sh 120 ./spvbench_out
cat ./spvbench_out/results.csv
```

## Empirical results

> **Status: not collected from the agent sandbox.**
>
> The Copilot Cloud Agent runner used for this PR does not have outbound TCP
> access to mainnet Dogecoin port 22556. With `./spvnode -d -p -c -m 4 -o 1
> scan` the binary produces zero bytes of debug output (no `version`/`verack`
> handshake) and `bash -c 'cat </dev/tcp/seed.multidoge.org/22556'` hangs to
> timeout, confirming the P2P port is firewalled. Any numbers we generate here
> would be synthetic. To honor the request without fabricating data, the
> harness `contrib/devtools/spvnode_bench.sh` and this report are committed
> together; running the harness on a host with normal outbound access will
> populate `results.csv` and `summary.txt` for direct comparison.

A previous verification log already in the tree shows the scheduler-side half
of the change empirically — distinct `lane_trim_offset` and `start_locator`
values across concurrent peers in the same dispatch cycle:

* `doc/verification/spvnode_ts_threaded_headers_sample.txt`
* `doc/verification/spvnode_ts_phase2_thread_safe_sample.txt`

These confirm peers receive **different** header requests in `_ts` mode (the
property the throughput uplift relies on), but they don't quantify the
end-to-end rate.

### Reproduction

On a Linux host with normal outbound networking:

```bash
sudo apt-get install -y autoconf automake libtool libevent-dev build-essential
./autogen.sh
./configure --with-net --with-tools --disable-bench --enable-test-passwd
make -j$(nproc) spvnode spvnode_ts
contrib/devtools/spvnode_bench.sh 120 ./spvbench_out
column -t -s, ./spvbench_out/results.csv
```

Append the resulting `results.csv` rows to the **Empirical results** section
above when posting follow-up.

## Analysis (what the harness is expected to show, and why)

The TS build changes three things on the header-download hot path:

1. **Out-of-order staging on the master committer (`src/spv.c`
   `spv_stage_batch` / `spv_stage_drain_for_tip`).** When a peer delivers a
   batch whose `prev_block` is not the current tip but is known elsewhere
   (e.g. a peer running ahead of us), legacy increments the peer's invalid
   streak and discards the work. TS instead stores it in a bounded map keyed
   by `prev_block`. After every successful commit the map is drained as long
   as batches connect. This converts a class of *wasted bandwidth* into
   *useful committed headers*. The `staged` counter in the harness is the
   direct measure of this effect; the matching reduction in `invalid_rejects`
   is the savings.

2. **Headersdb single-writer contract.** The legacy `headersdb_lock /
   headersdb_unlock` calls were removed from the SPV hot path
   (`src/headersdb_file.c`), and the field remains only as a reserved-ABI
   no-op. With the master-writer pattern there is exactly one thread mutating
   the file and no contention; this cuts per-batch commit overhead and removes
   the case where the network thread blocks on a worker holding the DB lock.
   In a contention-free single-thread test this is neutral, but at higher
   worker counts it prevents the throughput collapse that file-locking would
   otherwise cause.

3. **Lane-rotated locator scheduling.** Each dispatched peer in a cycle gets
   a different `lane_trim_offset` (0..N-1) so peers do not race to deliver
   the **same** 2000 headers. The verification samples above confirm distinct
   `start_locator` values across peers. This is what makes higher worker
   counts produce *different* batches instead of duplicates.

### Predicted shape

Given the above, the harness output is expected to look qualitatively like:

* `legacy_w1` — baseline rate, no staging, low `invalid_rejects` (single peer
  in flight).
* `legacy_w4` — modest or no improvement over `w1`. The legacy commit path
  serializes and out-of-order batches are dropped (`invalid_rejects` rises).
* `ts_w1` — comparable to `legacy_w1` (same single-peer rate; staging has
  little to do).
* `ts_w2` / `ts_w4` — clear uplift in `headers_per_s` and `batches_2000` over
  the legacy `w4` run, with a non-zero `staged` count and `invalid_rejects`
  near zero. This is the multithreaded download speed-up.
* `ts_w8` — diminishing returns once peer-side latency dominates the batch
  arrival rate; `staged` may grow if peers are far ahead.

### Honest caveats

* P2P throughput is dominated by network conditions and peer responsiveness;
  any single short run can be noisy. Average at least 3 runs per cell of the
  matrix before drawing conclusions.
* If the harness shows TS at `w>=2` *not* exceeding legacy, the most likely
  causes are (a) all peers happen to be at exactly the local tip (no advance
  peers, so staging has nothing to do), (b) the run was bounded by network
  RTT rather than commit throughput, or (c) the connected peer set has very
  similar tips. Increase `-m` and lengthen `DURATION_S` to mitigate.
* The wallet/btree reorg path is unchanged; this report is strictly about
  header download rate, not chain-tip correctness or reorg behavior.

## Files

* `contrib/devtools/spvnode_bench.sh` — runnable benchmark harness.
* `doc/verification/spvnode_ts_threaded_headers_sample.txt` — pre-existing
  evidence that lane offsets/locators differ across peers under `_ts`.
* `doc/verification/spvnode_ts_phase2_thread_safe_sample.txt` — Phase 2
  TS-mode banner and master-only tip advance.
* `doc/thread_safety.md` — architectural background and TS API contract.
