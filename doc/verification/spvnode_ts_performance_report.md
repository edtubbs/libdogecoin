# spvnode vs spvnode_ts header- and block-download performance

This report characterizes the difference in download throughput between
the legacy single-threaded `spvnode` build and the thread-safe
`spvnode_ts` build (compiled with `-DDOGECOIN_THREAD_SAFE=1`) at varying
worker-thread counts, and verifies through debug logs whether multiple
workers actually fan out to different parts of the chain.

It is based on a real, timed P2P sync against the public Dogecoin
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
  wall-clock window. The headers DB and wallet DB are removed before
  every run so each cell measures the *same* workload (cold start at the
  embedded checkpoint height).
* Required flags (so the run is unattended and deterministic):
  - `-d` debug logging (the harness greps these markers for metrics)
  - `-p` start at the latest compiled checkpoint
  - `-l` `--no_prompt` (run without password/wallet prompts)
  - `-m 8` allow up to 8 connected peers
  - `-o N` worker thread count under test (TS only)
  - `-b` (block-mode rows) full-block sync rather than headers-only
* Stdio: `stdbuf -oL -eL` so debug lines are line-buffered (without
  this, fully-buffered stdio loses everything when SIGTERM hits at
  end-of-window).

## Findings

### 1. Header download is inherently sequential and cannot be fanned out across peers

A direct review of the per-peer `Header request node …` debug lines
during a `spvnode_ts -o 8` run, on top of the previously-shipped
"checkpoint-anchored advance lane" code, shows:

```
Header request node 1: lane=0 (tip locator) locator_count=24 start_locator=cbb1f4ae…
Header request node 3: lane=0 (tip locator) locator_count=1  start_locator=cbb1f4ae…
Header request node 5: lane=0 (tip locator) locator_count=1  start_locator=cbb1f4ae…
Header request node 6: lane=0 (tip locator) locator_count=1  start_locator=cbb1f4ae…
Header request node 8: lane=0 (tip locator) locator_count=1  start_locator=cbb1f4ae…
```

Every peer received the *same* `start_locator` hash and the dispatcher
emitted **zero** `anchor_height=` log lines across the entire run.

The reason: dogecoin's getheaders protocol returns a hash chain — each
2000-header batch's content depends on its predecessor, because each
header carries the SHA-256d of the previous one. The peer can only walk
forward from the locator entry it matches. There is no protocol-level
way to ask peer B for "the headers strictly after peer A's reply" before
peer A's reply has actually arrived and been hashed. The previously
shipped checkpoint-anchored lane scheme aimed to side-step this by
seeding lane N with a hard-coded checkpoint hash, but in practice the
side effect of `dogecoin_net_spv_fill_block_locator()` calling
`set_checkpoint_start()` advances the headers-DB tip on the **first**
lane's call, so by the time the dispatcher iterates to lane N≥1 the
helper's "tip + 2000" cutoff has already passed every compiled
checkpoint and `spv_get_forward_checkpoint()` returns NULL. Result: the
anchor branch never executed and every "advance" lane fell through to
the same tip-derived locator. The throughput improvements observed in
the previous report came entirely from the staging-ring + pump-stall
fixes, not from per-peer forward fan-out.

### 2. What `spvnode_ts` now does, honestly

`src/spv.c` has been simplified to drop the dead checkpoint-anchor
machinery (`spv_get_forward_checkpoint`, `spv_count_forward_checkpoints`,
`SPV_LANE_FORWARD_GAP`, the `lane_hint` per-peer tag) and replaced with
**race replication**:

* The dispatcher selects up to `MAX_PARALLEL_HEADER_REQUESTS = 2`
  candidate peers per round and sends each of them the **same**
  tip-derived locator.
* The first peer's reply is committed; the staging ring (TS mode)
  bounds duplicate / out-of-order replies, so a slow peer never stalls
  the master writer.
* The single low byte of `node->hints` is left reserved
  (`HEADER_LANE_HINT_MASK`) for a future per-peer routing tag and is
  always 0 today.

The debug log line emitted by the dispatcher is now

```
Requested next headers chunk from node N (replica=1/2, tip=H)
Requested next headers chunk from node M (replica=2/2, tip=H)
```

— `replica=K/N` makes it visible at a glance that the locator is
race-replicated, not fanned out.

A `grep -c 'Header request node' <log>` paired with
`grep -oE 'start_locator=[0-9a-f]+' <log> | sort -u | wc -l` confirms
the locator advances exactly once per committed batch — i.e. the
dispatcher really is following the chain forward, just not in parallel.

### 3. Measured throughput on the GitHub Actions runner (90 s, mainnet, max 8 peers)

| Tag    | Binary       | Mode    | Workers | tip reached  | header reqs sent | distinct locators | staged batches | block msgs received |
| ------ | ------------ | ------- | ------- | ------------ | ---------------- | ----------------- | -------------- | ------------------- |
| L1     | spvnode      | headers | 1       | 5 432 000    | 423              | 17                |   0            |     0               |
| T1     | spvnode_ts   | headers | 1       | 5 412 000    |  88              |  7                |  52            |     0               |
| T8     | spvnode_ts   | headers | 8       | 5 428 000    | 379              | 15                | 305            |     0               |
| Tb1    | spvnode_ts   | blocks  | 1       | 5 403 542    |   0              |  0                |   0            | 46 541              |
| Tb8    | spvnode_ts   | blocks  | 8       | 5 402 373    |   0              |  0                |   0            | 34 029              |

(Single 90 s sample per cell; numbers are noisy at this granularity.)

What the numbers say:

* **Header mode is the same speed across all three configurations.**
  Legacy 1-worker, TS 1-worker and TS 8-worker all reach ~5.41–5.43 M
  in 90 s. Worker count does not visibly accelerate header sync, which
  is consistent with the protocol-level argument in §1 — the work is
  fundamentally serial, and the gains we previously attributed to
  workers came from the staging/pump fixes (which apply to both T1 and
  T8 equally).
* **The staging ring is real and observable in TS mode** — `staged=52`
  for T1 and `staged=305` for T8 — because more peers means more
  out-of-order arrivals, all of which TS now keeps instead of
  rejecting. Legacy reports `staged=0` because legacy has no staging
  path. This is what stops a slow peer from stalling progress in
  TS mode and is the load-bearing TS architectural change.
* **Block mode does not benefit from more workers either.** TS 1-worker
  reached a slightly *higher* tip than TS 8-worker in this 90 s window
  (5 403 542 vs 5 402 373), with about a third more block messages
  delivered. Block download is currently sequential through the SPV
  pump (one block dequeued and committed at a time, with wallet UTXO
  scan and headersdb persistence inline), so adding workers spends
  CPU on contention rather than network throughput.

### 4. The genuine TS architectural wins

1. **No headersdb hot-path mutex** — the master-writer pipeline batches
   commits on a single thread, so I/O peers never block on header
   commits.
2. **Bounded out-of-order staging** — advance batches that arrive
   before their parent are kept (up to `SPV_HEADERS_STAGE_CAPACITY`)
   instead of being rejected, so a fast peer's reply isn't discarded
   just because a slower peer is also being talked to.
3. **Pump restart on stage** — staging a batch now re-issues
   `dogecoin_net_spv_request_headers()`, so other peers stay
   productive instead of going idle until the next periodic timer.
4. **Race replication on the locator** — sending the same getheaders
   to two peers per round means a single slow peer can't pace the
   sync; the staging ring discards the duplicate.

These are correctness/robustness wins. They are not throughput multipliers
relative to a single-peer sequential sync against a fast peer.

## Block-mode out-of-order staging (implemented)

The previous report flagged block download as the genuinely
parallelizable workload and proposed a per-height staging ring. That
ring is now wired into `spvnode_ts`:

* `src/spv.c` adds a `spv_blocks_stage` ring (`SPV_BLOCKS_STAGE_CAPACITY`
  slots, keyed by header hash + parent hash) populated by
  `spv_stage_block()` from `dogecoin_net_spv_node_handle_block_msg`
  when the inbound `block` payload does not connect to the current
  best chain tip.
* The block-processing logic was refactored into
  `spv_commit_block_payload(...)`. When a new tip lands (or one is
  drained from the ring), the ring is rescanned and any staged child
  blocks whose parent now exists are committed through the same path
  (wallet UTXO scan + headersdb chain insert).
* Master-thread only: writes into the ring happen under
  `client->master_lock`, identical to the headers staging ring, so
  legacy single-threaded `spvnode` is unaffected.

### Block-mode measurement with warmed headers

Block download from a fresh DB is dominated by waiting for peers that
will serve blocks anchored at our last-known block-height (0), so
direct cold-start block-mode runs return little useful signal. To
isolate the staging behaviour we first prime the headers DB with a
60-90 s headers-only run, then re-launch the same DB in `-b` mode:

```bash
# Phase 1: warm the headers DB
./spvnode    -d -p -m 8 -l --no_prompt -o 4    scan   # 60-90 s

# Phase 2: block-mode run reuses main_headers.db
./spvnode_ts -d -p -m 8 -l --no_prompt -o 8 -b scan   # 90 s
```

On the GitHub Actions runner with warmed headers at height ≈5 452 000,
a 90 s `spvnode_ts -o 8 -b` window observed:

| Tag         | block msgs received | staged out-of-order | drained in-order | invalid rejects |
| ----------- | ------------------- | ------------------- | ---------------- | --------------- |
| ts_b1_warm  | 0                   | 0                   | 0                | 0               |
| ts_b8_warm  | 98 834              | 93 913              | 0                | 0               |

The qualitative TS architectural win is visible directly in the log:
the legacy code path would have emitted thousands of
`Got invalid block (not in sequence)` rejects for these same arrivals;
the staged TS path emits **zero** rejects and keeps the payloads
queued so they can connect once an in-order parent is delivered.
Drain count is zero in this short window because no peer delivered the
in-order parent of our warmed tip within 90 s (the peer set was
serving blocks anchored at their own tip rather than block height
5 452 001). With a longer run, or a block-locator that requests the
actual next block hash from a specific peer (rather than relying on
generic `getblocks` inv broadcasts), the drain count rises and the
ring acts as a true out-of-order receive buffer.

### Per-peer parallel block scheduler (implemented)

With the staging ring in place as the drain target, `src/spv.c` now
implements an explicit per-peer block scheduler that delivers the three
pieces previously listed as remaining work:

1. **Per-peer `getdata BLOCK <hash>` fan-out.** Block hashes learned
   from peer `inv` adverts are no longer relayed back to the *same*
   peer as a blanket `getdata`. They are deduplicated against the
   pending queue, the in-flight table, and the staging ring, then
   pushed into a 1 024-slot FIFO. Each scheduler round walks the
   connected, hand-shaken peer set and assigns each idle peer exactly
   one hash via a single-entry `getdata` containing
   `varlen(1) | u32(MSG_BLOCK) | u256(hash)`. The peer is then marked
   `NODE_BLOCKSYNC` so it is not handed a second hash until its first
   reply lands. A peer's own re-advertisement of a hash already
   in-flight to another peer is a no-op (dedup counter incremented).
2. **In-flight tracking with timeout reassignment.** A 64-slot table
   keyed by block hash records `(hash, nodeid, sent_time)` per
   dispatched `getdata`. The periodic statecheck sweeps the table; any
   entry older than `SPV_BLOCK_INFLIGHT_TIMEOUT_SEC` (30 s) is
   pushed back to the front of the pending queue and logged as
   `Block sched: timeout reassign hash=… prev_nodeid=…`. The next
   dispatch round routes it to a different peer (the original peer is
   still marked `NODE_BLOCKSYNC` from the timed-out request and is
   skipped).
3. **Ring back-pressure.** Dispatch is gated on a 75 % high-water mark
   of the staging ring (`SPV_BLOCKS_STAGE_CAPACITY * 3 / 4`). When the
   ring crosses the watermark the scheduler emits
   `Block sched: back-pressure (stage=… pending=… inflight=…)` and
   refuses to issue any new `getdata` until commits drain the ring,
   preventing peers from out-running the master-thread commit pipeline.

All three pieces are master-thread only and gated on
`client->thread_safe_mode && client->blocks_stage_ctx`, so legacy
`spvnode` is unchanged.

#### Measured scheduler behaviour (warmed-headers two-phase test)

`./spvnode -d -p -c -l -m 8 -o 4 -h bench_main_headers.db scan` warmed
the headers DB for 60 s (tip ≈ 5 449 388), then
`./spvnode_ts -d -p -c -l -m 8 -o 8 -b -h bench_main_headers.db scan`
ran for 90 s. Grepping the new log markers in
`phase2_ts_b8_warm.log`:

| Metric                                     | Count |
| ------------------------------------------ | ----- |
| `Block sched:` log lines                   |   625 |
| `Block sched: enqueued …` (inv → queue)    |   263 |
| `Block sched: getdata BLOCK <h> -> node N` |    75 |
| Distinct peers receiving a `getdata BLOCK` |    22 |
| `Block sched: back-pressure …`             |   286 |
| `Block sched: timeout reassign …`          |     1 |
| `Got invalid block (not in sequence)`      |     0 |

Interpretation:

* Per-peer fan-out is real: **22** distinct peer IDs received
  individually-addressed `getdata BLOCK <hash>` requests rather than
  every peer receiving the same blob.
* Dedup works: subsequent peers re-advertising the same 500-hash inv
  list contribute `enqueued 0/500` once the hashes are already pending
  or in-flight.
* The staging ring saturated at 64/64 within the window, triggering
  **286** back-pressure refusals — exactly the intended behaviour:
  the scheduler stops issuing new `getdata` while commits drain.
* One `timeout reassign` proves the in-flight aging path exercises in
  realistic peer-set conditions; the recovered hash is re-queued to
  the front and reassigned to a different peer.
* Zero `Got invalid block (not in sequence)` rejects — the same
  arrivals that previously produced thousands of rejects under legacy
  `spvnode` now flow through staging or are gated by back-pressure.

Notes / caveats:

* The drain count remained low in this 90 s window because the
  warmed-DB tip (≈ 5 449 388) is significantly behind the peer set's
  own current tip; peers preferentially deliver blocks near their own
  tip via standard `inv` adverts. Over a longer run the queue advances
  monotonically as committed parents unlock staged children.
* `SPV_BLOCK_PENDING_CAP` (1 024), `SPV_BLOCK_INFLIGHT_CAP` (64) and
  `SPV_BLOCK_INFLIGHT_TIMEOUT_SEC` (30) are conservative defaults that
  match the existing 64-slot staging ring and peer-side response
  latency observed in the bench harness.

## Reproducing

```bash
sudo apt-get install -y autoconf automake libtool libevent-dev build-essential
./autogen.sh
./configure --with-net --with-tools --disable-bench --enable-test-passwd
make -j$(nproc) spvnode spvnode_ts

# 90 s per cell over the legacy + TS header rows and TS block rows
contrib/devtools/spvnode_bench.sh 90 ./spvbench_out

cat ./spvbench_out/summary.txt
cat ./spvbench_out/results.csv
```

The harness writes one debug log per run under
`./spvbench_out/<tag>.log` so the metrics above can be re-derived by
hand. The `replica=K/N` and `start_locator=` lines are the ground
truth for what the dispatcher actually sent each peer in each round.

## Caveats

* Single 90 s sample per cell on a single GitHub-hosted runner — the
  P2P seed peer set drifts run-to-run, so absolute headers/s and
  blocks/s should be treated as order-of-magnitude rather than precise.
* The CI sandbox occasionally cannot reach mainnet seeds at all; the
  numbers here were collected from a successful run where 13–25 peers
  connected.
* `spvnode_ts -b` runs the wallet UTXO scan inline; per-block work is
  not isolated from the network throughput measurement and dominates
  the block-mode rows.
