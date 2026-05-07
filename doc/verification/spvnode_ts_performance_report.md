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

## Where parallelism could actually help (future work)

Block download (after headers are in) *is* genuinely parallelizable
because each block, given its header, is an independent blob that can
be requested with `getdata BLOCK <hash>` from any peer. The current
spvnode_ts implementation does not do this; the SPV pump dequeues and
commits blocks one at a time through `dogecoin_net_spv_node_handle_block_msg`.
A future change that:

1. Pipelines `getdata BLOCK` requests across N peers in flight,
2. Receives blocks out-of-order into a per-height block staging ring,
3. Drains them in-order into `wallet_check_transaction` /
   `headers_db->store_block`,

would convert worker count `-o N` into an actual throughput multiplier
for full-block sync. That is a separate piece of work and is not
attempted here.

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
