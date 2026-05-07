#!/usr/bin/env bash
#
# spvnode_bench.sh
#
# Benchmark harness comparing legacy `spvnode` vs the thread-safe
# `spvnode_ts` build at varying worker-thread counts. Measures header
# download throughput from a recent checkpoint over a fixed wall-clock
# window.
#
# Build prerequisites (see doc/getting_started.md):
#   sudo apt-get install -y autoconf automake libtool libevent-dev build-essential
#   ./autogen.sh && ./configure --with-net --with-tools --disable-bench --enable-test-passwd
#   make -j$(nproc) spvnode spvnode_ts
#
# Usage:
#   contrib/devtools/spvnode_bench.sh [DURATION_S] [OUTDIR]
#     DURATION_S  per-run wall clock budget (default: 120)
#     OUTDIR      where to write logs and report (default: ./spvbench_out)
#
# Notes:
#   * Requires outbound TCP to 22556 (mainnet P2P). In firewalled CI sandboxes
#     this script will produce empty logs; run it on a machine with normal
#     outbound network access.
#   * Each run starts from a fresh `-p` (checkpoint) state with `-f 0`-equivalent
#     headers DB removed between runs so all runs measure the same workload.
#   * Worker count is the SPV CLI worker pool (-o / --workers); the TS-mode
#     out-of-order staging and lane-rotated locator scheduling are exercised
#     only by the `spvnode_ts` binary.

set -euo pipefail

DURATION="${1:-120}"
OUTDIR="${2:-./spvbench_out}"
mkdir -p "$OUTDIR"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

if [[ ! -x ./spvnode || ! -x ./spvnode_ts ]]; then
  echo "ERROR: build spvnode and spvnode_ts first (see header of this script)" >&2
  exit 1
fi

run_one() {
  local bin="$1" workers="$2" tag="$3" mode="${4:-headers}"
  local log="$OUTDIR/${tag}.log"

  rm -f bench_main_headers.db bench_main_wallet.db
  local mode_flag=""
  if [[ "$mode" == "blocks" ]]; then
    mode_flag="-b"
  fi
  echo "=== $tag : $bin -o $workers ${mode_flag:+$mode_flag} (${DURATION}s) ===" \
    | tee -a "$OUTDIR/summary.txt"

  local t0 t1
  t0=$(date +%s)
  # -l (--no_prompt) is required so spvnode/spvnode_ts run unattended (no
  # password/wallet prompts). -p starts from the latest compiled checkpoint.
  # -b enables full-block sync mode. stdbuf forces line-buffered stdio so
  # log output is preserved when SIGTERM arrives at end-of-window.
  timeout --foreground --signal=INT --kill-after=5 "$DURATION" \
      stdbuf -oL -eL \
      ./"$bin" -d -p -c -l -m 8 -o "$workers" $mode_flag \
        -h ./bench_main_headers.db -w ./bench_main_wallet.db scan \
        > "$log" 2>&1 || true
  t1=$(date +%s)

  local elapsed=$((t1 - t0))

  # Sum of "DEBUG: Connected N headers" lines = headers committed to chain.
  # Field layout is: "DEBUG: Connected N headers", so the count is $3.
  local connected
  connected=$(awk '/DEBUG: Connected [0-9]+ headers/ {s+=$3} END {print s+0}' "$log")
  # Number of "Got 2000 headers" deliveries (raw batch arrivals)
  local batches
  batches=$(grep -c "Got 2000 headers" "$log" || true)
  # Number of staged out-of-order batches (TS-mode only) — match either the
  # legacy "staged prev=" tag or the live "Staged out-of-order headers batch"
  # log line.
  local staged
  staged=$(grep -cE "staged prev=|Staged out-of-order headers batch" "$log" || true)
  # Final tip height advanced
  local final_tip
  final_tip=$(awk '/Chaintip at height/ {h=$NF} END {print h+0}' "$log")
  # Invalid-streak rejections (legacy without staging will accumulate these)
  local invalid_rejects
  invalid_rejects=$(grep -c "invalid header streak" "$log" || true)
  # Distinct start_locator hashes seen in the dispatcher log — proxy for the
  # number of forward steps the chain actually advanced through (one new
  # locator hash per committed batch). NOT a fan-out metric: header download
  # is inherently sequential (the next locator depends on the previous batch
  # being committed), so all replica peers in a given round always see the
  # same start_locator hash. See doc/verification/spvnode_ts_performance_report.md.
  local distinct_anchors
  distinct_anchors=$(grep -oE "start_locator=[0-9a-f]+" "$log" | sort -u | wc -l)
  # Block deliveries (full-block sync mode only)
  local blocks_received
  blocks_received=$(grep -c "Connected block at height" "$log" || true)

  local rate
  if (( elapsed > 0 )); then
    rate=$(awk -v c="$connected" -v e="$elapsed" 'BEGIN{printf "%.1f", c/e}')
  else
    rate="0.0"
  fi

  printf "  elapsed=%ds  mode=%s  connected=%s  rate=%s/s  batches=%s  staged=%s  invalid=%s  anchors=%s  blocks=%s  final_tip=%s\n" \
         "$elapsed" "$mode" "$connected" "$rate" "$batches" "$staged" "$invalid_rejects" "$distinct_anchors" "$blocks_received" "$final_tip" \
         | tee -a "$OUTDIR/summary.txt"

  printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
         "$tag" "$bin" "$workers" "$mode" "$elapsed" "$connected" "$rate" "$batches" "$staged" "$invalid_rejects" "$distinct_anchors" "$blocks_received" \
         >> "$OUTDIR/results.csv"
}

echo "tag,bin,workers,mode,elapsed_s,connected_headers,headers_per_s,batches_2000,staged,invalid_rejects,distinct_locator_hashes,blocks_received" \
     > "$OUTDIR/results.csv"
: > "$OUTDIR/summary.txt"

# Header-sync matrix (default scan mode): legacy at w=1,4 (workers > legacy
# SMP doesn't increase fan-out) vs spvnode_ts at w=1,2,4,8 to characterize
# TS scaling.
run_one spvnode    1 legacy_w1 headers
run_one spvnode    4 legacy_w4 headers
run_one spvnode_ts 1 ts_w1     headers
run_one spvnode_ts 2 ts_w2     headers
run_one spvnode_ts 4 ts_w4     headers
run_one spvnode_ts 8 ts_w8     headers

# Block-sync matrix (-b): characterize full-block download throughput at the
# same worker counts so the TS gain (or absence thereof) in block mode can be
# compared head-to-head with header-only mode above. Block mode triggers the
# full-block code path which has different bottlenecks (per-block UTXO scan,
# wallet update, on-disk persistence) than headers-only sync.
run_one spvnode    1 legacy_b1 blocks
run_one spvnode    4 legacy_b4 blocks
run_one spvnode_ts 1 ts_b1     blocks
run_one spvnode_ts 4 ts_b4     blocks
run_one spvnode_ts 8 ts_b8     blocks

echo
echo "Results written to: $OUTDIR/results.csv and $OUTDIR/summary.txt"
echo "Per-run debug logs:  $OUTDIR/{legacy_w1,legacy_w4,ts_w1,ts_w2,ts_w4,ts_w8,legacy_b1,legacy_b4,ts_b1,ts_b4,ts_b8}.log"
