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
  local bin="$1" workers="$2" tag="$3"
  local log="$OUTDIR/${tag}.log"

  rm -f bench_main_headers.db bench_main_wallet.db
  echo "=== $tag : $bin -o $workers (${DURATION}s) ===" | tee -a "$OUTDIR/summary.txt"

  local t0 t1
  t0=$(date +%s)
  timeout "$DURATION" ./"$bin" -d -p -c -m 8 -o "$workers" \
        -h ./bench_main_headers.db -w ./bench_main_wallet.db scan \
        > "$log" 2>&1 || true
  t1=$(date +%s)

  local elapsed=$((t1 - t0))

  # Sum of "Connected N headers" lines = headers committed to chain
  local connected
  connected=$(awk '/Connected [0-9]+ headers/ {s+=$2} END {print s+0}' "$log")
  # Number of "Got 2000 headers" deliveries (raw batch arrivals)
  local batches
  batches=$(grep -c "Got 2000 headers" "$log" || true)
  # Number of staged out-of-order batches (TS-mode only)
  local staged
  staged=$(grep -c "staged prev=" "$log" || true)
  # Final tip height advanced
  local final_tip
  final_tip=$(awk '/Chaintip at height/ {h=$NF} END {print h+0}' "$log")
  # Invalid-streak rejections (legacy without staging will accumulate these)
  local invalid_rejects
  invalid_rejects=$(grep -c "invalid header streak" "$log" || true)

  local rate
  if (( elapsed > 0 )); then
    rate=$(awk -v c="$connected" -v e="$elapsed" 'BEGIN{printf "%.1f", c/e}')
  else
    rate="0.0"
  fi

  printf "  elapsed=%ds  connected=%s  rate=%s/s  batches=%s  staged=%s  invalid_rejects=%s  final_tip=%s\n" \
         "$elapsed" "$connected" "$rate" "$batches" "$staged" "$invalid_rejects" "$final_tip" \
         | tee -a "$OUTDIR/summary.txt"

  printf "%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
         "$tag" "$bin" "$workers" "$elapsed" "$connected" "$rate" "$batches" "$staged" "$invalid_rejects" \
         >> "$OUTDIR/results.csv"
}

echo "tag,bin,workers,elapsed_s,connected_headers,headers_per_s,batches_2000,staged,invalid_rejects" \
     > "$OUTDIR/results.csv"
: > "$OUTDIR/summary.txt"

# Matrix: legacy at w=1,4 (workers > legacy SMP doesn't increase fan-out)
# vs spvnode_ts at w=1,2,4,8 to characterize TS scaling.
run_one spvnode    1 legacy_w1
run_one spvnode    4 legacy_w4
run_one spvnode_ts 1 ts_w1
run_one spvnode_ts 2 ts_w2
run_one spvnode_ts 4 ts_w4
run_one spvnode_ts 8 ts_w8

echo
echo "Results written to: $OUTDIR/results.csv and $OUTDIR/summary.txt"
echo "Per-run debug logs:  $OUTDIR/{legacy_w1,legacy_w4,ts_w1,ts_w2,ts_w4,ts_w8}.log"
