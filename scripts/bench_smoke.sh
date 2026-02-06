#!/usr/bin/env bash
#
# Lightweight benchmark smoke + budget checks.
#
# Goal: catch catastrophic regressions (orders of magnitude), not tiny % changes.
# This intentionally uses generous thresholds to avoid CI flakiness.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf "ERROR: missing required command: %s\n" "$1" >&2
    exit 1
  fi
}

require_cmd cargo
require_cmd jq

WARMUP_SECS="${WARMUP_SECS:-0.05}"
MEASURE_SECS="${MEASURE_SECS:-0.05}"
SAMPLE_SIZE="${SAMPLE_SIZE:-10}"

bench_one() {
  local pkg="$1"
  local bench="$2"
  cargo bench -p "$pkg" --bench "$bench" -- \
    --noplot \
    --warm-up-time "$WARMUP_SECS" \
    --measurement-time "$MEASURE_SECS" \
    --sample-size "$SAMPLE_SIZE"
}

mean_ns() {
  local path="$1"
  jq -r '.mean.point_estimate' "$path"
}

assert_le_ns() {
  local name="$1"
  local path="$2"
  local max_ns="$3"

  if [[ ! -f "$path" ]]; then
    printf "ERROR: missing criterion estimates.json for %s at %s\n" "$name" "$path" >&2
    exit 1
  fi

  local val
  val="$(mean_ns "$path")"

  # Compare as floats via awk (portable enough for CI).
  awk -v v="$val" -v m="$max_ns" -v n="$name" 'BEGIN {
    if (v > m) {
      printf("ERROR: %s mean %.2f ns exceeds budget %.2f ns\n", n, v, m) > "/dev/stderr";
      exit 1
    }
  }'
}

echo "[bench_smoke] Running criterion benches (smoke)..."
bench_one pt-core collect_parsers
bench_one pt-core inference_posteriors
bench_one pt-core session_diff
bench_one pt-math beta_ops

echo "[bench_smoke] Checking generous budgets..."

# pt-core collect parsers
assert_le_ns \
  "pt-core parse_proc_stat_content simple_comm" \
  "target/criterion/collect_parsers/parse_proc_stat_content/simple_comm/new/estimates.json" \
  10000

assert_le_ns \
  "pt-core parse_proc_stat_content spaces_in_comm" \
  "target/criterion/collect_parsers/parse_proc_stat_content/spaces_in_comm/new/estimates.json" \
  10000

# Slashes become underscores for `bench_function("collect_parsers/parse_io_content", ...)`.
assert_le_ns \
  "pt-core parse_io_content" \
  "target/criterion/collect_parsers_parse_io_content/new/estimates.json" \
  20000

# pt-core posterior inference (order-of-magnitude budgets)
assert_le_ns \
  "pt-core compute_posterior idle_orphan" \
  "target/criterion/posterior/compute_posterior/idle_orphan/new/estimates.json" \
  500000

assert_le_ns \
  "pt-core compute_posterior active_tty_net" \
  "target/criterion/posterior/compute_posterior/active_tty_net/new/estimates.json" \
  500000

# 10k posterior computations should be comfortably under 1s on CI.
assert_le_ns \
  "pt-core compute_posterior_10k" \
  "target/criterion/posterior/compute_posterior_10k/new/estimates.json" \
  1000000000

# pt-core session diff (10k entries, large-ish HashMap + delta build)
assert_le_ns \
  "pt-core compute_diff_10k" \
  "target/criterion/session_diff/compute_diff_10k/new/estimates.json" \
  500000000

# pt-math beta kernels (pick representative regimes)
assert_le_ns \
  "pt-math log_beta_pdf uniform" \
  "target/criterion/beta/log_beta_pdf/uniform/new/estimates.json" \
  2000

assert_le_ns \
  "pt-math beta_inv_cdf uniform" \
  "target/criterion/beta/beta_inv_cdf/uniform/new/estimates.json" \
  50000

echo "[bench_smoke] OK"
