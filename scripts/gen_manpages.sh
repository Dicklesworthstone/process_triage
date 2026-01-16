#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "$0")/.." && pwd)
src_dir="$root_dir/docs/man/src"
dst_dir="$root_dir/docs/man"

mkdir -p "$dst_dir"

for src in "$src_dir"/*.in; do
  name=$(basename "$src" .in)
  cp "$src" "$dst_dir/$name"
done

