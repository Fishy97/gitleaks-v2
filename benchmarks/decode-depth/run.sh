#!/usr/bin/env sh
set -eu

GO_BIN="${GO_BIN:-go}"

echo "# Go toolchain"
"${GO_BIN}" version

echo "# Decode-depth benchmark"
"${GO_BIN}" test ./benchmarks/decode-depth \
  -run '^$' \
  -bench '^BenchmarkSyntheticDecodeDepth$' \
  -benchmem \
  "$@"
