# Decode-depth benchmark

This benchmark gives maintainers a reproducible way to measure recursive
decoding cost without scanning private repositories or publishing real
credentials. The fixture is generated in memory from synthetic values with the
`demo_secret_` prefix and intentionally avoids provider-looking token prefixes.

## Run

```sh
GO_BIN=/path/to/go sh benchmarks/decode-depth/run.sh
```

The benchmark runs these depths:

```text
--max-decode-depth=0
--max-decode-depth=1
--max-decode-depth=2
--max-decode-depth=5
```

The Go benchmark output records time, allocations, findings per operation, and
input bytes per operation. Capture the Go version, operating system, CPU, and
Gitleaks commit SHA when sharing results.

## Interpreting results

- Depth `0` is the no-decoding baseline.
- Depth `1`, `2`, and `5` show the incremental cost of recursive decoding.
- A production investigation should compare allocation growth and runtime across
  depths before proposing default-value or guardrail changes.
- Do not include real scan reports, repository names, credential values, or
  internal incident details in public benchmark output.
