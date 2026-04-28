# Upstream tracking

This fork should keep production changes scoped and avoid duplicating active
upstream work.

## Active upstream items to watch

| Topic | Upstream reference | Fork guidance |
|---|---|---|
| GitLab Code Quality report | gitleaks/gitleaks#2068 | Implemented here as native `gitlab-code-quality` and `gcq` report output. Keep the branch focused on report output and tests. |
| `pyproject.toml` config | gitleaks/gitleaks#2066 | Implemented here as `[tool.gitleaks]` discovery after `.gitleaks.toml` and before default config. |
| `.gitignore` support for `dir` scans | gitleaks/gitleaks#2060 and gitleaks/gitleaks#2061 | Do not open a competing implementation while the upstream PR is active. Contribute review or tests if useful. |
| `.gitleaksignore` wildcards | gitleaks/gitleaks#1870 and gitleaks/gitleaks#2090 | Do not duplicate the active wildcard PR. Review broad-ignore safety and test coverage instead. |
| GitHub Actions examples | gitleaks/gitleaks#2084 | Avoid overlapping documentation PRs. Keep fork examples narrowly tied to report and config behavior. |
| Decode-depth memory behavior | gitleaks/gitleaks#2019 | Use the synthetic benchmark in `benchmarks/decode-depth` before proposing default-value or guardrail changes. |

## Branch hygiene

- Keep fork-only planning files out of upstream-ready branches.
- Keep PR descriptions issue-focused and free of local workflow details.
- Include test evidence for every behavior change.
