# wrg-devguard

[![PyPI version](https://img.shields.io/pypi/v/wrg-devguard?color=%2334D058&label=pypi)](https://pypi.org/project/wrg-devguard/)
[![Python](https://img.shields.io/pypi/pyversions/wrg-devguard)](https://pypi.org/project/wrg-devguard/)
[![Downloads](https://img.shields.io/pypi/dm/wrg-devguard?label=downloads%2Fmo)](https://pypistats.org/packages/wrg-devguard)
[![CI](https://github.com/yakuphanycl/wrg-devguard/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/yakuphanycl/wrg-devguard/actions/workflows/ci.yml)
[![CodeQL](https://github.com/yakuphanycl/wrg-devguard/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/yakuphanycl/wrg-devguard/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Developer-first AI safety checks: prompt-policy lint + secret & PII scanning.**

Zero-dependency Python CLI that scans a repository for three classes of issues
before your PR lands:

1. **Leaked secrets** — API keys, private keys, tokens, common credential
   formats in tracked files.
2. **Prompt-policy violations** — deny-listed patterns in prompts, system
   messages, and AI-facing text assets (configurable via JSON policy).
3. **PII in logs** — emails, IPs, phone numbers, SSNs, credit cards in log
   files via the `scan-logs` subcommand (v0.2.0+).

Ships as:

- A Python package (`pip install wrg-devguard`)
- A GitHub Action (drop-in composite action for any repo)
- A Claude Code skill (`.claude/skills/wrg-devguard/`)
- A Cursor rule (`.cursor/rules/wrg-devguard.mdc`)

No external dependencies in the core scanner (stdlib only). Optional `[yaml]`
extra for YAML policy files. Optional `bandit` subcommand for Python security
scanning.

## Install

```bash
pip install wrg-devguard
```

For YAML policy support:

```bash
pip install "wrg-devguard[yaml]"
```

## Quick start

```bash
# Run both checks and fail on any high-severity finding
wrg-devguard check --path . --fail-on error

# Scan only for leaked secrets
wrg-devguard scan-secrets --path .

# Lint AI-facing text assets against a policy
wrg-devguard lint-policy --path . --profile strict

# Scan a log file for secrets + PII
wrg-devguard scan-logs app.log

# Emit a JSON report for CI
wrg-devguard check --path . --json-out wrg-devguard-report.json
```

## GitHub Action

```yaml
# .github/workflows/security.yml
name: security
on: [pull_request, push]

jobs:
  wrg-devguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: yakuphanycl/wrg-devguard@v1
        with:
          profile: strict
          fail-on: error
```

See [`action.yml`](./action.yml) for all inputs.

## GitHub Actions Marketplace

3-line quickstart (drop into any `.github/workflows/*.yml`):

```yaml
- uses: yakuphanycl/wrg-devguard@v1
  with:
    path: .
    fail-on: error
```

### Inputs

| Name | Required | Default | Description |
|---|---|---|---|
| `path` | no | `.` | Root path to scan |
| `fail-on` | no | `error` | Fail threshold: `error`, `warn`, `none` |
| `format` | no | `text` | Report format: `text`, `json`, `sarif` |
| `profile` | no | `baseline` | Policy profile: `baseline` or `strict` |
| `allowlist` | no | _empty_ | Optional path to allowlist JSON |
| `python-version` | no | `3.12` | Python version installed by the action |
| `version` | no | _latest_ | Pip version spec (e.g. `==0.1.1`) |

### Outputs

| Name | Description |
|---|---|
| `findings-count` | Total number of findings produced by the scan |
| `report-path` | Path to the generated report (empty when `format: text`) |

### Use cases

**1. PR check — block any error-severity finding:**

```yaml
name: security
on: pull_request
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: yakuphanycl/wrg-devguard@v1
        with:
          path: .
          fail-on: error
```

**2. Scheduled audit — emit SARIF, never fail the job, upload to code-scanning:**

```yaml
name: weekly-audit
on:
  schedule:
    - cron: '0 6 * * 1'
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - id: dg
        uses: yakuphanycl/wrg-devguard@v1
        with:
          format: sarif
          fail-on: none
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.dg.outputs.report-path }}
```

**3. Monorepo path filter — scan only one app, warn-level threshold:**

```yaml
- uses: yakuphanycl/wrg-devguard@v1
  with:
    path: apps/payments
    profile: strict
    fail-on: warn
    format: json
```

### Pinning

- `@v1` — moving major tag, fast-forwards on every minor/patch release
- `@v1.0.0` — immutable release tag (recommended for reproducible CI)

See the [Marketplace listing](https://github.com/marketplace/actions/wrg-devguard) for the latest published versions.

## Claude Code skill

Drop the skill into your workspace:

```bash
mkdir -p .claude/skills/wrg-devguard
curl -L https://raw.githubusercontent.com/yakuphanycl/wrg-devguard/main/.claude/skills/wrg-devguard/SKILL.md \
  -o .claude/skills/wrg-devguard/SKILL.md
```

Claude Code will surface the skill automatically when you ask things like
"scan for secrets", "is this safe to commit", or "check for leaks".

## Cursor rule

Drop the rule into your workspace:

```bash
mkdir -p .cursor/rules
curl -L https://raw.githubusercontent.com/yakuphanycl/wrg-devguard/main/.cursor/rules/wrg-devguard.mdc \
  -o .cursor/rules/wrg-devguard.mdc
```

Cursor will apply the rule before suggesting any `git commit` command.

## Policy file

Default lookup order:

1. `--policy <path>` argument if provided
2. `.wrg/policy.json` at the repo root
3. Built-in defaults

Profiles:

- `baseline` → PR-friendly baseline (recommended for CI, default)
- `strict` → stricter local/release audits (use `--profile strict`)

Place custom policies in `.wrg/policy.json` (JSON) or `.wrg/policy.yaml`
(requires `[yaml]` extra).

## Commands

```
wrg-devguard profiles                           # list available profiles
wrg-devguard lint-policy --path .               # policy lint only
wrg-devguard scan-secrets --path .              # secret scan only
wrg-devguard check --path .                     # both, single JSON report
wrg-devguard check --path . --profile strict
wrg-devguard check --path . --json-out report.json
wrg-devguard check --path . --fail-on warning
wrg-devguard check --path . --allowlist .wrg/allowlist.json
wrg-devguard scan-logs app.log                  # scan log file for secrets + PII
wrg-devguard scan-logs - < deploy.log           # read from stdin
wrg-devguard scan-logs app.log --fail-on medium # exit 1 on medium+ findings
wrg-devguard scan-logs app.log --json-out r.json
wrg-devguard bandit --path src/                 # optional: bandit wrapper
```

## Exit codes

- `0` — no findings above threshold
- `1` — findings at or above `--fail-on` threshold
- `2` — configuration or input error

## Output schema

The `scan-logs` subcommand (v0.2.0+) emits a frozen JSON contract documented at
[`schemas/log_scan_result.schema.json`](schemas/log_scan_result.schema.json).

Consumers (the GitHub Action, the Control Center log viewer, future CI
integrations) parse against this schema. Highlights:

- `schema_version`: `"1"` (frozen for the entire 0.x line).
- `source`: one of `manual`, `ci`, `cc-endpoint`. v0.2.0 ships `manual`;
  `ci` and `cc-endpoint` are coming in v0.3.0.
- `findings[].pattern_id`: stable `<NAMESPACE>-<NNN>` identifiers (`AWS-001`,
  `EMAIL-001`, etc.). 13 patterns across 6 categories. Patterns are versioned
  by ID — superseded patterns get a new ID, never reuse.
- `findings[].redacted_excerpt`: producers MUST middle-mask the matched value.
  Raw secrets never appear in the output.
- Categories and severities are open-enum-friendly: consumers should accept
  unknown values gracefully (treat as a generic finding) so future additions
  don't break existing readers.

### PII categories (v0.2.0)

| Category | Patterns | Example pattern IDs |
|----------|----------|---------------------|
| `secret` | 6 | AWS-001, AWS-002, GH-001, JWT-001, ANTHROPIC-001, OPENAI-001 |
| `pii_email` | 1 | EMAIL-001 |
| `pii_ip` | 2 | IP-001, IP-002 |
| `pii_phone` | 2 | PHONE-001, PHONE-002 |
| `pii_ssn` | 1 | SSN-001 |
| `pii_card` | 1 | CARD-001 |

Built-in false-positive guards: `rfc1918_private_range` (private IPs → info),
`example_domain` (example.com/test.com → info), `test_context` (JWT in test
lines → info), Luhn validation (credit cards).

Validation tests live at `tests/schemas/test_log_scan_result_schema.py`
(28 cases covering self-validation, fixture acceptance, and malformed-payload
rejection). To run them locally:

```bash
pip install -e ".[dev]"
pytest tests/schemas/ -v
```

## Why another secret scanner?

- **Zero runtime deps** — the core scanner is stdlib only, so `pip install` is
  instant and works in any sandbox.
- **Policy lint in the same tool** — most scanners only do secrets. We also
  catch prompt-policy violations (deny-listed patterns, hardcoded system
  prompts, PII in AI-facing text).
- **AI-native UX** — ships with a Claude skill and a Cursor rule so the
  scanner runs automatically inside your AI coding assistant, not just in CI.
- **Stable JSON schema** — `check --json-out` emits a versioned schema that
  never breaks.

## Coming in v0.3.0 (unreleased)

### Log source adapters (`--source ci|cc-endpoint`)

The `scan-logs` subcommand gains source-aware normalization:

```bash
# Scan a GitHub Actions log (strips ANSI, timestamps, group markers)
wrg-devguard scan-logs build.log --source ci

# Reserved — warns and falls back to manual for now
wrg-devguard scan-logs cc-output.log --source cc-endpoint
```

| Source | Behavior |
|--------|----------|
| `manual` (default) | Raw text, no normalization |
| `ci` | GitHub Actions log normalization (ANSI codes, `##[group]` markers, timestamps stripped) |
| `cc-endpoint` | Reserved — emits a warning and falls back to `manual` until adapter ships |

### NAME-001 — Personal name PII pattern

Adds `pii_name` category with a hybrid regex-bigram + stop-list strategy
(stdlib-only, no dictionary import). False-positive guards exclude place names,
code identifiers, and common English words.

### Marketplace draft releases

Non-prerelease tags now create **draft** GitHub Releases. The maintainer
promotes to published via the GitHub UI, which enables the Marketplace "Install"
banner. Pre-release tags (`v*-rc*`, `v*-beta*`) continue to auto-publish.

### Surface at a glance

| Metric | v0.2.0 | v0.3.0 (planned) |
|--------|--------|-------------------|
| PII/secret patterns | 13 | 14+ (NAME-001) |
| Categories | 6 | 7 (`pii_name`) |
| Log sources | 1 (`manual`) | 3 (`manual`, `ci`, `cc-endpoint`) |
| Tests | 183+ | TBD |

## Development

```bash
git clone https://github.com/yakuphanycl/wrg-devguard.git
cd wrg-devguard
pip install -e ".[dev]"
pytest -q
```

## License

MIT. See [LICENSE](./LICENSE).

## Contributing

Issues and PRs welcome. For substantial changes, open an issue first to
discuss scope.

---

Part of the [WinstonRedGuard](https://github.com/yakuphanycl/WinstonRedGuard)
ecosystem. The monorepo at `apps/wrg_devguard/` is the canonical source; this
repo is a distribution mirror kept in sync on every release.
