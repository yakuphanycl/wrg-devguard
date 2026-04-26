# Changelog

All notable changes to this project will be documented in this file.

## [0.2.1] — 2026-04-27

### Fixed — IP-002 false-positive class on CI logs

Patch release addressing two FP classes for the v0.2.0 IP-002 (IPv6)
detector surfaced by real-CI dogfood (PR #27, run IDs `24966427106`
and `24966008833`, total 10/10 IP-002 hits = 100% FP).

- **Timestamp shape rejection** (`_is_timestamp_shape`): IPv6 candidates
  with ≥3 colon-separated groups, every group ≤2 chars and all-decimal,
  are now rejected. Real IPv6 needs `::` to compress, so a sequence of
  3+ short decimal groups separated by single `:` is a clock value
  (`0:00:00`, `12:30:45`, `1:23:45`), not an address. Group-count
  threshold preserves loopback `::1` and `::ffff:` shapes.
  - **Eliminates** the 4/10 FP class observed in real CI logs of the
    `MB 24.4 MB/s  0:00:00` shape.
- **GitHub Actions workflow command guard**
  (`_GH_ANNOTATION_PREFIX_RE`): lines opening with `::error::`,
  `::warning::`, `::group::`, `::debug::`, `::set-output`,
  `::add-mask`, `::endgroup::`, etc. (the documented GitHub Actions
  workflow commands) skip IPv6 detection entirely. The leading `::` +
  single hex-shaped char (e.g. the `e` in `error`) satisfies the IPv6
  regex's third alt-branch, producing the bulk of the FP class.
  - **Eliminates** the 6/10 FP class observed in real CI logs of the
    `::error::fail-on must be one of ...` shape.

### Tests

15 new cases in `tests/test_pii_patterns.py`:
- `test_ip_002_rejects_timestamp_shape` — 6 parametrized
  HH:MM:SS shapes (`0:00:00`, `1:23:45`, `10:20:30`, etc.)
- `test_ip_002_rejects_gh_annotation_prefix` — 9 parametrized GH
  Actions workflow commands
- `test_ip_002_real_ipv6_after_annotation_keyword_in_prose` — sanity:
  prose containing the substring `error` doesn't trigger the guard
- `test_ip_002_real_ipv6_alongside_timestamp_on_same_line` — sanity:
  per-candidate guard preserves real IPv6 next to a timestamp
- `test_ip_002_short_loopback_not_timestamp_shape` — guard
  threshold (`::1`, single-group, must keep flagging)

All v0.2.0 IP-002 positive tests still pass verbatim. No schema or
public-API change — the contract `schemas/log_scan_result.schema.json`
remains v1, no `pattern_id` change.

### Notes

- This is a **pure FP-fix patch** — nothing additive. v0.3.0 work
  proceeds in parallel; this patch can ship immediately on the v0.2.x
  line.
- IP-002 severity (MEDIUM) and category (`pii_ip`) unchanged.

## [0.2.0] — 2026-04-26

### Added — log scanning + PII detection

- `wrg-devguard scan-logs <path|->` subcommand: scans a single log file (or
  stdin) for secrets and personally-identifiable information. Emits a JSON
  report that conforms to a frozen v1 schema.
- **Frozen output contract** at `schemas/log_scan_result.schema.json`
  (JSON Schema 2020-12). Consumers (CC log_viewer, future CI integrations)
  can pin against it. 28 schema-validation tests guard against drift.
- **PII detection engine** (`wrg_devguard.pii`, stdlib-only) covering
  13 patterns across 9 categories:
  - Secrets (HIGH): `AWS-001` (access key), `AWS-002` (secret key with
    self-corroborating context guard), `GH-001` (GitHub PAT), `JWT-001`,
    `ANTHROPIC-001`, `OPENAI-001` (deduplicated against ANTHROPIC).
  - PII: `EMAIL-001` (RFC-5322 simplified), `IP-001`/`IP-002` (IPv4 + IPv6
    with RFC-1918 down-classify), `PHONE-001` (TR + US shapes via
    rationale), `SSN-001` (US format), `CARD-001` (13–19 digits + Luhn
    check, with a Stripe-test-card whitelist for canonical demo numbers).
  - **False-positive suppressions**: `rfc1918_private_range`,
    `example_domain`, `test_context` — each downgrades severity to `info`
    and records the rule in `Finding.fp_suppression`. Aligned with the
    monorepo-audit dogfood discipline (target: <20% FP, achieved <10% on
    the 80-line integration fixture).
  - **Redaction-by-design**: every `redacted_excerpt` middle-masks the
    matched value (≤6 leading + ≤6 trailing chars + ≥4 stars). Raw
    secrets never enter the output — verified end-to-end by tests.
- `--strict`-style severity gating via `--fail-on
  {high|medium|low|info|error|warning}` (legacy `error`→`high`,
  `warning`→`medium` aliases preserved for cross-compat with the older
  `check` / `scan-secrets` subcommands).
- **Lazy detector resolution**: `scan_logs.py` imports `pii.py` lazily,
  so the CLI surface ships safely without the engine and gains it on
  first call once the package is installed. This is the seam used by
  the v0.2.0 release-cut order (scan-logs CLI landed before the engine).
- Validation fixtures: `tests/schemas/fixtures/clean.json` (empty
  findings) and `mixed.json` (4-finding sample covering all categories).
- Sample log fixture (`tests/fixtures/pii_sample_log.txt`, ~80 lines)
  exercising every pattern with both real-shape positive cases and
  false-positive-suppression cases.

### GitHub Actions Marketplace surface (continued from previous wave)

- GitHub Actions Marketplace publish-ready surface:
  - `action.yml` reshaped around the marketplace-friendly contract
    (`path`, `fail-on` ∈ `{error, warn, none}`, `format` ∈ `{text, json, sarif}`)
    with new outputs `findings-count` and `report-path`.
  - `scripts/json_to_sarif.py` — stdlib-only SARIF v2.1.0 converter so
    `format: sarif` integrates with GitHub code-scanning ingestion.
  - `.github/workflows/marketplace-release.yml` — tag-triggered release
    pipeline (`v*.*.*`): matrix CI on the tag commit, GitHub Release with
    notes extracted from this CHANGELOG, fast-forward of the moving `v1`
    major tag (skipped for pre-release tags such as `v1.0.0-rc.1`).
  - `tests/marketplace/` — 5 smoke tests pinning the redacted-JSON
    contract, the AKIA fixture exit-code signal, and the SARIF
    converter behaviour at 0/1/7 findings.
- README §"GitHub Actions Marketplace": 3-line quickstart, full
  inputs/outputs tables, three concrete use-cases (PR check, scheduled
  SARIF audit, monorepo path filter), and `@v1` vs immutable pinning
  guidance.

### Changed
- `ci.yml::action-composite` job migrated from the removed `json-out`
  input to `format: json` + the new `report-path` output.
- `findings-count` action output is exit-code-derived (`0` or `1`)
  rather than parsed from the JSON body. The package's CLI redacts
  findings from the on-disk JSON report by design — the exit code is
  the only reliable signal that findings hit the threshold.

### Notes
- Marketplace publish itself is a manual one-time approval flow at
  `https://github.com/marketplace/actions/wrg-devguard` after the first
  non-prerelease tag is pushed; the agent cannot click that button.
- v0.2.0 introduces 1 dev-only optional dependency (`jsonschema>=4.20`,
  used solely by the schema-validation test suite). The runtime surface
  remains stdlib-only — `pip install wrg-devguard` resolves with no
  transitive deps.
- Test count grew from 8 (v0.1.0) → 253 (v0.2.0): scan-logs CLI 35,
  PII patterns 98, schema 28, plus pre-existing policy/secrets/marketplace
  coverage. Full suite runs in ~1.6s.

[0.2.0]: https://github.com/yakuphanycl/wrg-devguard/releases/tag/v0.2.0

## [0.1.1] — 2026-04-16

### Fixed
- `--profile baseline|strict` no longer raises `ValueError` when the profile
  policy file is missing; falls back to the built-in default policy instead.
  This fixes failures on repositories that do not have a `.wrg/` directory.
- `action.yml` default `profile` input is now `baseline` (matches the CLI).
  Previously the default `default` was not a recognised profile name.

### Notes
- `0.1.0` shipped to PyPI included the bugs above; users on `0.1.0` should
  upgrade. The composite action `@v1` tag is fast-forwarded to this release.

## [0.1.0] — 2026-04-12

### Added
- Secret scanning: API keys, tokens, private keys, common credential formats
- Prompt-policy lint: deny-listed patterns in AI-facing text assets
- CLI: `wrg-devguard check` with `--path`, `--profile`, `--fail-on`, `--json-out`
- Profiles: `baseline` (default) and `strict`
- GitHub Action: composite action with 7 configurable inputs
- Claude Code skill: `.claude/skills/wrg-devguard/SKILL.md`
- Cursor rule: `.cursor/rules/wrg-devguard.mdc`
- Zero runtime dependencies (stdlib only), optional `[yaml]` extra
- 8 unit tests, Python 3.11–3.13 matrix CI

### Distribution
- PyPI: `pip install wrg-devguard` ([pypi.org/project/wrg-devguard](https://pypi.org/project/wrg-devguard/))
- GitHub Action: `uses: yakuphanycl/wrg-devguard@v1`

[0.1.1]: https://github.com/yakuphanycl/wrg-devguard/releases/tag/v0.1.1
[0.1.0]: https://github.com/yakuphanycl/wrg-devguard/releases/tag/v1.0.0
