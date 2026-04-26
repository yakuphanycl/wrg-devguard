# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] — v0.3.0

### Added — `NAME-001` PII pattern (First+Last name detection)

- **`NAME-001`** detector (`wrg_devguard.pii_names`, stdlib-only) flags
  First+Last name bigrams in scanned logs. Hybrid strategy:
  - Curated common-given-names dictionary (~150 entries spanning Anglo,
    Turkish, Slavic, East Asian, Hispanic, French/Irish, with diacritic
    coverage) anchors high-confidence matches at **0.95 → MEDIUM**.
  - NER-lite capitalized-bigram fallback fires on names outside the
    dictionary at **0.70 → LOW** when both words are ≥3 chars and clear
    of the place / phrase / token stop-lists.
- **False-positive guards** (all unit-tested): CamelCase identifiers
  (`FooBar`, `getUserName`), place-name prefixes (`New York`,
  `San Francisco`, `Saint Louis`, `Mount Everest`), code-line keywords
  (`def` / `class` / `function` / `import` / `return` / …),
  docstring/JSDoc parameter markers (`:param`, `@param`, `:returns:`,
  `@returns`), file paths (`/home/John Smith/.config/...`), URL fragments
  (`https://example.com/John Smith`), and a curated phrase stop-list
  (`Hello World`, `Thank You`, `Best Regards`, `Lorem Ipsum`, …).
- **Test-context downgrade**: lines containing `test_` / `fixture` /
  `sample` emit `severity=info` with `fp_suppression="test_context"` —
  same convention as `JWT-001` and `EMAIL-001` example domains.
- **Edge cases**: hyphenated (`Mary-Jane Watson`), apostrophe (`Sean
  O'Brien`), middle initial (`John Q. Smith`), and diacritics
  (`Çağrı Yıldız`, `José García`) all match. Single-name (`John`),
  all-caps (`HENRY FORD`), and short-bigram (`Ai Bo`) are deliberately
  not matched.
- **`Category.PII_NAME`** (`pii_name`) added to the schema's open enum
  per its v0.3.0 forward-compat note. `schema_version` stays at `1`
  (additive, consumer-tolerant change as documented in the original
  contract).

### Schema

- `schemas/log_scan_result.schema.json`: `Category` enum gains
  `pii_name`. `schema_version` unchanged. No producer-side breakage —
  consumers that already followed the "accept unknown values gracefully"
  guidance continue to work without changes.

### Severity rubric (NAME-001)

| pattern_id | category   | confidence | severity | fp_suppression  |
| ---------- | ---------- | ---------- | -------- | --------------- |
| NAME-001   | pii_name   | 0.95       | MEDIUM   | (none)          |
| NAME-001   | pii_name   | 0.70       | LOW      | (none)          |
| NAME-001   | pii_name   | 0.95/0.70  | INFO     | `test_context`  |

### Tests

- `tests/test_pii_names_patterns.py`: 25+ cases covering the TP / TN /
  edge matrix above plus pipeline-wiring invariants (`detect_line` ↔
  `detect_names`, schema-shape compatibility through
  `scan_logs._finding_to_dict`, redaction safety, and a regression guard
  that pins zero NAME-001 hits on the existing v0.2.0 fixture log).
- `tests/schemas/test_log_scan_result_schema.py`: `pii_name` added to
  the expected Category enum.

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
