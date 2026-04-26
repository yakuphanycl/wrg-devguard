# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
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
