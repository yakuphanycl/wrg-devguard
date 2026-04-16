# Changelog

All notable changes to this project will be documented in this file.

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
