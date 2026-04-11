# Changelog

All notable changes to this project will be documented in this file.

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

[0.1.0]: https://github.com/yakuphanycl/wrg-devguard/releases/tag/v1.0.0
