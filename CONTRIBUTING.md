# Contributing to wrg-devguard

Thanks for your interest. This repo is a distribution mirror — the canonical
source lives in the WinstonRedGuard monorepo at
[`apps/wrg_devguard/`](https://github.com/yakuphanycl/WinstonRedGuard/tree/main/apps/wrg_devguard).

## Where to open issues

Open issues here (`yakuphanycl/wrg-devguard`) for anything affecting the
standalone distribution: CLI bugs, GitHub Action behavior, Claude skill
wording, Cursor rule matching, policy semantics.

For monorepo-wide concerns, open an issue on
[WinstonRedGuard](https://github.com/yakuphanycl/WinstonRedGuard/issues).

## Where to submit PRs

Please open PRs against this repo. Accepted changes are merged here and then
synced back into the monorepo source of truth on the next release cycle.

## Local development

```bash
git clone https://github.com/yakuphanycl/wrg-devguard.git
cd wrg-devguard
pip install -e ".[dev,yaml]"
pytest -q
```

## Scope

`wrg-devguard` is **intentionally small**. Additions that expand scope
beyond "secret scanning + prompt-policy lint" should be discussed in an issue
before implementation. Proposals to bolt on unrelated scanners, fuzzers, or
linters will usually be declined — those belong in their own tools.

## Testing

Every PR must:

- Add or update a test under `tests/` for any behavioral change
- Pass `pytest -q` on Python 3.11, 3.12, and 3.13 (CI enforces this)
- Keep `wrg-devguard check --path .` green on the repo itself (self-scan CI)

## Commit style

Commits use conventional-ish prefixes (`feat:`, `fix:`, `docs:`, `test:`).
Keep commit messages focused on *why*, not just *what*.

## License

By contributing, you agree your contributions are MIT-licensed.
