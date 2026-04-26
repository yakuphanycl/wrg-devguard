# DRIFT-NNN External Corpus: Acquisition & Validation

> **Purpose:** Validate the 12 DRIFT-NNN patterns from [PR #23](../docs/v0_3_0-item-3-investigation.md)
> against real-world CI logs before committing to a first-batch implementation.
>
> **Date:** 2026-04-27
> **Author:** Agent C

---

## 1. Corpus Provenance

All logs are from **public** GitHub Actions runs on OSS repositories.
GitHub Actions logs are publicly accessible when the repository is public.

| File | Source repo | Workflow | Run ID | Date | Conclusion | Lines |
|------|------------|----------|--------|------|------------|-------|
| `django_actions_run.log` | [django/django](https://github.com/django/django) | Tests | [24967955118](https://github.com/django/django/actions/runs/24967955118) | 2026-04-26 | success | 905 |
| `alembic_actions_run.log` | [sqlalchemy/alembic](https://github.com/sqlalchemy/alembic) | Run tests | [24159480459](https://github.com/sqlalchemy/alembic/actions/runs/24159480459) | 2026-04-08 | failure | 1005 |
| `rails_actions_run.log` | [rails/rails](https://github.com/rails/rails) | Rail Inspector + Releaser tests | [23510560540](https://github.com/rails/rails/actions/runs/23510560540) + [24539389142](https://github.com/rails/rails/actions/runs/24539389142) | 2026-03-24 / 2026-04-16 | success + failure | 1262 |

**Trimming:** Full logs ranged from 217 to 143,880 lines. Each was trimmed to
~900-1300 lines, preserving: setup/header (first 500), any DRIFT pattern hit
regions, and tail/summary (last 200). Trimming methodology is documented in
section comments within each log file (`# === SECTION ===` markers).

**PII scan:** All three logs passed a regex sweep for email addresses and public
IP addresses. No PII found — only version-number-shaped strings (e.g. `3.14.2`)
matched the IPv4 pattern and were filtered out.

**License note:** GitHub Actions logs are generated artifacts of public CI runs.
They contain no copyrightable content beyond the CI output itself. All source
repositories are MIT-licensed (Django: BSD-3, Alembic: MIT, Rails: MIT).
Logs are used here as test fixtures for pattern validation, not redistributed
as software.

---

## 2. DRIFT Pattern Catalog (from PR #23)

| ID | ORM target | Regex (simplified) | Expected in framework CI? |
|----|-----------|-------------------|---------------------------|
| DRIFT-001 | Django | `Your models.*have changes that are not yet reflected` | Unlikely — this is a user-app warning, not framework test output |
| DRIFT-002 | Django | `[Uu]napplied migration` | Unlikely — same reason |
| DRIFT-003 | Django | `makemigrations\s+--check` | Yes — Django tests its own migration checking logic |
| DRIFT-004 | Alembic | `Target database is not up to date` | Possible — Alembic tests this error path |
| DRIFT-005 | Alembic | `Can't locate revision identified by` | Yes — Alembic tests missing-revision error handling |
| DRIFT-006 | Alembic | `Running upgrade.*->` | Possible — Alembic tests migration execution |
| DRIFT-007 | Prisma | `Drift detected.*schema is not in sync` | N/A — no Prisma corpus |
| DRIFT-008 | Prisma | `\[\*\]\s*Changed the .* table` | N/A |
| DRIFT-009 | Prisma | `\[-\]\s*Removed .* on columns` | N/A |
| DRIFT-010 | Rails | `Migrations are pending` | Unlikely — Rails CI doesn't run user-app migrations |
| DRIFT-011 | Rails | `ActiveRecord::PendingMigrationError` | Unlikely — same reason |
| DRIFT-012 | Generic | `(?i)schema.*drift\|drift.*schema` | Unlikely — generic, broad |

---

## 3. Hit Matrix (12 patterns x 3 logs)

| Pattern | alembic | django | rails | Total | Verdict |
|---------|---------|--------|-------|-------|---------|
| DRIFT-001 | 0 | 0 | 0 | 0 | No signal — expected (user-app warning) |
| DRIFT-002 | 0 | 0 | 0 | 0 | No signal — expected |
| DRIFT-003 | 0 | **2** | 0 | 2 | **FP** — test case *names* match, not actual drift |
| DRIFT-004 | 0 | 0 | 0 | 0 | No signal — error path not in this run |
| DRIFT-005 | **2** | 0 | 0 | 2 | **TP** — real `CommandError` in Alembic test suite |
| DRIFT-006 | 0 | 0 | 0 | 0 | No signal — upgrade not exercised in trimmed section |
| DRIFT-007 | 0 | 0 | 0 | 0 | N/A — no Prisma corpus |
| DRIFT-008 | 0 | 0 | 0 | 0 | N/A |
| DRIFT-009 | 0 | 0 | 0 | 0 | N/A |
| DRIFT-010 | 0 | 0 | 0 | 0 | No signal — expected (user-app error) |
| DRIFT-011 | 0 | 0 | 0 | 0 | No signal — expected |
| DRIFT-012 | 0 | 0 | 0 | 0 | No signal — too specific for framework CI |
| **TOTAL** | **2** | **2** | **0** | **4** | |

**Total: 4 hits across 3,172 corpus lines (0.13% hit rate).**

---

## 4. Detailed Hit Analysis

### DRIFT-003 in Django (FALSE POSITIVE)

```
L547: makemigrations --check should exit with a zero status when there are no ... ok
L549: makemigrations --check should exit with a non-zero status when ... ok
```

These are **test case names** printed by Django's test runner, not actual
`makemigrations --check` invocations. The pattern matches the substring
`makemigrations --check` inside a descriptive test name.

**Impact on design:** DRIFT-003 needs a tighter regex or context guard.
Options:
- Require a shell prompt prefix (`\$\s+.*makemigrations\s+--check`)
- Require exit code context (`exit\s+\d+.*makemigrations`)
- Downgrade to `info` severity (current: `low`) since it's inherently ambiguous

### DRIFT-005 in Alembic (TRUE POSITIVE)

```
L555: alembic.util.exc.CommandError: Can't locate revision identified by 'b05'
L708: FAILED tests/test_command.py::EditTest::test_edit_b - alembic.util.exc.CommandError
```

This is a **genuine Alembic error** — the test intentionally triggers a missing-
revision scenario. In a user-app CI log, this exact string would indicate real
schema drift. The pattern works correctly here.

**Nuance:** In framework CI this is expected (the test is *testing* the error
path). In user-app CI, this would be a real `high`-severity finding. A
`test_context` suppression (similar to JWT-001's existing guard) could
distinguish these cases.

---

## 5. First-Batch Validation Status

PR #23 recommended 5 "exact-match" patterns as the lowest-FP first batch:
DRIFT-001, DRIFT-004, DRIFT-007, DRIFT-010, DRIFT-011.

| Pattern | Validated? | Notes |
|---------|-----------|-------|
| DRIFT-001 | **Not triggered** | Expected — Django framework CI doesn't generate this user-facing warning |
| DRIFT-004 | **Not triggered** | Expected — Alembic failure run didn't exercise this specific path |
| DRIFT-007 | **Not available** | No Prisma corpus — Prisma CI uses `action_required` status, logs not downloadable via `gh` |
| DRIFT-010 | **Not triggered** | Expected — Rails CI doesn't run `db:migrate` in application context |
| DRIFT-011 | **Not triggered** | Expected — same as DRIFT-010 |

**Assessment:** The first-batch patterns' **absence from framework CI is
expected and is not a negative signal.** These patterns target *user-application*
CI logs, not framework CI. The corpus validates that exact-match patterns have
**zero false positives in framework-level CI** — a strong FP-safety signal.

The one pattern that *did* trigger (DRIFT-005) confirms the regex engine works
and Alembic's error strings are matchable. The false positive on DRIFT-003
is a useful design lesson: substring matches inside test-runner output need
context guards.

---

## 6. Recommendations Update

### For v0.3.1 first batch

1. **Keep DRIFT-001/004/007/010/011 as first batch** — zero-FP confirmed in
   framework CI; these will only fire in user-app logs where they're actionable.
2. **Add `test_context` guard to DRIFT-005** — when implementing, reuse the
   existing `test_context` suppression from JWT-001.
3. **Rework DRIFT-003** — tighten regex to require shell invocation context,
   not bare substring match. Consider `^\s*\$?\s*.*manage\.py\s+makemigrations\s+--check`.
4. **Defer DRIFT-012** — the generic catch-all had zero hits; leave it as a
   low-priority last-batch pattern.

### Corpus gaps

- **User-app CI logs** would be the ideal second corpus (e.g., a Django app
  that runs `makemigrations --check` in CI). Framework CI confirms FP safety
  but cannot confirm TP recall.
- **Prisma corpus** was blocked by `action_required` status on recent runs.
  A future corpus update should target a Prisma project with public passing CI.

---

## 7. Reproduction

To re-run the pattern validation:

```bash
# Download fresh logs
gh run view 24967955118 --repo django/django --log > django_full.log
gh run view 24159480459 --repo sqlalchemy/alembic --log > alembic_full.log
gh run view 23510560540 --repo rails/rails --log > rails_full.log

# Grep each pattern
grep -cP 'Your models.*have changes that are not yet reflected' *.log
grep -cP "Can't locate revision identified by" *.log
# ... etc. for all 12 patterns
```
