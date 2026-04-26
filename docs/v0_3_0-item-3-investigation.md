# v0.3.0 Item 3 — Schema Drift Detector: Pre-Design Investigation

> **Status:** INVESTIGATION (not a spec — informs user's reading decision)
> **Date:** 2026-04-26
> **Author:** Agent C
> **Context:** PR #19 (v0.3.0 brief) lists three possible readings for Item 3.
> This document provides evidence so the user can pick A, B, or C.

---

## 1. Reading A — Contract Guard (meta-tests on v1 schema)

### What exists today

`schemas/log_scan_result.schema.json` is a frozen v1 contract (Draft 2020-12).
28 tests in `tests/schemas/test_log_scan_result_schema.py` guard it:

| Category | Tests | What they catch |
|----------|-------|-----------------|
| Schema self-validation | 8 | Draft conformance, frozen `schema_version: "1"`, locked enums |
| Fixture positive | 2 | `clean.json` (0 findings) + `mixed.json` (4 findings) validate |
| Malformed-payload negative | 14 | Missing fields, unknown enums, bad pattern_id, length overflow |
| Optional-field acceptance | 4 | `fp_suppression`, `sha256`, `runtime_ms` absent OK |

The docstring (line 1-9) explicitly states these "guard against accidental
contract drift."

### What Reading A would add

Guard tests that the current 28 do **not** cover:

| Drift scenario | Current coverage | Proposed guard |
|----------------|-----------------|----------------|
| `required` field silently downgraded to optional | NOT covered — tests check required presence but not that the schema's `required` array is exhaustive | Assert `required == [exact list]` for top-level + Finding |
| Optional field promoted to required without major bump | NOT covered | Assert optional fields list frozen |
| Enum value removed (e.g. drop `"info"` from severity) | Partially — `test_schema_severity_levels` checks the list but doesn't assert it's a superset of v1 baseline | Assert severity/category enums are supersets of v1 frozen set |
| `pattern_id` regex loosened (e.g. allow lowercase) | NOT covered | Assert regex pattern string is exact match |
| `additionalProperties` added/removed on Finding | NOT covered | Assert `additionalProperties` absent or false |
| `$defs` shape changed (e.g. rename Finding → Match) | NOT covered | Assert `$defs` keys frozen |

### Blast radius & effort

- **Files touched:** 1 (`tests/schemas/test_schema_contract_guard.py`, NEW)
- **PR count:** 1
- **Lines est:** ~80-100
- **Risk:** Zero runtime risk (test-only, no src/ changes)
- **Ship time:** 1 agent session

---

## 2. Reading B — Content-Pattern Detector (ORM log signals)

### The problem space

Production and CI logs contain schema-drift evidence emitted by ORM/migration
tools. These signals are actionable — they indicate that the deployed database
schema is out of sync with application code. A content-pattern detector would
scan log files (via `scan-logs`) and flag these lines.

### Pattern catalog (12 patterns from 5 ORMs)

Patterns sourced from official documentation and GitHub issue trackers:

| ID | ORM | Pattern (simplified regex) | Example log line | Severity | FP risk |
|----|-----|---------------------------|------------------|----------|---------|
| DRIFT-001 | Django | `Your models.*have changes that are not yet reflected` | `Your models in app(s): 'auth', 'users' have changes that are not yet reflected in a migration` | medium | Low — highly specific message |
| DRIFT-002 | Django | `Unapplied migration\(s\)` | `You have 3 unapplied migration(s). Run 'manage.py migrate'` | medium | Low |
| DRIFT-003 | Django | `manage\.py makemigrations --check` exit 1 context | `makemigrations --check` in CI log + non-zero exit | low | Medium — needs exit-code context |
| DRIFT-004 | Alembic | `Target database is not up to date` | `FAILED: Target database is not up to date.` | high | Low — Alembic's exact error string |
| DRIFT-005 | Alembic | `Can't locate revision identified by` | `Can't locate revision identified by 'a1b2c3d4'` | high | Low |
| DRIFT-006 | Alembic | `INFO.*Running upgrade.*->` (informational) | `INFO [alembic.runtime.migration] Running upgrade -> 1a2b3c, add users table` | info | Low — informational, not error |
| DRIFT-007 | Prisma | `Drift detected:.*schema is not in sync` | `Drift detected: Your database schema is not in sync with your migration history` | high | Low — Prisma's exact banner |
| DRIFT-008 | Prisma | `\[\*\] Changed the .* table` | `[*] Changed the 'account' table` | medium | Low — Prisma bracket notation |
| DRIFT-009 | Prisma | `\[-\] Removed .* on columns` | `[-] Removed foreign key on columns (userId)` | medium | Medium — could appear in docs/comments |
| DRIFT-010 | Rails | `Migrations are pending` | `Migrations are pending. To resolve this issue, run: bin/rails db:migrate` | high | Low — ActiveRecord's exact message |
| DRIFT-011 | Rails | `ActiveRecord::PendingMigrationError` | `ActiveRecord::PendingMigrationError: Migrations are pending` | high | Low — exception class name |
| DRIFT-012 | Generic | `schema.*drift\|drift.*schema` (case-insensitive) | `WARNING: schema drift detected in production` | low | High — broad catch-all, needs context window |

### FP suppression strategies

| Strategy | Applies to | Mechanism |
|----------|-----------|-----------|
| `doc_context` | DRIFT-009, DRIFT-012 | Suppress if line is inside markdown/comment block (# or //) |
| `test_context` | DRIFT-003 | Only flag if CI exit-code context present |
| `info_downgrade` | DRIFT-006 | Always emit as info (migration running ≠ drift) |
| `exact_match` | DRIFT-001/004/007/010/011 | These are exact ORM strings — FP near zero |

### Naming decision: DRIFT-NNN vs MIGRATION-NNN vs DBLOG-NNN

| Option | Pro | Con | Recommendation |
|--------|-----|-----|----------------|
| `DRIFT-NNN` | Directly describes the problem (schema drift) | Could collide conceptually with monorepo-audit's `SCHEMA-NNN` (different scope, same problem domain) | **Recommended** |
| `MIGRATION-NNN` | Describes the mechanism (migration tool output) | Not all patterns are migration-specific (DRIFT-012 is generic) | Acceptable alternative |
| `DBLOG-NNN` | Broad, covers any DB log signal | Too vague — could mislead into non-drift DB patterns | Not recommended |

**Recommendation:** `DRIFT-NNN`. Clear, descriptive, and the `DRIFT-` prefix is
disjoint from monorepo-audit's `SCHEMA-` prefix. No collision.

### Structural difference from monorepo-audit's schema_drift

| Dimension | monorepo-audit (`SCHEMA-NNN`) | wrg-devguard Reading B (`DRIFT-NNN`) |
|-----------|-------------------------------|--------------------------------------|
| **What it scans** | Python source code + live SQLite DB files | Log file text (JSONL, plaintext, CI output) |
| **Detection method** | AST-walk for `CREATE TABLE` DDL → in-memory SQLite → PRAGMA comparison | Regex pattern matching on log lines |
| **Scope** | SQLite only, raw DDL only | Any ORM/tool (Django, Alembic, Prisma, Rails, generic) |
| **False-positive profile** | High on DORMANT apps (8/8 FP on WRG dogfood); zero-table DB is main source | Low for exact-match patterns; DRIFT-012 catch-all needs tuning |
| **Category in schema** | N/A (skill output, not JSON schema Finding) | Would add `"schema_drift"` to Finding category enum (additive, v1-safe) |
| **Runtime** | Needs live DB file access | Works on log snapshots (offline) |

These are **complementary, not competing** tools. monorepo-audit catches
code-vs-DB structural drift at dev time; Reading B catches ORM warning signals
in production/CI logs.

### New category enum value

Adding `"schema_drift"` to the Finding category enum is **v1-safe** — the
schema marks category as an open enum (line 111: "consumers must accept unknown
values gracefully"). No schema_version bump needed.

### Blast radius & effort

- **Files touched:** 2-3 (`src/wrg_devguard/drift.py` NEW + `pii.py` category enum + test file)
- **PR count:** 2 (patterns + integration with scan-logs)
- **Lines est:** ~250-350 (detector) + ~200 (tests)
- **Risk:** Low-medium (noisy signal class if DRIFT-012 not tuned)
- **Ship time:** 2-3 agent sessions
- **Dependency:** Should serialize after Item 2 if both touch `pii.py`, OR split
  into sibling module `drift.py` with lazy import (recommended)

---

## 3. Reading C — Park to v0.4.0

### What the user loses

- **No automated schema-drift detection** in CI logs. User continues doing:
  - Manual `grep -i "drift\|pending migration\|not up to date"` on CI output
  - Ad-hoc review of Alembic/Django warnings in deployment logs
  - Relying on monorepo-audit's code-vs-DB check (SQLite only, high FP on WRG)
- These are viable workarounds — schema drift is a "nice to detect" signal,
  not a "must have" for the v0.3.0 line.

### What gets unblocked

- v0.3.0 ships faster: Wave 1 (Items 1+2+4) is fully parallel-safe and can
  merge without waiting for Item 3 reading decision.
- Item 3 design benefits from real-world log data collected during v0.3.0
  adapter work (Item 1). CI adapter output will provide concrete log samples
  that validate or invalidate the pattern catalog above.

### Alternative Wave 1 candidates

| Option | Description | Effort |
|--------|-------------|--------|
| Expand Item 2 (Names PII) | Add NAME-002 (organizational names) alongside NAME-001 (personal) | +1 PR, low risk |
| Add YAML/TOML secret scanner | Detect hardcoded secrets in config files (beyond log scanning) | 2 PR, medium risk |
| `--watch` mode for scan-logs | inotify/polling for live log tailing | 2 PR, medium complexity |

None of these are as differentiated as schema-drift detection — they're
incremental improvements, not new signal classes.

---

## 4. Recommendation

**Pick Reading A now, queue Reading B for v0.3.1 or v0.4.0.**

1. Reading A is 1 PR / ~80 lines / zero runtime risk — it closes a real gap in
   contract guard coverage (6 drift scenarios currently unguarded) and ships in
   a single session alongside Wave 1.
2. Reading B is valuable but benefits from Item 1's CI adapter work landing
   first — real CI log samples will validate the pattern catalog and tune
   DRIFT-012's FP risk before implementation.
3. Parking B entirely (Reading C) wastes the research in this document; queueing
   it for v0.3.1 preserves the design while letting Item 1 provide live data.

---

## 5. Open Questions for User

1. **Reading A scope:** Should contract guard tests live in the existing
   `test_log_scan_result_schema.py` (28 tests → ~34) or a new dedicated
   `test_schema_contract_guard.py` file?

2. **Reading B first batch:** If B is queued for v0.3.1, is Django + Alembic
   (DRIFT-001 through DRIFT-006) sufficient for the first batch, or should all
   5 ORMs ship together?

3. **Reading B category enum:** Should the new category be `"schema_drift"`
   (matching monorepo-audit naming) or `"migration_drift"` (emphasizing
   log-based vs structural detection)?

4. **FP suppression reuse:** Can the existing `test_context` / `example_domain`
   suppression infrastructure be extended for `doc_context` (DRIFT-009/012), or
   does B need a new suppression mechanism?

---

## Sources

- [Django Migrations docs](https://docs.djangoproject.com/en/6.0/topics/migrations/)
- [Alembic Commands — check](https://alembic.sqlalchemy.org/en/latest/api/commands.html)
- [Alembic check discussion #1441](https://github.com/sqlalchemy/alembic/discussions/1441)
- [Prisma Drift Detection troubleshooting](https://www.prisma.io/docs/orm/prisma-migrate/workflows/troubleshooting)
- [Prisma "Drift detected" issues](https://github.com/prisma/prisma/issues/19100)
- [Rails ActiveRecord::Migration source](https://github.com/rails/rails/blob/main/activerecord/lib/active_record/migration.rb)
- [Django Forum — schema drift detection RFC](https://forum.djangoproject.com/t/deterministic-migration-replay-schema-drift-detection-for-django/44382)
- [django-migration-audit](https://forum.djangoproject.com/t/introducing-django-migration-audit-verify-your-database-schema-history/44361)
- [Prisma "Silent Schema Killer" article](https://medium.com/@sivasaravanan101004/prisma-migration-drift-the-silent-schema-killer-and-how-to-stop-it-076a5d756b1a)
- [Atlas v0.18 — drift detection + SQLAlchemy support](https://atlasgo.io/blog/2024/01/09/atlas-v-18)
