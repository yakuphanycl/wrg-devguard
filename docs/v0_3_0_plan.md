# wrg-devguard v0.3.0 — sequencing brief

_Status: **DRAFT** — needs user review before any implementation PR opens._
_Author: A. Reviewer: user. Created post-v0.2.0 (#18 merged 2026-04-26)._

## Scope of this document

v0.3.0 has four queued items. This brief decides:

1. What each item actually means in concrete file/contract terms.
2. Which items are **ready** vs **needs-design**.
3. Sequencing — which can ship in parallel, which gate on what.
4. Blast radius + PR count estimate per item.
5. Open questions that need user input before any code lands.

No detector or workflow change is implemented yet. The brief itself is
the only artifact. Once approved, item-level PRs open against `main`.

## Inputs

- Current release: **v0.2.0** (CHANGELOG line 5; merged via #18 on
  2026-04-26).
- Frozen contract: `schemas/log_scan_result.schema.json` (v1, locked
  for the 0.2.x line; bumping is a v1.0.0 conversation, not v0.3.0).
- Architecture seam already in place (`scan_logs.py:29`):
  ```
  ALLOWED_SOURCES = ("manual", "ci", "cc-endpoint")
  ```
  `manual` is the only one wired in v0.2.0; `ci` and `cc-endpoint` were
  declared during v0.2.0 specifically so v0.3.0 adapters fit without a
  schema bump.
- Dogfood discipline carries over from v0.2.0 (target: <20% raw FP,
  <10% real FP after tuning, redaction-by-design).

## Item map

### Item 1 — Log analysis CI / CC adapters

**Means:** wire actual source-aware parsers behind the two reserved
`ALLOWED_SOURCES` slots. Today `scan-logs --source ci foo.log` accepts
the source label but parses the file as a flat text stream; adapters
make it normalize GH-Actions step boundaries / ANSI codes / collapsed
group markers (CI), and the Control Center log envelope (CC).

**Files:**
- New: `src/wrg_devguard/log_sources/__init__.py`
- New: `src/wrg_devguard/log_sources/ci_github_actions.py`
- New: `src/wrg_devguard/log_sources/cc_endpoint.py`
- New: `src/wrg_devguard/log_sources/_normalize.py` (shared envelope)
- Touch: `src/wrg_devguard/scan_logs.py` (dispatch by source)
- Tests: `tests/log_sources/test_ci_github_actions.py`,
  `tests/log_sources/test_cc_endpoint.py`,
  `tests/log_sources/test_normalize.py`
- Fixtures: `tests/fixtures/logs/github_actions_clean.txt`,
  `cc_endpoint_sample.json`, `mixed_edge.txt`

**Status:** **Ready.** The seam exists; this is wiring, not redesign.
No schema change needed — pre-normalized text still flows through the
existing `pii.detect()` engine.

**Dependencies:** none external. Internal: doesn't touch `pii.py` or
the schema; sits between input loading and detection.

**PR count est:** 1 PR. Single seam, three new files + one touch.

**Blast radius:** Low. Additive. `--source manual` path stays bit-for-bit
unchanged. New tests, no existing test rewrites.

**Owner candidate (per draft prompts):** Codex.

### Item 2 — Names PII pattern

**Means:** add a `NAME-001` (or similar) detector to `pii.py` that flags
person-name PII in log content. The schema's `pattern_id` regex
(`^[A-Z][A-Z0-9]*-[0-9]{3}$`) already accepts the new ID — no schema
bump.

**Files:**
- Touch: `src/wrg_devguard/pii.py` (add detector function + register)
- New: `tests/test_pii_names.py` (≥10 cases per draft prompt)
- Touch: `tests/fixtures/pii_sample_log.txt` (add a few name lines)

**Status:** **Ready.** The engine takes plug-in detectors of fixed
shape; this is one more.

**Strategy decision needed (low stakes):** the draft prompt offered
three approaches —
(a) curated common-name dict + capitalized-bigram match,
(b) NER-lite regex (title-case bigram + stop-list),
(c) hybrid.
Recommendation: **(b)** — stays stdlib-only (matches the v0.2.0 zero-
runtime-dep contract), and the dogfood FP discipline is regex-friendly.
A curated dict drags ~10–100KB of names into the package.

**Dependencies:** none. Stdlib only.

**PR count est:** 1 PR.

**Blast radius:** Low. New pattern; existing 13 patterns and 98 tests
untouched. False-positive guard list (place names, code identifiers,
function/class params, file paths, docstrings) goes through the same
`fp_suppression` machinery v0.2.0 already ships.

**Owner candidate:** B.

### Item 3 — Schema drift detector

**Open question — needs user clarity before sequencing.** Two readings:

**Reading A — meta-guard on the v1 contract.**
Internal CI test that re-validates the frozen
`log_scan_result.schema.json` against the actual emit shape, plus
detects accidental drift (a finding field added, a required field
silently downgraded). This is more of a *test_schema_drift.py*
hardening than a "detector" in the user-facing sense. Target: lock
v1 down for the 0.2.x → 0.3.x evolution so a future v2 contract
becomes a deliberate decision, not a regression.

**Reading B — content-pattern detector.**
A new detector category that flags schema-drift *evidence in scanned
logs*: ORM warnings ("column X has no default"), runtime errors ("no
such column", "relation does not exist"), pending-migration banners.
Pattern ID space: `SQL-NNN` or new `SCHEMA-NNN`. Symmetric to the
v0.2.0 PII patterns but in a new category.

**Reading C — collision with monorepo-audit.**
The `wrg-skills` monorepo-audit skill (`scripts/audit.py:117`) already
has a `schema_drift` check that diffs source DDL against live SQLite
DBs. That check is *structurally* unrelated to either reading above
(it audits a Python monorepo's own DBs), but the name collision will
confuse maintainers if v0.3.0 also calls something `schema_drift`.

**Recommendation:** ask user to pick between A and B before sequencing.
If B, propose renaming the pattern category to `MIGRATION-NNN` or
`DBLOG-NNN` to avoid the name collision. If A, label the work
"contract guard" and keep it out of the user-facing pattern catalog.

**Files (provisional):**
- A: `tests/test_schema_contract_guard.py` only.
- B: `src/wrg_devguard/pii.py` (or split: `src/wrg_devguard/dblog.py`)
  + `tests/test_dblog_patterns.py` + fixture lines.

**Status:** **Needs design.** Blocks until user picks A or B.

**Dependencies:** if B, sits next to Item 2 in `pii.py` — they touch
the same file. Sequence them serially or split B into its own module.

**PR count est:** 1 (A) or 2 (B: implementation + fixture+rename).

**Blast radius:** Low (A) or Low–Medium (B). B's risk: false-positive
rate on a noisy log signal class. Needs the same dogfood discipline
v0.2.0 followed.

**Owner candidate:** A (me) — once user picks reading.

### Item 4 — Marketplace `--draft` workflow follow-up

**Means:** fix the
[`fix_marketplace_action_publish`](../../) gotcha — the v0.2.0 release
flow creates a final release authored by `github-actions[bot]`, which
suppresses the marketplace banner because marketplace requires a
**user-authored** release. Current workaround was manual: delete the
bot release, hand-create a user-authored one with same notes. Fix:
ship `--draft` from automation; user promotes via UI (taking
authorship in the process).

**Files:**
- Touch: `.github/workflows/marketplace-release.yml:89` — add
  `--draft` to the `gh release create` invocation. Conditional: only
  for non-prerelease tags (prereleases can keep auto-publishing — they
  don't need the marketplace banner).

**Status:** **Ready.** Mechanical change; gotcha is well-documented.

**Dependencies:** none.

**PR count est:** 1 PR (≤10 lines diff).

**Blast radius:** Low. Only affects future releases. Tested by tagging
a `v0.2.1-test` prerelease post-merge if we want belt-and-braces.

**Owner candidate:** any agent — small enough to bundle as a tail
task.

## Sequencing

| Wave | Items | Gating | Parallel-safe? |
|------|-------|--------|----------------|
| 0 | this brief | user approval | n/a |
| 1 | Item 1 (CI/CC adapters) + Item 2 (Names PII) + Item 4 (Marketplace draft) | Wave 0 | **yes** — disjoint files |
| 2 | Item 3 (Schema drift) | Wave 0 + reading A/B/C decision | depends on choice (A standalone; B serializes after Item 2 if both touch `pii.py`) |
| 3 | v0.3.0 release cut | all of Wave 1+2 merged | n/a |

**Wave 1 file disjointness check:**
- Item 1 → `src/wrg_devguard/log_sources/**`, `src/wrg_devguard/scan_logs.py`
- Item 2 → `src/wrg_devguard/pii.py`, `tests/test_pii_names.py`
- Item 4 → `.github/workflows/marketplace-release.yml`

No overlap. All three can ship in parallel under different agents
without merge conflicts.

**Wave 2 risk if Reading B chosen:**
- Item 2 + Item 3-B both touch `pii.py`. Either:
  - serialize (Item 2 first, Item 3 rebases on its main), or
  - split Item 3-B into a sibling module (`src/wrg_devguard/dblog.py`
    or `src/wrg_devguard/schema_signals.py`) so they're disjoint.
- Recommendation: split into a sibling module. v0.2.0's lazy-import
  pattern in `scan_logs.py:67` makes adding a second engine module
  cheap.

## Cross-repo / cross-skill notes

- **monorepo-audit collision** (already noted under Item 3): if v0.3.0
  ships anything called `schema_drift`, it collides with the existing
  monorepo-audit check. They have nothing in common architecturally.
  Recommend renaming v0.3.0's variant if Reading B wins.
- **Dogfood loop:** v0.2.0 added `wrg-devguard scan-logs` to the
  monorepo-audit dogfood pipeline (we should keep that). v0.3.0
  patterns get the same `<20% FP` test gate before merge.
- **CC adapter contract:** Item 1's `cc-endpoint` source needs CC's
  `log_viewer` JSON envelope to be stable. Pre-flight check: verify
  CC's log_viewer route schema hasn't shifted since the v0.2.0 design
  pass. If it has, that's a tiny CC-side PR before Item 1 lands.

## Acceptance for this brief

The brief is approved when the user answers:

1. **Reading for Item 3:** A (contract guard), B (content-pattern
   detector), or "park Item 3 to v0.4.0"?
2. **Item 3 naming:** if B, rename to `MIGRATION-NNN` / `DBLOG-NNN` to
   avoid monorepo-audit collision? Yes/no.
3. **Wave 1 ownership:** confirm
   - Item 1 → Codex
   - Item 2 → B
   - Item 4 → tail (any agent / bundle with another item)
4. **Item 2 name-detection strategy:** confirm regex bigram + stop-list
   over curated-dict / hybrid? (or override.)
5. **Release tag schedule:** target v0.3.0 in 1 wave (single tag once
   all items merge) or roll v0.2.1 / v0.2.2 increments per item?

## Out of scope for v0.3.0

- Schema v2 contract bump. The frozen `log_scan_result.schema.json` v1
  is the contract for the entire 0.x line; v2 is a v1.0.0 conversation.
- Streaming / large-file mode. v0.2.0's line-oriented detector is fine
  through ~100MB; >1GB inputs become a v0.4.0 conversation.
- Real-time / webhook ingestion. CI/CC adapters in v0.3.0 are
  one-shot file/stdin, matching v0.2.0's surface.

## Appendix — references

- `CHANGELOG.md:5` — v0.2.0 changelog block.
- `src/wrg_devguard/scan_logs.py:29` — `ALLOWED_SOURCES`.
- `schemas/log_scan_result.schema.json` — frozen v1 contract.
- `.github/workflows/marketplace-release.yml:89` — `gh release create`
  call to be `--draft`-ed.
- `wrg-skills/skills/monorepo-audit/scripts/audit.py:117` — existing
  `schema_drift` check (collision source).
- Memory: `fix_marketplace_action_publish.md` — Item 4 gotcha
  background.
