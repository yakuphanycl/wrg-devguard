# Dogfood — v0.3.0 `scan-logs` CLI surface against real CI logs

**Status:** evidence pass. Pre-merge dogfood for the v0.3.0 wave (PR
#20 NAME-001, PR #21/#24 `--source ci` dispatch, PR #23 DRIFT-NNN
catalog). All findings below are from running `wrg-devguard scan-logs`
against real GitHub Actions logs from this repository.

## 1. Test corpus

Two unmodified CI logs pulled via `gh run view <id> --log`:

| run id | trigger | step set | lines |
| ------ | ------- | -------- | ----- |
| 24966427106 | PR #23 (docs-only) | `test (3.11/3.12/3.13)` + `action-smoke` + `action-composite` + `self-scan` | 1608 |
| 24966008833 | PR #22 (workflow-only) | same matrix | 1608 |

No scrubbing was needed — `gh run view --log` does not expose secrets,
and ad-hoc grep for `AKIA*`, `gh[ps]_*`, `eyJ*`, RFC-5322 emails, and
public-range IPv4 returned **0 hits** in either log (good news for the
`self-scan (wrg-devguard on itself)` job — the surface is clean).

## 2. Run matrix

Detector stack: `wrg-devguard` main HEAD + PR #20's `pii_names.py`
mounted via `PYTHONPATH=src`. PR #21 + #24 are not yet merged so
`--source ci` still emits `manual`-shape output (the dispatch wiring is
gated behind those PRs); the call surface itself accepts the flag
already.

```bash
PYTHONPATH=src py -3 -m wrg_devguard.cli scan-logs \
    /tmp/wrg-dogfood/run_ci_<id>.log \
    --json-out /tmp/wrg-dogfood/scan_run<n>.json
```

## 3. Aggregate findings

| run | total | by_severity | by_category | by_pattern_id |
| --- | ----- | ----------- | ----------- | ------------- |
| run1 | **229** | low: 219, medium: 10 | pii_name: 219, pii_ip: 10 | NAME-001: 219, IP-002: 10 |
| run2 | **229** | low: 219, medium: 10 | pii_name: 219, pii_ip: 10 | NAME-001: 219, IP-002: 10 |

Identical totals across both runs reflect that ~95% of either log is
GitHub-Actions workflow scaffolding (image provisioning, step
boundaries, post-run actions) which is essentially deterministic
between PR runs.

### 3.1 NAME-001 — 100% false-positive on real CI logs

NAME-001 fired **219 times per log, 0 curated, 219 NER-bigram fallback,
0 true positives**. Top recurring bigrams (per log):

| count | bigram          | source                                       |
| ----- | --------------- | -------------------------------------------- |
| 165   | `Post Run`      | `Post Run actions/checkout` step boundaries  |
| 12    | `Runner Image`  | `##[group]Runner Image Provisioner`          |
| 6     | `Hosted Compute`| `Hosted Compute Agent` (image metadata)      |
| 6     | `Build Date`    | `Build Date: 2026-02-13T00:28:41Z`           |
| 6     | `Azure Region`  | `Azure Region: eastus2`                      |
| 6     | `Operating System` | `##[group]Operating System`               |
| 6     | `Included Software` | `Included Software: https://...`         |
| 6     | `Image Release` | `Image Release: https://...`                 |
| 6     | `Getting Git`   | `##[group]Getting Git version info`          |

Confirms the concern A flagged on PR #20: the **NER-lite bigram
fallback (0.70 → LOW)** is too permissive for non-prose text. The
guards (CamelCase, place names, code lines, paths, URLs, phrase stops)
catch identifiers but not the metadata-prose bigrams ubiquitous in CI
logs.

### 3.2 IP-002 — 100% false-positive on real CI logs

10 hits per log (medium severity). All 10 fall into 2 patterns:

| count | snippet                               | reason                                                            |
| ----- | ------------------------------------- | ----------------------------------------------------------------- |
| 6     | `::error::fail-on must be one of...`  | GitHub Actions annotation prefix `::error::` matches IPv6 regex   |
| 4     | `MB 24.4 MB/s  0:00:00`               | `0:00:00` HH:MM:SS timestamp matches IPv6 `(\d{1,4}:){2,7}\d{1,4}`|

The IPv6 regex (`pii.py::_IPV6_RE`) accepts colon-separated tokens
without sanity-checking the group count (timestamps have 3 groups, real
IPv6 needs ≥3 groups but with hex `[A-Fa-f0-9]{1,4}` per group;
`0:00:00` has decimal-only groups).

### 3.3 Other detectors — clean

`AWS-001` / `AWS-002` / `GH-001` / `JWT-001` / `ANTHROPIC-001` /
`OPENAI-001` / `EMAIL-001` / `IP-001` / `PHONE-001` / `PHONE-002` /
`SSN-001` / `CARD-001`: **0 hits across 3216 lines.** Either the
patterns are well-tuned for CI-log shapes or this corpus genuinely
lacks those secrets — both are good.

## 4. DRIFT-NNN cross-reference (PR #23 catalog)

Searched both logs for the 12 patterns from `docs/v0_3_0-item-3-investigation.md`:

| pattern | run1 | run2 | confirmed? |
| ------- | ---- | ---- | ---------- |
| DRIFT-001..012 | 0 | 0 | **none confirmed** |

**Why:** wrg-devguard CI runs pytest + CodeQL — no Django/Alembic/
Prisma/Rails/migration framework runs. The DRIFT catalog can't be
validated from this corpus alone. The patterns themselves remain
plausible (they were sourced from official ORM docs in PR #23), but
**a separate corpus is needed before declaring real-log priority**.

Suggested external corpus: scrape Django/Rails GitHub Actions logs from
public OSS repos (e.g. `django/django`, `rails/rails`, `prisma/prisma`
example repos) — out of scope for this dogfood, flagged as v0.3.1
prerequisite.

## 5. v0.3.1 tuning recommendations (data-backed)

### Priority 1 — NAME-001 NER fallback tightening (HIGH impact)

**Evidence:** 219 / 219 (100%) FP on real CI logs.

Options, in order of preference:

1. **Default-off the NER fallback.** Only emit `0.95 → MEDIUM` curated
   matches by default; require `--name-ner` (or policy flag) to opt
   into the 0.70 → LOW branch.
2. **Add a minimum length floor** (e.g. each word ≥4 chars). Would
   drop `Post Run`, `Build Date`, `Azure Region`, `Image Release` but
   keep most real names.
3. **Add a CI-noise stop-list** for common workflow tokens
   (`Post`, `Pre`, `Run`, `Build`, `Date`, `Image`, `Release`,
   `Agent`, `System`, `Compute`, `Region`, `Software`, `Version`,
   `Job`, `Step`).
4. **Annotation guard:** drop matches on lines that begin with
   `##[` (GitHub Actions group/section markers) or include the
   "step name" tab-prefixed shape from `gh run view --log`.

Recommended combo: (1) + (4). (1) buys the biggest win cheaply; (4)
addresses the CI-log-specific shape that produced 165/219 of the FP.

### Priority 2 — IP-002 sanity-check (MEDIUM impact)

**Evidence:** 10 / 10 (100%) FP on real CI logs.

Tighten `_IPV6_RE` post-match:

- Reject if every group is 1–2 chars AND all-decimal (HH:MM:SS shape).
- Reject if line starts with `::` immediately followed by an
  identifier-shaped run (`::error::`, `::warning::`, `::group::` —
  GitHub Actions annotation prefixes).

Both are stdlib-cheap and address all 10 observed FPs.

### Priority 3 — DRIFT-NNN first batch (DEFER until external corpus)

**Evidence:** zero from this corpus; cannot prioritize on real-log
basis.

Recommendation: ship the **5 exact-match patterns** PR #23 already
flagged as low-FP (`exact_match` suppression class):

- DRIFT-001 (Django models-not-reflected)
- DRIFT-004 (Alembic Target-not-up-to-date)
- DRIFT-007 (Prisma Drift-detected banner)
- DRIFT-010 (Rails Migrations-pending)
- DRIFT-011 (Rails ActiveRecord::PendingMigrationError)

Defer DRIFT-012 (catch-all `(?i)schema.*drift|drift.*schema`) until an
external corpus exists — its high-FP profile is a known risk and we
have no evidence to size it on.

### Priority 4 — `_is_test_context` substring breadth (A's PR #20 review)

**Evidence:** `test_` / `fixture` / `sample` substring counts in both
real CI logs: **0 / 0 / 0**. The over-suppress concern doesn't manifest
on this corpus — but the corpus also doesn't run pytest output through
`scan-logs`, so this is a non-finding rather than disconfirmation.
Recommend: keep A's review note as "TODO: validate on logs that
contain pytest output" and re-check once we have a `pytest --tb=short`
corpus.

## 6. cc-endpoint adapter shape (Codex stacked PR input)

The `gh run view --log` format is:

```
<job-name>\t<step-name>\t<timestamp> <content>
```

The job/step prefix is ASCII-tab separated. For the cc-endpoint
adapter (consumes CC log_viewer route output) we'd expect a different
shape — likely one CC log line per JSON record, no tab-prefix scaffold.

**Concrete suggestion for Codex:** the `GitHubActionsLogAdapter` (PR
#21) already strips the `<job>\t<step>\t<timestamp>` prefix from each
line before passing to the detector pipeline; the cc-endpoint adapter
should mirror that contract — **the detector pipeline expects "naked"
log content, not shape-wrapped lines**. Without that strip, all
detectors fire against scaffolding columns instead of payload content
(see §3.1 — the `Post Run` cluster lives in step-name columns, not
payload).

## 7. Open questions for user

1. **NAME-001 default:** should v0.3.1 ship with the NER fallback off
   by default, or keep current behaviour and document the tuning flag?
   Lean: off-by-default given 100% FP on the only real corpus we
   measured.
2. **IP-002 fix scope:** do we land the two sanity-checks (HH:MM:SS
   shape + GitHub annotation prefix) inside v0.3.1, or split into a
   v0.3.1-followup PR to keep the wave focused?
3. **DRIFT external corpus:** do we acquire it ourselves (scrape OSS
   Django/Rails Actions logs into `tests/fixtures/`) or accept that
   v0.3.1 ships DRIFT patterns "doc-validated, log-validation
   pending"? The first option adds ~1 PR; the second leaves a
   measurable gap until v0.4.0.
4. **`_is_test_context` substring breadth:** keep `sample` in the
   keyword list (A's concern), narrow it to `_sample_` / `samples/`,
   or drop entirely? No real-log evidence either way — needs a test
   pytest-output corpus to decide.

## 8. Reproduction

```bash
# Pull the corpus
mkdir -p /tmp/wrg-dogfood
gh run view 24966427106 --repo yakuphanycl/wrg-devguard --log \
    > /tmp/wrg-dogfood/run_ci_24966427106.log
gh run view 24966008833 --repo yakuphanycl/wrg-devguard --log \
    > /tmp/wrg-dogfood/run_ci_24966008833.log

# Run scan with NAME-001 active (PR #20 worktree)
cd D:/dev/wrg-devguard-pii-names
PYTHONPATH=src py -3 -m wrg_devguard.cli scan-logs \
    /tmp/wrg-dogfood/run_ci_24966427106.log \
    --json-out /tmp/wrg-dogfood/scan_run1.json
```

`scan_run1.json` and `scan_run2.json` are then the inputs for §3 and
§4 above. The DRIFT cross-reference is a Python regex grep — see
section 4 for the 12 patterns.
