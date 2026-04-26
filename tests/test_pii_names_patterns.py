"""Unit tests for the NAME-001 pattern (`wrg_devguard.pii_names`).

Coverage matrix:

  * True positives (TP): multi-origin first names (Anglo, Turkish,
    Slavic, East Asian, Hispanic), diacritics, hyphenated, apostrophe,
    middle initial, NER fallback (non-curated bigram).
  * True negatives (TN): CamelCase identifiers, place names, code lines,
    docstring parameters, file paths, URL fragments, common phrases.
  * Edge cases: single-name-only (no match), all-caps `HENRY FORD`
    (no match — too noisy in code/log contexts), middle initial
    (`John Q. Smith` → match).
  * Wiring: NAME-001 reachable through the public `detect()` /
    `detect_line()` API; `Category.PII_NAME` is exposed; severity
    bucketing maps confidence correctly; redaction never leaks the raw
    full-name string.
"""
from __future__ import annotations

import pytest

from wrg_devguard.pii import Category, PIIFinding, Severity, detect, detect_line
from wrg_devguard.pii_names import detect_names


def _name_findings(findings: list[PIIFinding]) -> list[PIIFinding]:
    return [f for f in findings if f.pattern_id == "NAME-001"]


# ──────────────────────────────────────────────────────────────────────
# True positives
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("text,first,last", [
    # Anglo (curated)
    ("contact: John Smith called yesterday", "John", "Smith"),
    # Turkish (curated, with diacritic)
    ("user Çağrı Yıldız updated profile", "Çağrı", "Yıldız"),
    # Slavic (curated)
    ("from Vladimir Petrov re: contract", "Vladimir", "Petrov"),
    # East Asian (curated, romanised)
    ("manager Hiroshi Tanaka approved", "Hiroshi", "Tanaka"),
    # Hispanic (curated, with diacritic)
    ("José García signed in", "José", "García"),
])
def test_name_001_curated_first_names(text: str, first: str, last: str) -> None:
    findings = _name_findings(detect_line(text, 1))
    assert findings, f"expected NAME-001 hit for {first} {last}"
    assert len(findings) == 1
    f = findings[0]
    assert f.category is Category.PII_NAME
    # Curated → MEDIUM severity bucket (0.95 confidence)
    assert f.severity is Severity.MEDIUM
    assert "curated" in f.rationale
    assert "0.95" in f.rationale


def test_name_001_hyphenated_first_name() -> None:
    findings = _name_findings(detect_line("intern Mary-Jane Watson onboarded", 5))
    assert findings, "Mary-Jane Watson should match"
    assert findings[0].severity is Severity.MEDIUM
    # Span covers the full hyphenated first name
    matched = "intern Mary-Jane Watson onboarded"[
        findings[0].span[0]: findings[0].span[1]
    ]
    assert matched == "Mary-Jane Watson"


def test_name_001_apostrophe_last_name() -> None:
    # NER fallback: O'Brien is not in the curated set; first name Sean is.
    findings = _name_findings(detect_line("dispatcher Sean O'Brien on call", 7))
    assert findings, "Sean O'Brien should match"
    f = findings[0]
    assert f.severity is Severity.MEDIUM  # Sean is curated
    matched = "dispatcher Sean O'Brien on call"[f.span[0]: f.span[1]]
    assert matched == "Sean O'Brien"


def test_name_001_middle_initial() -> None:
    findings = _name_findings(detect_line("memo from John Q. Smith dated today", 9))
    assert findings, "middle initial should not block the match"
    f = findings[0]
    assert "Middle initial Q" in f.rationale
    matched = "memo from John Q. Smith dated today"[f.span[0]: f.span[1]]
    assert matched == "John Q. Smith"


def test_name_001_ner_fallback_non_curated() -> None:
    # Neither name is in the curated dict — NER-lite branch fires at 0.70.
    findings = _name_findings(detect_line("article by Reginald Featherbottom", 11))
    assert findings, "non-curated bigram should still fire via NER fallback"
    f = findings[0]
    assert f.severity is Severity.LOW
    assert "NER-bigram" in f.rationale
    assert "0.70" in f.rationale


def test_name_001_test_context_downgraded() -> None:
    # Lines with `test_` / `fixture` / `sample` are emitted as INFO with
    # fp_suppression="test_context" — same convention as JWT-001.
    findings = _name_findings(
        detect_line("test_user_creation: John Smith fixture data", 13)
    )
    assert findings
    f = findings[0]
    assert f.severity is Severity.INFO
    assert f.fp_suppression == "test_context"


# ──────────────────────────────────────────────────────────────────────
# True negatives — false-positive guards
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("text", [
    # CamelCase identifiers — no whitespace between the bigram halves
    "FooBar.process()",
    "getUserName(request)",
    "MyClass instance = createInstance()",
    "the HelloWorld constant",
])
def test_name_001_no_match_camelcase(text: str) -> None:
    assert not _name_findings(detect_line(text, 1))


@pytest.mark.parametrize("text", [
    # Place-prefix words disqualify the bigram
    "headquartered in New York yesterday",
    "branch San Francisco opened",
    "office Los Angeles closed",
    "near Saint Louis on the river",
    "north of Mount Everest base camp",
])
def test_name_001_no_match_place_names(text: str) -> None:
    assert not _name_findings(detect_line(text, 1))


@pytest.mark.parametrize("line", [
    "def create_user(name, email):",
    "class UserAccount(BaseModel):",
    "function getData(request) {",
    "import React Component from 'react'",
    "from typing import Optional Iterable",
    "return Foo Bar",
])
def test_name_001_no_match_code_lines(line: str) -> None:
    assert not _name_findings(detect_line(line, 1))


@pytest.mark.parametrize("line", [
    ":param John Smith: example user fixture",   # docstring param marker
    "@param User Name the username to register",  # JSDoc param marker
    ":returns: John Smith on success",
    "@returns User Name on success",
])
def test_name_001_no_match_docstring_params(line: str) -> None:
    assert not _name_findings(detect_line(line, 1))


def test_name_001_no_match_file_path() -> None:
    # Slash-prefix → name span sits inside a path-like token
    line = "loaded /home/John Smith/.config/app.yml"
    assert not _name_findings(detect_line(line, 1))


def test_name_001_no_match_url_fragment() -> None:
    line = "see https://example.com/John Smith for details"
    assert not _name_findings(detect_line(line, 1))


@pytest.mark.parametrize("phrase", [
    "Hello World",
    "Thank You",
    "Best Regards",
    "Lorem Ipsum",
    "Foo Bar",
])
def test_name_001_no_match_common_phrases(phrase: str) -> None:
    assert not _name_findings(detect_line(f"prefix {phrase} suffix", 1))


# ──────────────────────────────────────────────────────────────────────
# Edge cases
# ──────────────────────────────────────────────────────────────────────


def test_name_001_no_match_single_name() -> None:
    """Single name is ambiguous (could be a username, project, anything)."""
    assert not _name_findings(detect_line("user John logged in", 1))


def test_name_001_no_match_all_caps() -> None:
    """All-caps bigrams ('HENRY FORD') match too many code constants."""
    assert not _name_findings(detect_line("vehicle HENRY FORD model T", 1))


def test_name_001_handles_short_words() -> None:
    """NER fallback requires both words ≥3 chars to limit FP."""
    # Short non-curated bigram → drop
    assert not _name_findings(detect_line("note Ai Bo testing", 1))


# ──────────────────────────────────────────────────────────────────────
# Wiring + invariants
# ──────────────────────────────────────────────────────────────────────


def test_name_001_reachable_via_detect() -> None:
    """Multi-line `detect()` exposes NAME-001 just like single-line."""
    text = "header line\ncontact: John Smith\nfooter line\n"
    findings = _name_findings(detect(text))
    assert len(findings) == 1
    assert findings[0].line_no == 2


def test_name_001_redaction_never_leaks_raw() -> None:
    raw = "John Smith"
    findings = _name_findings(detect_line(f"hello {raw} goodbye", 1))
    assert findings
    # Mask must keep ≥4 stars; raw substring must not appear in the excerpt
    assert raw not in findings[0].redacted_excerpt
    assert "*" in findings[0].redacted_excerpt


def test_name_001_pattern_id_matches_schema() -> None:
    """Pattern ID conforms to the schema's `^[A-Z][A-Z0-9]*-[0-9]{3}$`."""
    import re as _re
    findings = _name_findings(detect_line("from Mary Johnson at corp", 1))
    assert findings
    assert _re.fullmatch(r"[A-Z][A-Z0-9]*-[0-9]{3}", findings[0].pattern_id)


def test_name_001_serialises_through_scan_logs() -> None:
    """detect() output remains compatible with `_finding_to_dict`."""
    from wrg_devguard.scan_logs import _finding_to_dict  # noqa: PLC0415

    text = "audit: Mary Johnson approved deploy\n"
    findings = _name_findings(detect(text))
    assert findings
    d = _finding_to_dict(findings[0])
    assert d["category"] == "pii_name"
    assert d["pattern_id"] == "NAME-001"
    # span serialises as a 2-element list per the schema contract
    assert isinstance(d["span"], list) and len(d["span"]) == 2


def test_name_001_module_direct_call_matches_pipeline() -> None:
    """detect_names() called directly returns identical findings to detect_line()."""
    line = "from Mary Johnson at the audit team"
    direct = detect_names(line, 42)
    pipeline = _name_findings(detect_line(line, 42))
    assert len(direct) == 1
    assert len(pipeline) == 1
    a, b = direct[0], pipeline[0]
    assert (a.pattern_id, a.span, a.severity, a.line_no) == (
        b.pattern_id, b.span, b.severity, b.line_no,
    )


def test_name_001_no_match_on_existing_fixture() -> None:
    """Regression guard: NAME-001 must not fire on the v0.2.0 fixture log."""
    from pathlib import Path
    fixture = Path(__file__).parent / "fixtures" / "pii_sample_log.txt"
    text = fixture.read_text(encoding="utf-8")
    assert not _name_findings(detect(text))
