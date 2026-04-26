"""Tests for the scan-logs subcommand core (`wrg_devguard.scan_logs`).

PII detection is mocked here — the real PII engine ships in a parallel PR.
These tests verify:
- scan_text returns schema-conforming output (validated against the JSON Schema)
- detector dependency injection works (no real PII engine needed)
- summary/aggregation logic is correct
- fail_code semantics (severity ladder + legacy aliases)
- input loading handles file paths, stdin, and missing files
"""
from __future__ import annotations

import io
import json
from pathlib import Path

import jsonschema
import pytest
from jsonschema import Draft202012Validator

from wrg_devguard.scan_logs import (
    ALLOWED_SOURCES,
    SCHEMA_VERSION,
    fail_code,
    run_scan_logs,
    scan_text,
)

SCHEMA_PATH = Path(__file__).parent.parent / "schemas" / "log_scan_result.schema.json"


@pytest.fixture(scope="module")
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))


# ──────────────────────────────────────────────────────────────────────
# Mock PII detector
# ──────────────────────────────────────────────────────────────────────


class _MockFinding:
    """Mimics wrg_devguard.pii.PIIFinding's structural surface."""

    def __init__(self, pattern_id: str, category: str, severity: str,
                  line_no: int, span: tuple[int, int],
                  redacted_excerpt: str, rationale: str,
                  fp_suppression: str | None = None) -> None:
        self.pattern_id = pattern_id
        self.category = category
        self.severity = severity
        self.line_no = line_no
        self.span = span
        self.redacted_excerpt = redacted_excerpt
        self.rationale = rationale
        if fp_suppression is not None:
            self.fp_suppression = fp_suppression


def _detector_with(*findings: _MockFinding):
    def _detect(_: str) -> list:
        return list(findings)
    return _detect


def _no_op_detector(_: str) -> list:
    return []


# ──────────────────────────────────────────────────────────────────────
# scan_text — schema conformance
# ──────────────────────────────────────────────────────────────────────


def test_empty_scan_validates_against_schema(validator: Draft202012Validator) -> None:
    r = scan_text(
        "hello",
        source="manual",
        input_meta={"path": "x.log", "size_bytes": 5, "lines": 1},
        detector=_no_op_detector,
    )
    validator.validate(r)
    assert r["findings"] == []
    assert r["summary"]["total"] == 0


def test_scan_with_findings_validates(validator: Draft202012Validator) -> None:
    detector = _detector_with(
        _MockFinding("AWS-001", "secret", "high", 5, (2, 22),
                      "AKIA****EYID", "AWS access key"),
        _MockFinding("EMAIL-001", "pii_email", "medium", 12, (0, 18),
                      "u***@example.com", "RFC-5322 email"),
    )
    r = scan_text("text", source="manual",
                   input_meta={"path": "x", "size_bytes": 4, "lines": 1},
                   detector=detector)
    validator.validate(r)
    assert len(r["findings"]) == 2
    assert r["summary"]["by_severity"] == {"high": 1, "medium": 1}
    assert r["summary"]["by_category"] == {"secret": 1, "pii_email": 1}


def test_findings_sorted_by_line_then_span(validator: Draft202012Validator) -> None:
    detector = _detector_with(
        _MockFinding("X-001", "secret", "high", 10, (5, 10), "redacted", "x"),
        _MockFinding("Y-001", "secret", "high", 3, (0, 3), "redacted", "y"),
        _MockFinding("Z-001", "secret", "high", 10, (1, 4), "redacted", "z"),
    )
    r = scan_text("t", source="manual",
                   input_meta={"path": "x", "size_bytes": 1, "lines": 1},
                   detector=detector)
    validator.validate(r)
    pids = [f["pattern_id"] for f in r["findings"]]
    assert pids == ["Y-001", "Z-001", "X-001"]


def test_fp_suppression_propagates(validator: Draft202012Validator) -> None:
    detector = _detector_with(
        _MockFinding("IP-001", "pii_ip", "info", 1, (0, 13),
                      "192.168.***.10", "IPv4",
                      fp_suppression="rfc1918_private_range"),
    )
    r = scan_text("t", source="manual",
                   input_meta={"path": "x", "size_bytes": 1, "lines": 1},
                   detector=detector)
    validator.validate(r)
    assert r["findings"][0]["fp_suppression"] == "rfc1918_private_range"


def test_no_fp_suppression_omitted(validator: Draft202012Validator) -> None:
    detector = _detector_with(
        _MockFinding("AWS-001", "secret", "high", 1, (0, 4), "AKIA", "x"),
    )
    r = scan_text("t", source="manual",
                   input_meta={"path": "x", "size_bytes": 1, "lines": 1},
                   detector=detector)
    validator.validate(r)
    assert "fp_suppression" not in r["findings"][0]


def test_enum_typed_severity_serialized(validator: Draft202012Validator) -> None:
    """The PII engine may use an Enum; we accept both Enum and plain str."""
    from enum import Enum

    class Sev(str, Enum):
        HIGH = "high"

    class Cat(str, Enum):
        SECRET = "secret"

    detector = _detector_with(
        _MockFinding("AWS-001", Cat.SECRET, Sev.HIGH, 1, (0, 4), "redacted", "x"),
    )
    r = scan_text("t", source="manual",
                   input_meta={"path": "x", "size_bytes": 1, "lines": 1},
                   detector=detector)
    validator.validate(r)
    assert r["findings"][0]["severity"] == "high"
    assert r["findings"][0]["category"] == "secret"


# ──────────────────────────────────────────────────────────────────────
# scan_text — input + meta validation
# ──────────────────────────────────────────────────────────────────────


def test_unknown_source_rejected() -> None:
    with pytest.raises(ValueError, match="source must be one of"):
        scan_text("t", source="stdin",
                   input_meta={"path": "x", "size_bytes": 1, "lines": 1},
                   detector=_no_op_detector)


def test_input_meta_required() -> None:
    with pytest.raises(ValueError, match="input_meta"):
        scan_text("t", source="manual", input_meta=None,
                   detector=_no_op_detector)
    with pytest.raises(ValueError, match="input_meta"):
        scan_text("t", source="manual", input_meta={"size_bytes": 1},
                   detector=_no_op_detector)


def test_optional_sha256_appears_when_provided(validator) -> None:
    r = scan_text("t", source="manual",
                   input_meta={"path": "x", "size_bytes": 1, "lines": 1,
                                "sha256": "a" * 64},
                   detector=_no_op_detector)
    validator.validate(r)
    assert r["input"]["sha256"] == "a" * 64


def test_sha256_omitted_when_falsy(validator) -> None:
    r = scan_text("t", source="manual",
                   input_meta={"path": "x", "size_bytes": 1, "lines": 1,
                                "sha256": ""},
                   detector=_no_op_detector)
    validator.validate(r)
    assert "sha256" not in r["input"]


def test_allowed_sources_constant() -> None:
    assert set(ALLOWED_SOURCES) == {"manual", "ci", "cc-endpoint"}


def test_schema_version_constant() -> None:
    assert SCHEMA_VERSION == "1"


def test_runtime_ms_optional_in_summary(validator) -> None:
    r = scan_text("t", source="manual",
                   input_meta={"path": "x", "size_bytes": 1, "lines": 1},
                   detector=_no_op_detector,
                   runtime_ms=42)
    validator.validate(r)
    assert r["summary"]["runtime_ms"] == 42


# ──────────────────────────────────────────────────────────────────────
# fail_code — exit code semantics
# ──────────────────────────────────────────────────────────────────────


def _report_with(severities: list[str]) -> dict:
    return {
        "findings": [{"severity": s} for s in severities],
    }


@pytest.mark.parametrize("severities,fail_on,expected", [
    ([], "high", 0),
    ([], "info", 0),
    (["info"], "high", 0),
    (["info"], "info", 1),
    (["low"], "low", 1),
    (["low"], "medium", 0),
    (["medium"], "medium", 1),
    (["medium"], "high", 0),
    (["high"], "high", 1),
    (["high", "info"], "high", 1),
    (["info", "info", "high"], "medium", 1),
    # Legacy aliases
    (["high"], "error", 1),       # error == high
    (["medium"], "error", 0),
    (["medium"], "warning", 1),   # warning == medium
    (["low"], "warning", 0),
])
def test_fail_code_severity_ladder(severities, fail_on, expected) -> None:
    assert fail_code(_report_with(severities), fail_on) == expected


def test_fail_code_unknown_threshold_raises() -> None:
    with pytest.raises(ValueError, match="unknown fail-on"):
        fail_code(_report_with([]), "critical")


# ──────────────────────────────────────────────────────────────────────
# run_scan_logs — file + stdin loading
# ──────────────────────────────────────────────────────────────────────


def test_run_scan_logs_reads_file(tmp_path, validator) -> None:
    log = tmp_path / "build.log"
    # write_bytes to avoid Windows \n -> \r\n translation
    log.write_bytes(b"line one\nline two\n")
    r = run_scan_logs(path=str(log), source="manual",
                      detector=_no_op_detector)
    validator.validate(r)
    assert r["input"]["path"] == str(log)
    assert r["input"]["lines"] == 2
    assert r["input"]["size_bytes"] == 18
    assert "sha256" in r["input"]


def test_run_scan_logs_counts_unterminated_trailing_line(tmp_path, validator) -> None:
    log = tmp_path / "no-trailing-newline.log"
    log.write_bytes(b"a\nb\nc")  # 3 lines, last unterminated
    r = run_scan_logs(path=str(log), source="manual",
                      detector=_no_op_detector)
    validator.validate(r)
    assert r["input"]["lines"] == 3


def test_run_scan_logs_empty_file(tmp_path, validator) -> None:
    log = tmp_path / "empty.log"
    log.write_text("", encoding="utf-8")
    r = run_scan_logs(path=str(log), source="manual",
                      detector=_no_op_detector)
    validator.validate(r)
    assert r["input"]["size_bytes"] == 0
    assert r["input"]["lines"] == 0


def test_run_scan_logs_stdin(monkeypatch, validator) -> None:
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(
        io.BytesIO(b"piped content\n"), encoding="utf-8"
    ))
    r = run_scan_logs(path="-", source="manual", detector=_no_op_detector)
    validator.validate(r)
    assert r["input"]["path"] == "<stdin>"
    assert r["input"]["size_bytes"] == 14
    assert r["input"]["lines"] == 1


def test_run_scan_logs_missing_file_raises(tmp_path) -> None:
    with pytest.raises(OSError):
        run_scan_logs(path=str(tmp_path / "does-not-exist.log"),
                       source="manual", detector=_no_op_detector)


# ──────────────────────────────────────────────────────────────────────
# Default detector (lazy import) — works even without pii.py present
# ──────────────────────────────────────────────────────────────────────


def test_default_detector_is_safe_when_pii_module_absent(validator) -> None:
    """Pre-v0.2.0 (no pii.py): scan must still produce a valid empty report."""
    # Don't pass detector → falls back to lazy import. Our package may or
    # may not have pii.py at test-time; either way the report must validate
    # (when present, the engine returns its own findings; when absent, the
    # no-op detector returns []).
    r = scan_text("hello world",
                   source="manual",
                   input_meta={"path": "x", "size_bytes": 11, "lines": 1})
    validator.validate(r)
    # Don't assert findings count — depends on whether pii.py is bundled.
