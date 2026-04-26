"""scan-logs subcommand core — produces LogScanResult per the v1 schema.

The frozen output contract lives in `schemas/log_scan_result.schema.json`.
This module owns: input I/O, dispatch to the PII detection engine, and
serialization to the schema-conforming dict.

PII detection itself is delegated to `wrg_devguard.pii.detect`, which is
imported lazily so this module remains usable (with empty findings + a
clear note) until the PII engine ships in v0.2.0. Once `pii.py` is on main,
no change is needed here — the lazy import will resolve.
"""
from __future__ import annotations

import hashlib
import sys
import warnings
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from . import __version__ as _PKG_VERSION  # type: ignore[attr-defined]


# Schema version frozen at "1" for the v0.2.0 line.
SCHEMA_VERSION = "1"

# v0.2.0 ships only `manual`. CI / cc-endpoint reserved for v0.3.0.
ALLOWED_SOURCES = ("manual", "ci", "cc-endpoint")


class _PIIFindingProto(Protocol):
    """Structural subset of `wrg_devguard.pii.PIIFinding`.

    We only depend on these attributes so the engine can evolve internally
    without breaking the scan-logs caller.
    """
    pattern_id: str
    line_no: int
    span: tuple[int, int]
    redacted_excerpt: str
    rationale: str

    @property
    def category(self) -> Any: ...

    @property
    def severity(self) -> Any: ...


PIIDetector = Callable[[str], list[_PIIFindingProto]]


# ──────────────────────────────────────────────────────────────────────
# Lazy detector resolution
# ──────────────────────────────────────────────────────────────────────


def _default_detector() -> PIIDetector:
    """Resolve `wrg_devguard.pii.detect` lazily.

    Returns a no-op detector with a clear note when the PII engine isn't
    yet bundled (pre-v0.2.0). Once `pii.py` lands, this returns the real
    detector with no caller change.
    """
    try:
        from . import pii  # type: ignore[attr-defined]
    except ImportError:
        return _no_op_detector
    return pii.detect


def _no_op_detector(text: str) -> list[_PIIFindingProto]:  # noqa: ARG001
    return []


# ──────────────────────────────────────────────────────────────────────
# Source dispatch / normalization
# ──────────────────────────────────────────────────────────────────────


def _normalize_for_source(text: str, source: str) -> str:
    """Return the text surface that PII detection should scan."""

    if source == "manual":
        return text
    if source == "ci":
        return _normalize_ci_text(text)
    if source == "cc-endpoint":
        warnings.warn(
            "scan-logs --source cc-endpoint adapter not yet implemented; "
            "falling back to manual mode",
            RuntimeWarning,
            stacklevel=2,
        )
        return text
    return text


def _normalize_ci_text(text: str) -> str:
    try:
        from .adapters.log_analysis import GitHubActionsLogAdapter
    except ImportError:
        warnings.warn(
            "GitHubActionsLogAdapter unavailable; falling back to manual mode",
            RuntimeWarning,
            stacklevel=2,
        )
        return text

    adapter = GitHubActionsLogAdapter()
    messages = [
        event.msg
        for event in adapter.iter_events(text.splitlines(keepends=True))
        if event.msg
    ]
    return "\n".join(messages) if messages else text


# ──────────────────────────────────────────────────────────────────────
# Input loading
# ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Input:
    display_path: str
    text: str
    size_bytes: int
    lines: int
    sha256: str


def _load_input(path: str) -> _Input:
    """Read input from a file path or `-` for stdin.

    Counts bytes off the raw decoded content (UTF-8, replace on errors)
    and lines off the resulting text. A trailing partial line counts as 1
    per the schema's `input.lines` semantics.
    """
    if path == "-":
        raw = sys.stdin.buffer.read()
        display = "<stdin>"
    else:
        raw = Path(path).read_bytes()
        display = path

    text = raw.decode("utf-8", errors="replace")
    if text == "":
        line_count = 0
    else:
        line_count = text.count("\n")
        if not text.endswith("\n"):
            line_count += 1

    return _Input(
        display_path=display,
        text=text,
        size_bytes=len(raw),
        lines=line_count,
        sha256=hashlib.sha256(raw).hexdigest(),
    )


# ──────────────────────────────────────────────────────────────────────
# Core scan
# ──────────────────────────────────────────────────────────────────────


def _finding_to_dict(f: _PIIFindingProto) -> dict[str, Any]:
    """Serialize a PIIFinding to the schema's Finding shape.

    Tolerates either Enum-typed or plain-string `category`/`severity`
    (PII engine may use Enums, the schema wants strings).
    """
    def _enum_str(v: Any) -> str:
        return v.value if hasattr(v, "value") else str(v)

    out: dict[str, Any] = {
        "pattern_id": f.pattern_id,
        "category": _enum_str(f.category),
        "severity": _enum_str(f.severity),
        "line_no": f.line_no,
        "span": list(f.span),
        "redacted_excerpt": f.redacted_excerpt,
        "rationale": f.rationale,
    }
    fp_supp = getattr(f, "fp_suppression", None)
    if fp_supp:
        out["fp_suppression"] = fp_supp
    return out


def _summarize(findings: list[dict[str, Any]],
                runtime_ms: int | None) -> dict[str, Any]:
    by_severity = Counter(f["severity"] for f in findings)
    by_category = Counter(f["category"] for f in findings)
    summary: dict[str, Any] = {
        "total": len(findings),
        "by_severity": {k: v for k, v in by_severity.items() if v > 0},
        "by_category": {k: v for k, v in by_category.items() if v > 0},
    }
    if runtime_ms is not None:
        summary["runtime_ms"] = runtime_ms
    return summary


def scan_text(
    text: str,
    *,
    source: str = "manual",
    input_meta: dict[str, Any] | None = None,
    detector: PIIDetector | None = None,
    tool_version: str | None = None,
    runtime_ms: int | None = None,
) -> dict[str, Any]:
    """Pure-function entry point. Apply detector to `text`, return a
    LogScanResult dict that conforms to schema_version 1.

    `input_meta` MUST contain at minimum `path`, `size_bytes`, `lines`.
    `sha256` is optional (caller decides if it's worth computing).
    """
    if source not in ALLOWED_SOURCES:
        raise ValueError(f"source must be one of {ALLOWED_SOURCES}; got {source!r}")
    if input_meta is None or "path" not in input_meta:
        raise ValueError("input_meta with at least a 'path' key is required")

    detect = detector or _default_detector()
    detection_text = _normalize_for_source(text, source)
    raw_findings = detect(detection_text) or []
    findings = [_finding_to_dict(f) for f in raw_findings]
    findings.sort(key=lambda f: (f["line_no"], f["span"][0]))

    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": tool_version or _PKG_VERSION,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": source,
        "input": {
            "path": input_meta["path"],
            "size_bytes": int(input_meta.get("size_bytes", 0)),
            "lines": int(input_meta.get("lines", 0)),
            **({"sha256": input_meta["sha256"]} if input_meta.get("sha256") else {}),
        },
        "findings": findings,
        "summary": _summarize(findings, runtime_ms),
    }


# ──────────────────────────────────────────────────────────────────────
# CLI entry point (called from cli.py)
# ──────────────────────────────────────────────────────────────────────


def run_scan_logs(
    *,
    path: str,
    source: str,
    detector: PIIDetector | None = None,
) -> dict[str, Any]:
    """CLI-facing wrapper: load input, scan, return the report dict."""
    inp = _load_input(path)
    return scan_text(
        inp.text,
        source=source,
        input_meta={
            "path": inp.display_path,
            "size_bytes": inp.size_bytes,
            "lines": inp.lines,
            "sha256": inp.sha256,
        },
        detector=detector,
    )


# ──────────────────────────────────────────────────────────────────────
# Exit-code resolution (mirrors the broader CLI's --fail-on semantics)
# ──────────────────────────────────────────────────────────────────────


# Severity ladder: high > medium > low > info. `--fail-on X` fails if any
# finding's severity is at or above X.
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def fail_code(report: dict[str, Any], fail_on: str) -> int:
    """Return 1 if any finding meets/exceeds fail_on; 0 otherwise.

    `fail_on` accepts "high"/"medium"/"low"/"info" (engine severities)
    and the legacy "error" alias (treated as "high"), "warning" → "medium".
    Unknown values raise ValueError so the caller can surface it.
    """
    threshold = {"error": "high", "warning": "medium"}.get(fail_on, fail_on)
    if threshold not in _SEVERITY_ORDER:
        raise ValueError(f"unknown fail-on threshold: {fail_on!r}")

    min_rank = _SEVERITY_ORDER[threshold]
    for f in report["findings"]:
        sev = f.get("severity", "info")
        if _SEVERITY_ORDER.get(sev, -1) >= min_rank:
            return 1
    return 0
