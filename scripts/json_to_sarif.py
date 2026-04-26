"""Convert wrg-devguard JSON report to SARIF v2.1.0 for GitHub code-scanning.

Used by the composite action when `format: sarif` is selected. SARIF is the
GitHub-native format for code-scanning ingestion; emitting it here lets the
action drop in next to other security scanners on a Code Scanning page.

This is a small adapter — no network, stdlib only. SARIF spec reference:
https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "master/Schemata/sarif-schema-2.1.0.json"
)
TOOL_NAME = "wrg-devguard"
TOOL_URI = "https://github.com/yakuphanycl/wrg-devguard"


def _level(severity: str) -> str:
    s = (severity or "").lower()
    if s in ("error", "high", "critical"):
        return "error"
    if s in ("warning", "warn", "medium"):
        return "warning"
    return "note"


def _rule_id(finding: dict[str, Any]) -> str:
    """Extract the most specific rule identifier available.

    scan-logs findings carry `pattern_id` (e.g. "NAME-001") which is more
    actionable than the broader `category`. Legacy `check`/`scan-secrets`
    findings carry `rule` instead. Both fall back to `category`, then to
    a generic placeholder so SARIF always has a non-empty ruleId.
    """
    return str(
        finding.get("pattern_id")
        or finding.get("rule")
        or finding.get("category")
        or "wrg-devguard.finding"
    )


def _result(finding: dict[str, Any], default_path: str = "") -> dict[str, Any]:
    rule_id = _rule_id(finding)
    # scan-logs emits `rationale`; legacy emits `message`/`detail`/`description`
    message = str(
        finding.get("rationale")
        or finding.get("message")
        or finding.get("detail")
        or finding.get("description")
        or rule_id
    )
    # scan-logs threads path at the top level (input.path) since findings
    # are line-scoped within a single file; legacy emits per-finding `path`/`file`.
    location_path = str(finding.get("path") or finding.get("file") or default_path or "")
    # scan-logs emits `line_no`; legacy emits `line`.
    line = finding.get("line_no") or finding.get("line")
    physical: dict[str, Any] = {
        "artifactLocation": {"uri": location_path or "<unknown>"},
    }
    if isinstance(line, int) and line > 0:
        physical["region"] = {"startLine": line}
    return {
        "ruleId": rule_id,
        "level": _level(str(finding.get("severity", ""))),
        "message": {"text": message},
        "locations": [{"physicalLocation": physical}],
    }


def to_sarif(report: dict[str, Any], package_version: str | None = None) -> dict[str, Any]:
    findings = report.get("findings") or []
    # scan-logs reports thread the scanned-file path at top level under
    # `input.path`; legacy reports embed it per-finding. Resolve once for
    # the scan-logs case so each Result picks it up by default.
    input_meta = report.get("input") or {}
    default_path = str(input_meta.get("path") or "") if isinstance(input_meta, dict) else ""
    rule_ids = sorted({_rule_id(f) for f in findings})
    rules = [
        {
            "id": rid,
            "name": rid,
            "shortDescription": {"text": rid},
            "defaultConfiguration": {"level": "warning"},
        }
        for rid in rule_ids
    ]
    driver: dict[str, Any] = {
        "name": TOOL_NAME,
        "informationUri": TOOL_URI,
        "rules": rules,
    }
    if package_version:
        driver["version"] = package_version
    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {"driver": driver},
                "results": [_result(f, default_path) for f in findings],
            }
        ],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Convert wrg-devguard JSON to SARIF.")
    p.add_argument("--input", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--tool-version", default=None)
    args = p.parse_args(argv)

    report = json.loads(args.input.read_text(encoding="utf-8"))
    sarif = to_sarif(report, package_version=args.tool_version)
    args.output.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
