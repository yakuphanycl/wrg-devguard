from __future__ import annotations

import argparse
import fnmatch
import json
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from .policy import lint_policy, load_policy
from .secrets import scan_secrets
from .scan_logs import fail_code as _scan_logs_fail_code
from .scan_logs import run_scan_logs as _scan_logs_core
from .common import Finding, write_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wrg-devguard")
    sub = parser.add_subparsers(dest="command")

    lint = sub.add_parser("lint-policy", help="scan content against policy deny patterns")
    lint.add_argument("--path", default=".", help="scan root path")
    lint.add_argument("--policy", default=None, help="policy file (json/toml/yaml)")
    lint.add_argument("--profile", choices=["baseline", "strict"], default=None, help="use a predefined policy profile")
    lint.add_argument("--paths-file", default=None, dest="paths_file", help="newline-delimited relative file list")
    lint.add_argument("--allowlist", default=None, help="allowlist file path (json)")
    lint.add_argument("--json-out", default=None, dest="json_out", help="write JSON report")
    lint.add_argument("--fail-on", choices=["error", "warning"], default="error")

    sec = sub.add_parser("scan-secrets", help="scan for common secret leak patterns")
    sec.add_argument("--path", default=".", help="scan root path")
    sec.add_argument("--paths-file", default=None, dest="paths_file", help="newline-delimited relative file list")
    sec.add_argument("--allowlist", default=None, help="allowlist file path (json)")
    sec.add_argument("--json-out", default=None, dest="json_out", help="write JSON report")
    sec.add_argument("--fail-on", choices=["error", "warning"], default="error")

    check = sub.add_parser("check", help="run lint-policy + scan-secrets")
    check.add_argument("--path", default=".", help="scan root path")
    check.add_argument("--policy", default=None, help="policy file (json/toml/yaml)")
    check.add_argument("--profile", choices=["baseline", "strict"], default=None, help="use a predefined policy profile")
    check.add_argument("--paths-file", default=None, dest="paths_file", help="newline-delimited relative file list")
    check.add_argument("--allowlist", default=None, help="allowlist file path (json)")
    check.add_argument("--json-out", default=None, dest="json_out", help="write JSON report")
    check.add_argument("--fail-on", choices=["error", "warning"], default="error")

    prof = sub.add_parser("profiles", help="list available policy profiles")
    prof.add_argument("--path", default=".", help="repo root to inspect")

    bandit_p = sub.add_parser("bandit", help="run bandit security scanner on Python source")
    bandit_p.add_argument("--path", default=".", help="scan root path")
    bandit_p.add_argument("--app", help="scan specific app under apps/<app>/")
    bandit_p.add_argument("--severity", choices=["low", "medium", "high"], default="medium",
                          help="minimum severity to report (default: medium)")
    bandit_p.add_argument("--json-out", default=None, dest="json_out", help="write JSON report")

    logs = sub.add_parser(
        "scan-logs",
        help="scan a log file (or stdin) for secrets + PII; emits LogScanResult v1 JSON",
    )
    logs.add_argument("input", help="path to log file, or '-' for stdin")
    logs.add_argument("--source", choices=["manual", "ci", "cc-endpoint"], default="manual",
                      help="provenance label (v0.2.0: manual only)")
    logs.add_argument("--fail-on", choices=["error", "warning", "high", "medium", "low", "info"],
                      default="high",
                      help="exit non-zero if any finding is at or above this severity (default: high)")
    logs.add_argument("--json-out", default=None, dest="json_out",
                      help="write the full LogScanResult JSON to this path (otherwise stdout)")

    return parser


def _should_fail(findings: list[Finding], fail_on: str) -> bool:
    if fail_on == "warning":
        return len(findings) > 0
    return any(item.severity.upper() == "ERROR" for item in findings)


def _safe_finding_dict(item: Finding) -> dict[str, Any]:
    return {
        "check": item.check,
        "rule_id": item.rule_id,
        "severity": item.severity,
        "message": item.message,
        "file": item.file,
        "line": item.line,
        "column": item.column,
        # Never persist potentially sensitive matched text.
        "snippet": "[REDACTED]",
    }


def _safe_finding_mapping(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "check": str(item.get("check", "")),
        "rule_id": str(item.get("rule_id", "")),
        "severity": str(item.get("severity", "")),
        "message": str(item.get("message", "")),
        "file": str(item.get("file", "")),
        "line": int(item.get("line", 0)),
        "column": int(item.get("column", 0)),
        "snippet": "[REDACTED]",
    }


def _sanitize_suppressed_payload(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        entry: dict[str, Any] = dict(item)
        finding_obj = entry.get("finding")
        if isinstance(finding_obj, dict):
            entry["finding"] = _safe_finding_mapping(finding_obj)
        sanitized.append(entry)
    return sanitized


def _as_report(
    command: str,
    root: Path,
    findings: list[Finding],
    fail_on: str,
    suppressed: list[dict] | None = None,
) -> dict:
    suppressed_items = _sanitize_suppressed_payload(suppressed or [])
    error_count = sum(1 for item in findings if item.severity.upper() == "ERROR")
    warning_count = sum(1 for item in findings if item.severity.upper() == "WARNING")
    status = "FAIL" if _should_fail(findings, fail_on) else "PASS"
    return {
        "schema_version": "wrg_devguard.v1",
        "command": command,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scan_root": str(root),
        "status": status,
        "summary": {
            "total_findings": len(findings),
            "error": error_count,
            "warning": warning_count,
            "suppressed": len(suppressed_items),
            "fail_on": fail_on,
        },
        "findings": [_safe_finding_dict(item) for item in findings],
        "suppressed": suppressed_items,
    }


def _print_summary(command: str) -> None:
    print(f"{command}: completed (finding details are redacted by design)")


def _safe_json_report(command: str, root: Path) -> dict[str, Any]:
    return {
        "schema_version": "wrg_devguard.v1",
        "command": command,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scan_root": str(root),
        "status": "REDACTED",
        "summary": {
            "total_findings": "REDACTED",
            "error": "REDACTED",
            "warning": "REDACTED",
            "suppressed": "REDACTED",
            "fail_on": "REDACTED",
        },
        "findings": [],
        "suppressed": [],
    }


def _normalize_rel_path(value: str) -> str:
    text = value.strip().replace("\\", "/")
    if text.startswith("./"):
        text = text[2:]
    return PurePosixPath(text).as_posix()


def _load_allowed_files(paths_file: str | None, scan_root: Path) -> set[str] | None:
    if not paths_file:
        return None
    candidate = Path(paths_file).resolve()
    if not candidate.exists():
        raise ValueError(f"paths file not found: {candidate}")

    allowed: set[str] = set()
    for raw in candidate.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        path_value = Path(line)
        if path_value.is_absolute():
            try:
                normalized = path_value.resolve().relative_to(scan_root).as_posix()
            except Exception:
                continue
        else:
            normalized = _normalize_rel_path(line)
        allowed.add(normalized)
    return allowed


def _load_allowlist(allowlist_arg: str | None, scan_root: Path) -> list[dict]:
    if allowlist_arg:
        candidate = Path(allowlist_arg).resolve()
    else:
        candidate = scan_root / ".wrg" / "allowlist.json"
    if not candidate.exists():
        return []
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"allowlist file is not valid json: {candidate}") from exc
    if not isinstance(payload, dict):
        return []
    rules = payload.get("rules")
    if not isinstance(rules, list):
        return []
    return [item for item in rules if isinstance(item, dict)]


def _finding_matches_rule(finding: Finding, rule: dict) -> bool:
    check = rule.get("check")
    rule_id = rule.get("rule_id")
    severity = rule.get("severity")
    file_pattern = rule.get("file")
    snippet_contains = rule.get("snippet_contains")

    if isinstance(check, str) and check.strip() and finding.check != check.strip():
        return False
    if isinstance(rule_id, str) and rule_id.strip() and finding.rule_id != rule_id.strip():
        return False
    if isinstance(severity, str) and severity.strip() and finding.severity.upper() != severity.strip().upper():
        return False
    if isinstance(file_pattern, str) and file_pattern.strip():
        if not fnmatch.fnmatch(finding.file, file_pattern.strip()):
            return False
    if isinstance(snippet_contains, str) and snippet_contains.strip():
        if snippet_contains not in finding.snippet:
            return False
    return True


def _apply_allowlist(findings: list[Finding], allowlist_rules: list[dict]) -> tuple[list[Finding], list[dict]]:
    if not allowlist_rules:
        return findings, []
    active: list[Finding] = []
    suppressed: list[dict] = []
    for finding in findings:
        matched_rule = None
        for rule in allowlist_rules:
            if _finding_matches_rule(finding, rule):
                matched_rule = rule
                break
        if matched_rule is None:
            active.append(finding)
            continue
        suppressed.append(
            {
                "finding": _safe_finding_dict(finding),
                "reason": str(matched_rule.get("reason", "allowlisted")),
                "rule": {
                    "check": matched_rule.get("check"),
                    "rule_id": matched_rule.get("rule_id"),
                    "file": matched_rule.get("file"),
                },
            }
        )
    return active, suppressed


def _resolve_policy_argument(policy_arg: str | None, profile: str | None, scan_root: Path) -> str | None:
    if policy_arg and profile:
        raise ValueError("use either --policy or --profile, not both")
    if policy_arg:
        return policy_arg
    if profile is None:
        return None
    if profile == "baseline":
        candidate = scan_root / ".wrg" / "policy.json"
    else:
        candidate = scan_root / ".wrg" / "policy.strict.json"
    if not candidate.exists():
        return None  # fall back to built-in default policy
    return str(candidate)


def _run_bandit(args: argparse.Namespace) -> int:
    """Run bandit security scanner on Python source."""
    import subprocess
    import sys

    target = Path(args.path).resolve()
    if args.app:
        target = target / "apps" / args.app / "src"
        if not target.exists():
            target = Path(args.path).resolve() / "apps" / args.app
    if not target.exists():
        print(f"ERROR: path not found: {target}", file=sys.stderr)
        return 1

    sev_map = {"low": "l", "medium": "m", "high": "h"}
    sev_flag = sev_map.get(args.severity, "m")

    cmd = ["bandit", "-r", str(target), f"-l{sev_flag}", "-f", "json", "-q"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        print("ERROR: bandit not installed. Run: pip install bandit", file=sys.stderr)
        return 1

    if args.json_out:
        Path(args.json_out).write_text(result.stdout or "{}", encoding="utf-8")
        print(f"Report written to {args.json_out}")
    elif result.stdout:
        try:
            data = json.loads(result.stdout)
            issues = data.get("results", [])
            if not issues:
                print(f"bandit: no issues found (severity >= {args.severity})")
                return 0
            print(f"bandit: {len(issues)} issue(s) found (severity >= {args.severity})\n")
            for issue in issues:
                sev = issue.get("issue_severity", "?")
                conf = issue.get("issue_confidence", "?")
                text = issue.get("issue_text", "?")
                fname = issue.get("filename", "?")
                line = issue.get("line_number", "?")
                print(f"  [{sev}/{conf}] {fname}:{line}")
                print(f"    {text}\n")
        except json.JSONDecodeError:
            print(result.stdout)
    else:
        print(f"bandit: no issues found (severity >= {args.severity})")
        return 0

    return 1 if result.returncode != 0 else 0


def _run_profiles(scan_root: Path) -> int:
    baseline = scan_root / ".wrg" / "policy.json"
    strict = scan_root / ".wrg" / "policy.strict.json"
    print("wrg-devguard profiles:")
    print(f"- baseline: {baseline} | {'present' if baseline.exists() else 'missing'}")
    print(f"- strict:   {strict} | {'present' if strict.exists() else 'missing'}")
    return 0


def _run_lint_policy(
    scan_root: Path,
    policy_arg: str | None,
    fail_on: str,
    allowed_files: set[str] | None,
    allowlist_rules: list[dict],
) -> tuple[dict, int]:
    policy = load_policy(policy_arg, scan_root)
    findings = lint_policy(scan_root, policy, allowed_files=allowed_files)
    findings, suppressed = _apply_allowlist(findings, allowlist_rules)
    report = _as_report("lint-policy", scan_root, findings, fail_on, suppressed=suppressed)
    _print_summary("lint-policy")
    return report, (1 if report["status"] == "FAIL" else 0)


def _run_scan_secrets(
    scan_root: Path,
    fail_on: str,
    allowed_files: set[str] | None,
    allowlist_rules: list[dict],
) -> tuple[dict, int]:
    findings = scan_secrets(scan_root, allowed_files=allowed_files)
    findings, suppressed = _apply_allowlist(findings, allowlist_rules)
    report = _as_report("scan-secrets", scan_root, findings, fail_on, suppressed=suppressed)
    _print_summary("scan-secrets")
    return report, (1 if report["status"] == "FAIL" else 0)


def _run_check(
    scan_root: Path,
    policy_arg: str | None,
    fail_on: str,
    allowed_files: set[str] | None,
    allowlist_rules: list[dict],
) -> tuple[dict, int]:
    policy = load_policy(policy_arg, scan_root)
    policy_findings = lint_policy(scan_root, policy, allowed_files=allowed_files)
    secret_findings = scan_secrets(scan_root, allowed_files=allowed_files)
    findings, suppressed = _apply_allowlist([*policy_findings, *secret_findings], allowlist_rules)
    report = _as_report("check", scan_root, findings, fail_on, suppressed=suppressed)
    _print_summary("check")
    return report, (1 if report["status"] == "FAIL" else 0)


def _run_scan_logs(args: argparse.Namespace) -> int:
    """Dispatcher for the `scan-logs` subcommand.

    Reads the input (file or stdin), runs the LogScanResult pipeline, then
    writes either to `--json-out` or stdout. Exit code follows `--fail-on`
    (default `high`).
    """
    if args.input != "-" and not Path(args.input).is_file():
        print(f"scan-logs: input file not found: {args.input}")
        return 2

    try:
        report = _scan_logs_core(path=args.input, source=args.source)
    except OSError as exc:
        print(f"scan-logs: read failed: {exc}")
        return 2

    serialized = json.dumps(report, indent=2, ensure_ascii=False)
    if args.json_out:
        Path(args.json_out).write_text(serialized + "\n", encoding="utf-8")
    else:
        print(serialized)

    return _scan_logs_fail_code(report, args.fail_on)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    # scan-logs takes a file (or stdin), not a directory; route it before
    # the directory-based commands' shared scan_root validation runs.
    if args.command == "scan-logs":
        return _run_scan_logs(args)

    scan_root = Path(args.path).resolve()
    if not scan_root.exists():
        print(f"scan path does not exist: {scan_root}")
        return 2

    if args.command == "profiles":
        return _run_profiles(scan_root)

    if args.command == "bandit":
        return _run_bandit(args)

    try:
        allowed_files = _load_allowed_files(args.paths_file, scan_root)
        allowlist_rules = _load_allowlist(getattr(args, "allowlist", None), scan_root)
        resolved_policy = _resolve_policy_argument(
            getattr(args, "policy", None),
            getattr(args, "profile", None),
            scan_root,
        )
    except ValueError as exc:
        print(str(exc))
        return 2

    if args.command == "lint-policy":
        report, exit_code = _run_lint_policy(scan_root, resolved_policy, args.fail_on, allowed_files, allowlist_rules)
    elif args.command == "scan-secrets":
        report, exit_code = _run_scan_secrets(scan_root, args.fail_on, allowed_files, allowlist_rules)
    elif args.command == "check":
        report, exit_code = _run_check(scan_root, resolved_policy, args.fail_on, allowed_files, allowlist_rules)
    else:
        parser.print_help()
        return 1

    if args.json_out:
        write_json(args.json_out, _safe_json_report(args.command, scan_root))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
