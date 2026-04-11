from __future__ import annotations

import json
import re
from pathlib import Path

from .common import Finding, line_col, match_any, read_text_safely, relative_posix

DEFAULT_INCLUDE = [
    "**/*.md",
    "**/*.txt",
    "**/*.prompt",
    "**/*.yaml",
    "**/*.yml",
    "**/*.json",
    "**/*.py",
]

DEFAULT_EXCLUDE = [
    "**/.git/**",
    "**/.venv/**",
    "**/venv/**",
    "**/node_modules/**",
    "**/__pycache__/**",
    "**/.pytest_cache/**",
    "**/tests/**",
    "**/testdata/**",
    "**/fixtures/**",
    "**/.tmp/**",
    ".tmp/**",
    "**/.tmp_pytest/**",
    ".tmp_pytest/**",
    "**/_tmp*/**",
    "_tmp*/**",
    "**/.cache/**",
    "**/site-packages/**",
    "**/.train_venv/**",
    "**/data/**",
    "**/runs/**",
    "**/artifacts/**",
    "artifacts/**",
    "**/dist/**",
    "**/build/**",
    "**/*.png",
    "**/*.jpg",
    "**/*.jpeg",
    "**/*.gif",
    "**/*.svg",
    "**/*.ico",
    "**/*.lock",
]

DEFAULT_DENY_PATTERNS = [
    {
        "id": "prompt_injection_ignore_previous",
        "regex": r"ignore\s+previous\s+instructions",
        "severity": "ERROR",
        "message": "Potential prompt-injection control bypass.",
    },
    {
        "id": "prompt_injection_bypass_guardrails",
        "regex": r"bypass\s+(all\s+)?(safety|guardrails|policy|policies)",
        "severity": "ERROR",
        "message": "Potential policy bypass intent.",
    },
    {
        "id": "data_exfiltration_intent",
        "regex": r"(exfiltrate|leak|dump)\s+.*(secret|credential|token|password)",
        "severity": "ERROR",
        "message": "Potential exfiltration intent in prompt content.",
    },
]


def default_policy() -> dict:
    return {
        "include": list(DEFAULT_INCLUDE),
        "exclude": list(DEFAULT_EXCLUDE),
        "max_file_bytes": 1_048_576,
        "deny_patterns": list(DEFAULT_DENY_PATTERNS),
    }


def _parse_policy_file(policy_path: Path) -> dict:
    suffix = policy_path.suffix.lower()
    content = policy_path.read_text(encoding="utf-8")
    if suffix == ".json":
        return json.loads(content)
    if suffix == ".toml":
        import tomllib

        return tomllib.loads(content)
    if suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ModuleNotFoundError as exc:
            raise ValueError(
                "YAML policy requested but PyYAML is not installed. Install with: pip install -e \".[yaml]\""
            ) from exc
        payload = yaml.safe_load(content)
        return payload if isinstance(payload, dict) else {}
    return json.loads(content)


def load_policy(policy_arg: str | None, repo_root: Path) -> dict:
    if policy_arg:
        candidate = Path(policy_arg).resolve()
        if not candidate.exists():
            raise ValueError(f"Policy file not found: {candidate}")
        parsed = _parse_policy_file(candidate)
    else:
        default_path = repo_root / ".wrg" / "policy.json"
        parsed = _parse_policy_file(default_path) if default_path.exists() else {}

    policy = default_policy()
    if not isinstance(parsed, dict):
        return policy

    include = parsed.get("include")
    exclude = parsed.get("exclude")
    deny_patterns = parsed.get("deny_patterns")
    max_file_bytes = parsed.get("max_file_bytes")

    if isinstance(include, list) and include:
        policy["include"] = [str(item) for item in include if isinstance(item, str) and item.strip()]
    if isinstance(exclude, list) and exclude:
        policy["exclude"] = [str(item) for item in exclude if isinstance(item, str) and item.strip()]
    if isinstance(deny_patterns, list) and deny_patterns:
        normalized = []
        for item in deny_patterns:
            if not isinstance(item, dict):
                continue
            regex = item.get("regex")
            if not isinstance(regex, str) or not regex.strip():
                continue
            normalized.append(
                {
                    "id": str(item.get("id", "custom_pattern")),
                    "regex": regex,
                    "severity": str(item.get("severity", "ERROR")).upper(),
                    "message": str(item.get("message", "Custom deny pattern matched.")),
                }
            )
        if normalized:
            policy["deny_patterns"] = normalized
    if isinstance(max_file_bytes, int) and max_file_bytes > 0:
        policy["max_file_bytes"] = max_file_bytes
    return policy


def _iter_candidate_files(root: Path, include: list[str], exclude: list[str]) -> list[Path]:
    return _iter_candidate_files_filtered(root, include, exclude, allowed_files=None)


def _iter_candidate_files_filtered(
    root: Path,
    include: list[str],
    exclude: list[str],
    allowed_files: set[str] | None,
) -> list[Path]:
    results: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = relative_posix(path, root)
        if allowed_files is not None and rel not in allowed_files:
            continue
        if match_any(rel, exclude):
            continue
        if not match_any(rel, include):
            continue
        results.append(path)
    return results


def lint_policy(root: Path, policy: dict, allowed_files: set[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    include = policy.get("include", DEFAULT_INCLUDE)
    exclude = policy.get("exclude", DEFAULT_EXCLUDE)
    max_file_bytes = int(policy.get("max_file_bytes", 1_048_576))
    deny_patterns = policy.get("deny_patterns", DEFAULT_DENY_PATTERNS)
    candidates = _iter_candidate_files_filtered(root, include, exclude, allowed_files)

    compiled_patterns = []
    for rule in deny_patterns:
        if not isinstance(rule, dict):
            continue
        try:
            compiled_patterns.append(
                (
                    str(rule.get("id", "unknown_rule")),
                    re.compile(str(rule.get("regex", "")), re.IGNORECASE | re.MULTILINE),
                    str(rule.get("severity", "ERROR")).upper(),
                    str(rule.get("message", "Policy deny pattern matched.")),
                )
            )
        except re.error:
            continue

    for path in candidates:
        text = read_text_safely(path, max_bytes=max_file_bytes)
        if not text:
            continue
        rel = relative_posix(path, root)
        for rule_id, regex, severity, message in compiled_patterns:
            for match in regex.finditer(text):
                line, column = line_col(text, match.start())
                findings.append(
                    Finding(
                        check="lint-policy",
                        rule_id=rule_id,
                        severity=severity,
                        message=message,
                        file=rel,
                        line=line,
                        column=column,
                        # Never retain matched content in memory or output payloads.
                        snippet="[REDACTED]",
                    )
                )
    return findings
