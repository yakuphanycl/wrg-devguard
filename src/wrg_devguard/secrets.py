from __future__ import annotations

import re
from pathlib import Path

from .common import Finding, line_col, match_any, read_text_safely, relative_posix
from .policy import DEFAULT_EXCLUDE

SECRET_RULES = [
    {
        "id": "openai_api_key",
        "regex": r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",
        "severity": "ERROR",
        "message": "Possible OpenAI API key found.",
    },
    {
        "id": "github_token",
        "regex": r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
        "severity": "ERROR",
        "message": "Possible GitHub token found.",
    },
    {
        "id": "aws_access_key_id",
        "regex": r"\bAKIA[0-9A-Z]{16}\b",
        "severity": "ERROR",
        "message": "Possible AWS Access Key ID found.",
    },
    {
        "id": "slack_token",
        "regex": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        "severity": "ERROR",
        "message": "Possible Slack token found.",
    },
    {
        "id": "private_key_block",
        "regex": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "ERROR",
        "message": "Private key block found.",
    },
    {
        "id": "generic_secret_assignment",
        "regex": r"(?i)(api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        "severity": "WARNING",
        "message": "Potential hardcoded secret assignment.",
    },
]

DEFAULT_INCLUDE = [
    "**/*.env",
    "**/*.ini",
    "**/*.json",
    "**/*.toml",
    "**/*.yaml",
    "**/*.yml",
    "**/*.txt",
    "**/*.md",
    "**/*.py",
    "**/*.js",
    "**/*.ts",
    "**/*.sh",
    "**/*.ps1",
]


def scan_secrets(
    root: Path,
    max_file_bytes: int = 1_048_576,
    allowed_files: set[str] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    compiled_rules = [
        (
            rule["id"],
            re.compile(rule["regex"], re.MULTILINE),
            rule["severity"],
            rule["message"],
        )
        for rule in SECRET_RULES
    ]

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = relative_posix(path, root)
        if allowed_files is not None and rel not in allowed_files:
            continue
        if match_any(rel, DEFAULT_EXCLUDE):
            continue
        if not match_any(rel, DEFAULT_INCLUDE):
            continue
        text = read_text_safely(path, max_bytes=max_file_bytes)
        if not text:
            continue
        for rule_id, regex, severity, message in compiled_rules:
            for match in regex.finditer(text):
                line, column = line_col(text, match.start())
                findings.append(
                    Finding(
                        check="scan-secrets",
                        rule_id=rule_id,
                        severity=severity,
                        message=message,
                        file=rel,
                        line=line,
                        column=column,
                        # Never retain matched secret value in memory or output payloads.
                        snippet="[REDACTED]",
                    )
                )
    return findings
