"""Deployment log adapter for ``journalctl -o short-iso`` output.

Canonical format:

``YYYY-MM-DD HH:MM:SS host unit[pid]: message``

Systemd journal output was chosen because deployment and rollback logs usually
include service boundaries, monotonic lifecycle messages, and timestamps without
requiring Docker-specific build semantics.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from ._normalize import LogEvent, envelope, iter_clean_lines, make_event

JOURNAL_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<unit>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
DURATION_RE = re.compile(r"\b(?:in|duration:)\s*(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>ms|s)\b", re.I)
DEPLOY_RE = re.compile(r"\b(deploy(?:ment)?|release|rollout)\b", re.I)
ROLLBACK_RE = re.compile(r"\b(rollback|rolled back|revert)\b", re.I)
ERROR_RE = re.compile(r"\b(failed|failure|error|critical|unhealthy)\b", re.I)
SUCCESS_RE = re.compile(r"\b(succeeded|success|completed|started|healthy)\b", re.I)


class SystemdDeploymentLogAdapter:
    source = "deployment_systemd"

    def iter_events(self, lines: Iterable[str | bytes]) -> Iterator[LogEvent]:
        return iter_systemd_deploy_events(lines)

    def analyze(self, lines: Iterable[str | bytes]) -> dict:
        return analyze_systemd_deploy_log(lines)


def iter_systemd_deploy_events(lines: Iterable[str | bytes]) -> Iterator[LogEvent]:
    """Yield normalized events from systemd journal deploy logs."""

    current_step: str | None = None
    for clean in iter_clean_lines(lines):
        parsed = _parse_journal_line(clean.text)
        if parsed is None:
            yield make_event(
                ts=None,
                level="warning",
                step=current_step,
                msg=clean.text,
                malformed=True,
                line_no=clean.line_no,
            )
            continue

        ts, unit, msg = parsed
        step = _step_for(unit, msg, current_step)
        current_step = step or current_step
        yield make_event(
            ts=ts,
            level=_level_for(msg, clean.truncated),
            step=step,
            msg=msg,
            unit=unit,
            duration_ms=_duration_ms(msg),
            truncated=clean.truncated or None,
            line_no=clean.line_no,
        )


def analyze_systemd_deploy_log(lines: Iterable[str | bytes]) -> dict:
    return envelope(source=SystemdDeploymentLogAdapter.source, events=iter_systemd_deploy_events(lines))


def _parse_journal_line(line: str) -> tuple[str, str, str] | None:
    match = JOURNAL_RE.match(line)
    if not match:
        return None
    ts = match.group("ts").replace(" ", "T")
    return ts, match.group("unit"), match.group("msg").strip()


def _step_for(unit: str, msg: str, fallback: str | None) -> str | None:
    lowered = f"{unit} {msg}".lower()
    if ROLLBACK_RE.search(lowered):
        return "rollback"
    if DEPLOY_RE.search(lowered):
        return "deploy"
    if "docker" in lowered or "image" in lowered:
        return "build"
    if "systemd" in unit.lower() or "service" in lowered:
        return "service"
    return fallback


def _level_for(msg: str, truncated: bool) -> str:
    if ERROR_RE.search(msg):
        return "error"
    if truncated or ROLLBACK_RE.search(msg):
        return "warning"
    if SUCCESS_RE.search(msg):
        return "info"
    return "info"


def _duration_ms(msg: str) -> int | None:
    match = DURATION_RE.search(msg)
    if not match:
        return None
    value = float(match.group("value"))
    if match.group("unit").lower() == "s":
        value *= 1000
    return int(value)
