"""Stream parser for GitHub Actions logs."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from datetime import datetime

from ._normalize import LogEvent, envelope, iter_clean_lines, make_event

TIMESTAMP_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+(?P<body>.*)$"
)
GROUP_RE = re.compile(r"^##\[group\](?P<name>.+)$")
ERROR_RE = re.compile(r"^##\[error\](?P<msg>.*)$")
ENDGROUP = "##[endgroup]"
EXIT_RE = re.compile(
    r"(?:exit(?:ed)? code|exit status|returned non-zero exit status)\s+(?P<code>\d+)",
    re.IGNORECASE,
)
TRACEBACK_START = "Traceback (most recent call last):"
TRACEBACK_TAIL_RE = re.compile(r"^[A-Za-z_][\w.]*(?:Error|Exception|Exit):\s+.+")


class GitHubActionsLogAdapter:
    source = "github_actions"

    def iter_events(self, lines: Iterable[str | bytes]) -> Iterator[LogEvent]:
        return iter_github_actions_events(lines)

    def analyze(self, lines: Iterable[str | bytes]) -> dict:
        return analyze_github_actions_log(lines)


def iter_github_actions_events(lines: Iterable[str | bytes]) -> Iterator[LogEvent]:
    """Yield normalized events from a GitHub Actions line stream."""

    step_stack: list[tuple[str, datetime | None]] = []
    in_traceback = False

    for clean in iter_clean_lines(lines):
        ts, body = _split_timestamp(clean.text)
        current_step = step_stack[-1][0] if step_stack else None

        group = GROUP_RE.match(body)
        if group:
            step = group.group("name").strip()
            step_stack.append((step, _parse_ts(ts)))
            yield make_event(ts=ts, level="info", step=step, msg="step started")
            continue

        if body == ENDGROUP:
            step, started_at = step_stack.pop() if step_stack else (current_step, None)
            duration_ms = _duration_ms(started_at, _parse_ts(ts))
            yield make_event(
                ts=ts,
                level="info",
                step=step,
                msg="step finished",
                duration_ms=duration_ms,
            )
            continue

        error = ERROR_RE.match(body)
        if error:
            msg = error.group("msg").strip()
            exit_match = EXIT_RE.search(msg)
            yield make_event(
                ts=ts,
                level="error",
                step=current_step,
                msg=msg,
                exit_code=int(exit_match.group("code")) if exit_match else None,
                line_no=clean.line_no,
            )
            continue

        if body == TRACEBACK_START:
            in_traceback = True
            yield make_event(
                ts=ts,
                level="error",
                step=current_step,
                msg=body,
                kind="python_traceback",
                line_no=clean.line_no,
            )
            continue

        if in_traceback:
            yield make_event(
                ts=ts,
                level="error",
                step=current_step,
                msg=body,
                kind="python_traceback",
                line_no=clean.line_no,
            )
            if TRACEBACK_TAIL_RE.match(body):
                in_traceback = False
            continue

        exit_match = EXIT_RE.search(body)
        if exit_match:
            yield make_event(
                ts=ts,
                level="error",
                step=current_step,
                msg=body,
                exit_code=int(exit_match.group("code")),
                line_no=clean.line_no,
            )
            continue

        if clean.truncated:
            yield make_event(
                ts=ts,
                level="warning",
                step=current_step,
                msg=body,
                truncated=True,
                line_no=clean.line_no,
            )


def analyze_github_actions_log(lines: Iterable[str | bytes]) -> dict:
    return envelope(source=GitHubActionsLogAdapter.source, events=iter_github_actions_events(lines))


def _split_timestamp(line: str) -> tuple[str | None, str]:
    match = TIMESTAMP_RE.match(line)
    if not match:
        return None, line
    return match.group("ts"), match.group("body")


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _duration_ms(start: datetime | None, end: datetime | None) -> int | None:
    if start is None or end is None:
        return None
    return max(0, int((end - start).total_seconds() * 1000))
