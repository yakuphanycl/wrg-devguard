"""Common normalization helpers for log-analysis adapters.

The public envelope intentionally follows the wrg_mcp_server v1.0.2
``{ok, ...}`` convention: ``ok`` is always the first key and failures are
returned as data instead of raised to callers.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol

LOG = logging.getLogger(__name__)

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
MUTATION_ENV = "WRG_DEVGUARD_LOG_ANALYSIS_MUTATIONS"


@dataclass(slots=True)
class LogEvent:
    ts: str | None
    level: str
    step: str | None
    msg: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "ts": self.ts,
            "level": self.level,
            "step": self.step,
            "msg": self.msg,
        }
        payload.update(self.metadata)
        return payload


@dataclass(slots=True)
class CleanLine:
    text: str
    line_no: int
    truncated: bool = False


class LogAnalysisAdapter(Protocol):
    source: str

    def iter_events(self, lines: Iterable[str | bytes]) -> Iterator[LogEvent]:
        ...

    def analyze(self, lines: Iterable[str | bytes]) -> dict[str, Any]:
        ...


def make_event(
    *,
    ts: str | None,
    level: str,
    step: str | None,
    msg: str,
    **metadata: Any,
) -> LogEvent:
    return LogEvent(
        ts=ts,
        level=level.lower(),
        step=step,
        msg=msg.strip(),
        metadata={k: v for k, v in metadata.items() if v is not None},
    )


def iter_clean_lines(lines: Iterable[str | bytes]) -> Iterator[CleanLine]:
    """Yield sanitized lines without requiring the whole log in memory."""

    for line_no, raw in enumerate(lines, start=1):
        if isinstance(raw, bytes):
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                LOG.warning("skipping malformed log line %s: invalid utf-8", line_no)
                continue
        else:
            text = raw

        truncated = not text.endswith(("\n", "\r"))
        text = ANSI_RE.sub("", text.rstrip("\r\n"))
        if not text.strip():
            continue
        if CONTROL_RE.search(text):
            LOG.warning("skipping malformed log line %s: control bytes present", line_no)
            continue
        yield CleanLine(text=text, line_no=line_no, truncated=truncated)


def envelope(
    *,
    source: str,
    events: Iterable[LogEvent | dict[str, Any]],
    warnings: Iterable[str] | None = None,
    ok: bool = True,
    **metadata: Any,
) -> dict[str, Any]:
    """Return the stable log-analysis envelope.

    ``ok`` is first by construction to match the MCP tool envelope contract.
    """

    normalized_events = [
        event.to_dict() if isinstance(event, LogEvent) else dict(event)
        for event in events
    ]
    result: dict[str, Any] = {
        "ok": ok,
        "source": source,
        "events": normalized_events,
    }
    warning_list = [w for w in warnings or [] if w]
    if warning_list:
        result["warnings"] = warning_list
    result.update({k: v for k, v in metadata.items() if v is not None})
    return result


def mutations_allowed(env: dict[str, str] | None = None) -> bool:
    """Boundary for future state-changing sinks; parsers stay read-only."""

    raw = ((env or os.environ).get(MUTATION_ENV) or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def mutation_denied(operation: str) -> dict[str, Any]:
    return {
        "ok": False,
        "error": (
            f"{operation} is a mutation and {MUTATION_ENV} is not set. "
            f"Set {MUTATION_ENV}=1 to allow state-changing log analysis operations."
        ),
    }
