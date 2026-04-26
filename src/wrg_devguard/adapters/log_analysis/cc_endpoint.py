"""Control Center endpoint JSONL log adapter.

Canonical format:

One JSON object per line, shaped like:
``{"ts":"2026-04-26T12:00:00Z","level":"info","step":"login","msg":"..."}``

The Control Center log viewer endpoint contract is still evolving, so this
adapter uses a narrow JSONL event envelope that maps cleanly to LogEvent while
preserving extra fields as metadata.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator
from typing import Any

from ._normalize import LogEvent, envelope, iter_clean_lines, make_event

LOG = logging.getLogger(__name__)
RESERVED_KEYS = {"ts", "level", "step", "msg"}


class CcEndpointLogAdapter:
    source = "cc_endpoint"

    def iter_events(self, lines: Iterable[str | bytes]) -> Iterator[LogEvent]:
        return iter_cc_endpoint_events(lines)

    def analyze(self, lines: Iterable[str | bytes]) -> dict[str, Any]:
        return analyze_cc_endpoint_log(lines)


def iter_cc_endpoint_events(lines: Iterable[str | bytes]) -> Iterator[LogEvent]:
    """Yield normalized events from Control Center JSONL endpoint logs."""

    for clean in iter_clean_lines(lines):
        try:
            item = json.loads(clean.text)
        except json.JSONDecodeError:
            LOG.warning("skipping malformed cc-endpoint log line %s: invalid json", clean.line_no)
            continue
        if not isinstance(item, dict):
            LOG.warning("skipping malformed cc-endpoint log line %s: expected object", clean.line_no)
            continue

        msg = item.get("msg")
        if msg is None:
            LOG.warning("skipping malformed cc-endpoint log line %s: missing msg", clean.line_no)
            continue

        metadata = {str(k): v for k, v in item.items() if k not in RESERVED_KEYS}
        yield make_event(
            ts=_optional_str(item.get("ts")),
            level=_optional_str(item.get("level")) or "info",
            step=_optional_str(item.get("step")),
            msg=str(msg),
            line_no=clean.line_no,
            truncated=clean.truncated or None,
            **metadata,
        )


def analyze_cc_endpoint_log(lines: Iterable[str | bytes]) -> dict[str, Any]:
    return envelope(source=CcEndpointLogAdapter.source, events=iter_cc_endpoint_events(lines))


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)
