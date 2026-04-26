from __future__ import annotations

import logging
from itertools import chain
from pathlib import Path

from wrg_devguard.adapters.log_analysis.ci_github_actions import (
    analyze_github_actions_log,
    iter_github_actions_events,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "logs"


def test_github_actions_happy_path_extracts_steps_errors_and_timing() -> None:
    with (FIXTURES / "github_actions_clean.txt").open("rb") as log:
        result = analyze_github_actions_log(log)

    assert list(result.keys())[:3] == ["ok", "source", "events"]
    assert result["ok"] is True
    assert result["source"] == "github_actions"

    events = result["events"]
    assert any(e["step"] == "Checkout repository" and e["msg"] == "step started" for e in events)
    assert any(e.get("duration_ms") == 3000 and e["step"] == "Checkout repository" for e in events)
    assert any(e["level"] == "error" and e.get("kind") == "python_traceback" for e in events)
    assert any(e["level"] == "error" and e.get("exit_code") == 1 for e in events)


def test_github_actions_truncated_stream_gracefully_yields_warning() -> None:
    lines = iter(
        [
            b"2026-04-26T08:00:00Z ##[group]Run tests\n",
            b"2026-04-26T08:00:01Z pytest --maxfail=1",
        ]
    )

    events = list(iter_github_actions_events(lines))

    assert events[-1].level == "warning"
    assert events[-1].metadata["truncated"] is True
    assert events[-1].step == "Run tests"


def test_github_actions_malformed_bytes_are_skipped_and_warned(caplog) -> None:
    caplog.set_level(logging.WARNING)
    lines = [
        b"\xff\xfe\x00not utf8\n",
        b"2026-04-26T08:00:07Z ##[error]Process completed with exit code 1.\n",
    ]

    events = list(iter_github_actions_events(lines))

    assert len(events) == 1
    assert events[0].metadata["exit_code"] == 1
    assert "skipping malformed log line 1" in caplog.text


def test_github_actions_mixed_edge_strips_ansi_and_keeps_stream_order() -> None:
    with (FIXTURES / "mixed_edge.txt").open("rb") as log:
        events = list(
            iter_github_actions_events(
                chain(log, [b"2026-04-26T11:00:03Z partial line without newline"])
            )
        )

    assert events[0].step == "Lint package"
    assert any(e.level == "error" and e.metadata.get("exit_code") == 2 for e in events)
    assert events[-1].metadata.get("truncated") is True
