from __future__ import annotations

import logging
from pathlib import Path

from wrg_devguard.adapters.log_analysis.cc_endpoint import (
    analyze_cc_endpoint_log,
    iter_cc_endpoint_events,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "logs"


def test_cc_endpoint_happy_path_parses_jsonl_events() -> None:
    with (FIXTURES / "cc_endpoint_sample.json").open("rb") as log:
        result = analyze_cc_endpoint_log(log)

    assert list(result.keys())[:3] == ["ok", "source", "events"]
    assert result["ok"] is True
    assert result["source"] == "cc_endpoint"

    events = result["events"]
    assert len(events) == 3
    assert events[0]["ts"] == "2026-04-26T12:00:00Z"
    assert events[0]["level"] == "info"
    assert events[0]["step"] == "login"
    assert events[0]["msg"] == "user login succeeded for analyst@example.com"
    assert events[0]["user_id"] == "<redacted>"
    assert events[2]["status_code"] == 403


def test_cc_endpoint_malformed_lines_are_skipped_with_warning(caplog) -> None:
    caplog.set_level(logging.WARNING)
    lines = [
        b'{"ts":"2026-04-26T12:00:00Z","msg":"first ok"}\n',
        b"\xff\xfebad utf8\n",
        b"{not-json}\n",
        b'{"ts":"2026-04-26T12:00:03Z","msg":"second ok"}\n',
    ]

    events = list(iter_cc_endpoint_events(lines))

    assert [event.msg for event in events] == ["first ok", "second ok"]
    assert "invalid utf-8" in caplog.text
    assert "invalid json" in caplog.text


def test_cc_endpoint_empty_input_returns_empty_envelope() -> None:
    result = analyze_cc_endpoint_log([])

    assert result == {
        "ok": True,
        "source": "cc_endpoint",
        "events": [],
    }
