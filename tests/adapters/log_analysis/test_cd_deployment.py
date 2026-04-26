from __future__ import annotations

import logging
from pathlib import Path

from wrg_devguard.adapters.log_analysis.cd_deployment import (
    analyze_systemd_deploy_log,
    iter_systemd_deploy_events,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "logs"


def test_systemd_deploy_happy_path_extracts_deploy_and_rollback() -> None:
    with (FIXTURES / "deploy_systemd.txt").open("rb") as log:
        result = analyze_systemd_deploy_log(log)

    assert list(result.keys())[:3] == ["ok", "source", "events"]
    assert result["ok"] is True
    assert result["source"] == "deployment_systemd"

    events = result["events"]
    assert any(e["step"] == "deploy" and e.get("duration_ms") == 44000 for e in events)
    assert any(e["step"] == "rollback" and e["level"] == "warning" for e in events)
    assert any(e.get("unit") == "systemd" and e["step"] == "service" for e in events)


def test_systemd_deploy_truncated_stream_marks_last_event() -> None:
    lines = iter(
        [
            b"2026-04-26 09:15:00 ci-host deploy-api[1200]: deployment started\n",
            b"2026-04-26 09:15:44 ci-host deploy-api[1200]: deployment completed in 44s",
        ]
    )

    events = list(iter_systemd_deploy_events(lines))

    assert events[-1].metadata["truncated"] is True
    assert events[-1].metadata["duration_ms"] == 44000


def test_systemd_deploy_malformed_line_becomes_warning_event(caplog) -> None:
    caplog.set_level(logging.WARNING)
    lines = [
        b"\xfe\xffbad utf8\n",
        b"not a journal line\n",
        b"2026-04-26 09:15:44 ci-host deploy-api[1200]: deployment completed in 44s\n",
    ]

    events = list(iter_systemd_deploy_events(lines))

    assert len(events) == 2
    assert events[0].level == "warning"
    assert events[0].metadata["malformed"] is True
    assert events[1].metadata["duration_ms"] == 44000
    assert "skipping malformed log line 1" in caplog.text


def test_systemd_deploy_mixed_edge_detects_failed_deploy_and_rollback() -> None:
    with (FIXTURES / "mixed_edge.txt").open("rb") as log:
        events = list(iter_systemd_deploy_events(log))

    assert any(e.level == "error" and "failed health check" in e.msg for e in events)
    assert any(e.step == "rollback" for e in events)
