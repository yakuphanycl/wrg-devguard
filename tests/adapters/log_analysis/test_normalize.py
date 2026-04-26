from __future__ import annotations

import logging

from wrg_devguard.adapters.log_analysis._normalize import (
    LogAnalysisAdapter,
    envelope,
    iter_clean_lines,
    make_event,
    mutation_denied,
    mutations_allowed,
)
from wrg_devguard.adapters.log_analysis.cd_deployment import SystemdDeploymentLogAdapter
from wrg_devguard.adapters.log_analysis.ci_github_actions import GitHubActionsLogAdapter


def test_envelope_keeps_ok_first_and_normalizes_events() -> None:
    result = envelope(
        source="unit",
        events=[make_event(ts=None, level="INFO", step="parse", msg="done")],
    )

    assert list(result.keys())[:3] == ["ok", "source", "events"]
    assert result["ok"] is True
    assert result["events"] == [{"ts": None, "level": "info", "step": "parse", "msg": "done"}]


def test_iter_clean_lines_keeps_truncated_line_without_crashing() -> None:
    clean = list(iter_clean_lines([b"complete\n", b"cut mid-line"]))

    assert [line.text for line in clean] == ["complete", "cut mid-line"]
    assert clean[0].truncated is False
    assert clean[1].truncated is True


def test_iter_clean_lines_skips_binary_garbage_and_logs_warning(caplog) -> None:
    caplog.set_level(logging.WARNING)

    clean = list(iter_clean_lines([b"ok\n", b"bad\x00line\n", b"also-ok\r\n"]))

    assert [line.text for line in clean] == ["ok", "also-ok"]
    assert "control bytes present" in caplog.text


def test_mutation_gate_boundary_defaults_closed() -> None:
    assert mutations_allowed({}) is False
    assert mutations_allowed({"WRG_DEVGUARD_LOG_ANALYSIS_MUTATIONS": "1"}) is True

    denied = mutation_denied("persist_log_analysis")
    assert list(denied.keys())[0] == "ok"
    assert denied["ok"] is False


def test_adapters_satisfy_protocol_shape() -> None:
    adapters: list[LogAnalysisAdapter] = [
        GitHubActionsLogAdapter(),
        SystemdDeploymentLogAdapter(),
    ]

    assert [adapter.source for adapter in adapters] == ["github_actions", "deployment_systemd"]
