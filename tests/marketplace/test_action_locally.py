"""Marketplace action smoke test — invokes the CLI exactly the way action.yml does.

Runs `wrg-devguard check` against a fixture directory containing a known
test secret (AKIA-shaped key from AWS public docs) and asserts the
scanner's exit code reflects the finding. This is the same code path the
composite action's `Run wrg-devguard scan` step takes after pip-installing
the package.

The package deliberately redacts findings from the on-disk JSON report
(see `_safe_json_report` in `src/wrg_devguard/cli.py`) — only the exit
code is a reliable signal that findings were detected. The action.yml
honours this by surfacing `findings-count` derived from the exit code,
not from JSON parsing.

Also exercises the SARIF converter end-to-end so a regression in
`scripts/json_to_sarif.py` is caught at PR time, not at tag-push time.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = Path(__file__).parent / "fixtures"
SARIF_SCRIPT = REPO_ROOT / "scripts" / "json_to_sarif.py"


def _run_check(tmp_path: Path, fail_on: str = "error") -> tuple[int, Path]:
    """Mirror the action.yml `check` invocation; return (exit_code, json_path)."""
    report = tmp_path / "report.json"
    proc = subprocess.run(
        [
            "wrg-devguard", "check",
            "--path", str(FIXTURE_DIR),
            "--profile", "baseline",
            "--fail-on", fail_on,
            "--json-out", str(report),
        ],
        capture_output=True,
        text=True,
    )
    return proc.returncode, report


def test_fixture_aws_key_detected_via_exit_code(tmp_path: Path) -> None:
    """Action.yml's primary signal is the CLI exit code, not the JSON body."""
    rc, _ = _run_check(tmp_path, fail_on="error")
    assert rc == 1, (
        f"AKIA fixture should produce exit 1; got {rc}. "
        "If this regressed, the action's findings-count output will be wrong."
    )


def test_redacted_json_shape_is_stable(tmp_path: Path) -> None:
    """Confirm the on-disk JSON is the safe-redacted shape; action.yml relies on this."""
    _run_check(tmp_path, fail_on="error")
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["schema_version"] == "wrg_devguard.v1"
    # Findings are intentionally empty in the on-disk report.
    assert report["findings"] == []
    # Summary fields are REDACTED placeholders.
    assert report["summary"]["total_findings"] == "REDACTED"


import pytest  # noqa: E402  (kept after the always-run tests)


@pytest.mark.parametrize("fixture_findings", [0, 1, 7])
def test_sarif_converter_handles_arbitrary_input(
    tmp_path: Path, fixture_findings: int
) -> None:
    """SARIF converter is the action's `format: sarif` path. Test independently."""
    findings = [
        {
            "rule": "aws_access_key_id",
            "severity": "error",
            "path": f"file_{i}.txt",
            "line": i + 1,
            "message": f"redacted finding #{i}",
        }
        for i in range(fixture_findings)
    ]
    src = tmp_path / "in.json"
    src.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    dst = tmp_path / "out.sarif"

    proc = subprocess.run(
        [
            "python", str(SARIF_SCRIPT),
            "--input", str(src),
            "--output", str(dst),
            "--tool-version", "0.1.1-test",
        ],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr

    sarif = json.loads(dst.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    runs = sarif["runs"]
    assert len(runs) == 1
    assert runs[0]["tool"]["driver"]["name"] == "wrg-devguard"
    assert runs[0]["tool"]["driver"]["version"] == "0.1.1-test"
    assert len(runs[0]["results"]) == fixture_findings
