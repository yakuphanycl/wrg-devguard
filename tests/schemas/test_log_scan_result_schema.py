"""Schema contract tests for log_scan_result.schema.json.

The schema is the frozen v0.2.0 contract between:
- the producer (`wrg-devguard scan-logs`)
- the consumer (CC log_viewer route + future CI integrations)

These tests guard against accidental contract drift. If a test here fails,
either the schema regressed or a producer/consumer change is unsafe and
needs review.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema
import pytest
from jsonschema import Draft202012Validator

SCHEMAS_DIR = Path(__file__).parent.parent.parent / "schemas"
SCHEMA_PATH = SCHEMAS_DIR / "log_scan_result.schema.json"
FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def validator(schema: dict) -> Draft202012Validator:
    return Draft202012Validator(schema)


# ──────────────────────────────────────────────────────────────────────
# Schema self-validation
# ──────────────────────────────────────────────────────────────────────


def test_schema_is_valid_draft_2020_12(schema: dict) -> None:
    Draft202012Validator.check_schema(schema)


def test_schema_top_level_required_fields(schema: dict) -> None:
    expected = {"schema_version", "tool_version", "scanned_at", "source",
                "input", "findings", "summary"}
    assert set(schema["required"]) == expected


def test_schema_version_is_frozen_at_1(schema: dict) -> None:
    assert schema["properties"]["schema_version"]["const"] == "1"


def test_schema_source_enum_locked(schema: dict) -> None:
    assert set(schema["properties"]["source"]["enum"]) == {
        "manual", "ci", "cc-endpoint"
    }


def test_schema_severity_levels(schema: dict) -> None:
    assert set(schema["$defs"]["Severity"]["enum"]) == {
        "high", "medium", "low", "info"
    }


def test_schema_category_levels(schema: dict) -> None:
    assert set(schema["$defs"]["Category"]["enum"]) == {
        "secret",
        "pii_email", "pii_phone", "pii_ssn", "pii_ip", "pii_card",
        "pii_name",
    }


def test_schema_finding_required_fields(schema: dict) -> None:
    expected = {"pattern_id", "category", "severity", "line_no",
                "span", "redacted_excerpt", "rationale"}
    assert set(schema["$defs"]["Finding"]["required"]) == expected


def test_schema_examples_self_validate(validator: Draft202012Validator,
                                        schema: dict) -> None:
    for ex in schema["examples"]:
        validator.validate(ex)


# ──────────────────────────────────────────────────────────────────────
# Fixture validation (positive cases)
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("fixture_name", ["clean", "mixed"])
def test_fixture_validates(validator: Draft202012Validator,
                            fixture_name: str) -> None:
    payload = json.loads((FIXTURES_DIR / f"{fixture_name}.json").read_text(
        encoding="utf-8"
    ))
    validator.validate(payload)


# ──────────────────────────────────────────────────────────────────────
# Negative cases: malformed payloads MUST fail validation
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def base_payload() -> dict:
    return json.loads((FIXTURES_DIR / "mixed.json").read_text(encoding="utf-8"))


def _expect_invalid(validator: Draft202012Validator, payload: dict) -> None:
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(payload)


def test_missing_top_level_field_rejected(validator, base_payload):
    p = copy.deepcopy(base_payload)
    del p["summary"]
    _expect_invalid(validator, p)


def test_unknown_top_level_field_rejected(validator, base_payload):
    p = copy.deepcopy(base_payload)
    p["unexpected_key"] = "nope"
    _expect_invalid(validator, p)


def test_wrong_schema_version_rejected(validator, base_payload):
    p = copy.deepcopy(base_payload)
    p["schema_version"] = "2"
    _expect_invalid(validator, p)


def test_invalid_tool_version_rejected(validator, base_payload):
    p = copy.deepcopy(base_payload)
    p["tool_version"] = "v0.2.0"  # leading "v" is not semver
    _expect_invalid(validator, p)


def test_unknown_source_rejected(validator, base_payload):
    p = copy.deepcopy(base_payload)
    p["source"] = "stdin"
    _expect_invalid(validator, p)


def test_unknown_severity_rejected(validator, base_payload):
    p = copy.deepcopy(base_payload)
    p["findings"][0]["severity"] = "critical"
    _expect_invalid(validator, p)


def test_unknown_category_rejected(validator, base_payload):
    p = copy.deepcopy(base_payload)
    p["findings"][0]["category"] = "pii_unknown"
    _expect_invalid(validator, p)


def test_invalid_pattern_id_format_rejected(validator, base_payload):
    p = copy.deepcopy(base_payload)
    p["findings"][0]["pattern_id"] = "aws-001"  # lowercase rejected
    _expect_invalid(validator, p)


def test_zero_line_no_rejected(validator, base_payload):
    p = copy.deepcopy(base_payload)
    p["findings"][0]["line_no"] = 0  # 1-based
    _expect_invalid(validator, p)


def test_span_must_be_two_ints(validator, base_payload):
    p = copy.deepcopy(base_payload)
    p["findings"][0]["span"] = [12]  # missing end
    _expect_invalid(validator, p)


def test_redacted_excerpt_too_long_rejected(validator, base_payload):
    p = copy.deepcopy(base_payload)
    p["findings"][0]["redacted_excerpt"] = "x" * 201
    _expect_invalid(validator, p)


def test_negative_size_bytes_rejected(validator, base_payload):
    p = copy.deepcopy(base_payload)
    p["input"]["size_bytes"] = -1
    _expect_invalid(validator, p)


def test_invalid_sha256_rejected(validator, base_payload):
    p = copy.deepcopy(base_payload)
    p["input"]["sha256"] = "not-a-real-sha"
    _expect_invalid(validator, p)


def test_summary_by_severity_rejects_unknown_key(validator, base_payload):
    p = copy.deepcopy(base_payload)
    p["summary"]["by_severity"]["critical"] = 1
    _expect_invalid(validator, p)


# ──────────────────────────────────────────────────────────────────────
# Optional-field acceptance (additive surface)
# ──────────────────────────────────────────────────────────────────────


def test_finding_fp_suppression_optional(validator, base_payload):
    """fp_suppression is optional; absence MUST validate."""
    p = copy.deepcopy(base_payload)
    for f in p["findings"]:
        f.pop("fp_suppression", None)
    validator.validate(p)


def test_input_sha256_optional(validator, base_payload):
    p = copy.deepcopy(base_payload)
    p["input"].pop("sha256", None)
    validator.validate(p)


def test_summary_runtime_ms_optional(validator, base_payload):
    p = copy.deepcopy(base_payload)
    p["summary"].pop("runtime_ms", None)
    validator.validate(p)


def test_clean_scan_empty_findings_validates(validator):
    payload = json.loads((FIXTURES_DIR / "clean.json").read_text(
        encoding="utf-8"
    ))
    validator.validate(payload)
    assert payload["findings"] == []
    assert payload["summary"]["total"] == 0
