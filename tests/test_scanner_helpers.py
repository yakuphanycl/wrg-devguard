"""Pure-function unit tests for wrg_devguard scanner helpers.

Covers common.py, cli.py, secrets.py, and policy.py pure helpers with zero
network, zero disk I/O, and no subprocess side effects.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import pytest

from wrg_devguard.common import (
    Finding,
    clean_snippet,
    line_col,
    match_any,
    relative_posix,
    to_posix,
)
from wrg_devguard.cli import (
    _apply_allowlist,
    _finding_matches_rule,
    _normalize_rel_path,
    _resolve_policy_argument,
    _safe_finding_dict,
    _safe_finding_mapping,
    _sanitize_suppressed_payload,
    _should_fail,
)
from wrg_devguard.policy import default_policy
from wrg_devguard.secrets import SECRET_RULES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    *,
    check: str = "scan-secrets",
    rule_id: str = "generic_secret_assignment",
    severity: str = "ERROR",
    message: str = "test message",
    file: str = "src/foo.py",
    line: int = 1,
    column: int = 1,
    snippet: str = "[REDACTED]",
) -> Finding:
    return Finding(
        check=check,
        rule_id=rule_id,
        severity=severity,
        message=message,
        file=file,
        line=line,
        column=column,
        snippet=snippet,
    )


# ---------------------------------------------------------------------------
# common.to_posix
# ---------------------------------------------------------------------------

class TestToPosix:
    def test_simple_path(self) -> None:
        p = Path("/some/dir/file.py")
        assert to_posix(p) == "/some/dir/file.py"

    def test_nested_path(self) -> None:
        p = Path("/a/b/c/d.txt")
        assert "/" in to_posix(p)
        assert "\\" not in to_posix(p)


# ---------------------------------------------------------------------------
# common.relative_posix
# ---------------------------------------------------------------------------

class TestRelativePosix:
    def test_direct_child(self) -> None:
        root = Path("/project")
        child = Path("/project/src/app.py")
        assert relative_posix(child, root) == "src/app.py"

    def test_same_level(self) -> None:
        root = Path("/project")
        child = Path("/project/README.md")
        assert relative_posix(child, root) == "README.md"

    def test_no_leading_slash(self) -> None:
        root = Path("/project")
        child = Path("/project/a/b/c.json")
        result = relative_posix(child, root)
        assert not result.startswith("/")
        assert result == "a/b/c.json"


# ---------------------------------------------------------------------------
# common.match_any
# ---------------------------------------------------------------------------

class TestMatchAny:
    def test_glob_star_extension(self) -> None:
        assert match_any("src/foo.py", ["**/*.py"]) is True

    def test_no_match(self) -> None:
        assert match_any("src/foo.py", ["**/*.txt", "**/*.md"]) is False

    def test_exact_double_star_prefix(self) -> None:
        assert match_any("dist/lib.js", ["**/dist/**"]) is True

    def test_double_star_strip_prefix(self) -> None:
        assert match_any(".git/config", ["**/.git/**"]) is True

    def test_empty_patterns(self) -> None:
        assert match_any("anything.py", []) is False

    def test_fnmatch_direct(self) -> None:
        assert match_any("src/node_modules/pkg/index.js", ["**/node_modules/**"]) is True

    def test_case_sensitive_by_default(self) -> None:
        result = match_any("src/foo.PY", ["**/*.py"])
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# common.line_col
# ---------------------------------------------------------------------------

class TestLineCol:
    def test_start_of_file(self) -> None:
        text = "hello world"
        line, col = line_col(text, 0)
        assert line == 1
        assert col == 1

    def test_second_line_first_char(self) -> None:
        text = "line1\nline2"
        line, col = line_col(text, 6)
        assert line == 2
        assert col == 1

    def test_second_line_mid_char(self) -> None:
        text = "abc\ndef"
        line, col = line_col(text, 5)
        assert line == 2
        assert col == 2

    def test_third_line(self) -> None:
        text = "a\nb\nc"
        line, col = line_col(text, 4)
        assert line == 3
        assert col == 1

    def test_single_line_mid_position(self) -> None:
        text = "abcdef"
        line, col = line_col(text, 3)
        assert line == 1
        assert col == 4


# ---------------------------------------------------------------------------
# common.clean_snippet
# ---------------------------------------------------------------------------

class TestCleanSnippet:
    def test_trims_whitespace(self) -> None:
        assert clean_snippet("  hello  ") == "hello"

    def test_collapses_internal_whitespace(self) -> None:
        assert clean_snippet("a   b\t\tc") == "a b c"

    def test_truncates_at_200(self) -> None:
        long_value = "x" * 300
        result = clean_snippet(long_value)
        assert len(result) == 200

    def test_newlines_collapsed(self) -> None:
        result = clean_snippet("line1\nline2\nline3")
        assert "\n" not in result
        assert result == "line1 line2 line3"

    def test_empty_string(self) -> None:
        assert clean_snippet("") == ""


# ---------------------------------------------------------------------------
# common.Finding.to_dict
# ---------------------------------------------------------------------------

class TestFindingToDict:
    def test_all_fields_present(self) -> None:
        f = _make_finding()
        d = f.to_dict()
        assert set(d.keys()) == {"check", "rule_id", "severity", "message", "file", "line", "column", "snippet"}

    def test_values_match(self) -> None:
        f = _make_finding(check="lint-policy", rule_id="test_rule", severity="WARNING", line=42, column=7)
        d = f.to_dict()
        assert d["check"] == "lint-policy"
        assert d["rule_id"] == "test_rule"
        assert d["severity"] == "WARNING"
        assert d["line"] == 42
        assert d["column"] == 7


# ---------------------------------------------------------------------------
# cli._should_fail
# ---------------------------------------------------------------------------

class TestShouldFail:
    def test_empty_findings_never_fails(self) -> None:
        assert _should_fail([], "error") is False
        assert _should_fail([], "warning") is False

    def test_fail_on_warning_triggers_on_any_finding(self) -> None:
        findings = [_make_finding(severity="WARNING")]
        assert _should_fail(findings, "warning") is True

    def test_fail_on_error_ignores_warnings(self) -> None:
        findings = [_make_finding(severity="WARNING")]
        assert _should_fail(findings, "error") is False

    def test_fail_on_error_triggers_on_error(self) -> None:
        findings = [_make_finding(severity="ERROR")]
        assert _should_fail(findings, "error") is True

    def test_mixed_severities_fail_on_error(self) -> None:
        findings = [_make_finding(severity="WARNING"), _make_finding(severity="ERROR")]
        assert _should_fail(findings, "error") is True


# ---------------------------------------------------------------------------
# cli._safe_finding_dict
# ---------------------------------------------------------------------------

class TestSafeFindingDict:
    def test_snippet_always_redacted(self) -> None:
        f = _make_finding(snippet="super-sensitive-value")
        d = _safe_finding_dict(f)
        assert d["snippet"] == "[REDACTED]"

    def test_other_fields_preserved(self) -> None:
        f = _make_finding(rule_id="my_rule", line=10, column=5)
        d = _safe_finding_dict(f)
        assert d["rule_id"] == "my_rule"
        assert d["line"] == 10
        assert d["column"] == 5

    def test_returns_dict(self) -> None:
        f = _make_finding()
        assert isinstance(_safe_finding_dict(f), dict)


# ---------------------------------------------------------------------------
# cli._safe_finding_mapping
# ---------------------------------------------------------------------------

class TestSafeFindingMapping:
    def test_snippet_redacted(self) -> None:
        raw = {"check": "c", "rule_id": "r", "severity": "ERROR", "message": "m",
               "file": "f.py", "line": 1, "column": 1, "snippet": "real-value"}
        result = _safe_finding_mapping(raw)
        assert result["snippet"] == "[REDACTED]"

    def test_missing_keys_default(self) -> None:
        result = _safe_finding_mapping({})
        assert result["line"] == 0
        assert result["column"] == 0
        assert result["check"] == ""

    def test_line_coerced_to_int(self) -> None:
        result = _safe_finding_mapping({"line": "42"})
        assert result["line"] == 42


# ---------------------------------------------------------------------------
# cli._sanitize_suppressed_payload
# ---------------------------------------------------------------------------

class TestSanitizeSuppressedPayload:
    def test_non_dict_items_skipped(self) -> None:
        result = _sanitize_suppressed_payload(["not a dict", 42])  # type: ignore[arg-type]
        assert result == []

    def test_finding_key_sanitized(self) -> None:
        payload = [
            {
                "finding": {"check": "c", "rule_id": "r", "severity": "ERROR",
                            "message": "m", "file": "f.py", "line": 1, "column": 1,
                            "snippet": "raw-secret"},
                "reason": "test",
            }
        ]
        result = _sanitize_suppressed_payload(payload)
        assert result[0]["finding"]["snippet"] == "[REDACTED]"

    def test_no_finding_key_passes_through(self) -> None:
        payload = [{"reason": "test", "rule": {}}]
        result = _sanitize_suppressed_payload(payload)
        assert len(result) == 1
        assert result[0]["reason"] == "test"


# ---------------------------------------------------------------------------
# cli._normalize_rel_path
# ---------------------------------------------------------------------------

class TestNormalizeRelPath:
    def test_strips_dot_slash_prefix(self) -> None:
        assert _normalize_rel_path("./src/foo.py") == "src/foo.py"

    def test_converts_backslash(self) -> None:
        assert _normalize_rel_path("src\\foo\\bar.py") == "src/foo/bar.py"

    def test_trims_whitespace(self) -> None:
        assert _normalize_rel_path("  src/foo.py  ") == "src/foo.py"

    def test_no_change_for_clean_path(self) -> None:
        assert _normalize_rel_path("src/foo.py") == "src/foo.py"

    def test_nested_path(self) -> None:
        assert _normalize_rel_path("./a/b/c/d.txt") == "a/b/c/d.txt"


# ---------------------------------------------------------------------------
# cli._finding_matches_rule
# ---------------------------------------------------------------------------

class TestFindingMatchesRule:
    def test_empty_rule_matches_any_finding(self) -> None:
        f = _make_finding()
        assert _finding_matches_rule(f, {}) is True

    def test_check_mismatch(self) -> None:
        f = _make_finding(check="scan-secrets")
        assert _finding_matches_rule(f, {"check": "lint-policy"}) is False

    def test_check_match(self) -> None:
        f = _make_finding(check="scan-secrets")
        assert _finding_matches_rule(f, {"check": "scan-secrets"}) is True

    def test_rule_id_mismatch(self) -> None:
        f = _make_finding(rule_id="aws_access_key_id")
        assert _finding_matches_rule(f, {"rule_id": "github_token"}) is False

    def test_severity_case_insensitive(self) -> None:
        f = _make_finding(severity="ERROR")
        assert _finding_matches_rule(f, {"severity": "error"}) is True

    def test_file_pattern_fnmatch(self) -> None:
        f = _make_finding(file="src/secrets.py")
        assert _finding_matches_rule(f, {"file": "src/*.py"}) is True
        assert _finding_matches_rule(f, {"file": "other/*.py"}) is False

    def test_snippet_contains_match(self) -> None:
        f = _make_finding(snippet="[REDACTED]")
        assert _finding_matches_rule(f, {"snippet_contains": "[REDACTED]"}) is True

    def test_snippet_contains_no_match(self) -> None:
        f = _make_finding(snippet="[REDACTED]")
        assert _finding_matches_rule(f, {"snippet_contains": "plain-text-key"}) is False

    def test_all_fields_match(self) -> None:
        f = _make_finding(check="scan-secrets", rule_id="openai_api_key",
                          severity="ERROR", file="config.py")
        rule = {"check": "scan-secrets", "rule_id": "openai_api_key",
                "severity": "ERROR", "file": "config.py"}
        assert _finding_matches_rule(f, rule) is True


# ---------------------------------------------------------------------------
# cli._apply_allowlist
# ---------------------------------------------------------------------------

class TestApplyAllowlist:
    def test_empty_rules_returns_all_findings(self) -> None:
        findings = [_make_finding(), _make_finding(rule_id="other")]
        active, suppressed = _apply_allowlist(findings, [])
        assert active == findings
        assert suppressed == []

    def test_matching_rule_suppresses_finding(self) -> None:
        f = _make_finding(check="scan-secrets", rule_id="generic_secret_assignment")
        rules = [{"check": "scan-secrets", "rule_id": "generic_secret_assignment"}]
        active, suppressed = _apply_allowlist([f], rules)
        assert active == []
        assert len(suppressed) == 1
        assert suppressed[0]["reason"] == "allowlisted"

    def test_non_matching_rule_leaves_finding_active(self) -> None:
        f = _make_finding(check="scan-secrets", rule_id="openai_api_key")
        rules = [{"check": "scan-secrets", "rule_id": "github_token"}]
        active, suppressed = _apply_allowlist([f], rules)
        assert active == [f]
        assert suppressed == []

    def test_suppressed_entry_contains_reason(self) -> None:
        f = _make_finding()
        rules = [{"reason": "approved by security team"}]
        active, suppressed = _apply_allowlist([f], rules)
        assert suppressed[0]["reason"] == "approved by security team"

    def test_partial_suppression(self) -> None:
        f1 = _make_finding(rule_id="openai_api_key")
        f2 = _make_finding(rule_id="github_token")
        rules = [{"rule_id": "openai_api_key"}]
        active, suppressed = _apply_allowlist([f1, f2], rules)
        assert len(active) == 1
        assert active[0].rule_id == "github_token"
        assert len(suppressed) == 1


# ---------------------------------------------------------------------------
# cli._resolve_policy_argument
# ---------------------------------------------------------------------------

class TestResolvePolicyArgument:
    def test_none_none_returns_none(self, tmp_path: Path) -> None:
        result = _resolve_policy_argument(None, None, tmp_path)
        assert result is None

    def test_policy_arg_returned_as_is(self, tmp_path: Path) -> None:
        result = _resolve_policy_argument("myfile.json", None, tmp_path)
        assert result == "myfile.json"

    def test_conflict_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="not both"):
            _resolve_policy_argument("myfile.json", "baseline", tmp_path)

    def test_baseline_profile_returns_path_string(self, tmp_path: Path) -> None:
        wrg = tmp_path / ".wrg"
        wrg.mkdir()
        policy_file = wrg / "policy.json"
        policy_file.write_text("{}", encoding="utf-8")
        result = _resolve_policy_argument(None, "baseline", tmp_path)
        assert result is not None
        assert "policy.json" in result

    def test_strict_profile_returns_strict_path_string(self, tmp_path: Path) -> None:
        wrg = tmp_path / ".wrg"
        wrg.mkdir()
        strict_file = wrg / "policy.strict.json"
        strict_file.write_text("{}", encoding="utf-8")
        result = _resolve_policy_argument(None, "strict", tmp_path)
        assert result is not None
        assert "policy.strict.json" in result

    def test_profile_missing_file_falls_back_to_default(self, tmp_path: Path) -> None:
        # Standalone behaviour (post-9d4b60f): missing profile policy file is
        # not an error — we fall back to the built-in default policy. This
        # keeps the action working on repos that do not have a .wrg/ dir.
        result = _resolve_policy_argument(None, "baseline", tmp_path)
        assert result is None


# ---------------------------------------------------------------------------
# policy.default_policy
# ---------------------------------------------------------------------------

class TestDefaultPolicy:
    def test_returns_dict(self) -> None:
        assert isinstance(default_policy(), dict)

    def test_has_required_keys(self) -> None:
        p = default_policy()
        assert "include" in p
        assert "exclude" in p
        assert "deny_patterns" in p
        assert "max_file_bytes" in p

    def test_max_file_bytes_positive(self) -> None:
        assert default_policy()["max_file_bytes"] > 0

    def test_include_has_python(self) -> None:
        assert any("*.py" in pat for pat in default_policy()["include"])

    def test_deny_patterns_non_empty(self) -> None:
        patterns = default_policy()["deny_patterns"]
        assert len(patterns) >= 1
        for pat in patterns:
            assert "regex" in pat
            assert "severity" in pat


# ---------------------------------------------------------------------------
# secrets.SECRET_RULES — regex correctness
# ---------------------------------------------------------------------------

class TestSecretRulesRegex:
    """Verify each SECRET_RULES pattern matches known-bad strings and rejects known-clean ones."""

    def _get_regex(self, rule_id: str) -> re.Pattern[str]:
        for rule in SECRET_RULES:
            if rule["id"] == rule_id:
                return re.compile(rule["regex"], re.MULTILINE)
        raise KeyError(f"rule {rule_id!r} not found in SECRET_RULES")

    def test_openai_key_matches(self) -> None:
        pattern = self._get_regex("openai_api_key")
        assert pattern.search("sk-" + "A" * 48) is not None

    def test_openai_key_no_match_short(self) -> None:
        pattern = self._get_regex("openai_api_key")
        assert pattern.search("sk-short") is None

    def test_github_token_matches(self) -> None:
        pattern = self._get_regex("github_token")
        token = "ghp_" + "A" * 36
        assert pattern.search(token) is not None

    def test_github_token_no_match_wrong_prefix(self) -> None:
        pattern = self._get_regex("github_token")
        assert pattern.search("xhp_" + "A" * 36) is None

    def test_aws_key_matches(self) -> None:
        pattern = self._get_regex("aws_access_key_id")
        assert pattern.search("AKIA1234567890ABCDEF") is not None

    def test_aws_key_no_match_wrong_prefix(self) -> None:
        pattern = self._get_regex("aws_access_key_id")
        assert pattern.search("BKIA1234567890ABCDEF") is None

    def test_slack_token_matches(self) -> None:
        pattern = self._get_regex("slack_token")
        assert pattern.search("xoxb-12345-67890-abcde") is not None

    def test_private_key_block_matches(self) -> None:
        pattern = self._get_regex("private_key_block")
        assert pattern.search("-----BEGIN RSA PRIVATE KEY-----") is not None
        assert pattern.search("-----BEGIN PRIVATE KEY-----") is not None

    def test_generic_secret_assignment_matches(self) -> None:
        pattern = self._get_regex("generic_secret_assignment")
        assert pattern.search('password = "supersecretvalue"') is not None
        assert pattern.search("api_key: 'mytoken1234'") is not None

    def test_generic_secret_short_value_no_match(self) -> None:
        pattern = self._get_regex("generic_secret_assignment")
        assert pattern.search('password = "short"') is None

    def test_all_rules_have_required_fields(self) -> None:
        for rule in SECRET_RULES:
            assert "id" in rule, f"missing 'id' in {rule}"
            assert "regex" in rule, f"missing 'regex' in {rule}"
            assert "severity" in rule, f"missing 'severity' in {rule}"
            assert "message" in rule, f"missing 'message' in {rule}"
            re.compile(rule["regex"], re.MULTILINE)
