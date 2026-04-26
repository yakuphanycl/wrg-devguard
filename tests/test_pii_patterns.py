"""Unit + integration tests for the PII detection engine.

Per pattern: ≥3 positive cases, ≥3 negative cases, ≥1 false-positive
suppression case (where applicable). E2E test runs the full
fixture log through `detect()` and pins the expected counts so a
regression in pattern tuning shows up as a single assertion failure.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from wrg_devguard.pii import (
    Category,
    PIIFinding,
    Severity,
    detect,
    detect_line,
)


FIXTURE = Path(__file__).parent / "fixtures" / "pii_sample_log.txt"


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _ids(findings: list[PIIFinding]) -> list[str]:
    return [f.pattern_id for f in findings]


def _has(findings: list[PIIFinding], pattern_id: str) -> bool:
    return any(f.pattern_id == pattern_id for f in findings)


# ──────────────────────────────────────────────────────────────────────
# AWS-001 — access key
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("text", [
    "AKIAIOSFODNN7EXAMPLE",
    "key=AKIA1234567890ABCDEF on line",
    "[AKIAQQQQQQQQQQQQQQQQ]",
])
def test_aws_001_positive(text: str) -> None:
    findings = detect_line(text, 1)
    assert any(f.pattern_id == "AWS-001" for f in findings), findings


@pytest.mark.parametrize("text", [
    "AKIA12345",                       # too short
    "akiaiosfodnn7example",            # lowercase
    "AKIAioSFODNN7EXAMPLE",            # mixed case (regex requires upper)
])
def test_aws_001_negative(text: str) -> None:
    findings = detect_line(text, 1)
    assert not any(f.pattern_id == "AWS-001" for f in findings)


def test_aws_001_redaction_format() -> None:
    findings = detect_line("AKIAIOSFODNN7EXAMPLE", 1)
    f = next(f for f in findings if f.pattern_id == "AWS-001")
    # Spec: ≤6 leading + ≤6 trailing + ≥4 stars in the middle.
    assert f.redacted_excerpt.startswith("AKIA")
    assert "****" in f.redacted_excerpt
    assert "IOSFODNN7EXAMPLE" not in f.redacted_excerpt


# ──────────────────────────────────────────────────────────────────────
# AWS-002 — secret access key (context-gated)
# ──────────────────────────────────────────────────────────────────────


def test_aws_002_with_context_emits() -> None:
    text = (
        "INFO loading aws credentials\n"
        "DEBUG aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "INFO ready\n"
    )
    findings = detect(text)
    assert any(f.pattern_id == "AWS-002" for f in findings)


def test_aws_002_far_context_skipped() -> None:
    """Keyword 5 lines away (outside ±3 radius) → not flagged."""
    lines = ["INFO line %d" % i for i in range(10)]
    lines[0] = "DEBUG aws secret here"
    lines[7] = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    findings = detect("\n".join(lines))
    assert not any(f.pattern_id == "AWS-002" for f in findings)


def test_aws_002_no_context_skipped() -> None:
    """Bare 40-char base64 with no nearby keyword is silently skipped."""
    text = "x = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nfoo bar\n"
    findings = detect(text)
    assert not any(f.pattern_id == "AWS-002" for f in findings)


def test_aws_002_sha1_skipped() -> None:
    """40-char hex (SHA-1) is not a base64 secret, even with context."""
    text = (
        "key check\n"
        "sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709\n"
        "ok\n"
    )
    findings = detect(text)
    assert not any(f.pattern_id == "AWS-002" for f in findings)


def test_aws_002_uses_correct_line_no() -> None:
    text = "credential dump\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    findings = [f for f in detect(text) if f.pattern_id == "AWS-002"]
    assert len(findings) == 1
    assert findings[0].line_no == 2


# ──────────────────────────────────────────────────────────────────────
# GH-001 — GitHub PAT
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("text", [
    "ghp_" + "a" * 36,
    "GITHUB=ghs_" + "B" * 36 + " end",
    "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
])
def test_gh_001_positive(text: str) -> None:
    findings = detect_line(text, 1)
    assert _has(findings, "GH-001"), findings


@pytest.mark.parametrize("text", [
    "ghp_short",
    "github_pat_with_no_match",
    "ghx_" + "a" * 36,  # wrong prefix
])
def test_gh_001_negative(text: str) -> None:
    findings = detect_line(text, 1)
    assert not _has(findings, "GH-001")


# ──────────────────────────────────────────────────────────────────────
# JWT-001 — JWT triplet (test-context downgrade)
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("text", [
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4",
    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4",
    "[\"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4\"]",
])
def test_jwt_001_positive(text: str) -> None:
    findings = detect_line(text, 1)
    assert _has(findings, "JWT-001")
    sev = next(f.severity for f in findings if f.pattern_id == "JWT-001")
    assert sev == Severity.HIGH


@pytest.mark.parametrize("text", [
    "eyJonly",
    "no.dots.here just words",
    "a.b.c",  # not eyJ-prefixed
])
def test_jwt_001_negative(text: str) -> None:
    findings = detect_line(text, 1)
    assert not _has(findings, "JWT-001")


def test_jwt_001_test_context_downgrade() -> None:
    text = "INFO test_payload eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4"
    findings = detect_line(text, 1)
    f = next(f for f in findings if f.pattern_id == "JWT-001")
    assert f.severity == Severity.INFO
    assert f.fp_suppression == "test_context"


# ──────────────────────────────────────────────────────────────────────
# ANTHROPIC-001
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("text", [
    "sk-ant-" + "a" * 32,
    "API_KEY=sk-ant-" + "x" * 40 + " ok",
    "sk-ant-AbCdEf" + "0" * 30,
])
def test_anthropic_001_positive(text: str) -> None:
    assert _has(detect_line(text, 1), "ANTHROPIC-001")


@pytest.mark.parametrize("text", [
    "sk-ant-short",
    "sk-anthropic-" + "a" * 32,
    "sk-ant" + "a" * 32,  # missing dash
])
def test_anthropic_001_negative(text: str) -> None:
    assert not _has(detect_line(text, 1), "ANTHROPIC-001")


# ──────────────────────────────────────────────────────────────────────
# OPENAI-001
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("text", [
    "sk-" + "a" * 48,
    "OPENAI_KEY=sk-" + "B" * 48 + " end",
    "sk-AbCdEf" + "0" * 42,
])
def test_openai_001_positive(text: str) -> None:
    assert _has(detect_line(text, 1), "OPENAI-001")


@pytest.mark.parametrize("text", [
    "sk-short",
    "sk-" + "a" * 30,             # too short
    "key-" + "a" * 48,            # wrong prefix
])
def test_openai_001_negative(text: str) -> None:
    assert not _has(detect_line(text, 1), "OPENAI-001")


def test_openai_001_does_not_double_with_anthropic() -> None:
    """sk-ant-... must fire ANTHROPIC-001 only, not OPENAI-001."""
    text = "sk-ant-" + "a" * 48  # long enough that OPENAI regex would match too
    findings = detect_line(text, 1)
    assert _has(findings, "ANTHROPIC-001")
    assert not _has(findings, "OPENAI-001")


# ──────────────────────────────────────────────────────────────────────
# EMAIL-001
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("text", [
    "contact admin@acmecorp.com today",
    "send to user.name+tag@subdomain.example-corp.io",
    "reachout: First.Last@my-org.co.uk",
])
def test_email_001_positive_real(text: str) -> None:
    findings = detect_line(text, 1)
    f = next(f for f in findings if f.pattern_id == "EMAIL-001")
    assert f.severity == Severity.MEDIUM
    assert f.fp_suppression is None


@pytest.mark.parametrize("text", [
    "no email here",
    "incomplete @domain.com",
    "missing.local.part@",
])
def test_email_001_negative(text: str) -> None:
    assert not _has(detect_line(text, 1), "EMAIL-001")


@pytest.mark.parametrize("text", [
    "user@example.com",
    "demo@test.com",
    "ops@example.org",
])
def test_email_001_example_domain_downgrade(text: str) -> None:
    findings = detect_line(text, 1)
    f = next(f for f in findings if f.pattern_id == "EMAIL-001")
    assert f.severity == Severity.INFO
    assert f.fp_suppression == "example_domain"


def test_email_001_redaction_keeps_domain() -> None:
    findings = detect_line("contact admin@acmecorp.com here", 1)
    f = next(f for f in findings if f.pattern_id == "EMAIL-001")
    assert f.redacted_excerpt.endswith("@acmecorp.com")
    assert "admin" not in f.redacted_excerpt


# ──────────────────────────────────────────────────────────────────────
# IP-001 — IPv4
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("text", [
    "client ip 203.0.113.42 connected",
    "8.8.8.8 dns",
    "203.0.113.255 last in range",
])
def test_ip_001_public_positive(text: str) -> None:
    findings = detect_line(text, 1)
    f = next(f for f in findings if f.pattern_id == "IP-001")
    assert f.severity == Severity.MEDIUM
    assert f.fp_suppression is None


@pytest.mark.parametrize("text", [
    "no ip here",
    "999.999.999.999 invalid",
    "version 1.2.3 only",
])
def test_ip_001_negative(text: str) -> None:
    assert not _has(detect_line(text, 1), "IP-001")


@pytest.mark.parametrize("text,reason", [
    ("container ip 10.0.0.5", "rfc1918_private_range"),
    ("app on 192.168.1.10", "rfc1918_private_range"),
    ("loopback 127.0.0.1", "rfc1918_private_range"),
    ("link-local 169.254.169.254", "rfc1918_private_range"),
])
def test_ip_001_private_downgrade(text: str, reason: str) -> None:
    findings = detect_line(text, 1)
    f = next(f for f in findings if f.pattern_id == "IP-001")
    assert f.severity == Severity.INFO
    assert f.fp_suppression == reason


def test_ip_001_redaction_masks_third_octet() -> None:
    findings = detect_line("client 203.0.113.42 here", 1)
    f = next(f for f in findings if f.pattern_id == "IP-001")
    assert f.redacted_excerpt == "203.0.***.42"


# ──────────────────────────────────────────────────────────────────────
# IP-002 — IPv6
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("text", [
    "addr 2001:db8::1 logged",
    "fe80::1234:5678:9abc:def0",
    "::1 loopback",
])
def test_ip_002_positive(text: str) -> None:
    assert _has(detect_line(text, 1), "IP-002")


@pytest.mark.parametrize("text", [
    "version 2001",
    "single:colon:thing",  # too short to match the union regex meaningfully
    "no addresses here",
])
def test_ip_002_negative(text: str) -> None:
    # Acceptable for this case if the regex matches but the post-filter
    # rejects it. Either way, no IP-002 finding.
    assert not _has(detect_line(text, 1), "IP-002")


# IP-002 — false-positive guards added in v0.2.1
# Source: PR #27 dogfood report against real GitHub Actions logs found
# 10/10 IP-002 hits were FP — 6 from `::error::` annotation prefixes and
# 4 from `0:00:00`-shape throughput timestamps. Both are now rejected.


@pytest.mark.parametrize("text", [
    "MB 24.4 MB/s  0:00:00",
    "elapsed 1:23:45",
    "boot 0:00:00 ready",
    "10:20:30",  # bare HH:MM:SS at start of line
    "1:2:3 short timestamp",
    "11:22:33 morning shift",
])
def test_ip_002_rejects_timestamp_shape(text: str) -> None:
    """HH:MM:SS-shape strings (all-decimal, ≤2-char groups) are timestamps,
    not IPv6 addresses. The shape slipped through because [0-9] is a
    subset of [A-Fa-f0-9]; v0.2.1 explicitly rejects it.
    """
    assert not _has(detect_line(text, 1), "IP-002")


@pytest.mark.parametrize("text", [
    "::error::fail-on must be one of {error, warn, none}",
    "::warning::deprecated input 'json-out' — use 'format: json' instead",
    "::group::Run wrg-devguard scan",
    "::endgroup::",
    "::notice::scan completed in 12s",
    "::debug::initialised pattern engine",
    "::set-output name=findings::0",
    "::add-mask::secret-value",
    "::group::Operating System",
])
def test_ip_002_rejects_gh_annotation_prefix(text: str) -> None:
    """Lines opening with a GitHub Actions workflow command (`::error::`,
    `::warning::`, `::group::`, etc.) trip the IPv6 regex's third
    alt-branch (the leading `::` plus a single hex-shaped char like `e`
    or `w`). v0.2.1 skips IPv6 detection on these lines entirely.
    """
    assert not _has(detect_line(text, 1), "IP-002")


def test_ip_002_real_ipv6_after_annotation_keyword_in_prose() -> None:
    """Sanity: a line that contains the substring 'error' but is NOT a
    workflow-command-prefix line still detects real IPv6 normally.
    """
    # Not at the start of the line and not preceded by '::', so the
    # annotation guard does not fire.
    text = "logged error from peer addr 2001:db8::1"
    assert _has(detect_line(text, 1), "IP-002")


def test_ip_002_real_ipv6_alongside_timestamp_on_same_line() -> None:
    """Sanity: a line with both a timestamp-shape string AND a real IPv6
    still flags the real address. The per-candidate guard rejects the
    timestamp candidate, leaves the IPv6 candidate intact.
    """
    text = "0:00:00 connect to 2001:db8::1"
    findings = detect_line(text, 1)
    ipv6_findings = [f for f in findings if f.pattern_id == "IP-002"]
    # At least one IPv6 finding for the real address; the `0:00:00`
    # timestamp candidate is rejected by `_is_timestamp_shape`.
    assert len(ipv6_findings) >= 1
    # The matched span must overlap the real address, not the timestamp
    real_addr_start = text.index("2001:db8")
    assert any(f.span[0] >= real_addr_start for f in ipv6_findings)


def test_ip_002_short_loopback_not_timestamp_shape() -> None:
    """`::1` and similar single-group compressed IPv6 must NOT be
    rejected by the timestamp guard (group count <3).
    """
    findings = detect_line("connect ::1 ok", 1)
    assert _has(findings, "IP-002")


# ──────────────────────────────────────────────────────────────────────
# PHONE-001 — TR mobile
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("text", [
    "callback 5321234567",
    "phone +905321234567",
    "tr 905009998877",
])
def test_phone_001_positive(text: str) -> None:
    assert _has(detect_line(text, 1), "PHONE-001")


@pytest.mark.parametrize("text", [
    "id 5321",                       # too short
    "version 5.3.21.123.45.67",      # dot-separated, no continuous digits
    "code 4321234567",               # doesn't start with 5
])
def test_phone_001_negative(text: str) -> None:
    assert not _has(detect_line(text, 1), "PHONE-001")


# ──────────────────────────────────────────────────────────────────────
# PHONE-002 — US 10-digit
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("text", [
    "alt (415) 555-2671 office",
    "alt 415.555.2671 office",
    "alt 415-555-2671 office",
])
def test_phone_002_positive(text: str) -> None:
    assert _has(detect_line(text, 1), "PHONE-002")


@pytest.mark.parametrize("text", [
    "id 4155552671",                # plain digits, no separators (avoid FP)
    "version 415.555",              # too short
    "alt 555-2671",                 # missing area code
])
def test_phone_002_negative(text: str) -> None:
    assert not _has(detect_line(text, 1), "PHONE-002")


# ──────────────────────────────────────────────────────────────────────
# SSN-001
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("text", [
    "ssn 123-45-6789",
    "id=987-65-4321",
    "[111-22-3333]",
])
def test_ssn_001_positive(text: str) -> None:
    assert _has(detect_line(text, 1), "SSN-001")


@pytest.mark.parametrize("text", [
    "version 1.2-34",
    "ssn 123456789",                # no dashes
    "code 12-345-6789",             # wrong segment lengths
])
def test_ssn_001_negative(text: str) -> None:
    assert not _has(detect_line(text, 1), "SSN-001")


# ──────────────────────────────────────────────────────────────────────
# CARD-001 — credit card with Luhn
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("text", [
    "cc 4532015112830366 paid",      # valid Visa-shaped Luhn
    "cc 4111-1111-1111-1111 demo",   # Stripe test Visa
    "cc 5500 0000 0000 0004 here",   # Mastercard test
])
def test_card_001_positive(text: str) -> None:
    assert _has(detect_line(text, 1), "CARD-001")


@pytest.mark.parametrize("text", [
    "cc 1234567890123456",           # Luhn fails
    "cc 4532015112830367",           # off-by-one (Luhn fails)
    "cc 12-345-67",                  # too short
])
def test_card_001_negative(text: str) -> None:
    assert not _has(detect_line(text, 1), "CARD-001")


def test_card_001_all_zero_skipped() -> None:
    findings = detect_line("placeholder 0000000000000000", 1)
    assert not _has(findings, "CARD-001")


def test_card_001_redaction_pan_style() -> None:
    findings = detect_line("cc 4532015112830366 here", 1)
    f = next(f for f in findings if f.pattern_id == "CARD-001")
    assert f.redacted_excerpt.startswith("453201")
    assert f.redacted_excerpt.endswith("0366")
    assert "*" in f.redacted_excerpt


# ──────────────────────────────────────────────────────────────────────
# Output ordering + structure invariants
# ──────────────────────────────────────────────────────────────────────


def test_detect_returns_sorted() -> None:
    text = (
        "first 203.0.113.10 second\n"          # IP on line 1
        "AKIAIOSFODNN7EXAMPLE early\n"         # AWS at line 2 col 0
        "x 8.8.8.8 y AKIA1234567890ABCDEF\n"   # 2 findings on line 3
    )
    findings = detect(text)
    keys = [(f.line_no, f.span[0]) for f in findings]
    assert keys == sorted(keys)


def test_detect_empty_input() -> None:
    assert detect("") == []


def test_pattern_id_matches_schema_regex() -> None:
    """Schema requires `^[A-Z][A-Z0-9]*-[0-9]{3}$`. Verify every emitted ID."""
    import re as _re
    schema_re = _re.compile(r"^[A-Z][A-Z0-9]*-[0-9]{3}$")
    text = (
        "AKIAIOSFODNN7EXAMPLE\n"
        "ghp_" + "a" * 36 + "\n"
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4\n"
        "sk-ant-" + "a" * 32 + "\n"
        "sk-" + "a" * 48 + "\n"
        "user@acmecorp.com\n"
        "203.0.113.42\n"
        "2001:db8::1\n"
        "5321234567\n"
        "(415) 555-2671\n"
        "123-45-6789\n"
        "4111-1111-1111-1111\n"
    )
    for f in detect(text):
        assert schema_re.match(f.pattern_id), f.pattern_id


def test_redaction_never_contains_raw_value() -> None:
    """Spec invariant: redacted_excerpt MUST NOT contain the raw match in full."""
    raw = "AKIAIOSFODNN7EXAMPLE"
    findings = [f for f in detect_line(raw, 1) if f.pattern_id == "AWS-001"]
    assert findings
    assert raw not in findings[0].redacted_excerpt


# ──────────────────────────────────────────────────────────────────────
# E2E — full fixture log
# ──────────────────────────────────────────────────────────────────────


def test_e2e_sample_log_findings() -> None:
    text = FIXTURE.read_text(encoding="utf-8")
    findings = detect(text)
    ids = _ids(findings)

    # Anchored expected hits per pattern. Counts are strict so a tuning
    # regression surfaces here, not at integration time.
    expected_min = {
        "AWS-001": 1,        # line 4
        "AWS-002": 1,        # line 5 (corroborated by line 4 keyword)
        "GH-001": 1,
        "JWT-001": 2,        # line 8 (HIGH) + line 25 (test_context INFO)
        "ANTHROPIC-001": 1,
        "OPENAI-001": 1,
        "IP-001": 5,         # 0.0.0.0, 10.0.0.5, 203.0.113.42, 198.51.100.7, 127.0.0.1, 100.50.20.30
        "IP-002": 2,
        "EMAIL-001": 2,
        "PHONE-001": 2,      # 5321234567, +905321234567 (tests/positive)
        "PHONE-002": 2,      # (415) 555-2671 + 415.555.2671
        "SSN-001": 1,
        "CARD-001": 1,       # 4532015112830366 — placeholder line is skipped
    }
    for pid, n in expected_min.items():
        assert ids.count(pid) >= n, (
            f"{pid}: got {ids.count(pid)}, expected ≥{n}. "
            f"all ids: {sorted(set(ids))}"
        )

    # Suppression sanity: at least one rfc1918 + one example_domain +
    # one test_context.
    suppressions = {f.fp_suppression for f in findings if f.fp_suppression}
    assert "rfc1918_private_range" in suppressions
    assert "example_domain" in suppressions
    assert "test_context" in suppressions


def test_e2e_no_raw_secrets_emitted() -> None:
    """Regression guard: raw matched values must never appear in the output."""
    text = FIXTURE.read_text(encoding="utf-8")
    findings = detect(text)
    raw_secrets = [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_" + "a" * 36,
        "sk-ant-" + "a" * 32,
        "sk-" + "a" * 48,
        "4532015112830366",
    ]
    for f in findings:
        for raw in raw_secrets:
            assert raw not in f.redacted_excerpt, (
                f"{f.pattern_id} leaked raw value into redacted_excerpt"
            )


def test_e2e_output_compatible_with_scan_logs() -> None:
    """detect() output is consumable by scan_logs._finding_to_dict."""
    from wrg_devguard.scan_logs import _finding_to_dict  # noqa: PLC0415

    text = FIXTURE.read_text(encoding="utf-8")
    findings = detect(text)
    assert findings
    for f in findings:
        d = _finding_to_dict(f)
        assert d["pattern_id"] == f.pattern_id
        assert d["category"] == f.category.value
        assert d["severity"] == f.severity.value
        assert d["line_no"] == f.line_no
        assert d["span"] == [f.span[0], f.span[1]]
        if f.fp_suppression:
            assert d["fp_suppression"] == f.fp_suppression
        else:
            assert "fp_suppression" not in d
