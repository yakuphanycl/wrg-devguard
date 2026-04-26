"""PII / secret detection engine for `wrg-devguard scan-logs`.

Stdlib-only (regex + string operations). No ML, no external phone/email
libraries — the patterns below are tuned to the kind of content that
actually appears in build/runtime logs and CI artifacts. The output
shape is the structural protocol that `scan_logs._PIIFindingProto`
expects, and `scan_logs._finding_to_dict` serialises into the frozen
`schemas/log_scan_result.schema.json` contract.

Pattern IDs all follow the schema's `^[A-Z][A-Z0-9]*-[0-9]{3}$` format.
Regional variants are encoded in the rationale text, not the ID, so a
future schema-level pattern catalogue can stay machine-readable.

False-positive discipline (carries the lessons from the monorepo-audit
dogfood: 86% raw → 0% real after tuning):

  * AWS secret keys without nearby "secret"/"key" context are skipped
    silently — that 40-char base64 shape collides with too many hashes
    and IDs to flag without a corroborating signal.
  * RFC-1918 / loopback / link-local IPv4 ranges are downgraded to
    `info` with `fp_suppression="rfc1918_private_range"` — they are
    addresses but rarely sensitive in logs.
  * Emails on example.com / test.com / example.org / .test / .invalid
    / localhost are downgraded to `info` with
    `fp_suppression="example_domain"`.
  * JWT-shaped strings on a line that already looks like a test
    (substring "test_") are downgraded to `info` with
    `fp_suppression="test_context"`.
  * Card numbers are run through Luhn before emitting; numbers that
    fail Luhn or are all-zero are skipped (placeholder noise).

The detector is intentionally line-oriented so byte offsets in the
schema's `span` field stay simple (per-line, not whole-text) and so
context-window checks like AWS-002's ±3-line scan are cheap.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


__all__ = [
    "Severity",
    "Category",
    "PIIFinding",
    "detect",
    "detect_line",
]


# ──────────────────────────────────────────────────────────────────────
# Public types
# ──────────────────────────────────────────────────────────────────────


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    SECRET = "secret"
    PII_EMAIL = "pii_email"
    PII_PHONE = "pii_phone"
    PII_SSN = "pii_ssn"
    PII_IP = "pii_ip"
    PII_CARD = "pii_card"


@dataclass(frozen=True)
class PIIFinding:
    pattern_id: str
    category: Category
    severity: Severity
    line_no: int
    span: tuple[int, int]
    redacted_excerpt: str
    rationale: str
    fp_suppression: str | None = None


# ──────────────────────────────────────────────────────────────────────
# Compiled patterns
# ──────────────────────────────────────────────────────────────────────


_AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_AWS_SECRET_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40}(?![A-Za-z0-9+/])")
_GITHUB_PAT_RE = re.compile(r"\bgh[ps]_[A-Za-z0-9]{36}\b")
_JWT_RE = re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+\b")
_ANTHROPIC_RE = re.compile(r"\bsk-ant-[a-zA-Z0-9-]{32,}\b")
_OPENAI_RE = re.compile(r"\bsk-[a-zA-Z0-9]{48}\b")

# Simplified RFC-5322. Avoid the full dragon — it's well known to be
# essentially unmatchable with regex; this catches log-typical shapes.
_EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
# IPv6: at least one `::` or two `:` to avoid matching MAC-like strings.
_IPV6_RE = re.compile(
    r"(?<![:.\w])"
    r"(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}"
    r"|(?:[A-Fa-f0-9]{1,4}:){1,7}:"
    r"|::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}"
)
# TR mobile: optional `+` and 90 prefix, then 5 + 9 digits.
_PHONE_TR_RE = re.compile(r"(?<!\d)\+?(?:90)?5\d{9}(?!\d)")
# US 10-digit (with optional separators). Conservative: require area
# code separator when no leading paren so plain 10-digit IDs don't match.
_PHONE_US_RE = re.compile(
    r"(?<!\d)"
    r"(?:\(\d{3}\)\s?\d{3}[-.\s]\d{4}"
    r"|\d{3}[-.\s]\d{3}[-.\s]\d{4})"
    r"(?!\d)"
)
_SSN_US_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")


# Keywords that legitimise an AWS-002 candidate (±3-line context).
# Letter-boundary (not \b) so identifiers like `aws_secret_access_key`
# corroborate while a substring like "EXAMPLEKEY" inside the candidate
# itself does not (handled in `_line_has_aws_context` by stripping the
# base64-shaped run before searching).
_AWS_CONTEXT_RE = re.compile(
    r"(?:^|[^A-Za-z])(?:secret|key|credential|passwd|password)(?:[^A-Za-z]|$)",
    re.IGNORECASE,
)

# Domains that demote email severity.
_EXAMPLE_EMAIL_DOMAINS = {
    "example.com", "example.org", "example.net",
    "test.com", "test.org",
    "localhost",
}
_EXAMPLE_EMAIL_TLDS = {".test", ".invalid", ".example", ".localhost"}


# ──────────────────────────────────────────────────────────────────────
# Redaction helpers
# ──────────────────────────────────────────────────────────────────────


def _mask_generic(s: str, lead: int = 4, trail: int = 4) -> str:
    """Middle-mask: keep ≤6 lead + ≤6 trail, ≥4 stars between.

    Adjusts lead/trail downward for short strings so the star middle is
    always present and never wider than necessary.
    """
    n = len(s)
    lead = min(lead, 6)
    trail = min(trail, 6)
    if n <= lead + trail + 4:
        # Not enough room for the spec's ≥4-star middle without dipping
        # into the visible halves; shrink them proportionally.
        budget = max(0, n - 4)
        lead = budget // 2
        trail = budget - lead
    middle_len = max(4, n - lead - trail)
    head = s[:lead]
    tail = s[n - trail:] if trail else ""
    return head + ("*" * middle_len) + tail


def _mask_email(s: str) -> str:
    if "@" not in s:
        return _mask_generic(s)
    local, _, domain = s.partition("@")
    if not local:
        return "@" + domain
    keep = 1 if len(local) > 1 else 0
    masked_local = local[:keep] + ("*" * max(4, len(local) - keep))
    return f"{masked_local}@{domain}"


def _mask_ipv4(s: str) -> str:
    parts = s.split(".")
    if len(parts) != 4:
        return _mask_generic(s)
    return f"{parts[0]}.{parts[1]}.***.{parts[3]}"


def _mask_ipv6(s: str) -> str:
    # IPv6 strings are wide; keep first group and last group, mask the rest.
    if "::" in s:
        head, _, tail = s.partition("::")
        head_first = head.split(":", 1)[0] if head else ""
        tail_last = tail.rsplit(":", 1)[-1] if tail else ""
        return f"{head_first}::****:{tail_last}".replace("::****:", "::****:" if tail_last else "::****")
    parts = s.split(":")
    if len(parts) >= 3:
        return f"{parts[0]}:****:{parts[-1]}"
    return _mask_generic(s)


def _mask_card(s: str) -> str:
    digits = re.sub(r"\D", "", s)
    n = len(digits)
    if n < 8:
        return _mask_generic(s)
    head = digits[:6]
    tail = digits[-4:]
    middle_len = max(4, n - 10)
    return head + ("*" * middle_len) + tail


def _mask_phone(s: str) -> str:
    digits = re.sub(r"\D", "", s)
    n = len(digits)
    if n < 7:
        return _mask_generic(s)
    return digits[:3] + ("*" * max(4, n - 6)) + digits[-3:]


# ──────────────────────────────────────────────────────────────────────
# Validation helpers
# ──────────────────────────────────────────────────────────────────────


def _luhn(digits: str) -> bool:
    """Standard Luhn check digit validation."""
    total = 0
    for i, c in enumerate(reversed(digits)):
        if not c.isdigit():
            return False
        d = int(c)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _is_rfc1918_or_reserved(ip: str) -> bool:
    """RFC-1918 + loopback + link-local + multicast + broadcast.

    Treated as 'private/non-routable, downgrade severity'. Stdlib
    `ipaddress` would be cleaner — but the existing wrg-devguard core
    is stdlib-only and we don't want to import a (free, stdlib)
    dependency just for this one check. The hand rolled tuple is small
    and intent-aligned.
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b, _c, _d = (int(p) for p in parts)
    except ValueError:
        return False
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:  # loopback
        return True
    if a == 169 and b == 254:  # link-local
        return True
    if 224 <= a <= 239:  # multicast
        return True
    if a == 0 or a >= 240:  # reserved
        return True
    return False


def _email_is_example(email: str) -> bool:
    domain = email.partition("@")[2].lower()
    if domain in _EXAMPLE_EMAIL_DOMAINS:
        return True
    return any(domain.endswith(tld) for tld in _EXAMPLE_EMAIL_TLDS)


def _line_has_aws_context(lines: list[str], idx: int, radius: int = 3) -> bool:
    lo = max(0, idx - radius)
    hi = min(len(lines), idx + radius + 1)
    for i in range(lo, hi):
        # Strip the longest base64-shaped run on the candidate line so a
        # match like "...EXAMPLEKEY" can't self-corroborate.
        haystack = lines[i]
        if i == idx:
            haystack = re.sub(r"[A-Za-z0-9+/]{30,}", "", haystack)
        if _AWS_CONTEXT_RE.search(haystack):
            return True
    return False


# ──────────────────────────────────────────────────────────────────────
# Per-pattern detectors (line-scoped)
# ──────────────────────────────────────────────────────────────────────


def _emit_simple(
    line: str,
    line_no: int,
    pattern_id: str,
    category: Category,
    severity: Severity,
    rationale: str,
    masker,
    *,
    pattern: re.Pattern,
) -> list[PIIFinding]:
    out: list[PIIFinding] = []
    for m in pattern.finditer(line):
        out.append(PIIFinding(
            pattern_id=pattern_id,
            category=category,
            severity=severity,
            line_no=line_no,
            span=(m.start(), m.end()),
            redacted_excerpt=masker(m.group(0)),
            rationale=rationale,
        ))
    return out


def _detect_aws_001(line: str, line_no: int) -> list[PIIFinding]:
    return _emit_simple(
        line, line_no,
        pattern_id="AWS-001",
        category=Category.SECRET,
        severity=Severity.HIGH,
        rationale="AWS access key ID format match (AKIA prefix + 16 uppercase alphanumerics).",
        masker=_mask_generic,
        pattern=_AWS_ACCESS_KEY_RE,
    )


def _detect_aws_002(
    line: str, line_no_zero: int, all_lines: list[str]
) -> list[PIIFinding]:
    """40-char base64 candidate with ±3-line keyword corroboration.

    Skipped silently when no nearby "secret"/"key"/etc. is present —
    the shape is too noisy to flag by itself in a log.
    """
    if not _line_has_aws_context(all_lines, line_no_zero):
        return []
    out: list[PIIFinding] = []
    for m in _AWS_SECRET_RE.finditer(line):
        candidate = m.group(0)
        # Filter out obvious hex hashes (40 hex chars is SHA-1).
        if re.fullmatch(r"[0-9a-f]{40}", candidate):
            continue
        # AWS secret keys are mixed-case base64 + at least one digit.
        if not (any(c.isupper() for c in candidate)
                and any(c.islower() for c in candidate)
                and any(c.isdigit() for c in candidate)):
            continue
        out.append(PIIFinding(
            pattern_id="AWS-002",
            category=Category.SECRET,
            severity=Severity.HIGH,
            line_no=line_no_zero + 1,
            span=(m.start(), m.end()),
            redacted_excerpt=_mask_generic(candidate),
            rationale="AWS secret access key shape (40-char base64) with credential keyword in ±3 lines.",
        ))
    return out


def _detect_gh_001(line: str, line_no: int) -> list[PIIFinding]:
    return _emit_simple(
        line, line_no,
        pattern_id="GH-001",
        category=Category.SECRET,
        severity=Severity.HIGH,
        rationale="GitHub personal access token (ghp_/ghs_ prefix + 36 alphanumerics).",
        masker=_mask_generic,
        pattern=_GITHUB_PAT_RE,
    )


def _detect_jwt_001(line: str, line_no: int) -> list[PIIFinding]:
    out: list[PIIFinding] = []
    test_context = "test_" in line.lower()
    for m in _JWT_RE.finditer(line):
        if test_context:
            out.append(PIIFinding(
                pattern_id="JWT-001",
                category=Category.SECRET,
                severity=Severity.INFO,
                line_no=line_no,
                span=(m.start(), m.end()),
                redacted_excerpt=_mask_generic(m.group(0)),
                rationale="JWT-shaped triplet (header.payload.signature).",
                fp_suppression="test_context",
            ))
        else:
            out.append(PIIFinding(
                pattern_id="JWT-001",
                category=Category.SECRET,
                severity=Severity.HIGH,
                line_no=line_no,
                span=(m.start(), m.end()),
                redacted_excerpt=_mask_generic(m.group(0)),
                rationale="JWT-shaped triplet (header.payload.signature).",
            ))
    return out


def _detect_anthropic_001(line: str, line_no: int) -> list[PIIFinding]:
    return _emit_simple(
        line, line_no,
        pattern_id="ANTHROPIC-001",
        category=Category.SECRET,
        severity=Severity.HIGH,
        rationale="Anthropic API key format (sk-ant- prefix + ≥32 alphanumerics).",
        masker=_mask_generic,
        pattern=_ANTHROPIC_RE,
    )


def _detect_openai_001(line: str, line_no: int) -> list[PIIFinding]:
    out: list[PIIFinding] = []
    for m in _OPENAI_RE.finditer(line):
        candidate = m.group(0)
        # Avoid double-firing when the line already contains an
        # Anthropic-shaped match that starts with the same `sk-` prefix.
        if candidate.startswith("sk-ant-"):
            continue
        out.append(PIIFinding(
            pattern_id="OPENAI-001",
            category=Category.SECRET,
            severity=Severity.HIGH,
            line_no=line_no,
            span=(m.start(), m.end()),
            redacted_excerpt=_mask_generic(candidate),
            rationale="OpenAI API key format (sk- prefix + 48 alphanumerics).",
        ))
    return out


def _detect_email_001(line: str, line_no: int) -> list[PIIFinding]:
    out: list[PIIFinding] = []
    for m in _EMAIL_RE.finditer(line):
        candidate = m.group(0)
        if _email_is_example(candidate):
            out.append(PIIFinding(
                pattern_id="EMAIL-001",
                category=Category.PII_EMAIL,
                severity=Severity.INFO,
                line_no=line_no,
                span=(m.start(), m.end()),
                redacted_excerpt=_mask_email(candidate),
                rationale="Email address (RFC-5322 simplified).",
                fp_suppression="example_domain",
            ))
        else:
            out.append(PIIFinding(
                pattern_id="EMAIL-001",
                category=Category.PII_EMAIL,
                severity=Severity.MEDIUM,
                line_no=line_no,
                span=(m.start(), m.end()),
                redacted_excerpt=_mask_email(candidate),
                rationale="Email address (RFC-5322 simplified).",
            ))
    return out


def _detect_ip_001(line: str, line_no: int) -> list[PIIFinding]:
    out: list[PIIFinding] = []
    for m in _IPV4_RE.finditer(line):
        ip = m.group(0)
        if _is_rfc1918_or_reserved(ip):
            out.append(PIIFinding(
                pattern_id="IP-001",
                category=Category.PII_IP,
                severity=Severity.INFO,
                line_no=line_no,
                span=(m.start(), m.end()),
                redacted_excerpt=_mask_ipv4(ip),
                rationale="IPv4 address.",
                fp_suppression="rfc1918_private_range",
            ))
        else:
            out.append(PIIFinding(
                pattern_id="IP-001",
                category=Category.PII_IP,
                severity=Severity.MEDIUM,
                line_no=line_no,
                span=(m.start(), m.end()),
                redacted_excerpt=_mask_ipv4(ip),
                rationale="IPv4 address (public range).",
            ))
    return out


def _detect_ip_002(line: str, line_no: int) -> list[PIIFinding]:
    out: list[PIIFinding] = []
    seen_spans: list[tuple[int, int]] = []
    for m in _IPV6_RE.finditer(line):
        candidate = m.group(0)
        # Filter ambiguous matches: must contain at least one ":" group
        # and not look like a timestamp / version string.
        if ":" not in candidate:
            continue
        if candidate.count(":") < 2 and "::" not in candidate:
            continue
        # De-duplicate overlapping alt-branch matches (the union regex
        # can produce multiple matches at the same span).
        span = (m.start(), m.end())
        if any(s[0] <= span[0] and span[1] <= s[1] for s in seen_spans):
            continue
        seen_spans.append(span)
        out.append(PIIFinding(
            pattern_id="IP-002",
            category=Category.PII_IP,
            severity=Severity.MEDIUM,
            line_no=line_no,
            span=span,
            redacted_excerpt=_mask_ipv6(candidate),
            rationale="IPv6 address.",
        ))
    return out


def _detect_phone_001(line: str, line_no: int) -> list[PIIFinding]:
    out: list[PIIFinding] = []
    for m in _PHONE_TR_RE.finditer(line):
        out.append(PIIFinding(
            pattern_id="PHONE-001",
            category=Category.PII_PHONE,
            severity=Severity.MEDIUM,
            line_no=line_no,
            span=(m.start(), m.end()),
            redacted_excerpt=_mask_phone(m.group(0)),
            rationale="Turkish mobile number (5xx prefix, optional +90 country code).",
        ))
    return out


def _detect_phone_002(line: str, line_no: int, tr_spans: list[tuple[int, int]]) -> list[PIIFinding]:
    out: list[PIIFinding] = []
    for m in _PHONE_US_RE.finditer(line):
        # Skip if this region was already claimed by a TR match — a TR
        # mobile that happens to fit the US separator pattern shouldn't
        # double-count.
        span = (m.start(), m.end())
        if any(s[0] <= span[0] < s[1] for s in tr_spans):
            continue
        out.append(PIIFinding(
            pattern_id="PHONE-002",
            category=Category.PII_PHONE,
            severity=Severity.MEDIUM,
            line_no=line_no,
            span=span,
            redacted_excerpt=_mask_phone(m.group(0)),
            rationale="US-style phone number (10 digits with separators or area-code parens).",
        ))
    return out


def _detect_ssn_001(line: str, line_no: int) -> list[PIIFinding]:
    return _emit_simple(
        line, line_no,
        pattern_id="SSN-001",
        category=Category.PII_SSN,
        severity=Severity.HIGH,
        rationale="US Social Security Number (NNN-NN-NNNN).",
        masker=_mask_generic,
        pattern=_SSN_US_RE,
    )


def _detect_card_001(
    line: str, line_no: int, ssn_spans: list[tuple[int, int]]
) -> list[PIIFinding]:
    out: list[PIIFinding] = []
    for m in _CARD_RE.finditer(line):
        span = (m.start(), m.end())
        # Don't double-fire on SSN territory.
        if any(s[0] <= span[0] < s[1] for s in ssn_spans):
            continue
        candidate = m.group(0)
        digits = re.sub(r"\D", "", candidate)
        if len(digits) < 13 or len(digits) > 19:
            continue
        if all(d == "0" for d in digits):
            continue
        if not _luhn(digits):
            continue
        out.append(PIIFinding(
            pattern_id="CARD-001",
            category=Category.PII_CARD,
            severity=Severity.HIGH,
            line_no=line_no,
            span=span,
            redacted_excerpt=_mask_card(candidate),
            rationale="Credit-card-shaped digit run with a valid Luhn checksum.",
        ))
    return out


# ──────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────


def detect_line(line: str, line_no: int) -> list[PIIFinding]:
    """Single-line scan. Caller decides line numbering.

    Does not perform AWS-002 context-window detection (that needs the
    surrounding lines). Use `detect()` for full-fidelity scanning.
    """
    findings: list[PIIFinding] = []
    findings.extend(_detect_aws_001(line, line_no))
    findings.extend(_detect_gh_001(line, line_no))
    findings.extend(_detect_jwt_001(line, line_no))
    findings.extend(_detect_anthropic_001(line, line_no))
    findings.extend(_detect_openai_001(line, line_no))
    findings.extend(_detect_email_001(line, line_no))
    findings.extend(_detect_ip_001(line, line_no))
    findings.extend(_detect_ip_002(line, line_no))
    tr_results = _detect_phone_001(line, line_no)
    findings.extend(tr_results)
    tr_spans = [f.span for f in tr_results]
    findings.extend(_detect_phone_002(line, line_no, tr_spans))
    ssn_results = _detect_ssn_001(line, line_no)
    findings.extend(ssn_results)
    ssn_spans = [f.span for f in ssn_results]
    findings.extend(_detect_card_001(line, line_no, ssn_spans))
    findings.sort(key=lambda f: (f.line_no, f.span[0]))
    return findings


def detect(text: str) -> list[PIIFinding]:
    """Scan multi-line text. Return findings sorted by (line_no, span[0]).

    Output is the structural protocol that
    `scan_logs._PIIFindingProto` consumes — `scan_logs._finding_to_dict`
    handles Enum→string serialisation and span tuple→list conversion at
    the schema boundary.
    """
    if not text:
        return []
    lines = text.splitlines()
    findings: list[PIIFinding] = []
    for idx, line in enumerate(lines):
        line_no = idx + 1
        # Per-line patterns
        per_line = detect_line(line, line_no)
        findings.extend(per_line)
        # AWS-002 needs the line-window context, so it lives outside
        # `detect_line`.
        findings.extend(_detect_aws_002(line, idx, lines))
    findings.sort(key=lambda f: (f.line_no, f.span[0]))
    return findings
