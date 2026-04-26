"""PII name detection — hybrid strategy (NAME-001).

Strategy: hybrid (option **c**).

  (a) Pure curated common-name dictionary: high precision but high false-
      negatives — misses any culture not in the dict (Turkish, Slavic, East
      Asian variants, diacritic-heavy spellings).
  (b) Pure NER-lite capitalized-bigram regex: high recall but high false-
      positive rate — collides with CamelCase identifiers, place names
      ("New York", "United States"), greetings ("Hello World"), and code
      keywords. The user's own FP guard list rules this out as a sole
      strategy.
  (c) Hybrid: a curated common-given-names set anchors high-confidence
      matches; a NER-lite bigram fallback catches names outside the
      dictionary at lower confidence. Both branches share the same FP
      guard stack (CamelCase, place names, code lines, docstring params,
      file paths, URL fragments). This is the strategy in use.

Confidence model (encoded in `rationale`; severity bucket is the
contract-visible signal):

  0.95 — curated first name (any origin) + capitalized last name
  0.70 — NER-lite bigram, both words ≥3 chars, neither in stop-list
  <0.70 — not emitted

Severity from confidence:

  ≥ 0.85 → MEDIUM   (PII default; consistent with EMAIL-001 / IP-001 in
                     the public-range branches)
  0.70 – 0.84 → LOW (NER fallback — emit with caution, easy to flip off
                     in policy)

Test/fixture context (line contains `test_` / `fixture` / sample-shaped
path tokens) downgrades to INFO + `fp_suppression="test_context"` — same
convention as JWT-001 and EMAIL-001 example domains.

Implementation notes:

  * The bigram regex uses Python 3 `\\w` (Unicode-aware by default) and a
    permissive joiner class `[-'’]`. Title-case validation is delegated
    to `_is_name_shape` in Python so we don't have to enumerate every
    Latin-Extended uppercase letter inside the regex character class.
    This is the cleanest stdlib-only way to support Turkish (Çağrı,
    Yıldız), Polish (Łukasz), Romanian (Ștefan), and Hispanic (José,
    García) names without an exploding regex.
  * The code-line guard is intentionally narrow (matches only tight
    Python/JS/TS prefixes — `def name(`, `from x import`, `return`, etc.)
    so English prose lines like "from Mary Johnson re: contract" are
    not silently swallowed by the FP guard.
  * False positives caught by the guard stack are silently dropped,
    never emitted as INFO — INFO is reserved for matched candidates that
    are deliberately downgraded (test context).
"""
from __future__ import annotations

import re

from .pii import Category, PIIFinding, Severity, _mask_generic


__all__ = ["detect_names"]


# ──────────────────────────────────────────────────────────────────────
# Curated first-name set (multi-origin, ~150 entries)
#
# Keep small: this is the high-confidence anchor, not an exhaustive
# census. Rare/ambiguous spellings live in the NER-lite fallback bucket.
# All entries title-cased. Lookup case-sensitivity follows Python title
# case (`str.istitle()` semantics).
# ──────────────────────────────────────────────────────────────────────


_CURATED_FIRST_NAMES: frozenset[str] = frozenset({
    # Anglo / Western European
    "John", "James", "Robert", "Michael", "William", "David", "Richard",
    "Thomas", "Charles", "Christopher", "Daniel", "Matthew", "Anthony",
    "Mark", "Donald", "Steven", "Paul", "Andrew", "Joshua", "Kenneth",
    "Mary", "Patricia", "Jennifer", "Linda", "Elizabeth", "Barbara",
    "Susan", "Jessica", "Sarah", "Karen", "Nancy", "Lisa", "Margaret",
    "Henry", "Edward", "George", "Frank", "Gary", "Larry",
    # Turkish
    "Ahmet", "Mehmet", "Mustafa", "Ali", "Hüseyin", "Hasan", "İbrahim",
    "Emre", "Burak", "Kerem", "Cem", "Murat", "Yusuf", "Yakup",
    "Ayşe", "Fatma", "Hatice", "Zeynep", "Elif", "Selin", "Çağrı",
    "Gülşen", "Şule", "Özlem",
    # Slavic
    "Vladimir", "Ivan", "Dmitri", "Sergei", "Alexei", "Nikolai", "Mikhail",
    "Olga", "Natalia", "Anastasia", "Svetlana", "Tatiana", "Irina",
    "Katarzyna", "Aleksandra",
    # East Asian (romanised)
    "Wei", "Ming", "Hiroshi", "Kenji", "Akira", "Yuki", "Takeshi",
    "Sakura", "Mei", "Jin", "Lin",
    # Hispanic / Latin
    "José", "María", "Carlos", "Sofía", "Diego", "Lucía", "Pablo",
    "Javier", "Andrés", "Camila",
    # Irish / French
    "Liam", "Sean", "Niamh", "Aoife", "Pierre", "Jacques", "Camille",
    "Élise", "Hélène",
})

# Hyphenated / apostrophe given names retained as-is for direct lookup.
_CURATED_FIRST_NAMES_HYPHENATED: frozenset[str] = frozenset({
    "Mary-Jane", "Anne-Marie", "Jean-Pierre", "Jean-Luc", "Marie-Claire",
})


# ──────────────────────────────────────────────────────────────────────
# False-positive stop-lists
# ──────────────────────────────────────────────────────────────────────


# First-words that disqualify a bigram outright (place qualifiers).
_PLACE_PREFIXES: frozenset[str] = frozenset({
    "New", "Los", "Las", "San", "Santa", "Saint", "St", "Fort",
    "Mount", "Mt", "North", "South", "East", "West", "Upper", "Lower",
    "Old", "Great", "Big", "Little", "United", "Republic",
})

# Stand-alone tokens that are place names / countries — disqualify if
# either side of the bigram matches.
_PLACE_TOKENS: frozenset[str] = frozenset({
    "York", "Angeles", "Vegas", "Francisco", "Antonio",
    "States", "Kingdom", "America", "Canada", "Mexico", "Brazil",
    "Europe", "Asia", "Africa", "Australia",
    "Texas", "California", "Oregon", "Florida", "Nevada", "Arizona",
    "Istanbul", "Ankara", "Berlin", "Paris", "London", "Tokyo",
})

# Common bigrams that mimic name shapes (greetings, sign-offs, filler).
_PHRASE_STOPS: frozenset[str] = frozenset({
    "Hello World", "Hello There", "Hello Kitty",
    "Thank You", "Best Regards", "Kind Regards", "Yours Truly",
    "Sincerely Yours", "Dear Sir", "Dear Madam",
    "Good Morning", "Good Afternoon", "Good Evening", "Good Night",
    "Lorem Ipsum", "Foo Bar",
    "Happy Birthday", "Merry Christmas",
})


# Code-line guard — narrow patterns only. English prose lines starting
# with "from", "for", "if" etc. must NOT be swallowed by this guard;
# only actual Python/JS/TS code prefixes should be filtered.
_CODE_LINE_RE = re.compile(
    r"^\s*(?:"
    r"def\s+\w+\s*\("                            # Python def
    r"|class\s+\w+"                               # Python/JS class
    r"|function\s+\w+\s*\("                       # JS function
    r"|from\s+[\w.]+\s+import\b"                  # Python from-import
    r"|import\s+\w+"                              # generic import
    r"|return\b"                                  # return statement
    r"|(?:let|const|var)\s+\w+\s*="               # JS variable
    r"|(?:public|private|protected|static)\s+"   # access modifier
    r"|export\s+(?:default|class|function|const|let|var)\b"
    r"|interface\s+\w+"                           # TS interface
    r"|type\s+\w+\s*="                            # TS type alias
    r"|enum\s+\w+"
    r")"
)

# Docstring/JSDoc parameter markers.
_DOCSTRING_PARAM_RE = re.compile(
    r"(?::param\s|:returns?:|:raises?:|@param\s|@returns?\b|@throws?\b)"
)

# URL substring detector for span-overlap checks.
_URL_RE = re.compile(r"https?://\S+|[\w\-.]+@[\w\-.]+")

# ``sample`` is common prose; only downgrade when it looks like a fixture
# path/token (``sample_``, ``_sample``, ``samples/``).
_IS_TEST_CONTEXT_RE = re.compile(r"(?:^|[/_])samples?(?:[/_]|$)")


# ──────────────────────────────────────────────────────────────────────
# Name-shape regex
# ──────────────────────────────────────────────────────────────────────


# Latin-script uppercase / lowercase letter classes (BMP, common
# European). Listed explicitly so the bigram regex enforces the case
# pattern at match time — relying solely on Python `\\w` plus a post-
# match `_is_name_shape` check is insufficient because greedy `\\w`
# would happily eat lowercase prose ("hello John Smith goodbye" → tries
# "hello John" as the bigram, fails validation, then can't backtrack
# into the real "John Smith"). Listed code points cover Anglo + Latin-1
# Supplement + Turkish + Polish + Czech + Hungarian + Romanian +
# Hispanic + French — the cultures named in the user's TP matrix.
_UPPER_LATIN_CLS = (
    "A-Z"
    "À-ÖØ-Þ"
    "ĀĂĄĆĈĊČĎĐĒĔĖĘĚĜĞĠĢĤĦĨĪĬĮİĴĶĹĻĽĿŁ"
    "ŃŅŇŌŎŐŒŔŖŘŚŜŞŠŢŤŦŨŪŬŮŰŲŴŶŸŹŻŽ"
    "ȘȚ"
)
_LOWER_LATIN_CLS = (
    "a-z"
    "à-ÿ"
    "āăąćĉċčďđēĕėęěĝğġģĥħĩīĭįıĵķĺļľŀł"
    "ńņňōŏőœŕŗřśŝşšţťŧũūŭůűųŵŷźżž"
    "șț"
)

# Single-word name shape:
#   - "John"      : [U][L]+
#   - "Mary-Jane" : [U][L]+ - [U]?[L]+
#   - "O'Brien"   : [U] ' [U][L]+   (single-letter prefix + apostrophe)
_NAME_WORD = (
    rf"(?:"
    rf"[{_UPPER_LATIN_CLS}][{_LOWER_LATIN_CLS}]+"
    rf"(?:[-'’][{_UPPER_LATIN_CLS}]?[{_LOWER_LATIN_CLS}]+)?"
    rf"|[{_UPPER_LATIN_CLS}][-'’][{_UPPER_LATIN_CLS}][{_LOWER_LATIN_CLS}]+"
    rf")"
)

# Bigram: First [Middle.] Last. Letter boundaries are explicit so we
# don't bleed into surrounding identifiers.
_NAME_BIGRAM_RE = re.compile(
    rf"(?<![\w’])"
    rf"({_NAME_WORD})"
    rf"(?:\s+([{_UPPER_LATIN_CLS}])\.)?"
    rf"\s+"
    rf"({_NAME_WORD})"
    rf"(?![\w’])"
)


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _is_name_shape(word: str) -> bool:
    """Title-case check that handles hyphenated/apostrophe segments and
    full Unicode (Turkish, Polish, Romanian, etc.).

    Each segment between joiners (``-``, ``'``, ``’``) must:
    - start with an uppercase letter, AND
    - have only lowercase letters in the rest of the segment.
    """
    if not word or not word[0].isupper():
        return False
    bare = re.sub(r"[-'’]", "", word)
    if not bare or not bare.isalpha():
        return False
    segments = re.split(r"[-'’]", word)
    for seg in segments:
        if not seg:
            return False
        if not seg[0].isupper():
            return False
        for c in seg[1:]:
            if not c.islower():
                return False
    return True


def _span_overlaps_url(line: str, span: tuple[int, int]) -> bool:
    """True if any part of ``span`` overlaps a URL or email substring."""
    for m in _URL_RE.finditer(line):
        if not (span[1] <= m.start() or m.end() <= span[0]):
            return True
    return False


def _looks_like_path_fragment(line: str, span: tuple[int, int]) -> bool:
    """Span sits inside a slash- or extension-shaped path token."""
    pre = line[max(0, span[0] - 2): span[0]]
    post = line[span[1]: span[1] + 6]
    if "/" in pre or "\\" in pre:
        return True
    if re.match(r"\.(?:py|js|ts|jsx|tsx|md|txt|json|yaml|yml|html|css|sh)\b", post):
        return True
    return False


def _looks_like_code_line(line: str) -> bool:
    if _CODE_LINE_RE.search(line):
        return True
    if _DOCSTRING_PARAM_RE.search(line):
        return True
    return False


def _is_test_context(line: str) -> bool:
    low = line.lower()
    return ("test_" in low) or ("fixture" in low) or bool(_IS_TEST_CONTEXT_RE.search(low))


def _is_curated(word: str) -> bool:
    return word in _CURATED_FIRST_NAMES_HYPHENATED or word in _CURATED_FIRST_NAMES


def _confidence(first: str, last: str) -> float | None:
    """Score the bigram. ``None`` ⇒ drop (below floor).

    Returned scores: 0.95 (curated anchor) or 0.70 (NER fallback).
    """
    if _is_curated(first):
        return 0.95
    # NER fallback: both words must look name-shaped (≥3 letters,
    # neither in any stop bucket).
    if len(first) < 3 or len(last) < 3:
        return None
    if first in _PLACE_TOKENS or last in _PLACE_TOKENS:
        return None
    return 0.70


# ──────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────


def detect_names(line: str, line_no: int) -> list[PIIFinding]:
    """Detect First+Last name bigrams on a single line.

    Returns findings sorted by span-start (the regex iteration order
    already produces this). Caller (`pii.detect`) merges with other
    patterns and re-sorts globally.
    """
    if _looks_like_code_line(line):
        return []
    out: list[PIIFinding] = []
    for m in _NAME_BIGRAM_RE.finditer(line):
        first = m.group(1)
        middle = m.group(2)  # may be None
        last = m.group(3)
        span = (m.start(), m.end())

        # Title-case shape check (filters CamelCase, ALLCAPS, mixed).
        if not _is_name_shape(first):
            continue
        if not _is_name_shape(last):
            continue

        # Span-level guards
        if _span_overlaps_url(line, span):
            continue
        if _looks_like_path_fragment(line, span):
            continue

        # Token-level guards
        if first in _PLACE_PREFIXES:
            continue
        bigram = f"{first} {last}"
        if bigram in _PHRASE_STOPS:
            continue
        if last in _PLACE_TOKENS:
            continue

        confidence = _confidence(first, last)
        if confidence is None:
            continue

        if confidence >= 0.85:
            severity = Severity.MEDIUM
            strategy = "curated"
        else:
            severity = Severity.LOW
            strategy = "NER-bigram"

        fp_suppression: str | None = None
        if _is_test_context(line):
            severity = Severity.INFO
            fp_suppression = "test_context"

        rationale_parts = [
            f"First+Last name pattern (confidence={confidence:.2f}, strategy={strategy})."
        ]
        if middle:
            rationale_parts.append(f"Middle initial {middle}.")
        rationale = " ".join(rationale_parts)

        full = m.group(0)
        out.append(
            PIIFinding(
                pattern_id="NAME-001",
                category=Category.PII_NAME,
                severity=severity,
                line_no=line_no,
                span=span,
                redacted_excerpt=_mask_generic(full),
                rationale=rationale,
                fp_suppression=fp_suppression,
            )
        )
    return out
