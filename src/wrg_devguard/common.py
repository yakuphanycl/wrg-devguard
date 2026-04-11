from __future__ import annotations

import json
import fnmatch
import re
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable


@dataclass
class Finding:
    check: str
    rule_id: str
    severity: str
    message: str
    file: str
    line: int
    column: int
    snippet: str

    def to_dict(self) -> dict:
        return asdict(self)


def to_posix(path: Path) -> str:
    return path.as_posix()


def relative_posix(path: Path, root: Path) -> str:
    return to_posix(path.relative_to(root))


def match_any(path: str, patterns: Iterable[str]) -> bool:
    pp = PurePosixPath(path)
    for pattern in patterns:
        if fnmatch.fnmatch(path, pattern):
            return True
        if pp.match(pattern):
            return True
        if pattern.startswith("**/"):
            if pp.match(pattern[3:]):
                return True
    return False


def read_text_safely(path: Path, max_bytes: int = 1_048_576) -> str:
    if path.stat().st_size > max_bytes:
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def line_col(text: str, index: int) -> tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    line_start = text.rfind("\n", 0, index)
    column = index + 1 if line_start == -1 else index - line_start
    return line, column


def clean_snippet(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()[:200]


def write_json(path: str | Path, payload: dict) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
