"""Shared manifest reading and source-position mapping. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import json
import re
from pathlib import Path

from slopsquatgate.model import Location, ParseError

MAX_MANIFEST_BYTES = 2_000_000
STRING_TOKEN = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'[^\'\\\n]*\'')
SKIP_DIRECTORIES = frozenset(
    {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "target", "__pycache__", "dist", "build", ".tox", ".mypy_cache", ".pytest_cache"}
)


def read_text(path: Path) -> str:
    """Read a UTF-8 manifest with a hard size bound."""
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ParseError(f"cannot stat {path.as_posix()}: {error}") from error
    if size > MAX_MANIFEST_BYTES:
        raise ParseError(f"manifest exceeds {MAX_MANIFEST_BYTES} bytes: {path.as_posix()}")
    try:
        return path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as error:
        raise ParseError(f"cannot decode {path.as_posix()} as UTF-8: {error}") from error


def relative_path(path: Path, root: Path) -> str:
    """Return a stable POSIX-relative path."""
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def line_column(text: str, offset: int) -> tuple[int, int]:
    """Convert a character offset into one-based line and column numbers."""
    if offset <= 0:
        return 1, 1
    safe_offset = min(offset, len(text))
    prefix = text[:safe_offset]
    line = prefix.count("\n") + 1
    column = safe_offset - (prefix.rfind("\n") + 1) + 1
    return line, column


def make_location(path: str, text: str, offset: int = 0, snippet: str | None = None) -> Location:
    """Build a source location with a bounded single-line snippet."""
    line, column = line_column(text, offset)
    if snippet is None:
        line_start = text.rfind("\n", 0, offset) + 1
        line_end = text.find("\n", offset)
        if line_end < 0:
            line_end = len(text)
        snippet = text[line_start:line_end].strip()
    return Location(path=path, line=line, column=column, snippet=snippet[:160])


class StringIndex:
    """Locate decoded string literals in raw TOML or JSON text."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._tokens: list[tuple[str, int]] = []
        self._used: set[int] = set()
        for match in STRING_TOKEN.finditer(text):
            raw = match.group(0)
            try:
                value = json.loads(raw) if raw.startswith('"') else raw[1:-1].replace("\\'", "'")
            except (ValueError, UnicodeError):
                continue
            self._tokens.append((value, match.start()))

    def locate(self, value: str) -> int:
        """Return the offset of the first unused literal equal to value, or zero."""
        for index, (token, offset) in enumerate(self._tokens):
            if index not in self._used and token == value:
                self._used.add(index)
                return offset
        return 0
