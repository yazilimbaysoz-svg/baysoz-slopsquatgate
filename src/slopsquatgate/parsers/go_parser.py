"""Go module and checksum parser. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import re
from pathlib import Path

from slopsquatgate.model import Dependency, Manifest, Observation, ParseError
from slopsquatgate.parsers.common import make_location, read_text, relative_path

REQUIRE_RE = re.compile(r"^([^\s()]+)\s+(v[^\s]+)$")
REPLACE_RE = re.compile(r"^replace\s+(\S+)(?:\s+\S+)?\s+=>\s+(\S+)(?:\s+(\S+))?")


def parse_go(path: Path, root: Path, text: str | None = None) -> Manifest:
    """Parse go.mod or go.sum."""
    source = text if text is not None else read_text(path)
    relative = relative_path(path, root)
    if path.name == "go.mod":
        return Manifest(path=relative, ecosystem="go", kind="go.mod", **_go_mod(source, relative))
    if path.name == "go.sum":
        return Manifest(path=relative, ecosystem="go", kind="go.sum", **_go_sum(source, relative))
    raise ParseError(f"unsupported Go manifest: {relative}")


def _go_mod(text: str, relative: str) -> dict[str, tuple[Dependency, ...] | tuple[Observation, ...]]:
    dependencies: list[Dependency] = []
    observations: list[Observation] = []
    in_require_block = False
    for offset, raw_line in enumerate_lines(text):
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        location = make_location(relative, text, offset, raw_line.strip())
        if line == "require (":
            in_require_block = True
            continue
        if in_require_block and line == ")":
            in_require_block = False
            continue
        if line.startswith("replace "):
            match = REPLACE_RE.match(line)
            observations.append(Observation("replace", line, location, "go.mod"))
            if match:
                target, version = match.group(2), match.group(3) or ""
                source_kind = "path" if target.startswith(("./", "../")) else "registry"
                dependencies.append(Dependency("go", target, version, location, "replace", source_kind, target))
            continue
        if line.startswith(("exclude ", "retract ", "module ", "go ", "toolchain ")):
            continue
        candidate = line[8:].strip() if line.startswith("require ") else line if in_require_block else ""
        if not candidate:
            continue
        match = REQUIRE_RE.match(candidate)
        if match is None:
            observations.append(Observation("unparsed_line", line, location, "go.mod"))
            continue
        dependencies.append(Dependency("go", match.group(1), match.group(2), location, "require"))
    if in_require_block:
        raise ParseError(f"unterminated require block in {relative}")
    return {"dependencies": tuple(dependencies), "observations": tuple(observations)}


def _go_sum(text: str, relative: str) -> dict[str, tuple[Dependency, ...] | tuple[Observation, ...]]:
    dependencies: list[Dependency] = []
    for offset, raw_line in enumerate_lines(text):
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        name, version, checksum = parts[0], parts[1], parts[2]
        location = make_location(relative, text, offset, f"{name} {version}")
        dependencies.append(Dependency("go", name, version, location, "go.sum", "registry", "", checksum, locked=True))
    return {"dependencies": tuple(dependencies), "observations": ()}


def enumerate_lines(text: str) -> list[tuple[int, str]]:
    """Return (offset, line) pairs for line-oriented parsing."""
    pairs: list[tuple[int, str]] = []
    offset = 0
    for line in text.splitlines(keepends=True):
        pairs.append((offset, line.rstrip("\r\n")))
        offset += len(line)
    return pairs
