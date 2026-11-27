"""Python manifest and uv.lock parser. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import re
import tomllib
from dataclasses import replace
from pathlib import Path

from slopsquatgate.model import Dependency, Location, Manifest, Observation, ParseError
from slopsquatgate.normalize import fold_name
from slopsquatgate.parsers.common import StringIndex, make_location, read_text, relative_path

REQUIREMENT_RE = re.compile(r"^([^\s\[\]@=<>!~^,;]+)\s*(\[[^\]]+\])?\s*(.*)$")
GIT_SPEC_RE = re.compile(r"^(git\+[^#\s]+)(?:#egg=([^\s#]+))?")


def parse_python(path: Path, root: Path, text: str | None = None) -> Manifest:
    """Parse requirements/*.txt, pyproject.toml, or uv.lock into one Manifest."""
    source = text if text is not None else read_text(path)
    relative = relative_path(path, root)
    filename = path.name
    if filename.startswith("requirements") or path.suffix == ".txt":
        return Manifest(path=relative, ecosystem="pypi", kind="requirements", **_requirements(source, relative))
    if filename == "uv.lock":
        return Manifest(path=relative, ecosystem="pypi", kind="uv.lock", **_uv_lock(source, relative))
    if filename == "pyproject.toml":
        return Manifest(path=relative, ecosystem="pypi", kind="pyproject", **_pyproject(source, relative))
    raise ParseError(f"unsupported Python manifest: {relative}")


def _requirements(text: str, relative: str) -> dict[str, tuple[Dependency, ...] | tuple[Observation, ...]]:
    dependencies: list[Dependency] = []
    observations: list[Observation] = []
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        location = make_location(relative, text, _line_offset(text, number), line)
        if line.startswith(("-r", "--requirement", "-c", "--constraint")):
            observations.append(Observation("include", line, location, "requirements"))
            continue
        if line.startswith(("--index-url", "--extra-index-url", "--find-links", "-i", "-f")):
            observations.append(Observation("index", line, location, "requirements"))
            continue
        if line.startswith("--trusted-host"):
            observations.append(Observation("trusted_host", line, location, "requirements"))
            continue
        if line.startswith(("-e", "--editable")):
            value = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else ""
            name = Path(value.rstrip("/")).name or "editable-unknown"
            dependencies.append(
                Dependency("pypi", name, "", location, context="editable", source_kind="path", source_value=value)
            )
            continue
        if line.startswith("--hash="):
            if dependencies:
                previous = dependencies[-1]
                dependencies[-1] = replace(previous, integrity=previous.integrity + line.split("=", 1)[1])
            continue
        if line.startswith("--"):
            observations.append(Observation("option", line, location, "requirements"))
            continue
        clean = re.sub(r"\s+#.*$", "", line)
        git_match = GIT_SPEC_RE.match(clean)
        if git_match:
            name = git_match.group(2) or "git-unknown"
            dependencies.append(
                Dependency("pypi", name, "", location, source_kind="git", source_value=git_match.group(1))
            )
            continue
        match = REQUIREMENT_RE.match(clean)
        if match is None:
            observations.append(Observation("unparsed_line", clean, location, "requirements"))
            continue
        name, _extras, spec = match.groups()
        spec = spec.strip()
        integrity = ""
        if " --hash=" in spec:
            spec, hash_value = spec.split(" --hash=", 1)
            integrity = hash_value.strip()
        source_kind = "registry"
        source_value = ""
        if " @ " in spec:
            source_value = spec.split(" @ ", 1)[1].strip()
            source_kind = "url" if "://" in source_value else "path"
            spec = ""
        dependencies.append(
            Dependency("pypi", name, spec.strip(), location, source_kind=source_kind,
                       source_value=source_value, integrity=integrity)
        )
    return {"dependencies": tuple(dependencies), "observations": tuple(observations)}


def _line_offset(text: str, line_number: int) -> int:
    offset = 0
    for _ in range(line_number - 1):
        newline = text.find("\n", offset)
        if newline < 0:
            return len(text)
        offset = newline + 1
    return offset


def _pyproject(text: str, relative: str) -> dict[str, tuple[Dependency, ...] | tuple[Observation, ...]]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ParseError(f"invalid pyproject.toml in {relative}: {error}") from error
    strings = StringIndex(text)
    project = data.get("project", {})
    build = data.get("build-system", {})
    tool = data.get("tool", {})
    uv = tool.get("uv", {}) if isinstance(tool.get("uv", {}), dict) else {}
    sections: list[tuple[str, object]] = [("dependencies", project.get("dependencies", []))]
    for section_name in ("optional-dependencies",):
        section = project.get(section_name, {})
        if isinstance(section, dict):
            for group, values in sorted(section.items()):
                sections.append((f"optional-dependencies.{group}", values))
    groups = data.get("dependency-groups", {})
    if isinstance(groups, dict):
        for group, values in sorted(groups.items()):
            sections.append((f"dependency-groups.{group}", values))
    sections.append(("build-system.requires", build.get("requires", [])))

    dependencies: list[Dependency] = []
    for context, values in sections:
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, str):
                continue
            offset = strings.locate(value)
            location = make_location(relative, text, offset, value)
            dependencies.append(_pep508_dependency(value, location, context))

    sources = uv.get("sources", {})
    source_map: dict[str, dict[str, str]] = {}
    if isinstance(sources, dict):
        for name, value in sorted(sources.items()):
            if isinstance(value, str):
                source_map[fold_name(name, "pypi")] = {"kind": "index", "value": value}
            elif isinstance(value, dict):
                for kind, target in sorted(value.items()):
                    if isinstance(target, str) and kind in {"git", "url", "path", "index", "workspace"}:
                        source_map[fold_name(name, "pypi")] = {"kind": kind, "value": target}
                        break
    dependencies = [
        replace(dep, source_kind=source_map[fold_name(dep.name, "pypi")]["kind"],
                source_value=source_map[fold_name(dep.name, "pypi")]["value"])
        if fold_name(dep.name, "pypi") in source_map else dep
        for dep in dependencies
    ]

    observations: list[Observation] = []
    indexes = uv.get("index", [])
    if isinstance(indexes, list):
        for item in indexes:
            if not isinstance(item, dict):
                continue
            url = item.get("url", "")
            if isinstance(url, str) and url:
                observations.append(
                    Observation("index", url, make_location(relative, text, strings.locate(url), url), "tool.uv.index")
                )
    constraint = uv.get("constraint-dependencies", [])
    if isinstance(constraint, list):
        for value in constraint:
            if isinstance(value, str):
                observations.append(
                    Observation("constraint", value, make_location(relative, text, strings.locate(value), value), "tool.uv")
                )
    return {"dependencies": tuple(dependencies), "observations": tuple(observations)}


def _pep508_dependency(value: str, location: Location, context: str) -> Dependency:
    spec = value.strip()
    git_match = GIT_SPEC_RE.match(spec)
    if git_match:
        name = git_match.group(2) or "git-unknown"
        return Dependency("pypi", name, "", location, context, "git", git_match.group(1))
    match = REQUIREMENT_RE.match(spec)
    if match is None:
        return Dependency("pypi", "unparsed-entry", spec, location, context)
    name, _extras, version = match.groups()
    source_kind = "registry"
    source_value = ""
    if " @ " in version:
        source_value = version.split(" @ ", 1)[1].strip()
        source_kind = "url" if "://" in source_value else "path"
        version = ""
    return Dependency("pypi", name, version.strip(), location, context, source_kind, source_value)


def _uv_lock(text: str, relative: str) -> dict[str, tuple[Dependency, ...] | tuple[Observation, ...]]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ParseError(f"invalid uv.lock in {relative}: {error}") from error
    strings = StringIndex(text)
    dependencies: list[Dependency] = []
    packages = data.get("package", [])
    if not isinstance(packages, list):
        return {"dependencies": (), "observations": ()}
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name", "")
        if not isinstance(name, str) or not name:
            continue
        location = make_location(relative, text, strings.locate(name), name)
        source = package.get("source", {})
        source_kind = "registry"
        source_value = ""
        if isinstance(source, dict):
            for kind in ("git", "url", "path", "editable", "virtual"):
                value = source.get(kind)
                if isinstance(value, str):
                    source_kind = "path" if kind == "editable" else kind
                    source_value = value
                    break
        integrity = ""
        for field_name in ("sdist", "wheels"):
            item = package.get(field_name)
            candidates = item if isinstance(item, list) else [item]
            for candidate in candidates:
                if isinstance(candidate, dict) and isinstance(candidate.get("hash"), str):
                    integrity = candidate["hash"]
                    break
            if integrity:
                break
        version = package.get("version", "")
        dependencies.append(
            Dependency(
                "pypi", name, version if isinstance(version, str) else "", location,
                "uv.lock", source_kind, source_value, integrity, locked=True,
            )
        )
    return {"dependencies": tuple(dependencies), "observations": ()}
