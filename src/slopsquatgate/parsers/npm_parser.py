"""npm package.json, package-lock.json, and .npmrc parser. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import json
from pathlib import Path

from slopsquatgate.model import Dependency, Location, Manifest, Observation, ParseError
from slopsquatgate.parsers.common import StringIndex, make_location, read_text, relative_path

DEPENDENCY_SECTIONS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
    "overrides",
    "resolutions",
)
LIFECYCLE_SCRIPTS = frozenset({"preinstall", "install", "postinstall", "prepare", "prepack", "postpack"})


def parse_npm(path: Path, root: Path, text: str | None = None) -> Manifest:
    """Parse an npm manifest into one Manifest."""
    source = text if text is not None else read_text(path)
    relative = relative_path(path, root)
    if path.name == "package.json":
        return Manifest(path=relative, ecosystem="npm", kind="package.json", **_package_json(source, relative))
    if path.name == "package-lock.json":
        return Manifest(path=relative, ecosystem="npm", kind="package-lock.json", **_package_lock(source, relative))
    if path.name == ".npmrc":
        return Manifest(path=relative, ecosystem="npm", kind="npmrc", **_npmrc(source, relative))
    raise ParseError(f"unsupported npm manifest: {relative}")


def _load_json(text: str, relative: str) -> dict[str, object]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        raise ParseError(f"invalid JSON in {relative}: {error.msg} at line {error.lineno}") from error
    if not isinstance(data, dict):
        raise ParseError(f"{relative} must contain a JSON object")
    return data


def _package_json(text: str, relative: str) -> dict[str, tuple[Dependency, ...] | tuple[Observation, ...]]:
    data = _load_json(text, relative)
    strings = StringIndex(text)
    dependencies: list[Dependency] = []

    def collect(section: dict[str, object], context: str) -> None:
        for name, value in sorted(section.items()):
            if isinstance(value, dict):
                collect(value, f"{context}.{name}")
                continue
            if not isinstance(value, str):
                continue
            location = make_location(relative, text, strings.locate(value), f"{name}: {value}")
            dependencies.append(_npm_dependency(name, value, location, context))

    for section_name in DEPENDENCY_SECTIONS:
        section = data.get(section_name)
        if isinstance(section, dict):
            collect(section, section_name)
    scripts = data.get("scripts")
    observations: list[Observation] = []
    if isinstance(scripts, dict):
        for name, value in sorted(scripts.items()):
            if name in LIFECYCLE_SCRIPTS and isinstance(value, str):
                location = make_location(relative, text, strings.locate(value), f"{name}: {value}")
                observations.append(Observation("lifecycle_script", value, location, "scripts"))
    config = data.get("config")
    if isinstance(config, dict):
        registry = config.get("registry")
        if isinstance(registry, str):
            observations.append(
                Observation("index", registry, make_location(relative, text, strings.locate(registry), registry), "config")
            )
    return {"dependencies": tuple(dependencies), "observations": tuple(observations)}


def _npm_dependency(name: str, value: str, location: Location, context: str) -> Dependency:
    source_kind = "registry"
    source_value = ""
    spec = value.strip()
    if spec.startswith(("git+", "git://", "github:", "gitlab:", "bitbucket:")):
        source_kind = "git"
        source_value = spec
    elif spec.startswith(("http://", "https://")):
        source_kind = "url"
        source_value = spec
    elif spec.startswith(("file:", "link:")):
        source_kind = "path"
        source_value = spec.split(":", 1)[1]
    elif spec.startswith("workspace:"):
        source_kind = "workspace"
        source_value = spec
    return Dependency("npm", name, spec, location, context, source_kind, source_value)


def _package_lock(text: str, relative: str) -> dict[str, tuple[Dependency, ...] | tuple[Observation, ...]]:
    data = _load_json(text, relative)
    strings = StringIndex(text)
    dependencies: list[Dependency] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, entry in sorted(packages.items()):
            if not isinstance(entry, dict) or key == "":
                continue
            name = key.rsplit("node_modules/", 1)[-1]
            if not isinstance(name, str) or not name:
                continue
            version = entry.get("version", "")
            resolved = entry.get("resolved", "")
            integrity = entry.get("integrity", "")
            source_kind = "registry"
            if isinstance(resolved, str) and resolved:
                source_kind = "url" if "://" in resolved else "registry"
            location = make_location(relative, text, strings.locate(key) or strings.locate(name), f"{name}@{version}")
            dependencies.append(
                Dependency(
                    "npm", name, version if isinstance(version, str) else "", location,
                    "package-lock", source_kind,
                    resolved if isinstance(resolved, str) else "",
                    integrity if isinstance(integrity, str) else "",
                    locked=True,
                )
            )
    legacy = data.get("dependencies")
    if isinstance(legacy, dict) and not packages:
        for name, entry in sorted(legacy.items()):
            if not isinstance(entry, dict):
                continue
            version = entry.get("version", "")
            resolved = entry.get("resolved", "")
            integrity = entry.get("integrity", "")
            location = make_location(relative, text, strings.locate(key) or strings.locate(name), f"{name}@{version}")
            dependencies.append(
                Dependency(
                    "npm", name, version if isinstance(version, str) else "", location,
                    "package-lock", "url" if resolved else "registry",
                    resolved if isinstance(resolved, str) else "",
                    integrity if isinstance(integrity, str) else "",
                    locked=True,
                )
            )
    return {"dependencies": tuple(dependencies), "observations": ()}


def _npmrc(text: str, relative: str) -> dict[str, tuple[Dependency, ...] | tuple[Observation, ...]]:
    observations: list[Observation] = []
    for offset, raw_line in enumerate_lines(text):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if key.endswith("registry") or key == "registry":
            observations.append(Observation("index", value, make_location(relative, text, offset, line), key))
        elif key == "strict-ssl" and value.lower() in {"false", "0", "no"}:
            observations.append(Observation("tls_disabled", value, make_location(relative, text, offset, line), key))
        elif key == "ignore-scripts" and value.lower() in {"false", "0", "no"}:
            observations.append(Observation("scripts_enabled", value, make_location(relative, text, offset, line), key))
    return {"dependencies": (), "observations": tuple(observations)}


def enumerate_lines(text: str) -> list[tuple[int, str]]:
    """Return (offset, line) pairs for line-oriented parsing."""
    pairs: list[tuple[int, str]] = []
    offset = 0
    for line in text.splitlines(keepends=True):
        pairs.append((offset, line.rstrip("\r\n")))
        offset += len(line)
    return pairs
