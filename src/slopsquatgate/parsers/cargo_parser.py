"""Cargo manifest, lockfile, and cargo config parser. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import tomllib
from pathlib import Path

from slopsquatgate.model import Dependency, Manifest, Observation, ParseError
from slopsquatgate.parsers.common import StringIndex, make_location, read_text, relative_path

DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


def parse_cargo(path: Path, root: Path, text: str | None = None) -> Manifest:
    """Parse Cargo.toml, Cargo.lock, or .cargo/config.toml."""
    source = text if text is not None else read_text(path)
    relative = relative_path(path, root)
    if path.name == "Cargo.toml":
        return Manifest(path=relative, ecosystem="cargo", kind="Cargo.toml", **_cargo_toml(source, relative))
    if path.name == "Cargo.lock":
        return Manifest(path=relative, ecosystem="cargo", kind="Cargo.lock", **_cargo_lock(source, relative))
    if path.name == "config.toml":
        return Manifest(path=relative, ecosystem="cargo", kind="cargo-config", **_cargo_config(source, relative))
    raise ParseError(f"unsupported Cargo manifest: {relative}")


def _toml(text: str, relative: str) -> dict[str, object]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ParseError(f"invalid TOML in {relative}: {error}") from error
    return data


def _cargo_toml(text: str, relative: str) -> dict[str, tuple[Dependency, ...] | tuple[Observation, ...]]:
    data = _toml(text, relative)
    strings = StringIndex(text)
    dependencies: list[Dependency] = []
    observations: list[Observation] = []
    tables: list[tuple[str, object]] = []
    for table in DEPENDENCY_TABLES:
        tables.append((table, data.get(table, {})))
        workspace = data.get("workspace", {})
        if isinstance(workspace, dict):
            tables.append((f"workspace.{table}", workspace.get(table, {})))
    for target_name, target_value in sorted(data.get("target", {}).items()) if isinstance(data.get("target", {}), dict) else ():
        if not isinstance(target_value, dict):
            continue
        for table in DEPENDENCY_TABLES:
            tables.append((f"target.{target_name}.{table}", target_value.get(table, {})))
    for context, value in tables:
        if not isinstance(value, dict):
            continue
        for name, spec in sorted(value.items()):
            if isinstance(spec, str):
                offset = strings.locate(spec)
                dependencies.append(
                    Dependency("cargo", name, spec, make_location(relative, text, offset, f"{name}={spec}"), context)
                )
                continue
            if not isinstance(spec, dict):
                continue
            version = spec.get("version", "")
            version = version if isinstance(version, str) else ""
            git = spec.get("git", "")
            git = git if isinstance(git, str) else ""
            registry = spec.get("registry", "")
            registry = registry if isinstance(registry, str) else ""
            path = spec.get("path", "")
            path = path if isinstance(path, str) else ""
            rev = spec.get("rev", "")
            branch = spec.get("branch", "")
            tag = spec.get("tag", "")
            for key, target in (("rev", rev), ("branch", branch), ("tag", tag)):
                if isinstance(target, str) and target:
                    version = f"{version} {key}={target}".strip()
            source_kind = "registry"
            source_value = ""
            if git:
                source_kind = "git"
                source_value = f"{git}#{version}"
            elif path:
                source_kind = "path"
                source_value = path
            elif registry:
                source_value = registry
            offset = strings.locate(name)
            dependencies.append(
                Dependency("cargo", name, version, make_location(relative, text, offset, f"{name} = ..."), context,
                           source_kind, source_value)
            )
            if registry:
                observations.append(
                    Observation("registry", registry, make_location(relative, text, strings.locate(registry), registry),
                                f"{context}.{name}")
                )
    return {"dependencies": tuple(dependencies), "observations": tuple(observations)}


def _cargo_lock(text: str, relative: str) -> dict[str, tuple[Dependency, ...] | tuple[Observation, ...]]:
    data = _toml(text, relative)
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
        source = package.get("source", "")
        source = source if isinstance(source, str) else ""
        source_kind = "registry"
        if source.startswith("git+"):
            source_kind = "git"
        elif source.startswith(("path+", "file+")):
            source_kind = "path"
        checksum = package.get("checksum", "")
        integrity = checksum if isinstance(checksum, str) else ""
        version = package.get("version", "")
        dependencies.append(
            Dependency("cargo", name, version if isinstance(version, str) else "", location, "Cargo.lock",
                       source_kind, source, integrity, locked=True)
        )
    return {"dependencies": tuple(dependencies), "observations": ()}


def _cargo_config(text: str, relative: str) -> dict[str, tuple[Dependency, ...] | tuple[Observation, ...]]:
    data = _toml(text, relative)
    strings = StringIndex(text)
    observations: list[Observation] = []
    sources = data.get("source", {})
    if isinstance(sources, dict):
        for name, value in sorted(sources.items()):
            if not isinstance(value, dict):
                continue
            for key in ("registry", "replace-with", "git", "local-registry"):
                target = value.get(key)
                if isinstance(target, str) and target:
                    observations.append(
                        Observation("source_override", target,
                                    make_location(relative, text, strings.locate(target), f"[{name}] {key}={target}"),
                                    f"source.{name}.{key}")
                    )
    registries = data.get("registries", {})
    if isinstance(registries, dict):
        for name, value in sorted(registries.items()):
            if isinstance(value, dict) and isinstance(value.get("index"), str):
                index = value["index"]
                observations.append(
                    Observation("index", index, make_location(relative, text, strings.locate(index), index),
                                f"registries.{name}")
                )
    return {"dependencies": (), "observations": tuple(observations)}
