"""Ecosystem parser tests. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from pathlib import Path

import pytest

from slopsquatgate.model import ParseError
from slopsquatgate.parsers.cargo_parser import parse_cargo
from slopsquatgate.parsers.common import StringIndex, make_location
from slopsquatgate.parsers.go_parser import parse_go
from slopsquatgate.parsers.npm_parser import parse_npm
from slopsquatgate.parsers.python_parser import parse_python

HEADER = "# Baysöz Labs <baysozlabs@proton.me>"


def test_string_index_decodes_json_and_toml_literals() -> None:
    index = StringIndex('{"a": "caf\\u00e9", "b": \'raw\'}')
    assert index.locate("café") > 0
    assert index.locate("raw") > 0
    assert index.locate("missing") == 0


def test_make_location_tracks_lines_and_snippets() -> None:
    text = "line one\nline two\n"
    location = make_location("demo.txt", text, text.index("two"))
    assert (location.line, location.column) == (2, 6)
    assert location.snippet == "line two"


def test_requirements_parser(tmp_path: Path) -> None:
    text = "\n".join(
        [
            HEADER,
            "requests==2.32.3 --hash=sha256:abcdef",
            "git+https://github.com/org/repo.git#egg=internal-git",
            "-e ../shared",
            "-r base.txt",
            "--extra-index-url https://mirror.evil.invalid/simple",
            "--trusted-host mirror.evil.invalid",
        ]
    )
    manifest = parse_python(tmp_path / "requirements.txt", tmp_path, text)
    assert manifest.ecosystem == "pypi"
    names = [item.name for item in manifest.dependencies]
    assert names == ["requests", "internal-git", "shared"]
    assert manifest.dependencies[0].integrity == "sha256:abcdef"
    assert manifest.dependencies[1].source_kind == "git"
    assert manifest.dependencies[2].source_value == "../shared"
    kinds = {item.kind for item in manifest.observations}
    assert {"include", "index", "trusted_host"} <= kinds


def test_pyproject_parser_extracts_all_sections_and_uv_sources(tmp_path: Path) -> None:
    text = '\n'.join(
        [
            HEADER,
            '[project]',
            'dependencies = ["requests==2.32.3", "urllb3==2.2.3"]',
            '',
            '[project.optional-dependencies]',
            'redteam = ["semgrep==1.100.0"]',
            '',
            '[dependency-groups]',
            'dev = ["pytest==9.2.0"]',
            '',
            '[build-system]',
            'requires = ["hatchling>=1.26"]',
            '',
            '[[tool.uv.index]]',
            'name = "rogue"',
            'url = "https://index.evil.invalid/simple"',
            '',
            '[tool.uv.sources]',
            'urllb3 = { index = "rogue" }',
        ]
    )
    manifest = parse_python(tmp_path / "pyproject.toml", tmp_path, text)
    contexts = {item.context for item in manifest.dependencies}
    assert {
        "dependencies",
        "optional-dependencies.redteam",
        "dependency-groups.dev",
        "build-system.requires",
    } <= contexts
    urllb3 = [item for item in manifest.dependencies if item.name == "urllb3"][0]
    assert urllb3.source_kind == "index"
    assert any(item.kind == "index" for item in manifest.observations)


def test_uv_lock_parser_records_hashes(tmp_path: Path) -> None:
    text = "\n".join(
        [
            HEADER,
            "version = 1",
            "",
            "[[package]]",
            'name = "requests"',
            'version = "2.32.3"',
            "",
            "[package.source]",
            'registry = "https://pypi.org/simple"',
            "",
            "[[package.wheels]]",
            'url = "https://files.pythonhosted.org/requests.whl"',
            'hash = "sha256:0123456789abcdef"',
        ]
    )
    manifest = parse_python(tmp_path / "uv.lock", tmp_path, text)
    assert manifest.dependencies[0].locked is True
    assert manifest.dependencies[0].integrity.startswith("sha256:")


def test_package_json_parser_finds_lifecycle_scripts(tmp_path: Path) -> None:
    text = (
        '{"_attribution": "Baysöz Labs <baysozlabs@proton.me>", '
        '"dependencies": {"@scope/pkg": "^1.2.3", "tool": "file:../tool"}, '
        '"scripts": {"postinstall": "node hook.js", "test": "pytest"}}'
    )
    manifest = parse_npm(tmp_path / "package.json", tmp_path, text)
    names = {item.name for item in manifest.dependencies}
    assert names == {"@scope/pkg", "tool"}
    assert [item for item in manifest.dependencies if item.name == "tool"][0].source_kind == "path"
    assert len([item for item in manifest.observations if item.kind == "lifecycle_script"]) == 1


def test_package_lock_parser_reads_resolved_and_integrity(tmp_path: Path) -> None:
    text = (
        '{"_attribution": "Baysöz Labs <baysozlabs@proton.me>", "lockfileVersion": 3, '
        '"packages": {"node_modules/lodash": {"version": "4.17.21", '
        '"resolved": "https://registry.npmjs.org/lodash.tgz", "integrity": "sha512-abc"}}}'
    )
    manifest = parse_npm(tmp_path / "package-lock.json", tmp_path, text)
    entry = manifest.dependencies[0]
    assert entry.name == "lodash"
    assert entry.locked is True
    assert entry.integrity == "sha512-abc"


def test_npmrc_parser_flags_tls_and_registry(tmp_path: Path) -> None:
    text = "; Baysöz Labs <baysozlabs@proton.me>\nregistry=https://evil.invalid/\nstrict-ssl=false\nignore-scripts=true\n"
    manifest = parse_npm(tmp_path / ".npmrc", tmp_path, text)
    kinds = {item.kind for item in manifest.observations}
    assert {"index", "tls_disabled"} <= kinds
    assert "scripts_enabled" not in kinds


def test_cargo_toml_parser_handles_tables_and_branches(tmp_path: Path) -> None:
    text = "\n".join(
        [
            HEADER,
            '[package]',
            'name = "demo"',
            'version = "0.1.0"',
            "",
            '[dependencies]',
            'serde = "1.0.210"',
            'tokio = { git = "https://github.com/tokio-rs/tokio", branch = "main" }',
            "",
            '[build-dependencies]',
            'proc-macro2 = "1.0.92"',
        ]
    )
    manifest = parse_cargo(tmp_path / "Cargo.toml", tmp_path, text)
    tokio = [item for item in manifest.dependencies if item.name == "tokio"][0]
    assert tokio.source_kind == "git"
    assert "branch=main" in tokio.version_spec
    assert any("build-dependencies" in item.context for item in manifest.dependencies)


def test_cargo_lock_and_config_parsers(tmp_path: Path) -> None:
    lock_text = '\n'.join([HEADER, "", "[[package]]", 'name = "serde"', 'version = "1.0.210"', 'source = "registry+https://github.com/rust-lang/crates.io-index"', 'checksum = "sha256:abc"'])
    lock = parse_cargo(tmp_path / "Cargo.lock", tmp_path, lock_text)
    assert lock.dependencies[0].integrity == "sha256:abc"
    config_text = '\n'.join([HEADER, "[source.crates-io]", 'replace-with = "mirror"', "[registries.mirror]", 'index = "sparse+https://index.evil.invalid/"'])
    config = parse_cargo(tmp_path / "config.toml", tmp_path, config_text)
    assert {item.kind for item in config.observations} == {"source_override", "index"}


def test_go_mod_and_go_sum_parsers(tmp_path: Path) -> None:
    mod_text = "\n".join(
        [
            "// " + HEADER,
            "module example.com/demo",
            "",
            "require (",
            "\tgithub.com/google/uuid v1.6.0",
            ")",
            "require github.com/pkg/errors v0.9.1",
            "replace github.com/pkg/errors => github.com/fork/errors v0.9.2",
        ]
    )
    manifest = parse_go(tmp_path / "go.mod", tmp_path, mod_text)
    names = {item.name for item in manifest.dependencies}
    assert names == {"github.com/google/uuid", "github.com/pkg/errors", "github.com/fork/errors"}
    assert any(item.kind == "replace" for item in manifest.observations)
    sum_text = "// " + HEADER + "\ngithub.com/google/uuid v1.6.0 h1:abc=\n"
    checksums = parse_go(tmp_path / "go.sum", tmp_path, sum_text)
    assert checksums.dependencies[0].integrity == "h1:abc="


@pytest.mark.parametrize(
    ("parser", "filename", "text"),
    [
        (parse_python, "pyproject.toml", "[project\nname = 'x'"),
        (parse_npm, "package.json", "{not json}"),
        (parse_cargo, "Cargo.toml", "[package\nname = 'x'"),
        (parse_go, "go.mod", "require ("),
    ],
)
def test_parsers_raise_parse_error_on_malformed_input(
    parser: object, filename: str, text: str, tmp_path: Path
) -> None:
    with pytest.raises(ParseError):
        parser(tmp_path / filename, tmp_path, text)
