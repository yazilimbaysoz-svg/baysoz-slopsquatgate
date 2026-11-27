"""Offline scan orchestration with deterministic discovery. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from datetime import date
from fnmatch import fnmatchcase
from pathlib import Path

from slopsquatgate import ATTRIBUTION
from slopsquatgate.model import LockIndex, Manifest, ParseError, ScanResult
from slopsquatgate.normalize import fold_name
from slopsquatgate.parsers.cargo_parser import parse_cargo
from slopsquatgate.parsers.go_parser import parse_go
from slopsquatgate.parsers.npm_parser import parse_npm
from slopsquatgate.parsers.python_parser import parse_python
from slopsquatgate.parsers.common import make_location, relative_path
from slopsquatgate.policy import Policy
from slopsquatgate.rules import apply_waivers, generate_findings, parse_finding, sort_findings

DEFAULT_EXCLUDES = (
    ".git/**", ".venv/**", "venv/**", "node_modules/**", "target/**", "dist/**",
    "build/**", ".pytest_cache/**", ".mypy_cache/**", "tests/fixtures/**",
)
LOCK_KINDS = frozenset({"uv.lock", "Cargo.lock", "go.sum", "package-lock.json"})


def ecosystem_for(path: Path) -> str:
    """Classify a filename into a supported package ecosystem."""
    name = path.name
    if (name.startswith("requirements") and path.suffix == ".txt") or name in {"pyproject.toml", "uv.lock"}:
        return "pypi"
    if name in {"package.json", "package-lock.json", ".npmrc"}:
        return "npm"
    if name in {"Cargo.toml", "Cargo.lock"} or (name == "config.toml" and path.parent.name == ".cargo"):
        return "cargo"
    if name in {"go.mod", "go.sum"}:
        return "go"
    return ""


def discover_files(
    root: Path,
    include: str = "*",
    exclude: tuple[str, ...] = (),
) -> tuple[Path, ...]:
    """Discover supported manifests in stable path order."""
    candidates = sorted(root.rglob("*")) if root.is_dir() else [root]
    selected: list[Path] = []
    patterns = DEFAULT_EXCLUDES + tuple(exclude)
    for path in candidates:
        if not path.is_file():
            continue
        relative = relative_path(path, root)
        if not fnmatchcase(relative, include):
            continue
        if any(fnmatchcase(relative, pattern) for pattern in patterns):
            continue
        if ecosystem_for(path):
            selected.append(path)
    return tuple(selected)


def scan(
    root: str | Path,
    policy: Policy | None = None,
    as_of: date | None = None,
    include: str = "*",
    exclude: tuple[str, ...] = (),
) -> ScanResult:
    """Parse, analyze, and waive all findings under root."""
    target = Path(root)
    steward = policy if policy is not None else Policy()
    reference_date = as_of if as_of is not None else date.today()
    paths = discover_files(target, include, exclude)
    manifests: list[Manifest] = []
    findings = []
    scanned: list[str] = []
    for path in paths:
        relative = relative_path(path, target)
        scanned.append(relative)
        ecosystem = ecosystem_for(path)
        try:
            if ecosystem == "pypi":
                manifests.append(parse_python(path, target))
            elif ecosystem == "npm":
                manifests.append(parse_npm(path, target))
            elif ecosystem == "cargo":
                manifests.append(parse_cargo(path, target))
            else:
                manifests.append(parse_go(path, target))
        except (ParseError, ValueError, OSError) as error:
            findings.append(parse_finding(make_location(relative, "", 0, ATTRIBUTION), str(error)))
    ordered = tuple(sorted(manifests, key=lambda item: item.path))
    lock_index = LockIndex()
    for manifest in ordered:
        if manifest.kind not in LOCK_KINDS:
            continue
        for dependency in manifest.dependencies:
            lock_index.add(dependency, fold_name(dependency.name, dependency.ecosystem))
    findings.extend(generate_findings(ordered, lock_index, steward))
    active, suppressed, expired = apply_waivers(sort_findings(findings), steward, reference_date)
    return ScanResult(
        root=target.as_posix(),
        as_of=reference_date.isoformat(),
        manifests=ordered,
        findings=sort_findings([*active, *expired]),
        suppressed=suppressed,
        files_scanned=tuple(sorted(scanned)),
        policy_path=steward.source_path,
    )
