"""Core immutable data model. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}


@dataclass(frozen=True, slots=True)
class Location:
    """A byte-stable source position in a scanned manifest."""

    path: str
    line: int = 1
    column: int = 1
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
        }


@dataclass(frozen=True, slots=True)
class Dependency:
    """One declared or locked dependency."""

    ecosystem: str
    name: str
    version_spec: str
    location: Location
    context: str = "dependencies"
    source_kind: str = "registry"
    source_value: str = ""
    integrity: str = ""
    locked: bool = False

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version_spec": self.version_spec,
            "context": self.context,
            "source_kind": self.source_kind,
            "source_value": self.source_value,
            "integrity": self.integrity,
            "locked": self.locked,
            "location": self.location.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class Observation:
    """A manifest-level security-relevant setting, script, or registry override."""

    kind: str
    value: str
    location: Location
    context: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "context": self.context,
            "location": self.location.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class Manifest:
    """A parsed ecosystem manifest or lockfile."""

    path: str
    ecosystem: str
    kind: str
    dependencies: tuple[Dependency, ...] = ()
    observations: tuple[Observation, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "ecosystem": self.ecosystem,
            "kind": self.kind,
            "dependencies": [item.to_dict() for item in self.dependencies],
            "observations": [item.to_dict() for item in self.observations],
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """A deterministic, fingerprinted conformance finding."""

    rule_id: str
    title: str
    severity: str
    location: Location
    evidence: str
    recommendation: str
    subject: str = ""
    fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "subject": self.subject,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "fingerprint": self.fingerprint,
            "location": self.location.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ScanResult:
    """The complete outcome of one deterministic scan."""

    root: str
    as_of: str
    manifests: tuple[Manifest, ...] = ()
    findings: tuple[Finding, ...] = ()
    suppressed: tuple[Finding, ...] = ()
    files_scanned: tuple[str, ...] = ()
    policy_path: str = ""

    @property
    def counts(self) -> dict[str, int]:
        counts = {name: 0 for name in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "attribution": "Baysöz Labs <baysozlabs@proton.me>",
            "tool": "slopsquatgate",
            "root": self.root,
            "as_of": self.as_of,
            "policy_path": self.policy_path,
            "files_scanned": list(self.files_scanned),
            "summary": self.counts,
            "findings": [item.to_dict() for item in self.findings],
            "suppressed": [item.to_dict() for item in self.suppressed],
            "manifests": [item.to_dict() for item in self.manifests],
        }


@dataclass(slots=True)
class LockIndex:
    """Resolved lock entries keyed by ecosystem plus folded package name."""

    entries: dict[str, list[Dependency]] = field(default_factory=dict)
    ecosystems: set[str] = field(default_factory=set)

    def add(self, dependency: Dependency, folded_name: str) -> None:
        self.entries.setdefault(f"{dependency.ecosystem}:{folded_name}", []).append(dependency)
        self.ecosystems.add(dependency.ecosystem)

    def get(self, ecosystem: str, folded_name: str) -> tuple[Dependency, ...]:
        return tuple(self.entries.get(f"{ecosystem}:{folded_name}", ()))


class ParseError(ValueError):
    """Raised when a manifest cannot be parsed safely."""
