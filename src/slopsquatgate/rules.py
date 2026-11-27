"""Deterministic detection rules and waiver enforcement. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import date

from slopsquatgate.corpus import baseline_for
from slopsquatgate.model import Dependency, Finding, LockIndex, Location, Manifest, Observation
from slopsquatgate.normalize import exact_version, extract_host, fold_name, mutable_reasons, similarity_candidates, unicode_hazards
from slopsquatgate.policy import Policy

ATTRIBUTION = "Baysöz Labs <baysozlabs@proton.me>"


@dataclass(frozen=True, slots=True)
class RuleMeta:
    """Published rule metadata used by explain, SARIF, and the docs."""

    title: str
    severity: str
    recommendation: str


RULES: dict[str, RuleMeta] = {
    "SQ000": RuleMeta(
        "Manifest could not be parsed",
        "medium",
        "Fix the manifest syntax; an unparsed manifest is an unenforced supply-chain boundary.",
    ),
    "SQ001": RuleMeta(
        "Unicode control or confusable character in dependency reference",
        "high",
        "Replace the reference with plain ASCII and review the manifest for Trojan Source manipulation.",
    ),
    "SQ002": RuleMeta(
        "Near-miss dependency name (slopsquatting candidate)",
        "high",
        "Verify the package owner and registry namespace, then pin the exact vetted version or add an allowlist entry.",
    ),
    "SQ003": RuleMeta(
        "Private package name without an internal registry pin",
        "critical",
        "Bind the namespace to an internal registry with scoped credentials and a immutable version pin.",
    ),
    "SQ004": RuleMeta(
        "Mutable dependency reference",
        "medium",
        "Pin an exact version or an immutable commit SHA and reject wildcard or branch references.",
    ),
    "SQ005": RuleMeta(
        "Untrusted artifact host or TLS verification override",
        "high",
        "Remove the override or add the host to a reviewed trusted-hosts policy; never disable TLS verification.",
    ),
    "SQ006": RuleMeta(
        "Locked artifact missing integrity material",
        "medium",
        "Regenerate the lockfile with hashes for every registry artifact and enable strict hash checking.",
    ),
    "SQ007": RuleMeta(
        "Implicit code execution surface",
        "high",
        "Remove install lifecycle scripts or build dependencies, or isolate resolution in a hardened sandbox.",
    ),
    "SQ008": RuleMeta(
        "Lockfile drift or missing lockfile",
        "medium",
        "Regenerate and commit the lockfile so exact declared versions are verifiable in CI.",
    ),
    "SQ009": RuleMeta(
        "Expired waiver still suppresses a live finding",
        "high",
        "Renew the waiver with a dated, reviewed justification or remediate the underlying finding.",
    ),
}


def fingerprint(rule_id: str, location: Location, subject: str, evidence: str) -> str:
    """Stable content fingerprint; never includes wall-clock time or absolute paths."""
    material = f"{rule_id}|{location.path}|{location.line}|{location.column}|{subject}|{evidence}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def parse_finding(location: Location, evidence: str) -> Finding:
    """Build a deterministic SQ000 finding for an unreadable manifest."""
    return _finding("SQ000", location, location.path, evidence, Policy())


def generate_findings(
    manifests: tuple[Manifest, ...],
    lock_index: LockIndex,
    policy: Policy,
) -> tuple[Finding, ...]:
    """Run every rule over parsed manifests and return unsorted findings."""
    findings: list[Finding] = []
    findings.extend(_unicode_rules(manifests, policy))
    findings.extend(_typosquat_rules(manifests, policy))
    findings.extend(_private_shadow_rules(manifests, policy))
    findings.extend(_mutable_rules(manifests, policy))
    findings.extend(_registry_trust_rules(manifests, policy))
    findings.extend(_integrity_rules(manifests, policy))
    findings.extend(_execution_rules(manifests, policy))
    findings.extend(_lock_drift_rules(manifests, lock_index, policy))
    return sort_findings(findings)


def apply_waivers(
    findings: tuple[Finding, ...],
    policy: Policy,
    as_of: date,
) -> tuple[tuple[Finding, ...], tuple[Finding, ...], tuple[Finding, ...]]:
    """Return (active, suppressed, expired-waiver findings)."""
    active: list[Finding] = []
    suppressed: list[Finding] = []
    expired_findings: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()
    for finding in findings:
        active_waiver = None
        stale_waiver = None
        for waiver in policy.waivers:
            if not waiver.matches(finding):
                continue
            if waiver.is_expired(as_of):
                stale_waiver = waiver
            else:
                active_waiver = waiver
        if active_waiver is not None:
            suppressed.append(finding)
            continue
        if stale_waiver is not None:
            key = (stale_waiver.id, finding.rule_id, finding.location.path, finding.subject)
            if key not in seen:
                evidence = f"waiver {stale_waiver.id} expired on {stale_waiver.expires.isoformat()}"
                expired_findings.append(_finding("SQ009", finding.location, finding.subject, evidence, policy))
                seen.add(key)
        active.append(finding)
    return sort_findings(active), sort_findings(suppressed), sort_findings(expired_findings)


def sort_findings(findings: list[Finding] | tuple[Finding, ...]) -> tuple[Finding, ...]:
    """Canonical ordering makes every report byte-reproducible."""
    return tuple(
        sorted(
            findings,
            key=lambda item: (
                item.location.path,
                item.location.line,
                item.location.column,
                item.rule_id,
                item.subject,
                item.fingerprint,
            ),
        )
    )


def _finding(
    rule_id: str,
    location: Location,
    subject: str,
    evidence: str,
    policy: Policy,
    severity_override: str | None = None,
) -> Finding:
    meta = RULES[rule_id]
    severity = severity_override or policy.severity_for(rule_id, meta.severity)
    return Finding(
        rule_id=rule_id,
        title=meta.title,
        severity=severity,
        location=location,
        evidence=evidence,
        recommendation=meta.recommendation,
        subject=subject,
        fingerprint=fingerprint(rule_id, location, subject, evidence),
    )


def _all_dependencies(manifests: tuple[Manifest, ...]) -> list[Dependency]:
    return [dependency for manifest in manifests for dependency in manifest.dependencies]


def _all_observations(manifests: tuple[Manifest, ...]) -> list[tuple[Manifest, Observation]]:
    return [(manifest, observation) for manifest in manifests for observation in manifest.observations]


def _unicode_rules(manifests: tuple[Manifest, ...], policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    for dependency in _all_dependencies(manifests):
        for field_name, value in (
            ("name", dependency.name),
            ("version", dependency.version_spec),
            ("source", dependency.source_value),
        ):
            hazards = unicode_hazards(value)
            if hazards:
                detail = ", ".join(f"{char} {codepoint} {label}" for char, codepoint, label in hazards[:4])
                findings.append(
                    _finding("SQ001", dependency.location, dependency.name,
                             f"{field_name} contains hidden characters: {detail}", policy)
                )
    for manifest, observation in _all_observations(manifests):
        hazards = unicode_hazards(observation.value)
        if hazards:
            detail = ", ".join(f"{char} {codepoint} {label}" for char, codepoint, label in hazards[:4])
            findings.append(
                _finding("SQ001", observation.location, observation.value,
                         f"{manifest.kind} {observation.kind} contains hidden characters: {detail}", policy)
            )
    return findings


def _reference_pool(manifest: Manifest, policy: Policy) -> set[str]:
    pool = set(baseline_for(manifest.ecosystem)) if policy.baseline_enabled else set()
    for allowed in policy.allowlist:
        prefix = f"{manifest.ecosystem}:"
        if allowed.startswith(prefix):
            pool.add(allowed[len(prefix):])
    return pool


def _typosquat_rules(manifests: tuple[Manifest, ...], policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    for manifest in manifests:
        pool = _reference_pool(manifest, policy)
        if not pool:
            continue
        for dependency in manifest.dependencies:
            if "unknown" in dependency.name.lower() or policy.is_allowed(dependency.name, dependency.ecosystem):
                continue
            matches = similarity_candidates(
                dependency.name, frozenset(pool), dependency.ecosystem, policy.similarity_max_distance
            )
            if not matches:
                continue
            ranked = "; ".join(f"{item['name']} ({item['reason']}, distance {item['distance']})" for item in matches[:3])
            findings.append(
                _finding("SQ002", dependency.location, dependency.name,
                         f"'{dependency.name}' is near trusted names: {ranked}", policy)
            )
    return findings


def _private_shadow_rules(manifests: tuple[Manifest, ...], policy: Policy) -> list[Finding]:
    if not policy.private_prefixes:
        return []
    findings: list[Finding] = []
    internal_hosts = policy.internal_registry_hosts
    internal_indexes = {
        extract_host(observation.value)
        for _manifest, observation in _all_observations(manifests)
        if observation.kind in {"index", "registry", "source_override"}
    }
    bound_hosts = internal_hosts & internal_indexes
    for dependency in _all_dependencies(manifests):
        if not policy.is_private(dependency.name):
            continue
        host = extract_host(dependency.source_value)
        if host in internal_hosts or bound_hosts:
            continue
        findings.append(
            _finding("SQ003", dependency.location, dependency.name,
                     f"private namespace '{dependency.name}' resolves without an internal registry pin", policy)
        )
    return findings


def _mutable_rules(manifests: tuple[Manifest, ...], policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    for dependency in _all_dependencies(manifests):
        reasons = mutable_reasons(dependency.version_spec, dependency.source_kind, dependency.source_value)
        if reasons:
            findings.append(
                _finding("SQ004", dependency.location, dependency.name,
                         f"{dependency.name}: {', '.join(reasons)}", policy)
            )
    for _manifest, observation in _all_observations(manifests):
        if observation.kind == "include" and (".." in observation.value or "://" in observation.value):
            findings.append(
                _finding("SQ004", observation.location, observation.value,
                         f"include reference escapes the project or uses a URL: {observation.value}", policy)
            )
    return findings


def _registry_trust_rules(manifests: tuple[Manifest, ...], policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    checked: set[tuple[str, int, str, str]] = set()

    for dependency in _all_dependencies(manifests):
        if dependency.source_kind not in {"git", "url"}:
            continue
        host = extract_host(dependency.source_value)
        if host:
            checked.add((dependency.location.path, dependency.location.line, dependency.name, host))
            findings.extend(_host_finding(host, dependency.location, dependency.name, policy))

    for manifest, observation in _all_observations(manifests):
        if observation.kind == "trusted_host":
            findings.append(
                _finding("SQ005", observation.location, observation.value,
                         f"TLS certificate verification disabled: {observation.value}", policy)
            )
            continue
        if observation.kind not in {"index", "registry", "source_override", "replace", "resolved"}:
            continue
        host = extract_host(observation.value)
        if not host:
            continue
        key = (manifest.path, observation.location.line, observation.kind, observation.value)
        if key in checked and observation.kind != "resolved":
            continue
        checked.add(key)
        findings.extend(_host_finding(host, observation.location, observation.value, policy))
    return findings


def _host_finding(host: str, location: Location, subject: str, policy: Policy) -> list[Finding]:
    if host in policy.denied_hosts:
        return [
            _finding("SQ005", location, subject,
                     f"explicitly denied artifact host '{host}' referenced by '{subject}'",
                     policy, severity_override="critical")
        ]
    if host not in policy.trusted_hosts:
        return [
            _finding("SQ005", location, subject,
                     f"artifact host '{host}' is not in the trusted-hosts policy", policy)
        ]
    return []


def _integrity_rules(manifests: tuple[Manifest, ...], policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    for manifest in manifests:
        if not manifest.kind.endswith("lock") and manifest.kind != "package-lock.json":
            continue
        for dependency in manifest.dependencies:
            if dependency.source_kind not in {"registry", "url"} or dependency.integrity:
                continue
            findings.append(
                _finding("SQ006", dependency.location, dependency.name,
                         f"locked {manifest.kind} entry '{dependency.name}' has no checksum or integrity value", policy)
            )
    return findings


def _execution_rules(manifests: tuple[Manifest, ...], policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    for _manifest, observation in _all_observations(manifests):
        if observation.kind != "lifecycle_script":
            continue
        findings.append(
            _finding("SQ007", observation.location, observation.context,
                     f"npm lifecycle script '{observation.context}' runs automatically: {observation.value[:120]}", policy)
        )
    for dependency in _all_dependencies(manifests):
        if "build-dependencies" in dependency.context:
            findings.append(
                _finding("SQ007", dependency.location, dependency.name,
                         f"build dependency '{dependency.name}' executes during package resolution", policy)
            )
    return findings


def _lock_drift_rules(
    manifests: tuple[Manifest, ...],
    lock_index: LockIndex,
    policy: Policy,
) -> list[Finding]:
    findings: list[Finding] = []
    unlocked_ecosystems: dict[str, Location] = {}
    for manifest in manifests:
        if manifest.kind in {"uv.lock", "Cargo.lock", "go.sum", "package-lock.json"}:
            continue
        for dependency in manifest.dependencies:
            if dependency.source_kind in {"git", "url", "path", "workspace"}:
                continue
            pinned = exact_version(dependency.version_spec)
            if not pinned:
                continue
            if dependency.ecosystem not in lock_index.ecosystems:
                unlocked_ecosystems.setdefault(dependency.ecosystem, dependency.location)
                continue
            entries = lock_index.get(dependency.ecosystem, fold_name(dependency.name, dependency.ecosystem))
            if not entries:
                findings.append(
                    _finding("SQ008", dependency.location, dependency.name,
                             f"'{dependency.name}=={pinned}' has no matching lockfile entry", policy)
                )
                continue
            locked_versions = {exact_version(entry.version_spec) for entry in entries}
            if pinned not in locked_versions:
                findings.append(
                    _finding("SQ008", dependency.location, dependency.name,
                             f"'{dependency.name}' pinned to {pinned} but lockfile has {sorted(locked_versions)}", policy)
                )
    for ecosystem, location in sorted(unlocked_ecosystems.items()):
        findings.append(
            _finding("SQ008", location, ecosystem,
                     f"no lockfile discovered for ecosystem '{ecosystem}'; exact pins cannot be verified", policy)
        )
    return findings
