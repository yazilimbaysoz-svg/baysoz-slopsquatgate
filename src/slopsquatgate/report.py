"""Human, JSON, and SARIF 2.1.0 reporters. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from slopsquatgate import ATTRIBUTION, __version__
from slopsquatgate.model import SEVERITIES, Finding, ScanResult
from slopsquatgate.rules import RULES

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/yazilimbaysoz-svg/baysoz-slopsquatgate"
SARIF_LEVELS = {"info": "note", "low": "note", "medium": "warning", "high": "error", "critical": "error"}


def render_text(result: ScanResult, quiet: bool = False) -> str:
    """Render a compact, copy-pasteable terminal report."""
    lines = [
        f"slopsquatgate {__version__} — offline dependency-origin conformance oracle",
        ATTRIBUTION,
        f"root: {result.root} | as-of: {result.as_of} | files: {len(result.files_scanned)}",
    ]
    counts = result.counts
    summary = " ".join(f"{name} {counts[name]}" for name in reversed(SEVERITIES))
    lines.append(f"findings: {len(result.findings)} ({summary})")
    if not quiet:
        for finding in result.findings:
            location = finding.location
            lines.append(
                f"[{finding.severity.upper():8}] {finding.rule_id} {location.path}:{location.line}:{location.column} "
                f"{finding.subject}"
            )
            lines.append(f"           evidence: {finding.evidence}")
            lines.append(f"           fix: {finding.recommendation}")
    if result.suppressed:
        lines.append(f"waived: {len(result.suppressed)} finding(s) suppressed by active policy waivers")
    lines.append(f"report signed: {ATTRIBUTION}")
    return "\n".join(lines) + "\n"


def render_json(result: ScanResult) -> str:
    """Render the deterministic machine-readable report."""
    payload = result.to_dict()
    payload["tool_version"] = __version__
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_sarif(result: ScanResult) -> str:
    """Render a SARIF 2.1.0 report suitable for GitHub code scanning."""
    rules = []
    for rule_id, meta in sorted(RULES.items()):
        rules.append(
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": meta.title},
                "fullDescription": {"text": f"{meta.title}. Rule authored by {ATTRIBUTION}."},
                "help": {"text": meta.recommendation},
                "defaultConfiguration": {"level": SARIF_LEVELS[meta.severity]},
                "properties": {"tags": ["security", "supply-chain", "slopsquat"]},
            }
        )
    results = [_sarif_result(finding) for finding in result.findings]
    payload: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "slopsquatgate",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "fullName": f"slopsquatgate by {ATTRIBUTION}",
                        "organization": ATTRIBUTION.split(" <")[0],
                        "rules": rules,
                        "properties": {"attribution": ATTRIBUTION},
                    }
                },
                "results": results,
                "properties": {
                    "attribution": ATTRIBUTION,
                    "as_of": result.as_of,
                    "root": result.root,
                    "policy_path": result.policy_path,
                    "waived_count": len(result.suppressed),
                },
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _sarif_result(finding: Finding) -> dict[str, Any]:
    location = finding.location
    return {
        "ruleId": finding.rule_id,
        "level": SARIF_LEVELS[finding.severity],
        "message": {"text": f"{finding.title}: {finding.evidence}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": location.path, "uriBaseId": "%SRCROOT%"},
                    "region": {
                        "startLine": max(location.line, 1),
                        "startColumn": max(location.column, 1),
                        "snippet": {"text": location.snippet},
                    },
                }
            }
        ],
        "partialFingerprints": {"slopsquatgate/v1": finding.fingerprint},
        "properties": {
            "severity": finding.severity,
            "subject": finding.subject,
            "recommendation": finding.recommendation,
            "attribution": ATTRIBUTION,
        },
    }


def write_report(content: str, output: str | None) -> None:
    """Write a report to a file or standard output."""
    if output is None:
        sys.stdout.write(content)
        return
    Path(output).write_text(content, encoding="utf-8")
