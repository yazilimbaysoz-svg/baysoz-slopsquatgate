"""Steward policy and waiver tests. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from slopsquatgate.model import Finding, Location
from slopsquatgate.policy import Policy, PolicyError


def _finding(rule: str = "SQ004", subject: str = "legacy-tool", path: str = "requirements.txt") -> Finding:
    return Finding(
        rule_id=rule,
        title="test",
        severity="medium",
        location=Location(path=path, line=4, column=1, snippet="legacy-tool==*"),
        evidence="test evidence",
        recommendation="test fix",
        subject=subject,
        fingerprint="abc123",
    )


def test_template_is_valid_json_and_carries_attribution() -> None:
    data = json.loads(Policy.template())
    assert "Baysöz Labs <baysozlabs@proton.me>" in data["attribution"]
    assert Policy.from_dict(data).source_path == ""


def test_default_policy_trusts_core_registries() -> None:
    policy = Policy()
    assert "pypi.org" in policy.trusted_hosts
    assert "github.com" in policy.trusted_hosts
    assert policy.baseline_enabled is True


def test_from_dict_normalizes_allowlist_and_overrides() -> None:
    policy = Policy.from_dict(
        {"allowlist": ["pypi:Internal.Tool"], "severity_overrides": {"SQ004": "low"}, "private_prefixes": ["acme-"]}
    )
    assert policy.is_allowed("internal-tool", "pypi") is True
    assert policy.severity_for("SQ004", "medium") == "low"
    assert policy.is_private("acme-widget") is True
    assert policy.is_private("widget") is False


def test_from_dict_rejects_unknown_keys_bad_severity_and_bad_date() -> None:
    with pytest.raises(PolicyError, match="unknown policy keys"):
        Policy.from_dict({"unexpected": True})
    with pytest.raises(PolicyError, match="invalid severity"):
        Policy.from_dict({"severity_overrides": {"SQ004": "catastrophic"}})
    with pytest.raises(PolicyError, match="YYYY-MM-DD"):
        Policy.from_dict({"waivers": [{"id": "x", "rule": "SQ004", "path": "*", "name": "*", "expires": "soon", "reason": "r"}]})


def test_load_policy_file(tmp_path: Path) -> None:
    target = tmp_path / "policy.json"
    target.write_text(Policy.template(), encoding="utf-8")
    policy = Policy.load(target)
    assert policy.waivers[0].id == "legacy-bridge"
    assert policy.source_path == target.as_posix()


def test_waiver_matching_is_scoped_and_time_bounded() -> None:
    policy = Policy.from_dict(
        {
            "waivers": [
                {
                    "id": "w1",
                    "rule": "SQ004",
                    "path": "requirements*.txt",
                    "name": "legacy-*",
                    "expires": "2026-12-31",
                    "reason": "planned migration",
                }
            ]
        }
    )
    assert policy.waivers[0].matches(_finding()) is True
    assert policy.waivers[0].matches(_finding(rule="SQ002")) is False
    assert policy.waivers[0].matches(_finding(path="pyproject.toml")) is False
    assert policy.waivers[0].is_expired(date(2026, 11, 27)) is False
    assert policy.waivers[0].is_expired(date(2027, 1, 1)) is True
