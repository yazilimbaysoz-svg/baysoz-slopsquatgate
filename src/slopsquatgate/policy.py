"""Steward policy, waivers, and strict offline validation. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from slopsquatgate.model import Finding, SEVERITIES
from slopsquatgate.normalize import fold_name

ATTRIBUTION = "Baysöz Labs <baysozlabs@proton.me>"
DEFAULT_TRUSTED_HOSTS = frozenset(
    {
        "pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "crates.io",
        "static.crates.io", "index.crates.io", "proxy.golang.org", "sum.golang.org",
        "github.com", "gitlab.com", "golang.org", "google.golang.org", "gopkg.in",
        "go.uber.org", "raw.githubusercontent.com", "codeload.github.com",
    }
)
KNOWN_KEYS = frozenset(
    {
        "attribution", "allowlist", "trusted_hosts", "denied_hosts", "private_prefixes",
        "internal_registry_hosts", "baseline_enabled", "similarity_max_distance",
        "waivers", "severity_overrides",
    }
)
WAIVER_KEYS = frozenset({"id", "rule", "path", "name", "expires", "reason"})


class PolicyError(ValueError):
    """Raised for an invalid or unsafe steward policy."""


@dataclass(frozen=True, slots=True)
class Waiver:
    """A time-bounded, narrowly scoped finding suppression."""

    id: str
    rule: str
    path: str
    name: str
    expires: date
    reason: str

    def matches(self, finding: Finding) -> bool:
        rule_matches = fnmatchcase(finding.rule_id, self.rule)
        path_matches = fnmatchcase(finding.location.path, self.path)
        name_matches = fnmatchcase(finding.subject, self.name)
        return rule_matches and path_matches and name_matches

    def is_expired(self, as_of: date) -> bool:
        return self.expires < as_of

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "rule": self.rule,
            "path": self.path,
            "name": self.name,
            "expires": self.expires.isoformat(),
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class Policy:
    """All deterministic decision inputs that are not derived from scanned files."""

    allowlist: frozenset[str] = frozenset()
    trusted_hosts: frozenset[str] = DEFAULT_TRUSTED_HOSTS
    denied_hosts: frozenset[str] = frozenset()
    private_prefixes: tuple[str, ...] = ()
    internal_registry_hosts: frozenset[str] = frozenset()
    baseline_enabled: bool = True
    similarity_max_distance: int = 2
    waivers: tuple[Waiver, ...] = ()
    severity_overrides: dict[str, str] = field(default_factory=dict)
    source_path: str = ""

    def is_allowed(self, name: str, ecosystem: str) -> bool:
        folded = fold_name(name, ecosystem)
        return f"{ecosystem}:{folded}" in self.allowlist or folded in self.allowlist

    def is_private(self, name: str) -> bool:
        lowered = name.lower()
        return any(prefix and lowered.startswith(prefix.lower()) for prefix in self.private_prefixes)

    def severity_for(self, rule_id: str, default: str) -> str:
        return self.severity_overrides.get(rule_id, default)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attribution": ATTRIBUTION,
            "allowlist": sorted(self.allowlist),
            "trusted_hosts": sorted(self.trusted_hosts),
            "denied_hosts": sorted(self.denied_hosts),
            "private_prefixes": list(self.private_prefixes),
            "internal_registry_hosts": sorted(self.internal_registry_hosts),
            "baseline_enabled": self.baseline_enabled,
            "similarity_max_distance": self.similarity_max_distance,
            "waivers": [waiver.to_dict() for waiver in self.waivers],
            "severity_overrides": dict(sorted(self.severity_overrides.items())),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], source_path: str = "") -> Policy:
        if not isinstance(data, dict):
            raise PolicyError("policy root must be a JSON object")
        unknown = sorted(set(data) - KNOWN_KEYS)
        if unknown:
            raise PolicyError(f"unknown policy keys: {', '.join(unknown)}")
        allowlist = frozenset(
            fold_name(cls._string(item, "allowlist entry")) for item in cls._list(data, "allowlist")
        )
        trusted = frozenset(cls._string(item, "trusted_hosts entry").lower() for item in cls._list(data, "trusted_hosts"))
        waivers = tuple(cls._parse_waiver(item) for item in cls._list(data, "waivers"))
        distance = data.get("similarity_max_distance", 2)
        if isinstance(distance, bool) or not isinstance(distance, int) or not 1 <= distance <= 3:
            raise PolicyError("similarity_max_distance must be an integer between 1 and 3")
        baseline_enabled = data.get("baseline_enabled", True)
        if not isinstance(baseline_enabled, bool):
            raise PolicyError("baseline_enabled must be a boolean")
        overrides_raw = data.get("severity_overrides", {})
        if not isinstance(overrides_raw, dict):
            raise PolicyError("severity_overrides must be a JSON object")
        overrides: dict[str, str] = {}
        for key, value in overrides_raw.items():
            rule = cls._string(key, "severity_overrides rule")
            severity = cls._string(value, "severity_overrides severity")
            if severity not in SEVERITIES:
                raise PolicyError(f"invalid severity for {rule}: {severity}")
            overrides[rule] = severity
        return cls(
            allowlist=allowlist or frozenset(),
            trusted_hosts=trusted or DEFAULT_TRUSTED_HOSTS,
            denied_hosts=frozenset(
                cls._string(item, "denied_hosts entry").lower() for item in cls._list(data, "denied_hosts")
            ),
            private_prefixes=tuple(cls._string(item, "private_prefixes entry") for item in cls._list(data, "private_prefixes")),
            internal_registry_hosts=frozenset(
                cls._string(item, "internal_registry_hosts entry").lower()
                for item in cls._list(data, "internal_registry_hosts")
            ),
            baseline_enabled=baseline_enabled,
            similarity_max_distance=distance,
            waivers=waivers,
            severity_overrides=overrides,
            source_path=source_path,
        )

    @staticmethod
    def _list(data: dict[str, Any], key: str) -> list[Any]:
        value = data.get(key, [])
        if not isinstance(value, list):
            raise PolicyError(f"{key} must be a JSON array")
        return value

    @staticmethod
    def _string(value: Any, label: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise PolicyError(f"{label} must be a non-empty string")
        return value.strip()

    @staticmethod
    def _parse_waiver(item: Any) -> Waiver:
        if not isinstance(item, dict):
            raise PolicyError("each waiver must be a JSON object")
        unknown = sorted(set(item) - WAIVER_KEYS)
        if unknown:
            raise PolicyError(f"unknown waiver keys: {', '.join(unknown)}")
        for key in ("id", "rule", "path", "name", "expires", "reason"):
            if key not in item:
                raise PolicyError(f"waiver is missing required key: {key}")
        expires_raw = Policy._string(item["expires"], "waiver expires")
        try:
            expires = date.fromisoformat(expires_raw)
        except ValueError as error:
            raise PolicyError(f"waiver expires must be YYYY-MM-DD: {expires_raw}") from error
        return Waiver(
            id=Policy._string(item["id"], "waiver id"),
            rule=Policy._string(item["rule"], "waiver rule"),
            path=Policy._string(item["path"], "waiver path"),
            name=Policy._string(item["name"], "waiver name"),
            expires=expires,
            reason=Policy._string(item["reason"], "waiver reason"),
        )

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        """Load and validate a policy from disk."""
        source = Path(path)
        try:
            raw = source.read_text(encoding="utf-8")
        except OSError as error:
            raise PolicyError(f"cannot read policy {source}: {error}") from error
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as error:
            raise PolicyError(f"invalid policy JSON in {source}: {error.msg}") from error
        return cls.from_dict(data, source.as_posix())

    @classmethod
    def template(cls) -> str:
        """Return a documented, copyable policy template."""
        return json.dumps(
            {
                "attribution": ATTRIBUTION,
                "allowlist": ["pypi:internal-tool", "@acme/private-ui"],
                "trusted_hosts": sorted(DEFAULT_TRUSTED_HOSTS),
                "denied_hosts": ["evil.invalid"],
                "private_prefixes": ["acme-", "@acme/"],
                "internal_registry_hosts": ["registry.internal.invalid"],
                "baseline_enabled": True,
                "similarity_max_distance": 2,
                "waivers": [
                    {
                        "id": "legacy-bridge",
                        "rule": "SQ004",
                        "path": "requirements.txt",
                        "name": "legacy-bridge",
                        "expires": date(2026, 12, 31).isoformat(),
                        "reason": "Migration tracked in internal change request.",
                    }
                ],
                "severity_overrides": {"SQ004": "low"},
            },
            indent=2,
            sort_keys=True,
        ) + "\n"
