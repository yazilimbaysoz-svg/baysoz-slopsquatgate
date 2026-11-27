"""Rule-engine and scan-orchestration tests. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from slopsquatgate.policy import Policy
from slopsquatgate.report import render_json, render_sarif
from slopsquatgate.rules import RULES
from slopsquatgate.scan import discover_files, scan

AS_OF = date(2026, 11, 27)
HEADER = "# Baysöz Labs <baysozlabs@proton.me>"


def _write(tmp_path: Path, files: dict[str, str]) -> None:
    for name, content in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _rules(result: object) -> set[str]:
    return {item.rule_id for item in result.findings}


def test_clean_python_project_has_no_findings(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "requirements.txt": f"{HEADER}\nrequests==2.32.3\n",
            "uv.lock": (
                f"{HEADER}\nversion = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.32.3\"\n\n"
                "[[package.wheels]]\nurl = \"https://files.pythonhosted.org/requests.whl\"\n"
                "hash = \"sha256:abcdef\"\n"
            ),
        },
    )
    result = scan(tmp_path, as_of=AS_OF)
    assert result.findings == ()
    assert len(result.files_scanned) == 2


def test_typosquat_detection_and_allowlist(tmp_path: Path) -> None:
    _write(tmp_path, {"requirements.txt": f"{HEADER}\nreqeusts==2.32.3\n"})
    assert "SQ002" in _rules(scan(tmp_path, as_of=AS_OF))
    policy = Policy.from_dict({"allowlist": ["pypi:reqeusts"]})
    assert "SQ002" not in _rules(scan(tmp_path, policy=policy, as_of=AS_OF))


def test_unicode_confusable_name_is_reported(tmp_path: Path) -> None:
    _write(tmp_path, {"requirements.txt": f"{HEADER}\nr\u200bеquests==2.32.3\n"})
    findings = [item for item in scan(tmp_path, as_of=AS_OF).findings if item.rule_id == "SQ001"]
    assert len(findings) == 1
    assert "U+0435" in findings[0].evidence or "U+200B" in findings[0].evidence


def test_private_namespace_requires_internal_registry_pin(tmp_path: Path) -> None:
    _write(tmp_path, {"requirements.txt": f"{HEADER}\nacme-widget==1.0.0\n"})
    hosts = sorted(Policy().trusted_hosts | {"registry.internal.invalid"})
    policy = Policy.from_dict(
        {
            "private_prefixes": ["acme-"],
            "internal_registry_hosts": ["registry.internal.invalid"],
            "trusted_hosts": hosts,
        }
    )
    assert "SQ003" in _rules(scan(tmp_path, policy=policy, as_of=AS_OF))
    _write(tmp_path, {"requirements.txt": f"{HEADER}\nacme-widget==1.0.0\n--extra-index-url https://registry.internal.invalid/simple\n"})
    assert "SQ003" not in _rules(scan(tmp_path, policy=policy, as_of=AS_OF))


def test_mutable_reference_and_host_policy(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "requirements.txt": (
                f"{HEADER}\ngit+https://github.com/org/repo.git#egg=internal-git\n"
                "--index-url https://evil.invalid/simple\n"
            )
        },
    )
    policy = Policy.from_dict({"denied_hosts": ["evil.invalid"]})
    result = scan(tmp_path, policy=policy, as_of=AS_OF)
    assert "SQ004" in _rules(result)
    denied = [item for item in result.findings if item.rule_id == "SQ005" and "denied" in item.evidence]
    assert denied and denied[0].severity == "critical"


def test_integrity_and_lock_drift(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "package.json": (
                '{"_attribution": "Baysöz Labs <baysozlabs@proton.me>", '
                '"dependencies": {"lodash": "4.17.21"}}'
            ),
            "package-lock.json": (
                '{"_attribution": "Baysöz Labs <baysozlabs@proton.me>", "lockfileVersion": 3, '
                '"packages": {"node_modules/lodash": {"version": "4.17.20", '
                '"resolved": "https://registry.npmjs.org/lodash.tgz"}}}'
            ),
        },
    )
    found = _rules(scan(tmp_path, as_of=AS_OF))
    assert {"SQ006", "SQ008"} <= found


def test_execution_surfaces(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "package.json": (
                '{"_attribution": "Baysöz Labs <baysozlabs@proton.me>", '
                '"scripts": {"postinstall": "node hook.js"}}'
            ),
            "Cargo.toml": f'{HEADER}\n[build-dependencies]\nproc-macro2 = "1.0.92"\n',
        },
    )
    hooks = [item for item in scan(tmp_path, as_of=AS_OF).findings if item.rule_id == "SQ007"]
    assert len(hooks) == 2


def test_waiver_suppression_and_expiry(tmp_path: Path) -> None:
    _write(tmp_path, {"requirements.txt": f"{HEADER}\nlegacy-tool\n"})
    policy = Policy.from_dict(
        {
            "waivers": [
                {
                    "id": "legacy",
                    "rule": "SQ004",
                    "path": "requirements.txt",
                    "name": "legacy-tool",
                    "expires": "2026-12-31",
                    "reason": "tracked migration",
                }
            ]
        }
    )
    active = scan(tmp_path, policy=policy, as_of=AS_OF)
    assert "SQ004" not in _rules(active)
    assert len(active.suppressed) == 1
    expired = scan(tmp_path, policy=policy, as_of=date(2027, 1, 1))
    assert "SQ009" in _rules(expired)
    assert any(item.rule_id == "SQ004" for item in expired.findings)


def test_parse_error_is_never_silent(tmp_path: Path) -> None:
    _write(tmp_path, {"pyproject.toml": "[project\nname = 'broken'"})
    findings = [item for item in scan(tmp_path, as_of=AS_OF).findings if item.rule_id == "SQ000"]
    assert len(findings) == 1
    assert "invalid pyproject.toml" in findings[0].evidence


def test_discovery_excludes_noise(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "requirements.txt": f"{HEADER}\nrequests==2.32.3\n",
            "node_modules/dep/package.json": '{"dependencies": {"lodahs": "*"}}',
            ".venv/requirements.txt": "evil==*\n",
        },
    )
    paths = [item.name for item in discover_files(tmp_path)]
    assert paths == ["requirements.txt"]


def test_reports_are_deterministic_and_sarif_valid(tmp_path: Path) -> None:
    _write(tmp_path, {"requirements.txt": f"{HEADER}\nreqeusts==2.32.3\n"})
    first = render_json(scan(tmp_path, as_of=AS_OF))
    second = render_json(scan(tmp_path, as_of=AS_OF))
    assert first == second
    assert "Baysöz Labs <baysozlabs@proton.me>" in first
    payload = render_sarif(scan(tmp_path, as_of=AS_OF))
    assert '"version": "2.1.0"' in payload
    import json

    sarif = json.loads(payload)
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == len(RULES)
    assert sarif["runs"][0]["results"][0]["partialFingerprints"]["slopsquatgate/v1"]


def test_adversarial_examples_cover_every_detection_family() -> None:
    examples = Path(__file__).resolve().parents[1] / "examples" / "adversarial"
    result = scan(examples, as_of=AS_OF)
    assert "SQ000" not in _rules(result)
    assert {"SQ001", "SQ002", "SQ004", "SQ005", "SQ006", "SQ007", "SQ008"} <= _rules(result)
