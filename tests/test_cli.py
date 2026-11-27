"""CLI contract tests. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from slopsquatgate.cli import main

ATTRIBUTION = "Baysöz Labs <baysozlabs@proton.me>"


@pytest.mark.parametrize("arguments", [["--version"], ["--help"], ["scan", "--help"], ["rules", "--help"]])
def test_every_top_level_help_surface_attributes_baysöz_labs(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(arguments)
    assert exit_info.value.code == 0
    output = capsys.readouterr().out
    assert ATTRIBUTION in output


def test_scan_exit_codes_and_human_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "requirements.txt").write_text(f"# {ATTRIBUTION}\nreqeusts==2.32.3\n", encoding="utf-8")
    assert main(["scan", str(tmp_path), "--as-of", "2026-11-27", "--fail-on", "high"]) == 1
    output = capsys.readouterr().out
    assert ATTRIBUTION in output
    assert "SQ002" in output
    assert main(["scan", str(tmp_path), "--as-of", "2026-11-27", "--fail-on", "never"]) == 0


def test_scan_json_and_sarif_to_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "requirements.txt").write_text(f"# {ATTRIBUTION}\nreqeusts==2.32.3\n", encoding="utf-8")
    json_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif"
    assert main(["scan", str(tmp_path), "--format", "json", "--out", str(json_path), "--fail-on", "never"]) == 0
    assert main(["scan", str(tmp_path), "--format", "sarif", "--out", str(sarif_path), "--fail-on", "never"]) == 0
    capsys.readouterr()
    report = json.loads(json_path.read_text(encoding="utf-8"))
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert report["attribution"] == ATTRIBUTION
    assert sarif["runs"][0]["tool"]["driver"]["properties"]["attribution"] == ATTRIBUTION


def test_init_policy_explain_and_rules(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "policy.json"
    assert main(["init-policy", "--out", str(target)]) == 0
    assert ATTRIBUTION in json.loads(target.read_text(encoding="utf-8"))["attribution"]
    assert main(["explain", "sq002"]) == 0
    explained = capsys.readouterr().out
    assert ATTRIBUTION in explained and "SQ002" in explained
    assert main(["rules"]) == 0
    listed = capsys.readouterr().out
    assert ATTRIBUTION in listed and "SQ009" in listed
    assert main(["explain", "SQ999"]) == 2
    assert ATTRIBUTION in capsys.readouterr().err


def test_invalid_policy_and_date_return_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad_policy = tmp_path / "policy.json"
    bad_policy.write_text("{invalid", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text(f"# {ATTRIBUTION}\nrequests==2.32.3\n", encoding="utf-8")
    assert main(["scan", str(tmp_path), "--policy", str(bad_policy)]) == 2
    assert ATTRIBUTION in capsys.readouterr().err
    assert main(["scan", str(tmp_path), "--as-of", "not-a-date"]) == 2
    assert ATTRIBUTION in capsys.readouterr().err


def test_module_entry_point_is_wired(monkeypatch: pytest.MonkeyPatch) -> None:
    import runpy

    monkeypatch.setattr(sys, "argv", ["slopsquatgate", "--version"])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("slopsquatgate", run_name="__main__")
    assert exit_info.value.code == 0
