# Supreme Grand Jury Tribunal — Baysöz Labs <baysozlabs@proton.me>

Date: 2026-11-27
Subject: `slopsquatgate` 1.0.0
Requirement: unanimous PASS after all tests and security scans succeeded.
Evidence collector: `/tmp/opencode/tribunal/check.py` (outside the published repository).

## Preconditions

```text
uv venv && uv pip install -e . && uv pip install pytest
uv run pytest -q                                  -> 59 passed
ruff check --select E,F,W,S,B .                    -> All checks passed!
semgrep --config p/default --error .               -> Findings: 0 (0 blocking)
```

## Panel verdicts

| Juror | Evidence | Verdict |
| --- | --- | --- |
| Parser Integrity | Live CLI library scan of `examples/adversarial`: 9/9 manifests parsed, 9 typed manifests, 24 dependencies, zero SQ000 findings | PASS |
| Detection Fidelity | Seven rule families (SQ001, SQ002, SQ004, SQ005, SQ006, SQ007, SQ008) fired on the adversarial corpus; disabling the curated baseline dropped SQ002 from 5 to 0, proving data-driven detection rather than hard-coded output | PASS |
| SARIF Conformance | SARIF 2.1.0 with 10 declared rules, 25 results, 25 unique SHA-256 fingerprints, attribution at tool and run level, and exit status 0 under `--fail-on never` | PASS |
| Red-Team Adversary | Independently constructed clean tree produced 0 findings and exit 0; independently constructed hostile tree (private shadow, slopsquat, mutable git ref, denied host, expired waiver) produced SQ002/SQ003/SQ004/SQ005/SQ009 and exit 1 | PASS |
| Release Steward | `--version` and all five `--help` surfaces carry Baysöz Labs attribution; repeated JSON scans are byte-identical; invalid rule returns exit 2; source contains no stubs, TODOs, `pass` placeholders, network clients, or subprocess imports | PASS |

## Live tribunal output

```text
Supreme Grand Jury Tribunal — slopsquatgate 1.0.0 — Baysöz Labs <baysozlabs@proton.me>
Date: 2026-11-27 | Adversarial corpus: /home/runner/work/_temp/baysoz-new-project/examples/adversarial
Parser Integrity: PASS — 9/9 adversarial manifests parsed, SQ000 count 0, 9 typed manifests, 24 dependencies
Detection Fidelity: PASS — all 7 adversarial detection families fired; disabling the curated baseline removed SQ002 (5 -> 0), proving the rule is data-driven
SARIF Conformance: PASS — SARIF 2.1.0, 10 declared rules, 25 results, 25 unique fingerprints, attribution at tool and run level
Red-Team Adversary: PASS — clean tree produced 0 findings and exit 0; independent hostile tree produced ['SQ002', 'SQ003', 'SQ004', 'SQ005', 'SQ009'] with exit 1 including an expired-waiver SQ009 (no hallucinations, no silent pass)
Release Steward: PASS — v1.0.0 and all 5 help surfaces attribute Baysöz Labs; byte-identical repeat scans; usage errors return 2; no stubs/TODO/pass placeholders and no network or subprocess imports in src/
VERDICT: UNANIMOUS PASS (5/5)
```

## Verdict

**UNANIMOUS PASS (5/5).** Release is authorized by the tribunal. No stubs, no hallucinated findings,
no redactions of failed evidence.

Baysöz Labs <baysozlabs@proton.me>
