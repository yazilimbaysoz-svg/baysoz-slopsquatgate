# Delivery plan — Baysöz Labs <baysozlabs@proton.me>

Project: `baysoz-slopsquatgate`
Owner: Baysöz Labs <baysozlabs@proton.me>
Status: implementation complete; quality gates clean; tribunal unanimous PASS; release authorized.

## Phase 0 — Market selection (complete)

- Inspected all 45 entries in `existing-repos.json`.
- Mined live GitHub trends and issues with `gh search repos`, `gh search issues`, and `gh issue view`.
- Selected dependency-origin/slopsquatting gating as a non-redundant pre-resolution boundary.
- Evidence recorded in `docs/MARKET_RESEARCH.md`.

## Phase 1 — Core engine (complete)

- Immutable data model, Unicode normalization, curated baseline, strict policy/waiver engine.
- Ten deterministic rules with SHA-256 fingerprints and canonical ordering.

## Phase 2 — Parsers (complete)

- Python, npm, Cargo, and Go manifest/lockfile parsers with accurate source locations.
- Bounded I/O and explicit parse-error findings so no manifest is silently skipped.

## Phase 3 — Interfaces (complete)

- CLI: `scan`, `init-policy`, `explain`, `rules`; exit codes 0/1/2.
- Reporters: text, JSON, SARIF 2.1.0.
- Library API: `scan(root, policy, as_of)`.

## Phase 4 — Documentation (complete)

- `README.md`, `docs/MARKET_RESEARCH.md`, `docs/ARCHITECTURE.md`, `SECURITY.md`,
  `CHANGELOG.md`, `LICENSE`, `pyproject.toml`, CI workflow, `.gitignore`.

## Phase 5 — Quality gates (complete)

```bash
uv venv && uv pip install -e . && uv pip install pytest
uv run pytest -q
ruff check --select E,F,W,S,B .
semgrep --config p/default --error .
```

Recorded results:

- `uv run pytest -q`: 59 passed (zero failures).
- `ruff check --select E,F,W,S,B .`: All checks passed (zero findings).
- `semgrep --config p/default --error .`: 0 findings, 0 blocking.

## Phase 6 — Supreme Grand Jury Tribunal (complete)

Required panels: Parser Integrity, Detection Fidelity, SARIF Conformance, Red-Team Adversary,
Release Steward. Each panel executes the built CLI against real adversarial inputs and must return
PASS. Release is blocked unless the verdict is unanimous. Record kept in `docs/TRIBUNAL.md`.
Observed verdict: **UNANIMOUS PASS (5/5)**.

## Phase 7 — Publication (in progress)

```bash
git init
gh repo create yazilimbaysoz-svg/baysoz-slopsquatgate --public --source=. --remote=origin --push
```

Then write the factory result JSON to the showcase workspace without touching any other file there.

Baysöz Labs <baysozlabs@proton.me>
