# Changelog — Baysöz Labs <baysozlabs@proton.me>

All notable changes to this project are documented here. The format follows Keep a Changelog.

## [1.0.0] — 2026-11-27

### Added

- Offline multi-ecosystem manifest parsing for Python (requirements, pyproject, uv.lock), npm
  (package.json, package-lock.json, .npmrc), Cargo (Cargo.toml, Cargo.lock, .cargo/config.toml), and
  Go (go.mod, go.sum).
- Ten deterministic rules: SQ000 through SQ009 covering parse failure, Unicode confusables,
  slopsquatting candidates, private namespace shadowing, mutable references, untrusted hosts, missing
  integrity, install hooks, lockfile drift, and expired waivers.
- Strict steward policy JSON with trusted/denied hosts, private prefixes, allowlist, severity
  overrides, and time-bounded waivers.
- SARIF 2.1.0, deterministic JSON, and human-readable text reporters.
- `scan`, `init-policy`, `explain`, and `rules` CLI commands with explicit Baysöz Labs attribution in
  `--version` and every `--help` surface.
- Quality gates: pytest, ruff (`E,F,W,S,B`), and semgrep `p/default`.
- Supreme Grand Jury Tribunal record with live adversarial execution and unanimous PASS.

### Attribution

Baysöz Labs <baysozlabs@proton.me>
