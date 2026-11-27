# Market research — Baysöz Labs <baysozlabs@proton.me>

Date of evidence: 2026-11-27. All star counts and issue titles below were collected live with
`gh search repos`, `gh search issues`, and `gh issue view` using the authenticated GitHub CLI.
The complete prior portfolio was read from `/home/runner/work/_temp/existing-repos.json` (45 entries).

## 1. Live ecosystem signal

| Observation | Live evidence | What it means |
| --- | --- | --- |
| AI-assisted offensive security is the dominant 2026 trend | `usestrix/strix` 77,808 stars; `KeygraphHQ/shannon` 52,358; `NVIDIA/SkillSpector` 27,814; `openai/codex-security` 14,412; `microsoft/PyRIT` 5,128 | Repositories that *find* vulnerabilities are abundant; repositories that *gate the dependency names AI agents write* are not |
| Agent governance and sandbox policy are accelerating | `microsoft/agent-governance-toolkit` 6,614; `provos/ironcurtain` 685; `strands-agents/box` 623; `agentjail` 105 | The market has moved from "scan the agent" to "constrain the agent's execution boundary" |
| Name-confusion tooling exists but is narrow and aging | `visma-prodsec/confused` 793; `agivanttechnologies/SlopSquatShield` 50; `Checkmarx/dustilock` 41; `rustfoundation/typomania` 40; `elementsinteractive/twyn` 56 | Existing tools are single-ecosystem checkers or live-registry lookups; none provide a deterministic, offline, multi-ecosystem CI oracle with SARIF and dated waivers |
| Issue-level pain is real and specific | `NVIDIA/SkillSpector#1205`: a version-pinned `npx` package is still reported as unpinned when the pin lives in manifest frontmatter; `NVIDIA/SkillSpector#1198`: a bundled `env.PATH` shadowing `git` scans as SAFE with score 0 | Parsing context and hidden execution surfaces are exactly where scanners silently miss; a rule engine must distinguish manifest metadata from prose and must model resolution context |
| Search-qualifier caveat | `gh search issues 'typosquatting is:issue is:open'` returned no results while keyword searches and direct `gh issue view` returned detailed reports | Ecosystem pain must be mined with multiple search modes, not a single query shape |

Representative queries executed:

```bash
gh search repos 'topic:appsec created:>2025-01-01' --sort stars --limit 20
gh search repos 'red team security in:name,description created:>2025-01-01' --sort stars --limit 20
gh search repos 'slopsquatting OR "dependency confusion" OR typosquatting in:name,description' --sort stars --limit 15
gh search repos 'sandbox policy created:>2025-01-01' --sort stars --limit 15
gh search repos 'topic:ai-security created:>2026-01-01' --sort stars --limit 15
gh search issues 'slopsquatting' --limit 8
gh search issues 'dependency confusion' --limit 8
gh issue view 1205 -R NVIDIA/SkillSpector
gh issue view 1198 -R NVIDIA/SkillSpector
```

## 2. Portfolio gap analysis

The 45 existing repositories cluster into: XML/SAML signature scope, OTel/Prometheus conformance,
sampling, cardinality and trace continuity; Kubernetes CEL/NetworkPolicy/Gateway/disruption and
Kubernetes CEL admission; OAuth/OIDC/JOSE; SLSA provenance and GitHub Actions lockfiles; OpenAPI and
GraphQL contracts; SBOM reachability; archive confinement; SSRF and HTTP desync; CSP; eBPF CO-RE;
PostgreSQL DDL; pprof; alert routes; Terraform blast radius; log masking and env drift.

**No repository decides whether a declared dependency *name* is the one the organization intended to
resolve.** The nearest neighbours solve different problems:

- `baysoz-actionlock` — GitHub Actions dependency lockfile drift only; not application manifests.
- `baysoz-provenancegate` — DSSE/SLSA artifact trust after build; it does not challenge a name at declaration time.
- `baysoz-reachoracle` — SBOM + advisory reachability; assumes the package identity is correct.
- `baysoz-archivebound` — filesystem extraction confinement; unrelated to registry namespace ownership.
- `baysoz-skillbound` / `baysoz-mcpcontract` — agent capability contracts, not package-origin policy.

This project is therefore additive, not redundant: it is the **pre-resolution boundary** that the rest
of the portfolio assumes.

## 3. Why the problem is genuinely needed in 2026-2027

1. **AI-generated dependency names are a new attack surface.** Coding agents produce plausible package
   names that do not exist. Public registries resolve first-come, first-served, so an attacker can
   register the hallucinated name and collect installs, CI secrets, and build hooks.
2. **Private namespace shadowing is still unsolved by default.** A package named `acme-internal`
   resolves from a public index when the internal registry is not explicitly scoped, even when the
   internal package exists.
3. **Parser context is where scanners fail.** The live SkillSpector issues show that the same string
   is interpreted differently in frontmatter and body, and that an environment path override can be
   invisible to a risk score. A deterministic oracle must parse each manifest kind explicitly and
   never infer structure from prose.
4. **Red teams need evidence, not vibes.** A finding must include file, line, column, evidence,
   remediation, and a stable fingerprint so a SARIF diff between two commits is meaningful.

## 4. Chosen solution

`slopsquatgate` is a Python 3.13+, stdlib-only, zero-service CLI and library that:

- parses Python (`requirements*.txt`, `pyproject.toml`, `uv.lock`), npm (`package.json`,
  `package-lock.json`, `.npmrc`), Cargo (`Cargo.toml`, `Cargo.lock`, `.cargo/config.toml`), and Go
  (`go.mod`, `go.sum`) manifests;
- applies ten deterministic rules covering Unicode confusables, near-miss names, private namespace
  shadowing, mutable references, untrusted hosts, missing integrity, install hooks, lockfile drift,
  and expired waivers;
- emits SARIF 2.1.0, JSON, and human text with explicit **Baysöz Labs <baysozlabs@proton.me>**
  attribution;
- never contacts a registry, starts a service, or loads a model.

Python 3.13 is selected because the mandated quality gate uses `uv` and `pytest`, `tomllib` is in the
standard library, and the tool must be embeddable in existing CI without a runtime.

Baysöz Labs <baysozlabs@proton.me>
