# Security — Baysöz Labs <baysozlabs@proton.me>

## Supported use

`slopsquatgate` is defensive software for authorized application-security testing, CI enforcement,
and supply-chain review. It analyzes text manifests only. It does not contact package registries,
execute package scripts, or open network sockets.

## Reporting a vulnerability

Email **baysozlabs@proton.me** with a description, a minimal manifest or policy that reproduces the
issue, the affected version, and the expected versus observed finding set. Do not open a public issue
for an unpatched security defect. Target response window: 72 hours for acknowledgement, 14 days for a
fix or a written mitigation plan.

## Threat model

| Asset | Protection |
| --- | --- |
| Manifest text | UTF-8 decode with 2 MB bound; no eval, no dynamic import, no shell execution |
| Steward policy | Strict schema; unknown keys and invalid values are fatal usage errors |
| Waivers | Time-bounded; expired waivers create SQ009 instead of silently suppressing |
| CI integrity | Stable fingerprints and canonical ordering; no wall-clock values in fingerprints |
| Reporter output | JSON/SARIF are serialized with the standard library; no template injection |

## Hardening guidance for deployment

1. Commit `policy.json` and review every change to `trusted_hosts`, `denied_hosts`, and `waivers`.
2. Pin `--as-of` in CI to the review date so waiver behavior is reproducible.
3. Run with `--fail-on high` (the default) and upload `--format sarif` output to code scanning.
4. Keep private prefixes complete; an unlisted private namespace cannot be shadow-checked.
5. Treat SQ003 and denied-host SQ005 as release blockers.

## Safe adversarial testing

Red-team fixtures should use reserved invalid domains (`*.invalid`) and fake package names. The
shipped `examples/adversarial/` directory follows this rule. Never point fixtures at a live registry
you do not own.

## Disclosure of limitations

The curated baseline is intentionally offline and versioned; it is not a live registry index. A name
outside the baseline is only flagged when it is near a known name, matches a private prefix, or is
bound to an untrusted host. Extend `allowlist` or the baseline for organization-specific packages.

Baysöz Labs <baysozlabs@proton.me>
