"""Production CLI for the dependency-origin oracle. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from datetime import date
from pathlib import Path

from slopsquatgate import ATTRIBUTION, __version__
from slopsquatgate.model import SEVERITIES, SEVERITY_RANK
from slopsquatgate.policy import Policy, PolicyError
from slopsquatgate.report import render_json, render_sarif, render_text, write_report
from slopsquatgate.rules import RULES
from slopsquatgate.scan import scan

EPILOG = f"Authored and maintained by {ATTRIBUTION}. Offline by design: no network, no services, no local models."
FORMATS = ("sarif", "json", "text")


def build_parser() -> argparse.ArgumentParser:
    """Construct the full argument parser with attribution on every help surface."""
    parser = argparse.ArgumentParser(
        prog="slopsquatgate",
        description=(
            "Offline dependency-origin conformance oracle: slopsquatting, private-namespace shadowing, "
            "mutable refs, registry drift and SARIF CI gates."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"slopsquatgate {__version__} — {ATTRIBUTION}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    scan_command = commands.add_parser(
        "scan",
        help="scan manifests in a directory",
        description="Deterministically scan Python, npm, Cargo, and Go manifests and lockfiles.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan_command.add_argument("path", nargs="?", default=".", help="repository or manifest path (default: .)")
    scan_command.add_argument("--policy", help="steward policy JSON file")
    scan_command.add_argument("--format", choices=FORMATS, default="text", help="report format (default: text)")
    scan_command.add_argument("--out", help="write report to a file instead of stdout")
    scan_command.add_argument(
        "--fail-on",
        choices=(*SEVERITIES, "never"),
        default="high",
        help="exit 1 when a finding is at or above this severity (default: high)",
    )
    scan_command.add_argument("--as-of", help="waiver evaluation date, YYYY-MM-DD (default: today)")
    scan_command.add_argument("--include", default="*", help="glob filter for relative manifest paths")
    scan_command.add_argument("--exclude", action="append", default=[], help="additional exclude glob (repeatable)")
    scan_command.add_argument("--no-baseline", action="store_true", help="disable the curated trusted-name baseline")
    scan_command.add_argument("--quiet", action="store_true", help="summary only in text format")

    policy_command = commands.add_parser(
        "init-policy",
        help="print a commented steward policy template",
        description="Emit a policy template with trusted hosts, private prefixes, and a dated waiver.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    policy_command.add_argument("--out", help="write the template to a file instead of stdout")

    explain_command = commands.add_parser(
        "explain",
        help="explain one rule",
        description="Print title, default severity, and remediation guidance for a rule.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    explain_command.add_argument("rule", help="rule identifier, for example SQ002")

    commands.add_parser(
        "rules",
        help="list all rules",
        description="List every rule with its default severity and remediation guidance.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point returning a POSIX exit status."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _run_scan(args)
        if args.command == "init-policy":
            return _run_init_policy(args)
        if args.command == "explain":
            return _run_explain(args)
        return _run_rules()
    except (PolicyError, ValueError, OSError) as error:
        print(f"error: {error} — {ATTRIBUTION}", file=sys.stderr)
        return 2


def _run_scan(args: argparse.Namespace) -> int:
    policy = Policy.load(args.policy) if args.policy else Policy()
    if args.no_baseline:
        policy = replace(policy, baseline_enabled=False)
    as_of = date.fromisoformat(args.as_of) if args.as_of else date.today()
    result = scan(
        args.path,
        policy=policy,
        as_of=as_of,
        include=args.include,
        exclude=tuple(args.exclude),
    )
    if args.format == "sarif":
        content = render_sarif(result)
    elif args.format == "json":
        content = render_json(result)
    else:
        content = render_text(result, quiet=args.quiet)
    write_report(content, args.out)
    if args.fail_on == "never":
        return 0
    threshold = SEVERITY_RANK[args.fail_on]
    return 1 if any(SEVERITY_RANK[item.severity] >= threshold for item in result.findings) else 0


def _run_init_policy(args: argparse.Namespace) -> int:
    template = Policy.template()
    if args.out:
        Path(args.out).write_text(template, encoding="utf-8")
    else:
        sys.stdout.write(template)
    return 0


def _run_explain(args: argparse.Namespace) -> int:
    rule_id = args.rule.strip().upper()
    if rule_id not in RULES:
        print(f"error: unknown rule {args.rule} — {ATTRIBUTION}", file=sys.stderr)
        return 2
    meta = RULES[rule_id]
    print(f"{rule_id} — {meta.title}")
    print(f"default severity: {meta.severity}")
    print(f"remediation: {meta.recommendation}")
    print(f"rule authored by {ATTRIBUTION}")
    return 0


def _run_rules() -> int:
    for rule_id, meta in sorted(RULES.items()):
        print(f"{rule_id} [{meta.severity:8}] {meta.title}")
    print(f"rules authored by {ATTRIBUTION}")
    return 0
