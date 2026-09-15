from __future__ import annotations

import argparse
import json
import sys

from forgeguard import __version__
from forgeguard.models import Severity
from forgeguard.scanner import scan_repository

ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def render_text(report) -> str:
    lines = [
        "ForgeGuard Repository Report",
        "=" * 30,
        f"Path:   {report.root}",
        f"Score:  {report.score}/100",
        f"Checks: {report.checks_run}  Files: {report.files_scanned}  Findings: {len(report.findings)}",
        "",
    ]
    if not report.findings:
        lines.append("No findings. This does not guarantee the repository is secure.")
    for severity in ORDER:
        items = [f for f in report.findings if f.severity == severity]
        for finding in items:
            location = f" ({finding.path}:{finding.line})" if finding.path and finding.line else f" ({finding.path})" if finding.path else ""
            lines.extend(
                [
                    f"[{severity.value.upper()}] {finding.check_id}: {finding.title}{location}",
                    f"  {finding.message}",
                    f"  Fix: {finding.remediation}",
                ]
            )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="forgeguard", description="Scan repository security and health locally.")
    parser.add_argument("--version", action="version", version=f"ForgeGuard {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Scan a local repository")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    scan.add_argument("--fail-on", choices=("none", "critical", "high", "medium", "low"), default="none")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = scan_repository(args.path)
    except ValueError as error:
        print(f"forgeguard: error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report.to_dict(), indent=2) if args.format == "json" else render_text(report))
    if args.fail_on != "none":
        threshold = ORDER.index(Severity(args.fail_on))
        if any(ORDER.index(f.severity) <= threshold for f in report.findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

