from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from forgeguard import __version__
from forgeguard.config import Config, ConfigError, load_config
from forgeguard.models import Severity
from forgeguard.sarif import render_sarif
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
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("--config", type=Path, help="Configuration file (default: <path>/forgeguard.yml)")
    scan.add_argument("--ignore", action="append", default=[], metavar="CHECK_ID")
    scan.add_argument("--fail-on", choices=("none", "critical", "high", "medium", "low"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = Path(args.path).expanduser().resolve()
        config_path = args.config if args.config else root / "forgeguard.yml"
        config = load_config(config_path, required=args.config is not None)
        config = Config(config.enabled, config.ignore | frozenset(args.ignore), args.fail_on or config.fail_on)
        report = scan_repository(root, config)
    except (ValueError, ConfigError, OSError) as error:
        print(f"forgeguard: error: {error}", file=sys.stderr)
        return 2
    payload = render_sarif(report) if args.format == "sarif" else report.to_dict()
    print(json.dumps(payload, indent=2) if args.format in {"json", "sarif"} else render_text(report))
    if config.fail_on != "none":
        threshold = ORDER.index(Severity(config.fail_on))
        if any(ORDER.index(f.severity) <= threshold for f in report.findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
