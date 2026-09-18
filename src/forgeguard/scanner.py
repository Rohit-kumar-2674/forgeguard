from __future__ import annotations

from pathlib import Path

from forgeguard.checks import BUILTIN_CHECKS
from forgeguard.config import Config
from forgeguard.files import repository_files
from forgeguard.models import ScanContext, ScanReport, Severity


def scan_repository(path: str | Path, config: Config | None = None) -> ScanReport:
    root = Path(path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Repository path is not a directory: {root}")
    context = ScanContext(root=root, files=repository_files(root))
    config = config or Config()
    checks = [check_type() for check_type in BUILTIN_CHECKS]
    checks = [check for check in checks if config.enabled[check.config_category]]
    findings = [finding for check in checks for finding in check.run(context)]
    findings = [finding for finding in findings if finding.check_id not in config.ignore]
    priority = {severity: index for index, severity in enumerate(Severity)}
    findings.sort(key=lambda f: (priority[f.severity], f.path or "", f.line or 0, f.check_id))
    return ScanReport(str(root), findings, len(context.files), len(checks))
