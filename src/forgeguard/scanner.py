from __future__ import annotations

from pathlib import Path

from forgeguard.checks import BUILTIN_CHECKS
from forgeguard.models import ScanContext, ScanReport

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build"}


def scan_repository(path: str | Path) -> ScanReport:
    root = Path(path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Repository path is not a directory: {root}")
    context = ScanContext(root=root)
    findings = [finding for check_type in BUILTIN_CHECKS for finding in check_type().run(context)]
    findings.sort(key=lambda f: (f.severity.value, f.path or "", f.line or 0, f.check_id))
    files_scanned = sum(
        1
        for item in root.rglob("*")
        if item.is_file() and not any(part in SKIP_DIRS for part in item.parts)
    )
    return ScanReport(str(root), findings, files_scanned, len(BUILTIN_CHECKS))

