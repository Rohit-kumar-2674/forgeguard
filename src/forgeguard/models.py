from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    severity: Severity
    category: str
    message: str
    remediation: str
    path: str | None = None
    line: int | None = None
    evidence: str | None = None
    documentation_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class ScanContext:
    root: Path


@dataclass
class ScanReport:
    root: str
    findings: list[Finding]
    files_scanned: int
    checks_run: int

    @property
    def score(self) -> int:
        weights = {
            Severity.CRITICAL: 30,
            Severity.HIGH: 15,
            Severity.MEDIUM: 7,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }
        return max(0, 100 - sum(weights[item.severity] for item in self.findings))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1",
            "tool": {"name": "ForgeGuard", "version": "0.1.0"},
            "root": self.root,
            "score": self.score,
            "summary": {
                severity.value: sum(f.severity == severity for f in self.findings)
                for severity in Severity
            },
            "files_scanned": self.files_scanned,
            "checks_run": self.checks_run,
            "findings": [finding.to_dict() for finding in self.findings],
        }

