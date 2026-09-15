from __future__ import annotations

from typing import ClassVar

from forgeguard.checks.base import Check
from forgeguard.models import Finding, ScanContext, Severity


class CommunityFilesCheck(Check):
    check_id = "FG-DOC-001"
    name = "Community files"
    category = "documentation"
    config_category = "documentation"

    REQUIRED: ClassVar[dict[str, tuple[Severity, str]]] = {
        "README.md": (Severity.MEDIUM, "Add a README explaining purpose, installation, and use."),
        "LICENSE": (Severity.MEDIUM, "Add an OSI-approved license file."),
        "SECURITY.md": (Severity.LOW, "Document a private vulnerability reporting process."),
        "CONTRIBUTING.md": (Severity.LOW, "Document how contributors can develop and submit changes."),
    }

    def run(self, context: ScanContext) -> list[Finding]:
        findings = []
        names = {path.name.lower() for path in context.root.iterdir() if path.is_file()}
        for filename, (severity, remediation) in self.REQUIRED.items():
            if filename.lower() not in names:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title=f"Missing {filename}",
                        severity=severity,
                        category=self.category,
                        message=f"The repository root does not contain {filename}.",
                        remediation=remediation,
                        path=filename,
                        documentation_url="https://docs.github.com/communities/setting-up-your-project-for-healthy-contributions",
                    )
                )
        return findings
