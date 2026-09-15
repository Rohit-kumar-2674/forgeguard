from __future__ import annotations

from typing import ClassVar

from forgeguard.checks.base import Check
from forgeguard.models import Finding, ScanContext, Severity


class LockfileCheck(Check):
    check_id = "FG-DEP-001"
    name = "Dependency lockfiles"
    category = "dependencies"
    config_category = "dependencies"

    PAIRS: ClassVar[dict[str, tuple[str, ...]]] = {
        "package.json": ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb"),
        "pyproject.toml": ("uv.lock", "poetry.lock", "Pipfile.lock"),
    }

    def run(self, context: ScanContext) -> list[Finding]:
        findings = []
        for manifest, lockfiles in self.PAIRS.items():
            if (context.root / manifest).exists() and not any((context.root / f).exists() for f in lockfiles):
                findings.append(
                    Finding(
                        self.check_id,
                        f"No recognized lockfile for {manifest}",
                        Severity.LOW,
                        self.category,
                        "Unpinned dependency resolution can reduce reproducibility.",
                        f"Commit an appropriate lockfile: {', '.join(lockfiles)}.",
                        manifest,
                    )
                )
        return findings
