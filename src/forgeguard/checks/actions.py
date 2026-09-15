from __future__ import annotations

import re

from forgeguard.checks.base import Check
from forgeguard.models import Finding, ScanContext, Severity

ACTION_RE = re.compile(r"\buses:\s*([^\s#]+)@([^\s#]+)")
FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


class GitHubActionsCheck(Check):
    check_id = "FG-ACT-001"
    name = "GitHub Actions hardening"
    category = "github-actions"
    config_category = "actions"

    def run(self, context: ScanContext) -> list[Finding]:
        workflow_dir = context.root / ".github" / "workflows"
        if not workflow_dir.exists():
            return []
        findings = []
        for path in (*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")):
            text = path.read_text(encoding="utf-8", errors="replace")
            if "permissions: write-all" in text:
                line = text[: text.index("permissions: write-all")].count("\n") + 1
                findings.append(
                    Finding(
                        self.check_id,
                        "Overly broad workflow permissions",
                        Severity.HIGH,
                        self.category,
                        "The workflow grants write access to every GitHub token scope.",
                        "Declare only the read/write scopes required by each job.",
                        str(path.relative_to(context.root)),
                        line,
                        "permissions: write-all",
                        "https://docs.github.com/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token",
                    )
                )
            for number, line_text in enumerate(text.splitlines(), 1):
                match = ACTION_RE.search(line_text)
                if match and not match.group(1).startswith("./") and not FULL_SHA_RE.match(match.group(2)):
                    findings.append(
                        Finding(
                            self.check_id,
                            "Third-party action is not pinned to a commit",
                            Severity.MEDIUM,
                            self.category,
                            f"{match.group(1)} uses a mutable reference.",
                            "Pin the action to a reviewed 40-character commit SHA and retain a version comment.",
                            str(path.relative_to(context.root)),
                            number,
                            f"{match.group(1)}@{match.group(2)}",
                            "https://docs.github.com/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
                        )
                    )
        return findings
