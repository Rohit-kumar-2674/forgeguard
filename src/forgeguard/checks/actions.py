from __future__ import annotations

import re

from forgeguard.checks.base import Check
from forgeguard.files import read_text
from forgeguard.models import Finding, ScanContext, Severity

ACTION_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^\s'\"#]+)")
FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
PERMISSIONS_RE = re.compile(r"^\s*permissions:\s*(['\"]?)write-all\1\s*(?:#.*)?$")
IMAGE_DIGEST_RE = re.compile(r"@sha256:[0-9a-fA-F]{64}$")


class GitHubActionsCheck(Check):
    check_id = "FG-ACT-001"
    name = "GitHub Actions hardening"
    category = "github-actions"
    config_category = "actions"

    def run(self, context: ScanContext) -> list[Finding]:
        findings = []
        for path in context.files:
            relative = path.relative_to(context.root)
            if relative.parts[:2] != (".github", "workflows") or len(relative.parts) != 3:
                continue
            if path.suffix not in {".yml", ".yaml"}:
                continue
            text = read_text(path)
            if text is None:
                continue
            for line, line_text in enumerate(text.splitlines(), 1):
                if not PERMISSIONS_RE.match(line_text):
                    continue
                findings.append(
                    Finding(
                        self.check_id,
                        "Overly broad workflow permissions",
                        Severity.HIGH,
                        self.category,
                        "The workflow grants write access to every GitHub token scope.",
                        "Declare only the read/write scopes required by each job.",
                        relative.as_posix(),
                        line,
                        "permissions: write-all",
                        "https://docs.github.com/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token",
                    )
                )
            for number, line_text in enumerate(text.splitlines(), 1):
                match = ACTION_RE.search(line_text)
                if not match:
                    continue
                reference = match.group(1)
                if reference.startswith("./"):
                    continue
                pinned = (
                    bool(IMAGE_DIGEST_RE.search(reference)) if reference.startswith("docker://")
                    else bool(FULL_SHA_RE.fullmatch(reference.rpartition("@")[2]))
                )
                if not pinned:
                    findings.append(
                        Finding(
                            self.check_id,
                            "Third-party action is not pinned to a commit",
                            Severity.MEDIUM,
                            self.category,
                            f"{reference.split('@')[0]} uses a mutable or missing reference.",
                            "Pin a repository action to a reviewed 40-character commit SHA, or a container action to a sha256 digest.",
                            relative.as_posix(),
                            number,
                            reference,
                            "https://docs.github.com/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
                        )
                    )
        return findings
