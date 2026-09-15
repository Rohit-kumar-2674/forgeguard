from __future__ import annotations

import re

from forgeguard.checks.base import Check
from forgeguard.models import Finding, ScanContext, Severity

PATTERNS = {
    "Private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,255}\b"),
}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build"}
MAX_FILE_BYTES = 1_000_000


def redact(value: str) -> str:
    if "PRIVATE KEY" in value:
        return "-----BEGIN ******** PRIVATE KEY-----"
    if len(value) <= 8:
        return "********"
    return f"{value[:4]}{'*' * min(12, len(value) - 8)}{value[-4:]}"


class SecretPatternsCheck(Check):
    check_id = "FG-SEC-001"
    name = "Secret patterns"
    category = "secrets"
    config_category = "secrets"

    def run(self, context: ScanContext) -> list[Finding]:
        findings = []
        for path in context.root.rglob("*"):
            if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES or b"\0" in path.read_bytes()[:1024]:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for label, pattern in PATTERNS.items():
                for match in pattern.finditer(text):
                    findings.append(
                        Finding(
                            self.check_id,
                            f"Potential {label} detected",
                            Severity.HIGH,
                            self.category,
                            "A value matching a sensitive credential pattern was found. The value is redacted.",
                            "Revoke the credential, remove it from history, and use a secret manager.",
                            str(path.relative_to(context.root)),
                            text[: match.start()].count("\n") + 1,
                            redact(match.group(0)),
                            "https://docs.github.com/code-security/secret-scanning/introduction/about-secret-scanning",
                        )
                    )
        return findings
