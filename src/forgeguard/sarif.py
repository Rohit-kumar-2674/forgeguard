from __future__ import annotations

from urllib.parse import quote

from forgeguard import __version__
from forgeguard.models import ScanReport, Severity

SARIF_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def render_sarif(report: ScanReport) -> dict:
    unique_rules = {}
    results = []
    for finding in report.findings:
        unique_rules.setdefault(
            finding.check_id,
            {
                "id": finding.check_id,
                "name": finding.title.replace(" ", ""),
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.remediation},
                "helpUri": finding.documentation_url,
                "properties": {"category": finding.category},
            },
        )
        result = {
            "ruleId": finding.check_id,
            "level": SARIF_LEVELS[finding.severity],
            "message": {"text": finding.message},
            "partialFingerprints": {"forgeguardFingerprint/v1": finding.fingerprint},
        }
        if finding.path:
            location = {"artifactLocation": {"uri": quote(finding.path.replace("\\", "/"), safe="/")}}
            if finding.line:
                location["region"] = {"startLine": finding.line}
            result["locations"] = [{"physicalLocation": location}]
        results.append(result)
    rules = []
    for rule in unique_rules.values():
        if rule["helpUri"] is None:
            del rule["helpUri"]
        rules.append(rule)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ForgeGuard",
                        "informationUri": "https://github.com/Rohit-kumar-2674/forgeguard",
                        "semanticVersion": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
