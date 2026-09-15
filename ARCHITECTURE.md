# Architecture

ForgeGuard 0.1 is deliberately a small Python package with four layers:

1. `models.py` defines findings, scan context, severities, and reports.
2. `checks/` contains isolated checks implementing the `Check` interface.
3. `scanner.py` orchestrates registered checks without coupling them to presentation.
4. `cli.py` renders reports and applies exit-code policy.

Checks receive a read-only repository root and return findings. They must not modify a scanned repository, make undocumented network requests, or include raw secrets in output. Future SARIF and API renderers will consume `ScanReport` rather than reimplementing scanning.

## Scoring

The initial score starts at 100 and subtracts 30/15/7/2 points for critical/high/medium/low findings. It bottoms out at zero. Informational findings have no penalty. This deliberately simple model is versioned and will evolve only with documented compatibility notes.

## Trust boundaries

Repository contents are untrusted data. Checks avoid executing repository code. Files larger than 1 MB and common generated/vendor directories are skipped by secret scanning. Network-backed vulnerability intelligence is outside the 0.1 trust boundary.

