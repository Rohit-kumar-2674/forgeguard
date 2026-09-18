# Changelog

All notable changes follow Keep a Changelog, and releases follow Semantic Versioning.

## [Unreleased]

- Prune excluded directories before traversal, skip symlinks and special files, and bound text reads to 1,000,000 bytes.
- Reject malformed configuration and missing explicit config files with actionable errors.
- Handle quoted action references, comment lines, and pinned Docker digests more accurately.
- Encode SARIF paths as portable URIs and sort findings by severity.
- Add `python -m forgeguard`, 17 regression checks, package builds, and Windows/macOS CI checks.

## [0.2.0] - 2026-09-15

### Added

- Validated local configuration with category toggles, thresholds, and ignored check IDs.
- SARIF 2.1 output for code-scanning integrations.
- Stable SHA-256 fingerprints in JSON and SARIF findings.
- CLI overrides for configuration path, ignored checks, and failure threshold.

## [0.1.0] - 2026-09-14

### Added

- Local repository scanner with four modular checks.
- Redacted secret-pattern findings.
- Human-readable and JSON reports with CI failure thresholds.
- Tests, secure CI configuration, and open-source project documentation.
