# ForgeGuard

**Secure. Maintain. Understand. Ship.**

ForgeGuard is a local-first, open-source repository security and health scanner. It gives maintainers explainable findings without uploading source code or discovered credentials.

> [!IMPORTANT]
> ForgeGuard is an early alpha. It reduces review toil; it does not guarantee that software is secure.

## Current capabilities

- Finds missing community-health files.
- Flags `permissions: write-all` and third-party GitHub Actions not pinned to a commit SHA.
- Detects a conservative set of credential patterns and always redacts matching values.
- Reports missing npm and Python lockfiles.
- Produces human-readable, stable JSON, and SARIF 2.1 reports.
- Supports configurable CI failure thresholds.
- Supports category toggles and ignored check IDs through `forgeguard.yml`.
- Emits deterministic finding fingerprints for result tracking.
- Uses only the Python standard library at runtime.

## Quick start

Python 3.10 or newer is required.

```bash
python -m pip install -e .
forgeguard scan /path/to/repository
forgeguard scan . --format json
forgeguard scan . --format sarif > forgeguard.sarif
forgeguard scan . --fail-on high
```

Run tests:

```bash
python -m pip install -e '.[dev]'
pytest
ruff check .
```

## Design promises

- Local processing and no telemetry by default.
- Findings include evidence, severity, remediation, and references.
- Potential secrets are never printed in full.
- Built-in checks share a small, documented interface.
- Scores are deterministic and explainable, not claims of absolute security.

See [the architecture](ARCHITECTURE.md), [roadmap](ROADMAP.md), and [contribution guide](CONTRIBUTING.md).

## Configuration

ForgeGuard automatically reads `forgeguard.yml` from the scanned repository. Its deliberately
small YAML subset supports booleans, strings, integers, nested mappings, and the `ignore` list:

```yaml
version: 1
scan:
  documentation: true
  actions: true
  secrets: true
  dependencies: true
thresholds:
  fail_on: high
ignore:
  - FG-DOC-001
```

Use `--config path/to/file.yml` to select another file, or repeat `--ignore FG-ID` for temporary
command-line exclusions. Unknown keys and invalid values fail closed with a clear error.

## License

MIT © Rocky
