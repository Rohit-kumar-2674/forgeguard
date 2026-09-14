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
- Produces human-readable and stable JSON reports.
- Supports configurable CI failure thresholds.
- Uses only the Python standard library at runtime.

## Quick start

Python 3.10 or newer is required.

```bash
python -m pip install -e .
forgeguard scan /path/to/repository
forgeguard scan . --format json
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

## License

MIT © Rocky

