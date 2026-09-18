# Scan scope and reliable automation

ForgeGuard evaluates local repository files using explainable heuristics. It does not execute repository code, query vulnerability databases, or prove that a project is secure.

## File handling

The scanner inventories regular files beneath the selected root in a stable order. It prunes `.git`, `.venv`, `venv`, `node_modules`, `dist`, `build`, and `__pycache__` before entering those directories. Names above the selected root do not affect this scope. Symbolic links and special files are excluded.

Text checks skip binary files and files larger than 1,000,000 bytes. Reads are bounded even if a file grows during the scan. The existing JSON field `files_scanned` reports regular files inventoried, including binary and oversized files; it is not a claim that every file's contents were checked. Keep the repository stable while scanning. This is file hygiene, not an operating-system sandbox.

An unreadable file or traversal failure produces exit code 2 instead of a successful incomplete scan. Use stderr to diagnose the failure; do not treat an absent JSON report as an empty findings list.

## Configuration errors are visible

The default `<repository>/forgeguard.yml` is optional. An explicit `--config` path must exist. Configuration supports top-level keys, two-space indented mappings, a two-space indented `ignore` list, and whole-line comments. Duplicate keys, unsupported nesting, invalid types, and unknown threshold keys are errors. Files must be UTF-8 and at most 64 KB.

```bash
python -m forgeguard scan . --config forgeguard.yml --fail-on high --format json
```

| Exit | Meaning |
| --- | --- |
| 0 | Scan completed; configured severity threshold was not reached. |
| 1 | Scan completed; at least one finding reached the threshold. |
| 2 | Input, configuration, or filesystem error; scan did not complete. |

## GitHub Actions checks

Whole-line comments are ignored. Quoted action references work. Repository actions require a full commit SHA; Docker actions require a `sha256` image digest. Local `./` actions are excluded from external pin checks. These checks inspect conventional `uses:` and `permissions:` lines, not a full YAML syntax tree; block scalars and unusual YAML constructs can produce false positives or omissions.

## Portable reports

Findings are ordered by severity, then location. SARIF locations use slash-separated, percent-encoded relative URIs, including filenames containing spaces or `#`. Secret values remain redacted. Reports still contain repository paths and filenames; review them before sharing.
