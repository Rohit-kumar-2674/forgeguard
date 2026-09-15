# Contributing

Thank you for improving ForgeGuard. Open an issue before large architectural work. Small fixes can go directly to a pull request.

1. Fork and clone the repository.
2. Create a virtual environment.
3. Run `python -m pip install -e '.[dev]'`.
4. Add tests for behavior changes.
5. Run `pytest` and `ruff check .`.
6. Submit a focused pull request using the template.

New checks must have a unique ID, explain their evidence and remediation, avoid executing repository code, redact secrets, and include positive and negative fixtures.

