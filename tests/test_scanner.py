import json

from forgeguard.cli import main
from forgeguard.scanner import scan_repository


def test_missing_community_files_are_reported(tmp_path):
    (tmp_path / "hello.py").write_text("print('hello')")
    report = scan_repository(tmp_path)
    titles = {item.title for item in report.findings}
    assert "Missing README.md" in titles
    assert "Missing SECURITY.md" in titles


def test_secret_is_redacted(tmp_path):
    secret = "AKIA" + "A" * 16
    (tmp_path / "config.txt").write_text(f"token={secret}")
    report = scan_repository(tmp_path)
    finding = next(item for item in report.findings if "AWS" in item.title)
    assert secret not in finding.evidence
    assert "*" in finding.evidence


def test_unpinned_action_and_write_all_are_reported(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("permissions: write-all\nsteps:\n  - uses: actions/checkout@v4\n")
    report = scan_repository(tmp_path)
    titles = {item.title for item in report.findings}
    assert "Overly broad workflow permissions" in titles
    assert "Third-party action is not pinned to a commit" in titles


def test_json_output(tmp_path, capsys):
    assert main(["scan", str(tmp_path), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "1"
    assert payload["tool"]["name"] == "ForgeGuard"

