import json

from forgeguard.cli import main
from forgeguard.config import ConfigError, load_config
from forgeguard.sarif import render_sarif
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


def test_config_disables_category_and_ignores_check(tmp_path):
    (tmp_path / "forgeguard.yml").write_text(
        "version: 1\nscan:\n  documentation: false\n  actions: true\n"
        "  secrets: true\n  dependencies: true\nignore:\n  - FG-DEP-001\n"
    )
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n")
    config = load_config(tmp_path / "forgeguard.yml")
    report = scan_repository(tmp_path, config)
    assert report.checks_run == 3
    assert all(item.check_id not in {"FG-DOC-001", "FG-DEP-001"} for item in report.findings)


def test_invalid_config_is_rejected(tmp_path):
    config_path = tmp_path / "forgeguard.yml"
    config_path.write_text("version: 9\n")
    try:
        load_config(config_path)
    except ConfigError as error:
        assert "version must be 1" in str(error)
    else:
        raise AssertionError("Expected ConfigError")


def test_fingerprint_is_stable(tmp_path):
    first = scan_repository(tmp_path).findings[0]
    second = scan_repository(tmp_path).findings[0]
    assert first.fingerprint == second.fingerprint
    assert len(first.fingerprint) == 64


def test_sarif_output_has_locations_and_fingerprints(tmp_path):
    report = scan_repository(tmp_path)
    payload = render_sarif(report)
    assert payload["version"] == "2.1.0"
    result = payload["runs"][0]["results"][0]
    assert result["ruleId"].startswith("FG-")
    assert result["partialFingerprints"]["forgeguardFingerprint/v1"]


def test_cli_sarif_and_config_threshold(tmp_path, capsys):
    (tmp_path / "forgeguard.yml").write_text(
        "version: 1\nthresholds:\n  fail_on: medium\n"
    )
    assert main(["scan", str(tmp_path), "--format", "sarif"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["$schema"].endswith("sarif-2.1.0.json")
