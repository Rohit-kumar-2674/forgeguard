import json
import os

import pytest

from forgeguard.cli import main
from forgeguard.config import ConfigError, load_config
from forgeguard.sarif import render_sarif
from forgeguard.scanner import scan_repository


@pytest.mark.parametrize(
    "body",
    [
        "version: true\n",
        "version: 1\nscan: false\n",
        "version: 1\nthresholds: 3\n",
        "version: 1\nthresholds:\n  typo: high\n",
        "version: 1\nignore:\n  bad: value\n",
        "version: 1\nversion: 1\n",
        "version: 1\nscan:\n  secrets: true\n  secrets: false\n",
        "version: 1\nscan:\n    secrets: false\n",
        "version: 1\nscan:\n\tsecrets: false\n",
    ],
)
def test_bad_config_shapes_raise_config_error(tmp_path, body):
    path = tmp_path / "forgeguard.yml"
    path.write_text(body)
    with pytest.raises(ConfigError):
        load_config(path)


def test_explicit_missing_config_is_not_silently_ignored(tmp_path, capsys):
    assert main(["scan", str(tmp_path), "--config", str(tmp_path / "typo.yml")]) == 2
    assert "does not exist" in capsys.readouterr().err


def test_root_inside_a_directory_named_node_modules_is_scanned(tmp_path):
    root = tmp_path / "node_modules" / "my-project"
    root.mkdir(parents=True)
    (root / "example.txt").write_text("AKIA" + "A" * 16)
    report = scan_repository(root)
    assert report.files_scanned == 1
    assert any(f.category == "secrets" for f in report.findings)


def test_ignored_tree_is_not_entered(tmp_path, monkeypatch):
    ignored = tmp_path / "node_modules"
    ignored.mkdir()
    (ignored / "private.txt").write_text("AKIA" + "A" * 16)
    original = os.scandir

    def guarded(path):
        assert os.fspath(path) != os.fspath(ignored)
        return original(path)

    monkeypatch.setattr(os, "scandir", guarded)
    assert scan_repository(tmp_path).files_scanned == 0


def test_symlink_files_and_directories_are_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "credential.txt").write_text("AKIA" + "A" * 16)
    root = tmp_path / "repo"
    root.mkdir()
    try:
        (root / "linked.txt").symlink_to(outside / "credential.txt")
        (root / "linked-dir").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Creating symlinks is not permitted on this runner")
    report = scan_repository(root)
    assert report.files_scanned == 0
    assert not any(f.category == "secrets" for f in report.findings)


def test_oversized_and_binary_files_are_not_secret_scanned(tmp_path):
    (tmp_path / "large.txt").write_bytes(("AKIA" + "A" * 16).encode() + b"x" * 1_000_000)
    (tmp_path / "binary.bin").write_bytes(b"\0" + ("AKIA" + "A" * 16).encode())
    assert not any(f.category == "secrets" for f in scan_repository(tmp_path).findings)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO is a POSIX file type")
def test_special_files_are_not_opened(tmp_path):
    os.mkfifo(tmp_path / "pipe")
    assert scan_repository(tmp_path).files_scanned == 0


def test_actions_comments_quoted_pins_and_container_digests(tmp_path):
    folder = tmp_path / ".github" / "workflows"
    folder.mkdir(parents=True)
    (folder / "ci.yml").write_text(
        "# permissions: write-all\n# - uses: actions/checkout@main\n"
        + '- uses: "actions/checkout@'
        + "a" * 40
        + '"\n'
        + "- uses: docker://alpine@sha256:"
        + "b" * 64
        + "\n"
        + "- uses: ./local-action\n"
    )
    assert not any(f.category == "github-actions" for f in scan_repository(tmp_path).findings)
    (folder / "bad.yml").write_text('permissions: "write-all"\n- uses: docker://alpine:latest\n')
    assert (
        len([f for f in scan_repository(tmp_path).findings if f.category == "github-actions"]) == 2
    )


def test_sarif_paths_are_uris_and_secrets_stay_redacted(tmp_path):
    secret = "AKIA" + "A" * 16
    (tmp_path / "key # one.txt").write_text(secret)
    report = scan_repository(tmp_path)
    sarif = render_sarif(report)
    result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "FG-SEC-001")
    assert (
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "key%20%23%20one.txt"
    )
    assert secret not in json.dumps(report.to_dict())
