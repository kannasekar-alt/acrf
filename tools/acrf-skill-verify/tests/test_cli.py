"""Tests for acrf_skill_verify.cli"""
import json

import pytest
from acrf_skill_verify.cli import main


@pytest.fixture
def skill_file(tmp_path):
    f = tmp_path / "skill.py"
    f.write_text("legitimate code")
    return f


@pytest.fixture
def registry_path(tmp_path, monkeypatch):
    path = tmp_path / "registry.json"
    monkeypatch.setenv("ACRF_SKILL_REGISTRY", str(path))
    return path


def test_hash_command_outputs_sha256(skill_file, capsys):
    rc = main(["hash", str(skill_file)])
    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out.strip().startswith("sha256:")


def test_hash_command_handles_missing_file(capsys):
    rc = main(["hash", "/tmp/does-not-exist-acrf-skill-test.py"])
    assert rc == 1


def test_register_creates_entry(skill_file, registry_path, capsys):
    rc = main(["register", "good-skill", str(skill_file)])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Registered" in captured.out
    assert registry_path.exists()

    data = json.loads(registry_path.read_text())
    assert "good-skill" in data["approved"]


def test_block_adds_to_blocklist(registry_path, capsys):
    rc = main(["block", "malicious-skill"])
    assert rc == 0
    data = json.loads(registry_path.read_text())
    assert "malicious-skill" in data["blocklist"]


def test_verify_succeeds_after_register(skill_file, registry_path, capsys):
    main(["register", "good-skill", str(skill_file)])
    rc = main(["verify", "good-skill", str(skill_file)])
    assert rc == 0
    captured = capsys.readouterr()
    assert "OK" in captured.out


def test_verify_fails_when_tampered(skill_file, registry_path, capsys):
    main(["register", "good-skill", str(skill_file)])
    skill_file.write_text("malicious code")
    rc = main(["verify", "good-skill", str(skill_file)])
    assert rc == 1
    captured = capsys.readouterr()
    assert "FAIL" in captured.err


def test_verify_fails_when_unregistered(skill_file, registry_path, capsys):
    # Create empty registry
    main(["block", "_dummy"])
    rc = main(["verify", "unknown-skill", str(skill_file)])
    assert rc == 1


def test_list_shows_approved_and_blocked(skill_file, registry_path, capsys):
    main(["register", "good-skill", str(skill_file)])
    main(["block", "evil-skill"])
    rc = main(["list"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "good-skill" in captured.out
    assert "evil-skill" in captured.out


def test_list_handles_missing_registry(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ACRF_SKILL_REGISTRY", str(tmp_path / "nonexistent.json"))
    rc = main(["list"])
    assert rc == 0


def test_missing_env_var_exits_2(skill_file, monkeypatch):
    monkeypatch.delenv("ACRF_SKILL_REGISTRY", raising=False)
    with pytest.raises(SystemExit) as exc_info:
        main(["register", "good-skill", str(skill_file)])
    assert exc_info.value.code == 2


def test_register_handles_missing_skill_path(registry_path, capsys):
    rc = main(["register", "bad", "/tmp/does-not-exist-acrf-skill.py"])
    assert rc == 1


def test_verify_handles_missing_registry(skill_file, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ACRF_SKILL_REGISTRY", str(tmp_path / "nonexistent.json"))
    rc = main(["verify", "anything", str(skill_file)])
    assert rc == 1
