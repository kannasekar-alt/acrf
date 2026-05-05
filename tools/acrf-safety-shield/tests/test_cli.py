"""Tests for acrf_safety_shield.cli"""
import json

import pytest
from acrf_safety_shield.cli import main


@pytest.fixture
def shield_path(tmp_path, monkeypatch):
    path = tmp_path / "shield.json"
    monkeypatch.setenv("ACRF_SAFETY_SHIELD", str(path))
    return path


def _bootstrap_admin(tmp_path, capsys):
    """Helper: generate admin and trust it. Returns (private_path, public_path)."""
    private_path = tmp_path / "admin_private.json"
    public_path = tmp_path / "admin_public.json"
    main([
        "generate-admin", "security-team",
        "--out", str(private_path),
        "--public-out", str(public_path),
    ])
    capsys.readouterr()
    main(["trust-admin", str(public_path)])
    capsys.readouterr()
    return private_path, public_path


def test_generate_admin_creates_files(tmp_path, capsys):
    priv = tmp_path / "p.json"
    pub = tmp_path / "pub.json"
    rc = main([
        "generate-admin", "test-admin",
        "--out", str(priv), "--public-out", str(pub),
    ])
    assert rc == 0
    assert priv.exists()
    assert pub.exists()
    pub_data = json.loads(pub.read_text())
    assert "private_key_b64" not in pub_data


def test_set_with_admin_succeeds(shield_path, tmp_path, capsys):
    priv, _ = _bootstrap_admin(tmp_path, capsys)

    rc = main(["set", "max_trade", "1000", "--admin", str(priv)])
    captured = capsys.readouterr()
    assert rc == 0
    assert "OK" in captured.out


def test_get_returns_value(shield_path, tmp_path, capsys):
    priv, _ = _bootstrap_admin(tmp_path, capsys)
    main(["set", "max_trade", "1000", "--admin", str(priv)])
    capsys.readouterr()

    rc = main(["get", "max_trade"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "1000" in captured.out


def test_get_returns_1_when_missing(shield_path, tmp_path, capsys):
    _bootstrap_admin(tmp_path, capsys)
    rc = main(["get", "missing_key"])
    assert rc == 1


def test_list_command(shield_path, tmp_path, capsys):
    priv, _ = _bootstrap_admin(tmp_path, capsys)
    main(["set", "a", "1", "--admin", str(priv)])
    main(["set", "b", "2", "--admin", str(priv)])
    capsys.readouterr()

    rc = main(["list"])
    captured = capsys.readouterr()
    assert rc == 0
    data = json.loads(captured.out)
    assert data == {"a": 1, "b": 2}


def test_delete_with_admin_succeeds(shield_path, tmp_path, capsys):
    priv, _ = _bootstrap_admin(tmp_path, capsys)
    main(["set", "max_trade", "1000", "--admin", str(priv)])
    capsys.readouterr()

    rc = main(["delete", "max_trade", "--admin", str(priv)])
    captured = capsys.readouterr()
    assert rc == 0
    assert "deleted" in captured.out


def test_set_handles_missing_admin_file(shield_path, tmp_path, capsys):
    rc = main(["set", "k", "v", "--admin", str(tmp_path / "missing.json")])
    assert rc == 1


def test_audit_log_command(shield_path, tmp_path, capsys):
    priv, _ = _bootstrap_admin(tmp_path, capsys)
    main(["set", "max_trade", "1000", "--admin", str(priv)])
    capsys.readouterr()

    rc = main(["audit"])
    captured = capsys.readouterr()
    assert rc == 0
    log = json.loads(captured.out)
    assert any(r["operation"] == "set_guardrail" for r in log)


def test_missing_env_var_exits_2(monkeypatch):
    monkeypatch.delenv("ACRF_SAFETY_SHIELD", raising=False)
    with pytest.raises(SystemExit) as exc_info:
        main(["list"])
    assert exc_info.value.code == 2


def test_init_creates_shield_file(tmp_path, capsys):
    path = tmp_path / "shield.json"
    rc = main(["init", "--out", str(path)])
    assert rc == 0
    assert path.exists()


def test_init_refuses_to_overwrite(tmp_path, capsys):
    path = tmp_path / "shield.json"
    main(["init", "--out", str(path)])
    capsys.readouterr()
    rc = main(["init", "--out", str(path)])
    assert rc == 1
