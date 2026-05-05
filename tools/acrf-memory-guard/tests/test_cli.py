"""Tests for acrf_memory_guard.cli"""
import json
import tempfile
from pathlib import Path

import pytest
from acrf_memory_guard import sign_entry
from acrf_memory_guard.cli import main

SECRET = "test-secret-key-do-not-use-in-production"


@pytest.fixture
def temp_store():
    """Create a JSON memory store with two valid signed entries."""
    store = {
        "john": sign_entry({"user_id": "john", "role": "Junior Dev"}, SECRET),
        "alice": sign_entry({"user_id": "alice", "role": "Manager"}, SECRET),
    }
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)  # noqa: SIM115
    json.dump(store, tmp)
    tmp.close()
    yield Path(tmp.name)
    Path(tmp.name).unlink(missing_ok=True)


@pytest.fixture
def secret_env(monkeypatch):
    monkeypatch.setenv("ACRF_MEMORY_SECRET", SECRET)


def test_verify_store_succeeds(temp_store, secret_env, capsys):
    rc = main(["verify-store", str(temp_store)])
    assert rc == 0
    captured = capsys.readouterr()
    assert "OK" in captured.out
    assert "2 entries verified" in captured.out


def test_verify_store_fails_when_tampered(temp_store, secret_env, capsys):
    # Tamper with one entry
    store = json.loads(temp_store.read_text())
    store["john"]["role"] = "SysAdmin"
    temp_store.write_text(json.dumps(store))

    rc = main(["verify-store", str(temp_store)])
    assert rc == 1
    captured = capsys.readouterr()
    assert "FAIL" in captured.err
    assert "john" in captured.err


def test_verify_store_fails_when_unsigned_entry(temp_store, secret_env, capsys):
    # Add an unsigned entry
    store = json.loads(temp_store.read_text())
    store["bob"] = {"user_id": "bob", "role": "Manager"}
    temp_store.write_text(json.dumps(store))

    rc = main(["verify-store", str(temp_store)])
    assert rc == 1
    captured = capsys.readouterr()
    assert "FAIL" in captured.err
    assert "bob" in captured.err


def test_verify_store_handles_missing_file(secret_env, capsys):
    rc = main(["verify-store", "/tmp/does-not-exist-acrf-memory-test.json"])
    assert rc == 1


def test_missing_secret_env_var_exits_2(temp_store, monkeypatch):
    monkeypatch.delenv("ACRF_MEMORY_SECRET", raising=False)
    with pytest.raises(SystemExit) as exc_info:
        main(["verify-store", str(temp_store)])
    assert exc_info.value.code == 2


def test_verify_store_handles_invalid_json(secret_env, capsys, tmp_path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("not valid json {{{")
    rc = main(["verify-store", str(bad_file)])
    assert rc == 1
    captured = capsys.readouterr()
    assert "not valid JSON" in captured.err
