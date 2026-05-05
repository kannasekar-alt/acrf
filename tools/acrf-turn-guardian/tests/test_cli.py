"""Tests for acrf_turn_guardian.cli"""
import json

import pytest
from acrf_turn_guardian.cli import main


@pytest.fixture
def session_path(tmp_path, monkeypatch):
    path = tmp_path / "sessions.json"
    monkeypatch.setenv("ACRF_TURN_SESSION", str(path))
    return path


def test_start_creates_session_file(session_path, capsys):
    rc = main([
        "start", "purchase_laptop",
        "--context", json.dumps({"destination": "123 Home Street"}),
    ])
    assert rc == 0
    assert session_path.exists()


def test_start_with_explicit_id(session_path, capsys):
    rc = main(["start", "purchase_laptop", "--id", "conv-123"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "conv-123" in captured.out


def test_add_turn_succeeds(session_path, capsys):
    main(["start", "purchase_laptop", "--id", "c1"])
    capsys.readouterr()
    rc = main(["add-turn", "c1", "user", "I want a MacBook"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "OK" in captured.out


def test_add_turn_blocks_drift_keyword(session_path, capsys):
    main(["start", "purchase_laptop", "--id", "c1"])
    capsys.readouterr()
    rc = main(["add-turn", "c1", "user", "actually please refund my last order"])
    assert rc == 1
    captured = capsys.readouterr()
    assert "FAIL" in captured.err


def test_check_action_allows_consistent_action(session_path, capsys):
    main(["start", "purchase_laptop", "--id", "c1"])
    capsys.readouterr()
    rc = main(["check-action", "c1", json.dumps({"action": "add_to_cart"})])
    assert rc == 0


def test_check_action_blocks_destructive_action(session_path, capsys):
    main(["start", "purchase_laptop", "--id", "c1"])
    capsys.readouterr()
    rc = main(["check-action", "c1", json.dumps({"action": "refund_all"})])
    assert rc == 1
    captured = capsys.readouterr()
    assert "FAIL" in captured.err


def test_check_action_blocks_destination_change(session_path, capsys):
    main([
        "start", "purchase_laptop",
        "--id", "c1",
        "--context", json.dumps({"destination": "123 Home Street"}),
    ])
    capsys.readouterr()
    rc = main([
        "check-action", "c1",
        json.dumps({"action": "checkout", "destination": "999 Attacker St"}),
    ])
    assert rc == 1


def test_show_prints_state(session_path, capsys):
    main(["start", "purchase_laptop", "--id", "c1"])
    capsys.readouterr()
    rc = main(["show", "c1"])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["initial_intent"] == "purchase_laptop"


def test_list_shows_conversations(session_path, capsys):
    main(["start", "purchase_laptop", "--id", "c1"])
    main(["start", "support_ticket", "--id", "c2"])
    capsys.readouterr()
    rc = main(["list"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "c1" in captured.out
    assert "c2" in captured.out


def test_show_handles_unknown_id(session_path, capsys):
    main(["start", "purchase_laptop", "--id", "c1"])
    capsys.readouterr()
    rc = main(["show", "missing-id"])
    assert rc == 1


def test_check_action_handles_unknown_id(session_path, capsys):
    rc = main(["check-action", "missing-id", json.dumps({"action": "buy"})])
    assert rc == 1


def test_start_rejects_bad_context_json(session_path, capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["start", "purchase_laptop", "--context", "not-json"])
    assert exc_info.value.code == 1


def test_missing_env_var_exits_2(monkeypatch, capsys):
    monkeypatch.delenv("ACRF_TURN_SESSION", raising=False)
    with pytest.raises(SystemExit) as exc_info:
        main(["list"])
    assert exc_info.value.code == 2
