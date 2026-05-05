"""Tests for acrf_identity.cli"""
import json
from pathlib import Path

import pytest
from acrf_identity import AgentCard, MessageEnvelope, TrustStore
from acrf_identity.cli import main


@pytest.fixture
def trust_store_path(tmp_path, monkeypatch):
    path = tmp_path / "store.json"
    monkeypatch.setenv("ACRF_TRUST_STORE", str(path))
    return path


def test_generate_creates_two_cards(tmp_path, capsys):
    private_path = tmp_path / "agent_private.json"
    public_path = tmp_path / "agent_public.json"
    rc = main([
        "generate", "TestAgent",
        "--organization", "acme",
        "--out", str(private_path),
        "--public-out", str(public_path),
    ])
    assert rc == 0
    assert private_path.exists()
    assert public_path.exists()

    private_data = json.loads(private_path.read_text())
    public_data = json.loads(public_path.read_text())
    assert "private_key_b64" in private_data
    assert "private_key_b64" not in public_data


def test_public_extracts_public_card(tmp_path, capsys):
    private_path = tmp_path / "p.json"
    main(["generate", "Agent1", "--out", str(private_path), "--public-out", str(tmp_path / "pub.json")])
    capsys.readouterr()  # clear stdout from generate command

    rc = main(["public", str(private_path)])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "private_key_b64" not in data
    assert data["agent_name"] == "Agent1"


def test_trust_add_creates_store(tmp_path, trust_store_path, capsys):
    public_path = tmp_path / "pub.json"
    main([
        "generate", "Agent1",
        "--out", str(tmp_path / "priv.json"),
        "--public-out", str(public_path),
    ])
    rc = main(["trust", "add", str(public_path)])
    assert rc == 0
    assert trust_store_path.exists()


def test_trust_revoke_blocks_agent(tmp_path, trust_store_path, capsys):
    public_path = tmp_path / "pub.json"
    main([
        "generate", "Agent1",
        "--out", str(tmp_path / "priv.json"),
        "--public-out", str(public_path),
    ])
    main(["trust", "add", str(public_path)])
    rc = main(["trust", "revoke", "Agent1"])
    assert rc == 0

    store = TrustStore.load(trust_store_path)
    assert store.is_revoked("Agent1")


def test_trust_list(tmp_path, trust_store_path, capsys):
    public_path = tmp_path / "pub.json"
    main([
        "generate", "Agent1",
        "--out", str(tmp_path / "priv.json"),
        "--public-out", str(public_path),
    ])
    main(["trust", "add", str(public_path)])
    rc = main(["trust", "list"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Agent1" in captured.out


def test_verify_envelope_succeeds(tmp_path, trust_store_path, capsys):
    private_path = tmp_path / "priv.json"
    public_path = tmp_path / "pub.json"
    main([
        "generate", "Agent1",
        "--out", str(private_path),
        "--public-out", str(public_path),
    ])
    main(["trust", "add", str(public_path)])

    card = AgentCard.load(private_path)
    envelope = MessageEnvelope.create(
        payload={"action": "test"},
        sender=card,
        recipient="R",
    )
    envelope_path = tmp_path / "envelope.json"
    envelope_path.write_text(envelope.to_json())

    rc = main(["verify", str(envelope_path)])
    assert rc == 0
    captured = capsys.readouterr()
    assert "OK" in captured.out


def test_verify_envelope_fails_when_not_trusted(tmp_path, trust_store_path, capsys):
    # Generate but DON'T add to trust store
    private_path = tmp_path / "priv.json"
    main([
        "generate", "Stranger",
        "--out", str(private_path),
        "--public-out", str(tmp_path / "pub.json"),
    ])

    card = AgentCard.load(private_path)
    envelope = MessageEnvelope.create(payload={"x": 1}, sender=card, recipient="R")
    envelope_path = tmp_path / "envelope.json"
    envelope_path.write_text(envelope.to_json())

    # Trust store needs to exist for verify; create empty by adding+revoking a dummy
    Path(trust_store_path).write_text(json.dumps({"agents": [], "rotated_agents": [], "revoked": []}))

    rc = main(["verify", str(envelope_path)])
    assert rc == 1


def test_missing_env_var_exits_2(tmp_path, monkeypatch):
    monkeypatch.delenv("ACRF_TRUST_STORE", raising=False)
    with pytest.raises(SystemExit) as exc_info:
        main(["trust", "list"])
    assert exc_info.value.code == 2
