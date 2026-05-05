"""Tests for acrf_tokens.cli"""
import json

import pytest
from acrf_tokens import TokenIssuer
from acrf_tokens.cli import main


@pytest.fixture
def env_paths(tmp_path, monkeypatch):
    public_path = tmp_path / "public.json"
    revocations_path = tmp_path / "revocations.json"
    monkeypatch.setenv("ACRF_TOKENS_PUBLIC", str(public_path))
    monkeypatch.setenv("ACRF_TOKENS_REVOCATIONS", str(revocations_path))
    return public_path, revocations_path


def test_generate_issuer_creates_two_files(tmp_path, capsys):
    private_path = tmp_path / "issuer_priv.json"
    public_path = tmp_path / "issuer_pub.json"
    rc = main([
        "generate-issuer", "test-issuer",
        "--out", str(private_path),
        "--public-out", str(public_path),
    ])
    assert rc == 0
    assert private_path.exists()
    assert public_path.exists()

    pub_data = json.loads(public_path.read_text())
    assert "private_key_b64" not in pub_data


def test_issue_outputs_token_string(tmp_path, capsys):
    issuer_path = tmp_path / "iss.json"
    main([
        "generate-issuer", "test",
        "--out", str(issuer_path),
        "--public-out", str(tmp_path / "pub.json"),
    ])
    capsys.readouterr()  # clear

    rc = main([
        "issue",
        "--issuer", str(issuer_path),
        "--agent", "PricingAgent",
        "--scopes", "read,write",
        "--ttl", "60",
    ])
    assert rc == 0
    captured = capsys.readouterr()
    token_string = captured.out.strip()
    assert "." in token_string


def test_validate_succeeds_for_fresh_token(env_paths, tmp_path, capsys):
    public_path, revocations_path = env_paths
    issuer_path = tmp_path / "iss.json"
    main([
        "generate-issuer", "test",
        "--out", str(issuer_path),
        "--public-out", str(public_path),
    ])
    capsys.readouterr()

    main([
        "issue",
        "--issuer", str(issuer_path),
        "--agent", "A",
        "--scopes", "read",
        "--ttl", "60",
    ])
    captured = capsys.readouterr()
    token_string = captured.out.strip()

    rc = main(["validate", token_string])
    assert rc == 0
    captured = capsys.readouterr()
    assert "OK" in captured.out


def test_validate_fails_for_garbage_token(env_paths, tmp_path, capsys):
    public_path, _ = env_paths
    issuer_path = tmp_path / "iss.json"
    main([
        "generate-issuer", "test",
        "--out", str(issuer_path),
        "--public-out", str(public_path),
    ])
    capsys.readouterr()

    rc = main(["validate", "garbage.token"])
    assert rc == 1


def test_revoke_persists(env_paths, tmp_path, capsys):
    public_path, revocations_path = env_paths
    issuer_path = tmp_path / "iss.json"
    main([
        "generate-issuer", "test",
        "--out", str(issuer_path),
        "--public-out", str(public_path),
    ])
    capsys.readouterr()

    main([
        "issue",
        "--issuer", str(issuer_path),
        "--agent", "A",
        "--scopes", "read",
        "--ttl", "60",
    ])
    captured = capsys.readouterr()
    token_string = captured.out.strip()

    main(["validate", token_string])
    captured = capsys.readouterr()
    # extract token_id from output
    output = captured.out
    # parse the JSON block printed after "OK: token valid"
    json_start = output.find("{")
    claims = json.loads(output[json_start:])
    token_id = claims["token_id"]

    rc = main(["revoke", token_id])
    assert rc == 0

    # Now validation should fail
    rc = main(["validate", token_string])
    assert rc == 1


def test_list_shows_revocations(env_paths, capsys):
    public_path, _ = env_paths
    # Create empty issuer first so validator can load
    issuer = TokenIssuer.generate(issuer_name="test")
    issuer.save_public(public_path)

    main(["revoke", "abc-123"])
    capsys.readouterr()

    rc = main(["list"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "abc-123" in captured.out


def test_missing_env_var_exits_2(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ACRF_TOKENS_PUBLIC", raising=False)
    monkeypatch.delenv("ACRF_TOKENS_REVOCATIONS", raising=False)
    with pytest.raises(SystemExit) as exc_info:
        main(["validate", "anything"])
    assert exc_info.value.code == 2
