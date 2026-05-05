"""Tests for acrf_mcp_scan.cli"""
import json

from acrf_mcp_scan.cli import main


def _write_config(path, data):
    path.write_text(json.dumps(data))


def test_inventory_command_writes_file(tmp_path, capsys):
    cfg = tmp_path / "mcp_config.json"
    out = tmp_path / "inv.json"
    _write_config(cfg, {
        "mcpServers": {
            "A": {
                "command": "python",
                "args": [],
                "publisher": "trusted",
                "signature": "sha256:abc",
            }
        }
    })

    rc = main(["inventory", str(cfg), "--out", str(out)])
    assert rc == 0
    assert out.exists()
    data = json.loads(out.read_text())
    assert "servers" in data
    assert len(data["servers"]) == 1


def test_inventory_command_prints_json_when_no_out(tmp_path, capsys):
    cfg = tmp_path / "mcp_config.json"
    _write_config(cfg, {
        "mcpServers": {
            "A": {
                "command": "python",
                "args": [],
                "publisher": "trusted",
                "signature": "sha256:abc",
            }
        }
    })

    rc = main(["inventory", str(cfg)])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "servers" in data


def test_check_command_returns_0_when_clean(tmp_path, capsys):
    cfg = tmp_path / "mcp_config.json"
    _write_config(cfg, {
        "mcpServers": {
            "A": {
                "command": "python",
                "args": [],
                "publisher": "trusted",
                "signature": "sha256:abc",
            }
        }
    })

    rc = main(["check", str(cfg)])
    captured = capsys.readouterr()
    # Default scanner has no allowed_publishers configured, so even publisher
    # "trusted" produces no allowlist finding. Signature is present and no
    # autoApprove, so the server is clean.
    assert rc == 0
    assert "OK" in captured.out


def test_check_command_returns_1_when_suspicious(tmp_path, capsys):
    cfg = tmp_path / "mcp_config.json"
    _write_config(cfg, {
        "mcpServers": {
            "Risky": {
                "command": "python",
                "args": [],
                "publisher": "trusted",
                "signature": "sha256:abc",
                "autoApprove": ["refund_all"],
            }
        }
    })

    rc = main(["check", str(cfg)])
    assert rc == 1
    captured = capsys.readouterr()
    assert "Risky" in captured.out


def test_check_command_handles_missing_file(tmp_path, capsys):
    rc = main(["check", str(tmp_path / "missing.json")])
    assert rc == 1


def test_compare_command_detects_added(tmp_path, capsys):
    current = {
        "format_version": "1.0",
        "servers": [
            {"name": "A", "source": "x", "command": "python"},
            {"name": "B", "source": "x", "command": "python"},
        ],
    }
    trusted = {
        "format_version": "1.0",
        "servers": [
            {"name": "A", "source": "x", "command": "python"},
        ],
    }
    cur_path = tmp_path / "current.json"
    tru_path = tmp_path / "trusted.json"
    cur_path.write_text(json.dumps(current))
    tru_path.write_text(json.dumps(trusted))

    rc = main(["compare", str(cur_path), str(tru_path)])
    assert rc == 1
    captured = capsys.readouterr()
    assert "Unauthorized" in captured.out
    assert "B" in captured.out


def test_compare_command_returns_0_when_identical(tmp_path, capsys):
    payload = {
        "format_version": "1.0",
        "servers": [
            {"name": "A", "source": "x", "command": "python", "version": "1.0"},
        ],
    }
    cur_path = tmp_path / "current.json"
    tru_path = tmp_path / "trusted.json"
    cur_path.write_text(json.dumps(payload))
    tru_path.write_text(json.dumps(payload))

    rc = main(["compare", str(cur_path), str(tru_path)])
    assert rc == 0


def test_compare_command_handles_missing_file(tmp_path, capsys):
    rc = main(["compare", str(tmp_path / "missing.json"), str(tmp_path / "also_missing.json")])
    assert rc == 1
