"""Tests for acrf_mcp_scan.scanner"""
import json

import pytest
from acrf_mcp_scan import MCPScanner
from acrf_mcp_scan.exceptions import InvalidConfigError
from acrf_mcp_scan.inventory import (
    RISK_CRITICAL,
)
from acrf_mcp_scan.scanner import ScannerOptions


def _write_config(tmp_path, data):
    path = tmp_path / "mcp_config.json"
    path.write_text(json.dumps(data))
    return path


def test_scan_config_file_basic(tmp_path):
    cfg = _write_config(tmp_path, {
        "mcpServers": {
            "TicketApp": {
                "command": "python",
                "args": ["app.py"],
                "publisher": "trusted-vendor",
                "version": "1.0",
                "signature": "sha256:abc",
                "autoApprove": [],
            }
        }
    })
    scanner = MCPScanner(ScannerOptions(allowed_publishers={"trusted-vendor"}))
    inv = scanner.scan_config_file(cfg)

    assert len(inv.servers) == 1
    server = inv.servers[0]
    assert server.name == "TicketApp"
    assert server.publisher == "trusted-vendor"
    # Should be clean
    assert not server.is_suspicious()


def test_scan_config_flags_missing_publisher(tmp_path):
    cfg = _write_config(tmp_path, {
        "mcpServers": {
            "Mystery": {
                "command": "python",
                "args": [],
                "signature": "sha256:abc",
            }
        }
    })
    scanner = MCPScanner()
    inv = scanner.scan_config_file(cfg)
    rules = {f.rule for f in inv.servers[0].findings}
    assert "unknown_publisher" in rules


def test_scan_config_flags_missing_signature(tmp_path):
    cfg = _write_config(tmp_path, {
        "mcpServers": {
            "NoSig": {
                "command": "python",
                "args": [],
                "publisher": "x",
            }
        }
    })
    scanner = MCPScanner()
    inv = scanner.scan_config_file(cfg)
    rules = {f.rule for f in inv.servers[0].findings}
    assert "missing_signature" in rules


def test_scan_config_flags_destructive_auto_approve(tmp_path):
    cfg = _write_config(tmp_path, {
        "mcpServers": {
            "Risky": {
                "command": "python",
                "args": [],
                "publisher": "trusted-vendor",
                "signature": "sha256:abc",
                "autoApprove": ["refund_all", "delete_user"],
            }
        }
    })
    scanner = MCPScanner(ScannerOptions(allowed_publishers={"trusted-vendor"}))
    inv = scanner.scan_config_file(cfg)
    server = inv.servers[0]
    assert server.risk_level() == RISK_CRITICAL


def test_scan_config_flags_publisher_not_allowed(tmp_path):
    cfg = _write_config(tmp_path, {
        "mcpServers": {
            "Outside": {
                "command": "python",
                "args": [],
                "publisher": "rando",
                "signature": "sha256:abc",
            }
        }
    })
    scanner = MCPScanner(ScannerOptions(allowed_publishers={"trusted-vendor"}))
    inv = scanner.scan_config_file(cfg)
    rules = {f.rule for f in inv.servers[0].findings}
    assert "publisher_not_allowed" in rules


def test_scan_config_rejects_missing_file(tmp_path):
    scanner = MCPScanner()
    with pytest.raises(InvalidConfigError):
        scanner.scan_config_file(tmp_path / "nope.json")


def test_scan_config_rejects_bad_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json {{{")
    scanner = MCPScanner()
    with pytest.raises(InvalidConfigError):
        scanner.scan_config_file(bad)


def test_scan_config_rejects_missing_mcpservers(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"foo": "bar"}))
    scanner = MCPScanner()
    with pytest.raises(InvalidConfigError):
        scanner.scan_config_file(bad)


def test_scan_directory_with_package_json(tmp_path):
    server_dir = tmp_path / "weather-mcp"
    server_dir.mkdir()
    (server_dir / "package.json").write_text(json.dumps({
        "name": "weather-mcp",
        "version": "1.2.3",
        "author": "trusted-vendor",
        "description": "Weather server",
        "license": "MIT",
    }))

    scanner = MCPScanner(ScannerOptions(
        allowed_publishers={"trusted-vendor"},
        require_signature=False,
        scan_source_files=False,
    ))
    inv = scanner.scan_directory(tmp_path)
    server = inv.by_name()["weather-mcp"]
    assert server.publisher == "trusted-vendor"
    assert server.version == "1.2.3"


def test_scan_source_file_flags_dangerous_imports(tmp_path):
    server_dir = tmp_path / "evil-mcp"
    server_dir.mkdir()
    (server_dir / "main.py").write_text(
        "import subprocess\n"
        "subprocess.run([\"rm\", \"-rf\", \"/\"])\n"
    )

    scanner = MCPScanner(ScannerOptions(require_signature=False))
    inv = scanner.scan_directory(tmp_path)
    rules = {f.rule for f in inv.by_name()["evil-mcp"].findings}
    assert any(r.startswith("dangerous_import:subprocess") for r in rules)


def test_scan_source_file_flags_eval(tmp_path):
    server_dir = tmp_path / "evil-mcp"
    server_dir.mkdir()
    (server_dir / "main.py").write_text("eval(\"1 + 1\")\n")

    scanner = MCPScanner(ScannerOptions(require_signature=False))
    inv = scanner.scan_directory(tmp_path)
    findings = inv.by_name()["evil-mcp"].findings
    assert any(f.rule.startswith("dangerous_call:eval") for f in findings)


def test_scan_source_file_flags_external_url(tmp_path):
    server_dir = tmp_path / "exfil-mcp"
    server_dir.mkdir()
    (server_dir / "main.py").write_text(
        "URL = \"https://evil-collector.example.com/leak\"\n"
    )

    scanner = MCPScanner(ScannerOptions(
        require_signature=False,
        allowed_network_hosts={"trusted-api.example.com"},
    ))
    inv = scanner.scan_directory(tmp_path)
    findings = inv.by_name()["exfil-mcp"].findings
    rules = [f.rule for f in findings]
    assert "network_endpoint" in rules


def test_scan_source_file_allows_localhost(tmp_path):
    server_dir = tmp_path / "local-mcp"
    server_dir.mkdir()
    (server_dir / "main.py").write_text(
        "URL = \"http://localhost:8080/api\"\n"
    )

    scanner = MCPScanner(ScannerOptions(require_signature=False))
    inv = scanner.scan_directory(tmp_path)
    rules = {f.rule for f in inv.by_name()["local-mcp"].findings}
    assert "network_endpoint" not in rules
