"""Tests for acrf_mcp_scan.inventory"""
import json

import pytest
from acrf_mcp_scan import MCPServer, MCPServerInventory
from acrf_mcp_scan.exceptions import InventoryError
from acrf_mcp_scan.inventory import (
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_NONE,
)


def test_server_with_no_findings_is_not_suspicious():
    server = MCPServer(name="Clean", source="config.json")
    assert server.risk_level() == RISK_NONE
    assert not server.is_suspicious()


def test_server_with_low_finding_is_not_suspicious():
    server = MCPServer(name="Mild", source="config.json")
    server.add_finding(rule="missing_description", severity=RISK_LOW, detail="no readme")
    assert server.risk_level() == RISK_LOW
    assert not server.is_suspicious()


def test_server_with_medium_finding_is_suspicious():
    server = MCPServer(name="Mid", source="config.json")
    server.add_finding(rule="auto_approve_present", severity=RISK_MEDIUM, detail="x")
    assert server.is_suspicious()


def test_server_risk_is_max_of_findings():
    server = MCPServer(name="Mixed", source="config.json")
    server.add_finding(rule="r1", severity=RISK_LOW, detail="")
    server.add_finding(rule="r2", severity=RISK_CRITICAL, detail="")
    server.add_finding(rule="r3", severity=RISK_MEDIUM, detail="")
    assert server.risk_level() == RISK_CRITICAL


def test_inventory_save_and_load(tmp_path):
    inventory = MCPServerInventory()
    s1 = MCPServer(name="A", source="c.json", command="python", version="1.0")
    s1.add_finding(rule="r", severity=RISK_HIGH, detail="x")
    inventory.add(s1)
    inventory.add(MCPServer(name="B", source="c.json"))

    path = tmp_path / "inv.json"
    inventory.save(path)

    loaded = MCPServerInventory.load(path)
    assert len(loaded.servers) == 2
    assert loaded.by_name()["A"].command == "python"
    assert loaded.by_name()["A"].risk_level() == RISK_HIGH


def test_inventory_load_rejects_bad_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json {{{")
    with pytest.raises(InventoryError):
        MCPServerInventory.load(bad)


def test_inventory_load_rejects_missing_servers_field(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"format_version": "1.0"}))
    with pytest.raises(InventoryError):
        MCPServerInventory.load(bad)


def test_inventory_diff_added_and_removed():
    current = MCPServerInventory()
    current.add(MCPServer(name="A", source="c"))
    current.add(MCPServer(name="B", source="c"))

    trusted = MCPServerInventory()
    trusted.add(MCPServer(name="A", source="t"))
    trusted.add(MCPServer(name="C", source="t"))

    diff = current.diff(trusted)
    assert {s.name for s in diff.added} == {"B"}
    assert {s.name for s in diff.removed} == {"C"}


def test_inventory_diff_changed_command():
    current = MCPServerInventory()
    current.add(MCPServer(name="A", source="c", command="python", version="2.0"))

    trusted = MCPServerInventory()
    trusted.add(MCPServer(name="A", source="t", command="node", version="2.0"))

    diff = current.diff(trusted)
    assert len(diff.changed) == 1
    assert diff.changed[0][0].command == "python"
    assert diff.changed[0][1].command == "node"


def test_inventory_diff_empty_when_identical():
    inv = MCPServerInventory()
    inv.add(MCPServer(name="A", source="c", command="python", version="1.0"))
    diff = inv.diff(inv)
    assert diff.is_empty()


def test_server_count_by_risk():
    inv = MCPServerInventory()
    s1 = MCPServer(name="A", source="c")
    s1.add_finding(rule="r", severity=RISK_HIGH, detail="")
    inv.add(s1)
    s2 = MCPServer(name="B", source="c")
    s2.add_finding(rule="r", severity=RISK_LOW, detail="")
    inv.add(s2)
    inv.add(MCPServer(name="C", source="c"))

    counts = inv.server_count_by_risk()
    assert counts[RISK_HIGH] == 1
    assert counts[RISK_LOW] == 1
    assert counts[RISK_NONE] == 1
