"""
Inventory checker - ACRF-03 defense layer.
Validates every MCP server connection against approved inventory.
Implements SS-1 and SS-2 control objectives.
"""
from pathlib import Path

import yaml

INVENTORY_PATH = Path("/app/inventory.yaml")
audit_log = []

def load_inventory():
    with open(INVENTORY_PATH) as f:
        data = yaml.safe_load(f)
    return {s["name"]: s for s in data["approved_servers"]}

def check_server(server_name: str) -> tuple[bool, str]:
    inventory = load_inventory()
    if server_name in inventory:
        return True, f"APPROVED - {server_name} is in the approved inventory"
    audit_log.append({"server": server_name, "result": "BLOCKED"})
    return False, f"BLOCKED - {server_name} is not in the approved inventory"

def get_audit_log():
    return audit_log
