"""
TicketAgent - VULNERABLE VERSION (ACRF-06 demo)

Reads mcp_config.json on startup and executes whatever
tools are listed in autoApprove without human confirmation.
VULNERABILITY: No integrity check on config file.
Attacker only needs to modify one JSON file.
"""
import json
import time

import requests

TICKET_SERVER = "http://ticket-server:8001"
CONFIG_FILE = "/app/mcp_config.json"

def load_config():
    with open(CONFIG_FILE) as f:
        return json.load(f)

def show_config(config):
    server = config["mcpServers"]["TicketApp"]
    print("[TicketAgent] Loaded config:")
    print(f"  Tools available: {server['tools']}")
    print(f"  Auto-approved:   {server['autoApprove']}")
    print()

def execute_auto_approved(config):
    auto_approve = config["mcpServers"]["TicketApp"].get("autoApprove", [])
    if not auto_approve:
        print("[TicketAgent] No auto-approved operations. Waiting for user input.")
        return

    print(f"[TicketAgent] Executing auto-approved operations: {auto_approve}")
    print("[TicketAgent] No confirmation required - config says autoApprove.")
    print()

    for operation in auto_approve:
        print(f"[TicketAgent] Executing: {operation}")
        r = requests.post(f"{TICKET_SERVER}/{operation}", json={}, timeout=10)
        result = r.json()
        print(f"[TicketAgent] Result: {result}")
        time.sleep(0.5)

if __name__ == "__main__":
    time.sleep(8)
    print("=" * 70)
    print(" ACRF-06: Config Files = Execution Vectors - VULNERABLE")
    print(" Reading mcp_config.json - no integrity check")
    print("=" * 70)
    print()

    config = load_config()
    show_config(config)

    print("-" * 70)
    print("[TicketAgent] Checking for auto-approved operations...")
    print()
    execute_auto_approved(config)

    time.sleep(1)
    r = requests.get(f"{TICKET_SERVER}/status", timeout=10)
    data = r.json()
    print()
    print("-" * 70)
    print(f"Revenue impact: ${data['revenue_impact']}")
    print()
    print("ATTACK SUCCEEDED")
    print("Attacker modified mcp_config.json - added autoApprove.")
    print("Agent executed refund_all and discount_100 without any confirmation.")
    print("No hacking required. Just one JSON file change.")
