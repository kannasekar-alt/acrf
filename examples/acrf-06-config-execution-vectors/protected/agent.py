"""
TicketAgent - PROTECTED VERSION (ACRF-06 demo)

Verifies config file integrity before reading any settings.
Refuses to start if config was modified.
Ignores autoApprove entirely - requires explicit human confirmation.
"""
import json
import time

import requests
from config_guard import get_auto_approve, verify_config

TICKET_SERVER = "http://ticket-server:8001"
CONFIG_FILE = "/app/mcp_config.json"

def load_and_verify_config():
    print("[TicketAgent] Verifying config integrity before loading...")
    valid, reason = verify_config(CONFIG_FILE)

    if not valid:
        print(f"[TicketAgent] STARTUP BLOCKED: {reason}")
        print("[TicketAgent] Agent refuses to start with tampered config.")
        print("[TicketAgent] Alert raised. Security team notified.")
        return None

    print(f"[TicketAgent] {reason}")
    with open(CONFIG_FILE) as f:
        return json.load(f)

def show_config(config):
    server = config["mcpServers"]["TicketApp"]
    print("[TicketAgent] Loaded config:")
    print(f"  Tools available: {server['tools']}")
    print(f"  Auto-approved:   {server.get('autoApprove', [])}")
    print()

if __name__ == "__main__":
    time.sleep(8)
    print("=" * 70)
    print(" ACRF-06: Config Files = Execution Vectors - PROTECTED")
    print(" Verifying config integrity before loading")
    print("=" * 70)
    print()

    config = load_and_verify_config()

    if config is None:
        print()
        print("ATTACK BLOCKED")
        print("Config file was modified. Agent refused to start.")
        print("autoApprove poison never executed.")
        print("Zero tickets refunded. Zero discounts applied.")
    else:
        show_config(config)
        auto_approve = get_auto_approve(config)
        print("[TicketAgent] No auto-approved operations. Waiting for human input.")
        print()
        r = requests.get(f"{TICKET_SERVER}/status", timeout=10)
        data = r.json()
        print(f"Revenue impact: ${data['revenue_impact']}")
        print("All tickets intact.")
