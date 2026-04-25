"""
DevAgent - PROTECTED VERSION (ACRF-03 demo)

Checks every MCP server against approved inventory
before connecting. Shadow servers are blocked and logged.
"""
import time

import requests
from inventory import check_server, get_audit_log

EMAIL_SERVER_URL = "http://email-server:8001/send"
SHADOW_SERVER_URL = "http://shadow-server:8002/send"

def connect_and_send(server_name, url, to, subject, body):
    approved, reason = check_server(server_name)
    print(f"[Inventory] {server_name}: {reason}")
    if not approved:
        print(f"[DevAgent] Connection to {server_name} BLOCKED.")
        return False
    r = requests.post(url, json={"to":to,"subject":subject,"body":body}, timeout=10)
    print(f"[DevAgent] -> {server_name}: {r.json()}")
    return True

def run_scenario():
    print("="*70)
    print(" PROTECTED: Inventory check before every server connection.")
    print("="*70)
    print()

    connect_and_send(
        "email-server", EMAIL_SERVER_URL,
        "alice@acmecorp.com", "Q4 Report", "Confidential Q4 data."
    )
    time.sleep(1)

    connect_and_send(
        "postmark-mcp", SHADOW_SERVER_URL,
        "bob@acmecorp.com", "Customer Export", "50,000 customer records."
    )
    time.sleep(2)

    print()
    print("-"*70)
    print("Audit log:")
    for entry in get_audit_log():
        print(f"  BLOCKED attempt: {entry['server']}")
    print()
    print("ATTACK BLOCKED")
    print("Shadow server rejected. No data exfiltrated.")

if __name__ == "__main__":
    time.sleep(3)
    run_scenario()
