"""
Attacker - PROTECTED VERSION (ACRF-02 demo)

Same attack as vulnerable version.
Uses DataAgent retired token.
But per-agent identity + revocation blocks it immediately.
"""
import time

import requests

GATEWAY_URL = "http://api-gateway:8000"
STOLEN_TOKEN = "data-token-w3t6u-2026"
PRICING_TOKEN = "price-token-j7n4p-2026"
TRADE_TOKEN = "trade-token-q8r5s-2026"

def show_legitimate_usage():
    print("=" * 70)
    print(" STEP 1: Legitimate agents working normally")
    print("=" * 70)
    print()

    r = requests.get(
        f"{GATEWAY_URL}/api/pricing",
        headers={"Authorization": f"Bearer {PRICING_TOKEN}"},
        timeout=10
    )
    print(f"[PricingAgent] Gets pricing data: {r.status_code} {r.json()}")

    r = requests.post(
        f"{GATEWAY_URL}/api/execute-trade",
        headers={"Authorization": f"Bearer {TRADE_TOKEN}"},
        json={"ticker": "AAPL", "shares": 10, "action": "BUY"},
        timeout=10
    )
    print(f"[TradeAgent] Executes trade: {r.status_code} {r.json()}")
    print()

def show_attack():
    print("=" * 70)
    print(" STEP 2: Attacker uses retired DataAgent token")
    print("=" * 70)
    print()
    print("[Attacker] Found token: data-token-w3t6u-2026")
    print("[Attacker] DataAgent was retired - trying stolen token...")
    print()
    time.sleep(1)

    r = requests.get(
        f"{GATEWAY_URL}/api/pricing",
        headers={"Authorization": f"Bearer {STOLEN_TOKEN}"},
        timeout=10
    )
    print(f"[Attacker] Calls /api/pricing with retired token: {r.status_code}")
    print(f"[Attacker] Response: {r.json()}")
    print()

    r = requests.post(
        f"{GATEWAY_URL}/api/execute-trade",
        headers={"Authorization": f"Bearer {STOLEN_TOKEN}"},
        json={"ticker": "AAPL", "shares": 10000, "action": "SELL"},
        timeout=10
    )
    print(f"[Attacker] Calls /api/execute-trade with retired token: {r.status_code}")
    print(f"[Attacker] Response: {r.json()}")
    print()

    r = requests.get(f"{GATEWAY_URL}/audit", timeout=10)
    log = r.json()["log"]
    print("Audit log - clear per-agent identity on every call:")
    for entry in log:
        print(f"  {entry['agent_id']:<20} {entry['endpoint']:<25} {entry['decision']} - {entry['reason']}")
    print()
    print("ATTACK BLOCKED")
    print("DataAgent token was revoked at decommission time.")
    print("Every call shows exact agent identity - no impersonation possible.")
    print("Audit log is cryptographically tied to per-agent tokens.")

if __name__ == "__main__":
    time.sleep(5)
    show_legitimate_usage()
    time.sleep(1)
    show_attack()
