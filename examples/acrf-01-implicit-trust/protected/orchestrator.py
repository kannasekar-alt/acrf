"""TravelOrchestrator Agent — PROTECTED VERSION (signs every message)."""
import base64
import hashlib
import json
import time
from pathlib import Path

import requests
from cryptography.hazmat.primitives import serialization

from keygen import ensure_keys_exist

BOOKING_SERVICE_URL = "http://booking-executor:8000/book"
AGENT_NAME = "TravelOrchestrator"

def load_private_key():
    key_path = Path(f"/app/keys/{AGENT_NAME}.private.pem")
    return serialization.load_pem_private_key(key_path.read_bytes(), password=None)

def canonicalize(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

def sign_message(payload, private_key):
    canonical = canonicalize(payload)
    signature = private_key.sign(canonical)
    return {
        "payload": payload,
        "sender": AGENT_NAME,
        "signature": base64.b64encode(signature).decode(),
        "payload_hash": hashlib.sha256(canonical).hexdigest(),
    }

def send_booking_request(user, route, amount, card_owner, private_key):
    payload = {
        "action": "book_flight",
        "user": user,
        "route": route,
        "amount": amount,
        "card_owner": card_owner,
        "timestamp": time.time(),
    }
    envelope = sign_message(payload, private_key)
    print("[TravelOrchestrator] Signing message with private key")
    print(f"[TravelOrchestrator] -> BookingExecutor: Book {route} for {user} (${amount})")
    response = requests.post(BOOKING_SERVICE_URL, json=envelope, timeout=10)
    if response.status_code == 200:
        print(f"[BookingExecutor] {response.json()['message']}")
        return True
    else:
        err = response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text
        print(f"[BookingExecutor] REJECTED: {err}")
        return False

def run_legitimate_scenario(private_key):
    print("=" * 70)
    print(" SCENARIO 1: Legitimate booking — signed with real private key")
    print("=" * 70)
    print("Alice wants to fly from SFO to JFK.")
    print("TravelOrchestrator signs the request with its Ed25519 private key.")
    print()
    send_booking_request("Alice", "SFO->JFK", 420.00, "Alice", private_key)
    print()

if __name__ == "__main__":
    ensure_keys_exist()
    time.sleep(3)
    private_key = load_private_key()
    run_legitimate_scenario(private_key)
    print("[TravelOrchestrator] Legitimate booking completed.")
    print("[TravelOrchestrator] Watch what happens when an attacker tries to spoof me...")
    print()
    time.sleep(60)
