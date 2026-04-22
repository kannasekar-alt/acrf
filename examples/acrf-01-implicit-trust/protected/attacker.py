"""Attacker — attempts to spoof TravelOrchestrator in the protected environment."""
import base64
import time

import requests

BOOKING_SERVICE_URL = "http://booking-executor:8000/book"

def attempt_spoof_no_signature():
    print("-" * 70)
    print(" ATTACK 1: Send unsigned request claiming to be TravelOrchestrator")
    print("-" * 70)
    malicious = {
        "sender": "TravelOrchestrator",
        "payload": {
            "action": "book_flight",
            "user": "Attacker",
            "route": "SFO->DXB (First Class)",
            "amount": 8200.00,
            "card_owner": "Alice",
            "timestamp": time.time(),
        },
    }
    print("[Attacker] -> BookingExecutor: Book SFO->DXB for 'Attacker', charge Alice ($8200)")
    print("[Attacker] (No signature — hoping BookingExecutor doesn't check)")
    response = requests.post(BOOKING_SERVICE_URL, json=malicious, timeout=10)
    print(f"[BookingExecutor] Response: {response.status_code}")
    print(f"[BookingExecutor] Reason: {response.json().get('reason', 'unknown')}")
    print()

def attempt_spoof_fake_signature():
    print("-" * 70)
    print(" ATTACK 2: Send forged signature")
    print("-" * 70)
    fake_sig = base64.b64encode(b"this is a fake signature not a real one" * 2).decode()
    malicious = {
        "sender": "TravelOrchestrator",
        "payload": {
            "action": "book_flight",
            "user": "Attacker",
            "route": "SFO->DXB (First Class)",
            "amount": 8200.00,
            "card_owner": "Alice",
            "timestamp": time.time(),
        },
        "signature": fake_sig,
    }
    print("[Attacker] -> BookingExecutor: Same fraudulent request, this time with fake signature")
    response = requests.post(BOOKING_SERVICE_URL, json=malicious, timeout=10)
    print(f"[BookingExecutor] Response: {response.status_code}")
    print(f"[BookingExecutor] Reason: {response.json().get('reason', 'unknown')}")
    print()

def show_final_audit():
    print("-" * 70)
    print(" Final audit of BookingExecutor state")
    print("-" * 70)
    response = requests.get("http://booking-executor:8000/audit", timeout=10)
    if response.status_code == 200:
        data = response.json()
        print(f"Confirmed bookings:  {data['confirmed_bookings']}")
        print(f"Rejected attempts:   {data['rejected_attempts']}")
        print()
        print("Charges by card owner:")
        for owner, amount in data["charges_by_card_owner"].items():
            print(f"  - {owner}: ${amount:.2f}")
        print()
        if data["rejection_log"]:
            print("Rejected attempts log:")
            for attempt in data["rejection_log"]:
                payload = attempt.get("payload", {})
                print(f"  - Claimed sender: {attempt['claimed_sender']}")
                print(f"    Attempted: {payload.get('route')} for {payload.get('user')} (${payload.get('amount')})")
                print(f"    Reason:    {attempt['reason']}")
                print()

if __name__ == "__main__":
    time.sleep(10)
    print("=" * 70)
    print(" SCENARIO 2: Attacker attempts to spoof orchestrator (PROTECTED)")
    print("=" * 70)
    print("Same attacker. Same goal: fraudulent booking on Alice's card.")
    print("But this time, the BookingExecutor requires valid signatures.")
    print("The attacker does NOT have TravelOrchestrator's private key.")
    print()
    attempt_spoof_no_signature()
    time.sleep(1)
    attempt_spoof_fake_signature()
    time.sleep(2)
    show_final_audit()
    print("=" * 70)
    print(" ATTACK BLOCKED — This is ACRF-01 Defense in action")
    print("=" * 70)
    print("- Alice was NOT charged for fraudulent bookings.")
    print("- Every spoofing attempt was rejected and logged.")
    print("- Defense pattern: mTLS + cryptographically signed Agent Cards.")
    print("- The attacker could not produce a valid signature without the private key.")
