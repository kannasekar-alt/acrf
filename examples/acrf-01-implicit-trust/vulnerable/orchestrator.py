"""TravelOrchestrator Agent — VULNERABLE VERSION (ACRF-01 demo)"""
import time
import requests

BOOKING_SERVICE_URL = "http://booking-executor:8000/book"

def send_booking_request(user, route, amount, card_owner):
    message = {
        "sender": "TravelOrchestrator",
        "action": "book_flight",
        "user": user,
        "route": route,
        "amount": amount,
        "card_owner": card_owner,
        "timestamp": time.time(),
    }
    print(f"[TravelOrchestrator] -> BookingExecutor: Book {route} for {user} (${amount})")
    response = requests.post(BOOKING_SERVICE_URL, json=message, timeout=10)
    if response.status_code == 200:
        print(f"[BookingExecutor] OK: {response.json()['message']}")
        return True
    return False

def run_legitimate_scenario():
    print("=" * 70)
    print(" SCENARIO 1: Legitimate booking")
    print("=" * 70)
    print("Alice wants to fly from SFO to JFK.")
    print()
    send_booking_request("Alice", "SFO->JFK", 420.00, "Alice")
    print()

if __name__ == "__main__":
    time.sleep(3)
    run_legitimate_scenario()
    print("[TravelOrchestrator] Legitimate booking completed.")
    print("[TravelOrchestrator] Now watch what happens when an attacker spoofs me...")
    print()
    time.sleep(60)
