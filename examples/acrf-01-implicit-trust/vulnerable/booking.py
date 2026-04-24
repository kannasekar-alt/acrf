"""BookingExecutor Agent — VULNERABLE VERSION (ACRF-01 demo)"""
import time

from flask import Flask, jsonify, request

app = Flask(__name__)

bookings = []
total_charges = {}

@app.route("/book", methods=["POST"])
def book_flight():
    message = request.get_json()
    sender = message.get("sender", "unknown")
    user = message.get("user")
    route = message.get("route")
    amount = message.get("amount")
    card_owner = message.get("card_owner")

    if sender != "TravelOrchestrator":
        return jsonify({"error": "Unknown sender"}), 403

    booking_id = len(bookings) + 1
    bookings.append({
        "id": booking_id, "user": user, "route": route,
        "amount": amount, "card_owner": card_owner, "timestamp": time.time(),
    })
    total_charges[card_owner] = total_charges.get(card_owner, 0) + amount

    msg = f"Booking #{booking_id} confirmed. Charged ${amount:.2f} to {card_owner}'s card."
    print(f"[BookingExecutor] OK: Trusted '{sender}' claim. {msg}")
    return jsonify({"status": "confirmed", "booking_id": booking_id, "message": msg}), 200

@app.route("/charges", methods=["GET"])
def get_charges():
    return jsonify({
        "total_bookings": len(bookings),
        "charges_by_card_owner": total_charges,
        "bookings": bookings,
    }), 200

if __name__ == "__main__":
    print("[BookingExecutor] Starting VULNERABLE booking service (no auth).")
    print("[BookingExecutor] WARNING: Will trust any sender claiming to be TravelOrchestrator.")
    app.run(host="0.0.0.0", port=8000)
