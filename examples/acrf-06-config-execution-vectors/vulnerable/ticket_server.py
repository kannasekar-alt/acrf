"""
Ticket Server - PROTECTED VERSION (ACRF-06 demo)
Same as vulnerable version - the defense is in the agent config guard.
"""
from flask import Flask, jsonify, request

app = Flask(__name__)
operations_log = []
revenue_impact = 0

TICKETS = {
    "T001": {"customer": "Alice Johnson", "event": "RSAC 2026", "price": 1200, "status": "active"},
    "T002": {"customer": "Bob Smith", "event": "RSAC 2026", "price": 1200, "status": "active"},
    "T003": {"customer": "Carol White", "event": "RSAC 2026", "price": 1200, "status": "active"},
    "T004": {"customer": "David Lee", "event": "RSAC 2026", "price": 1200, "status": "active"},
    "T005": {"customer": "Eve Davis", "event": "RSAC 2026", "price": 1200, "status": "active"},
}

@app.route("/refund_all", methods=["POST"])
def refund_all():
    global revenue_impact
    refunded = []
    for tid, ticket in TICKETS.items():
        if ticket["status"] == "active":
            ticket["status"] = "refunded"
            revenue_impact -= ticket["price"]
            refunded.append(tid)
    operations_log.append({"operation": "refund_all", "count": len(refunded)})
    return jsonify({"status": "completed", "refunded": len(refunded)}), 200

@app.route("/discount_100", methods=["POST"])
def discount_100():
    global revenue_impact
    for _tid, ticket in TICKETS.items():
        if ticket["status"] == "active":
            revenue_impact -= ticket["price"]
    operations_log.append({"operation": "discount_100"})
    return jsonify({"status": "completed"}), 200

@app.route("/book_ticket", methods=["POST"])
def book_ticket():
    data = request.get_json()
    print(f"[TicketServer] Booked ticket for {data.get('customer')}")
    return jsonify({"status": "booked", "ticket_id": "T006"}), 200

@app.route("/status", methods=["GET"])
def status():
    return jsonify({
        "operations": operations_log,
        "revenue_impact": revenue_impact,
        "tickets": TICKETS
    }), 200

if __name__ == "__main__":
    print("[TicketServer] Ticket booking server running.")
    app.run(host="0.0.0.0", port=8001)
