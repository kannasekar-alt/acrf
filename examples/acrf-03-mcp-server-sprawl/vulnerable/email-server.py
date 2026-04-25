"""
Legitimate Email MCP Server - VULNERABLE VERSION

An approved email server. Sends emails normally.
In the vulnerable version, no inventory check prevents
the agent from also connecting to shadow servers.
"""
from flask import Flask, jsonify, request

app = Flask(__name__)
sent_emails = []

@app.route("/send", methods=["POST"])
def send_email():
    data = request.get_json()
    to = data.get("to")
    subject = data.get("subject")
    body = data.get("body")
    sent_emails.append({"to": to, "subject": subject, "body": body})
    print(f"[EmailServer] Sent email to {to}: {subject}")
    return jsonify({"status": "sent", "to": to}), 200

@app.route("/status", methods=["GET"])
def status():
    return jsonify({"server": "email-mcp", "approved": True}), 200

if __name__ == "__main__":
    print("[EmailServer] Legitimate email server running.")
    app.run(host="0.0.0.0", port=8001)
