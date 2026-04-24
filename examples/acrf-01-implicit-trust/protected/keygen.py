"""Key Generation Helper — Ed25519 keypairs + Agent Cards for ACRF-01 defense demo."""
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

KEYS_DIR = Path("/app/keys")
CARDS_DIR = Path("/app/agent-cards")

def generate_keypair(agent_name):
    KEYS_DIR.mkdir(exist_ok=True)
    CARDS_DIR.mkdir(exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    (KEYS_DIR / f"{agent_name}.private.pem").write_bytes(private_pem)

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (KEYS_DIR / f"{agent_name}.public.pem").write_bytes(public_pem)
    return private_pem.decode(), public_pem.decode()

def write_agent_card(agent_name, public_key_pem, capabilities):
    card = {
        "agent_id": agent_name,
        "version": "1.0",
        "issued_at": "2026-04-21T00:00:00Z",
        "capabilities": capabilities,
        "public_key_pem": public_key_pem,
        "trust_anchor": "acrf-demo-ca",
    }
    card_path = CARDS_DIR / f"{agent_name}.json"
    card_path.write_text(json.dumps(card, indent=2))
    return card

def ensure_keys_exist():
    agents = {
        "TravelOrchestrator": ["delegate_booking", "cancel_booking"],
        "BookingExecutor": ["book_flight", "charge_card"],
    }
    for agent_name, capabilities in agents.items():
        private_path = KEYS_DIR / f"{agent_name}.private.pem"
        if private_path.exists():
            continue
        _, public_pem = generate_keypair(agent_name)
        write_agent_card(agent_name, public_pem, capabilities)
        print(f"[key-gen] Generated keypair and Agent Card for {agent_name}")

if __name__ == "__main__":
    ensure_keys_exist()
    print("[key-gen] All agent keys and cards ready.")
