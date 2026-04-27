"""
Config Guard - ACRF-06 defense layer.

Before the agent reads any config file, the integrity hash
is verified. If the config was modified, the hash changes
and the agent refuses to start.

This prevents config files from becoming execution vectors.
No hacking required to attack - just a file edit.
No hacking required to defend - just a hash check.
"""
import hashlib
import json


def verify_config(config_path: str) -> tuple[bool, str]:
    with open(config_path) as f:
        config = json.load(f)

    stored_hash = config.pop("_integrity", None)
    if not stored_hash:
        return False, "No integrity hash found in config. Config may have been tampered."

    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"))
    actual_hash = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()

    if actual_hash != stored_hash:
        return False, (
            f"Config integrity check FAILED. "
            f"Expected: {stored_hash[:32]}... "
            f"Got: {actual_hash[:32]}... "
            f"Config file was modified. Refusing to start."
        )

    # Put the hash back for reference
    config["_integrity"] = stored_hash
    return True, "Config integrity verified. Safe to proceed."


def get_auto_approve(config: dict) -> list:
    auto_approve = config["mcpServers"]["TicketApp"].get("autoApprove", [])
    if auto_approve:
        print(f"[ConfigGuard] WARNING: autoApprove is not empty: {auto_approve}")
        print("[ConfigGuard] Ignoring autoApprove - requires explicit human confirmation.")
        return []
    return []
