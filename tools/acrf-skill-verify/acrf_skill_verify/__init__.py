"""
acrf-skill-verify
=================

Skill integrity verification for AI agents.
Implements the ACRF-05 (Supply Chain Toxicity) defense pattern.

Quick start:

    from acrf_skill_verify import SkillRegistry, install_safe

    # Build your trusted skill registry
    registry = SkillRegistry()
    registry.register("customer-insights-mcp", expected_hash="sha256:9f4a...")
    registry.register("email-mcp", expected_hash="sha256:3c7e...")
    registry.block("malicious-skill-mcp")
    registry.save("trusted_skills.json")

    # Before installing any skill, verify it
    install_safe(
        "customer-insights-mcp",
        skill_content="/downloads/customer-insights-mcp",
        registry=registry
    )

If the skill content does not match the registered hash, install_safe
raises SkillIntegrityError. Your application fails closed.

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
"""
from acrf_skill_verify.core import (
    SkillIntegrityError,
    SkillRegistry,
    compute_hash,
    hash_directory,
    hash_file,
    install_safe,
    verify_skill,
)

__version__ = "0.1.0"
__all__ = [
    "SkillRegistry",
    "SkillIntegrityError",
    "compute_hash",
    "hash_file",
    "hash_directory",
    "verify_skill",
    "install_safe",
]
