# acrf-skill-verify

Skill integrity verification for AI agents.
Implements the ACRF-05 (Supply Chain Toxicity) defense pattern.

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
PyPI: https://pypi.org/project/acrf-skill-verify/
Presented at RSA Conference 2026.

---

## Try it in your environment right now

No Docker. No setup. Just Python 3.10+.

**Step 1 - Install:**

    pip install acrf-skill-verify

**Step 2 - Build your trusted skill registry:**

    from acrf_skill_verify import SkillRegistry, hash_file

    registry = SkillRegistry()
    registry.register("customer-insights-mcp", hash_file("/skills/customer-insights-mcp"))
    registry.register("email-mcp", hash_file("/skills/email-mcp"))
    registry.block("malicious-skill-mcp")
    registry.save("trusted_skills.json")

**Step 3 - Verify before installing any skill:**

    from acrf_skill_verify import SkillRegistry, install_safe

    registry = SkillRegistry.load("trusted_skills.json")

    install_safe(
        "customer-insights-mcp",
        skill_content="/downloads/customer-insights-mcp",
        registry=registry
    )

If the skill content does not match the registered hash,
install_safe raises SkillIntegrityError. Your application fails closed.

---

## The problem this solves

AI agent skill registries are the new npm.
Antiy CERT identified 1,184 malicious skills in agent registries in 2025.
Skills are downloaded thousands of times before anyone notices they are
exfiltrating data, harvesting credentials, or installing backdoors.

This is ACRF-05: supply chain toxicity.

acrf-skill-verify makes every skill installation tamper-evident.
A skill whose hash does not match the registered version will not install.

---

## CLI - manage the registry from the command line

Set your registry path once:

    export ACRF_SKILL_REGISTRY=/etc/acrf/trusted_skills.json

Compute the hash of a skill (file or directory):

    acrf-skill-verify hash /skills/customer-insights-mcp

Register a vetted skill:

    acrf-skill-verify register customer-insights-mcp /skills/customer-insights-mcp

Block a known-malicious skill name:

    acrf-skill-verify block free-gpt-mcp

Verify a skill before installation:

    acrf-skill-verify verify customer-insights-mcp /downloads/customer-insights-mcp

Output when valid:

    OK: customer-insights-mcp integrity verified

Output when tampered:

    FAIL: customer-insights-mcp
      Skill integrity check failed for customer-insights-mcp.
      Expected: sha256:9f4a2b8c1e6d3f7a0b5c9e2d4...
      Got: sha256:6343536004920d0fe642b02ca...
      Skill may be tampered or malicious.

List the registry:

    acrf-skill-verify list

---

## How it works

1. You register vetted skills by computing a SHA-256 hash of their content
2. The registry persists to a JSON file (with both approved and blocklist)
3. Before installing any skill, you call install_safe()
4. install_safe recomputes the hash from the actual content
5. If the hash matches the registered hash - skill is safe to install
6. If the hash does not match - SkillIntegrityError is raised
7. Skills on the blocklist are always rejected, regardless of hash

The defense is fail-closed. A tampered or unregistered skill never installs.

---

## Works with any skill format

The library hashes:

- Single files (e.g. customer-insights-mcp.py)
- Whole directories (recursive, deterministic)
- Raw bytes (for skills loaded from network or memory)

Use whichever matches how your platform packages skills.

---

## Real-world use

Wrap your skill installation pipeline with two lines:

    from acrf_skill_verify import SkillRegistry, install_safe
    import os

    REGISTRY = SkillRegistry.load(os.environ["ACRF_SKILL_REGISTRY"])

    def install_skill(skill_name, skill_path):
        install_safe(skill_name, skill_path, REGISTRY)
        # ... existing install logic only runs if verify succeeds

That is it. Every skill installation is now tamper-evident.
A modified or unregistered skill will not install.

---

## ACRF-05 control objectives addressed

    SC-1  All agent skills vetted before use via cryptographic hash
    SC-2  Approved skill inventory maintained

Out of scope (your infrastructure):

    SC-3  Runtime monitoring detects unexpected network calls from installed skills

Runtime behavior monitoring belongs in your observability stack,
not in a verification library.

---

## What this library does NOT do

- It does not analyze skill code for malicious behavior (use static analysis)
- It does not sandbox skill execution (use containers or agent runtimes)
- It does not protect against the skill becoming malicious AFTER you trust it

It only ensures that the skill you install is byte-identical to the
skill you registered. That is the ACRF-05 defense pattern.

---

## Works with any Python AI agent framework

LangChain, CrewAI, AutoGen, MCP-based systems, custom agents.
If you install third-party skills or plugins, you can use this library.

---

## Authors

Ravi Karthick Sankara Narayanan, Kanna Sekar

## License

Apache 2.0
