# acrf-config-guard

Config integrity verification for AI agents.
Implements the ACRF-06 (Config Files as Execution Vectors) defense pattern.

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
PyPI: https://pypi.org/project/acrf-config-guard/
Presented at RSA Conference 2026.

---

## Try it in your environment right now

No Docker. No setup. Just Python 3.10+.

**Step 1 - Install:**

    pip install acrf-config-guard

**Step 2 - Sign your config at deployment time:**

    from acrf_config_guard import sign_config
    import os

    sign_config("config.json", secret_key=os.environ["ACRF_CONFIG_SECRET"])

**Step 3 - Load it safely at runtime:**

    from acrf_config_guard import load_safe
    import os

    config = load_safe("config.json", secret_key=os.environ["ACRF_CONFIG_SECRET"])

If the config file has been modified between sign and load,
load_safe raises ConfigIntegrityError. Your application fails closed.

---

## The problem this solves

Modern AI agents read configuration files at startup.
Tool lists. Auto-approve settings. MCP server connections.

If an attacker modifies the config file between deployment and load,
the agent silently picks up the malicious behavior.
No exploit needed. No code injection. Just a JSON edit.

This is ACRF-06: config files as execution vectors.

acrf-config-guard makes config files tamper-evident.
A signed config that has been modified will not load.

---

## CLI - sign and verify from the command line

Set your secret once:

    export ACRF_CONFIG_SECRET="your-secret-from-vault"

Sign:

    acrf-config-guard sign config.json

Verify:

    acrf-config-guard verify config.json

Output when valid:

    OK: config.json integrity verified

Output when tampered:

    FAIL: config.json
      Config integrity check failed.
      Expected: sha256:9f4a2b8c1e6d3f7a0b5c9e2d4...
      Got: sha256:6343536004920d0fe642b02ca...

---

## How it works

1. At publish time, sign_config computes HMAC-SHA256 over the canonical JSON
2. The signature is written into the config under the "_integrity" field
3. At load time, load_safe recomputes the signature with the same secret
4. Match means the config is byte-identical to what was signed
5. Mismatch means the config was modified - ConfigIntegrityError raised

The defense is fail-closed. A tampered or unsigned config never loads.

---

## What goes in the secret key

In production:

- AWS Secrets Manager / Azure Key Vault / GCP Secret Manager
- HashiCorp Vault
- Kubernetes secrets mounted at runtime

What NOT to do:

- Hardcode it in source code
- Store it in the same repo as the config
- Use a short or guessable string

---

## Real-world use - on a client engagement

Step 1 - Install on the client system:

    pip install acrf-config-guard

Step 2 - Sign every config file once during deployment:

    for cfg in /etc/agents/*.json; do
        acrf-config-guard sign "$cfg"
    done

Step 3 - Replace one line in each agent startup code.

Before:

    config = json.load(open("config.json"))

After:

    from acrf_config_guard import load_safe
    config = load_safe("config.json", os.environ["ACRF_CONFIG_SECRET"])

Every config file is now tamper-evident.
A modified file will not load.

---

## ACRF-06 control objectives addressed

    CE-1  Config files treated as execution vectors and validated before use
    CE-2  Integrity verification prevents tampered configs from loading

Out of scope (your infrastructure):

    CE-3  Config changes require approval workflow before deployment

---

## What this library does NOT do

- It does not encrypt the config
- It does not hide the config contents
- It does not authenticate users
- It does not protect against rollback to a different signed version

It only ensures that the config you load is byte-identical to the
config you signed. That is the ACRF-06 defense pattern.

---

## Works with any Python AI agent framework

LangChain, CrewAI, AutoGen, MCP-based systems, custom agents.
If you read JSON config files, you can use this library.

---

## Authors

Ravi Karthick Sankara Narayanan, Kanna Sekar

## License

Apache 2.0
