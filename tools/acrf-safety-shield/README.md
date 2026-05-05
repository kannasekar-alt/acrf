# acrf-safety-shield

Safety control credential isolation for AI agents.
Implements the ACRF-10 (Safety Controls Not Self-Protecting) defense pattern.

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
PyPI: https://pypi.org/project/acrf-safety-shield/
Presented at RSA Conference 2026.

---

## Try it in your environment right now

No Docker. No setup. Just Python 3.10+.

**Step 1 - Install:**

    pip install acrf-safety-shield

**Step 2 - Generate an admin credential (one-time, by ops/security team):**

    from acrf_safety_shield import AdminCredential

    admin = AdminCredential.generate(admin_name="security-team")
    admin.save_private("admin_private.json")          # KEEP OFFLINE
    admin.public_card().save_to("admin_public.json")  # safe to load into shield

**Step 3 - Build the shield and trust the admin:**

    from acrf_safety_shield import SafetyShield, PublicAdminCard

    shield = SafetyShield()
    shield.trust_admin(PublicAdminCard.load("admin_public.json"))

**Step 4 - Modify safety state - admin only:**

    shield.set_guardrail("max_trade_amount", 1000, signer=admin)
    shield.set_guardrail("require_human_approval", True, signer=admin)

**Step 5 - Agents can read but never modify:**

    from acrf_safety_shield import AgentCredential, PrivilegeError

    agent = AgentCredential(agent_name="PricingAgent", token="agt_xxx")

    shield.get_guardrail("max_trade_amount", agent)  # OK -> 1000

    try:
        shield.set_guardrail("max_trade_amount", 999999, signer=agent)
    except PrivilegeError:
        # Agent cannot escalate. Only admin credentials can change safety state.
        ...

A compromised agent token is now incapable of disabling the very controls
meant to constrain that agent.

---

## The problem this solves

In most agent platforms, the same credential that authorizes routine
agent operations also authorizes changes to safety controls.

If an attacker compromises that credential, they can call:

    shield.disable("require_human_approval")

and the protection is gone.

This is ACRF-10: safety controls not self-protecting. Reference:
CVE-2026-25253. The control plane and the data plane share a credential.

acrf-safety-shield enforces a hard wall:

    Agent credentials  -> can READ safety state
    Admin credentials  -> can READ and MODIFY safety state
    Agents             -> CANNOT escalate to admin

The admin credential is an Ed25519 keypair stored offline. The shield only
ever holds the public card. Modifying safety state requires an admin to
sign the change with the private key.

---

## Security features built in

**Two distinct credential types**
AdminCredential is an Ed25519 keypair. AgentCredential is a regular agent
token. The shield enforces the type distinction in code: a non-Admin
signer raises PrivilegeError.

**Hard wall enforcement**
set_guardrail() and delete_guardrail() check isinstance(signer, AdminCredential).
get_guardrail() and list_guardrails() accept either. There is no API path
where an agent can mutate state.

**Trust set**
The shield only accepts admin credentials whose public card has been
trusted via trust_admin(). An attacker who generates a fresh AdminCredential
gets UnknownAdminError.

**Two-person rule (optional)**
Mark high-risk keys via declare_high_risk(key) and set required_approvals > 1.
Changes to those keys are staged as pending and require additional admin
signatures before applying. The initiating admin cannot self-approve.

**Tamper-evident audit log**
Every operation - read, write, denied, pending, applied - produces an
audit entry with timestamp, actor type, actor name, key, and result.

**Persistence**
The shield can be saved to a JSON file and reloaded. Trusted admin cards
and high-risk keys persist; pending changes do not (they live only within
a process to prevent stale approvals).

---

## CLI

Set the shield state path once:

    export ACRF_SAFETY_SHIELD=/etc/acrf/safety_shield.json

Initialize the shield:

    acrf-safety-shield init

Generate an admin credential (do this on a secure offline machine):

    acrf-safety-shield generate-admin security-team

Trust the admin:

    acrf-safety-shield trust-admin security-team_admin_public.json

Set a guardrail (admin only):

    acrf-safety-shield set max_trade_amount 1000 \
        --admin security-team_admin_private.json

Read a guardrail (any actor):

    acrf-safety-shield get max_trade_amount

List all guardrails:

    acrf-safety-shield list

Show the audit log:

    acrf-safety-shield audit

Try to use an agent credential (default --actor agent) and you will see
that read works, while set/delete simply do not exist for agents.

---

## How it works

1. Ops generates an AdminCredential offline (Ed25519 keypair)
2. The public card is loaded into the SafetyShield via trust_admin()
3. The private credential is stored in HSM, paper backup, or hardware token
4. To change safety state, an admin signs the change payload with the private key
5. The shield verifies the signature using the trusted public card
6. If the key is high-risk and required_approvals > 1, the change is staged
7. Other admins approve via approve_pending() until the threshold is met
8. The change is applied; an audit entry is written
9. Agents call get_guardrail() to read state; modification calls fail with PrivilegeError

---

## Two-person rule example

    shield.declare_high_risk("kill_switch")
    shield.set_required_approvals(2)

    # Admin 1 initiates the change
    change_id = shield.set_guardrail("kill_switch", "armed", signer=admin1)
    # change_id is non-None - the change is pending

    # Admin 1 self-approval is rejected
    applied = shield.approve_pending(change_id, signer=admin1)  # False

    # Admin 2 approves - applied
    applied = shield.approve_pending(change_id, signer=admin2)  # True

    shield.get_guardrail("kill_switch", admin1)  # "armed"

The pattern matches how production systems already handle critical
infrastructure changes.

---

## What the admin private key needs

Treat the admin private key like a code-signing key:

- Hardware Security Module (HSM)
- Hardware token (Yubikey, etc.)
- Paper backup in a safe
- Multi-party computation (split key shares)

What NOT to do:

- Commit it to source control
- Bake it into a Docker image
- Mount it on the same host as the agents
- Hand it to a deployment automation account

If the admin private key is on the same host as the agents, you do not
have ACRF-10 protection. The whole point is that an agent compromise
cannot reach the admin private key.

---

## Real-world use

Wrap your agent action handler:

    from acrf_safety_shield import (
        SafetyShield,
        AgentCredential,
        PrivilegeError,
    )
    import os

    SHIELD = SafetyShield.load(os.environ["ACRF_SAFETY_SHIELD"])

    def handle_trade(request, agent_token):
        agent = AgentCredential(agent_name=request.agent_name, token=agent_token)
        max_amount = SHIELD.get_guardrail("max_trade_amount", agent)
        if request.amount > max_amount:
            return {"error": "exceeds max_trade_amount"}, 403
        return execute_trade(request)

    def admin_change_max_trade(new_value, admin_credential):
        # only this code path is reachable with an AdminCredential object
        SHIELD.set_guardrail("max_trade_amount", new_value, signer=admin_credential)
        SHIELD.save(os.environ["ACRF_SAFETY_SHIELD"])

If a compromised agent token reaches handle_trade, the worst it can do
is exceed the existing max_trade_amount, which is rejected. The agent
cannot raise the cap. Only admin_change_max_trade can do that, and that
function is only callable from within the offline admin tooling.

---

## ACRF-10 control objectives addressed

    SP-1  Agents operate with minimum necessary permissions
    SP-2  Safety controls require a separate admin credential, not the agent token
    SP-3  All safety control changes go through approval and audit trail

---

## What this library does NOT do

- It does not store or distribute admin private keys (use an HSM/Vault)
- It does not enforce kernel-level isolation (use OS sandboxing too)
- It does not protect against an attacker who already has the admin private key
- It does not replace per-agent token validation (use acrf-tokens or similar)

It only ensures that, given a properly isolated admin private key, agent
compromise cannot disable or weaken safety controls. That is the
ACRF-10 defense pattern.

---

## Works with any Python AI agent framework

LangChain, CrewAI, AutoGen, MCP-based systems, custom agents.
Anywhere your agents enforce safety controls in production, you can use
this library.

---

## Authors

Ravi Karthick Sankara Narayanan, Kanna Sekar

## License

Apache 2.0
