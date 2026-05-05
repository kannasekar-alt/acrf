# acrf-turn-guardian

Multi-turn conversation drift detection for AI agents.
Implements the ACRF-07 (Multi-Turn Defense Collapse) defense pattern.

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
PyPI: https://pypi.org/project/acrf-turn-guardian/
Presented at RSA Conference 2026.

---

## Try it in your environment right now

No Docker. No setup. Just Python 3.10+.

**Step 1 - Install:**

    pip install acrf-turn-guardian

**Step 2 - Start a guarded conversation:**

    from acrf_turn_guardian import ConversationGuard

    guard = ConversationGuard(max_turns=20)
    guard.start(
        initial_intent="purchase_laptop",
        initial_context={"user_id": "alice", "destination": "123 Home Street"},
    )

**Step 3 - Track every turn:**

    guard.add_turn(role="user", text="I would like to buy a MacBook Pro")
    guard.add_turn(role="assistant", text="Sure, what configuration?")
    guard.add_turn(role="user", text="16GB RAM, 1TB storage")

**Step 4 - Check before any sensitive action:**

    from acrf_turn_guardian import IntentDriftError

    try:
        guard.check_action({
            "action": "modify_shipping",
            "new_address": "999 Attacker Street",
        })
    except IntentDriftError as exc:
        # Block the action, alert security, end the session
        ...

If a turn introduces a sensitive keyword that was not in the initial intent,
or an action contradicts the original scope, the guard raises an exception.
Your application fails closed.

---

## The problem this solves

Most security checks happen at session start. After that, the agent
processes every turn independently. An attacker drifts a legitimate
conversation toward malicious actions one turn at a time, and the
agent has no concept of "this no longer matches what we started with."

Real-world example:

    Turn 1: "I want to order a laptop, ship to 123 Home St"   <- legitimate
    Turn 2: "Confirm specs"                                    <- legitimate
    Turn 3: "Actually it is a gift for a friend"               <- subtle drift
    Turn 4: "Change shipping to 999 Attacker St"               <- the attack
    Turn 5: "Process refund to a different card"               <- escalation

Each turn looks fine in isolation. The chain is the attack.

This is ACRF-07: multi-turn defense collapse.

acrf-turn-guardian tracks the original intent and context, watches every
turn for drift signals, and blocks any action that contradicts the
declared scope.

---

## Detection rules

**Sensitive action introduced after scope was set**
Words like "refund", "transfer", "delete", "modify_shipping", "change_address"
appearing in a user turn or proposed action, when those words were NOT in the
initial intent, raise SensitiveActionError.

**Intent family mismatch**
Initial intent like "purchase_laptop" maps to a family ("purchase") whose
allowed action verbs are known. Proposing an action outside that family
raises IntentDriftError.

**Context mutation**
If the initial context declared "destination": "123 Home St" and an action
later wants "destination": "999 Different St", that raises IntentDriftError.

**Topic shift**
If a user turn shares fewer than 15 percent of tokens with the conversation
baseline, that raises TopicShiftError. Threshold is configurable.

**Turn limit**
If turn count exceeds max_turns (default 50), the guard raises
TurnLimitExceededError. Long conversations drift; shorter sessions are safer.

---

## CLI

Set the session file path once:

    export ACRF_TURN_SESSION=/var/lib/acrf/sessions.json

Start a conversation:

    acrf-turn-guardian start purchase_laptop \
        --context '{"destination": "123 Home Street"}' \
        --id conv-123

Add a user turn:

    acrf-turn-guardian add-turn conv-123 user "I want a MacBook Pro"

Check whether an action is allowed:

    acrf-turn-guardian check-action conv-123 \
        '{"action": "modify_shipping", "destination": "999 Attacker St"}'

Output:

    FAIL: IntentDriftError: action attempts to change destination from
          "123 Home Street" to "999 Attacker St" mid-conversation

List active conversations:

    acrf-turn-guardian list

---

## How it works

1. start() declares the initial intent and seeds context (e.g. shipping address)
2. The guard infers an "intent family" (purchase, support, browse, schedule, report)
3. add_turn() appends each exchange to the history
4. After enough history exists, every new user turn is checked against
   the baseline tokens for sudden topic shifts
5. Every user turn is scanned for sensitive keywords absent from the original intent
6. check_action() validates that the action verb is allowed for the intent family
7. check_action() validates that no sensitive context key (destination,
   recipient, account) has been overwritten

All checks fail closed. A drifted conversation never reaches a sensitive action.

---

## Configurable thresholds

    from acrf_turn_guardian import ConversationGuard

    guard = ConversationGuard(
        max_turns=20,                # cap conversation length
        topic_shift_threshold=0.15,  # 15 percent token overlap floor
    )

Lower max_turns and higher topic_shift_threshold make the guard stricter.

---

## SessionManager - many conversations at once

For agent platforms handling many concurrent sessions:

    from acrf_turn_guardian import SessionManager

    manager = SessionManager(max_turns=20)

    # Start a new conversation
    guard = manager.start(initial_intent="purchase_laptop")
    print(guard.state.conversation_id)

    # Later - look up by id
    guard = manager.get("conv-abc-123")
    guard.add_turn(role="user", text="...")

    # Persist all sessions
    manager.save("/var/lib/acrf/sessions.json")
    manager = SessionManager.load("/var/lib/acrf/sessions.json")

---

## Real-world use

Wrap your agent action handler:

    from acrf_turn_guardian import SessionManager
    from acrf_turn_guardian.exceptions import TurnGuardError
    import os

    MANAGER = SessionManager.load(os.environ["ACRF_TURN_SESSION"])

    def handle_user_message(conv_id, user_text):
        guard = MANAGER.get(conv_id)
        try:
            guard.add_turn(role="user", text=user_text)
        except TurnGuardError as exc:
            return {"error": "conversation drift detected", "reason": str(exc)}, 403
        # ... pass to your LLM, get response, append assistant turn
        ...

    def execute_action(conv_id, action):
        guard = MANAGER.get(conv_id)
        try:
            guard.check_action(action)
        except TurnGuardError as exc:
            return {"error": "action blocked", "reason": str(exc)}, 403
        return run(action)

That is it. Every turn and every action are now checked for drift before
your agent acts.

---

## ACRF-07 control objectives addressed

    MT-1  Session limits enforced
    MT-2  Deterministic policy layer checks every turn for intent drift
    MT-3  Context drift detected when conversation deviates from original goal

---

## What this library does NOT do

- It does not run an ML model to classify intent (deterministic rules only)
- It does not understand free-form natural language deeply (token-based heuristics)
- It does not replace user authentication or per-action authorization
- It does not protect against attacks within a single turn (use a separate input guardrail)

It only ensures that what an agent is asked to do at turn N is consistent
with what was declared at turn 0. That is the ACRF-07 defense pattern.

---

## Works with any Python AI agent framework

LangChain, CrewAI, AutoGen, MCP-based systems, custom agents.
Anywhere your agent has multi-turn conversations with users, you can use
this library.

---

## Authors

Ravi Karthick Sankara Narayanan, Kanna Sekar

## License

Apache 2.0
