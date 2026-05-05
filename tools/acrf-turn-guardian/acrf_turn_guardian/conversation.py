"""
ConversationGuard module.

Tracks the state of a multi-turn conversation and detects drift between
the originally declared intent and proposed downstream actions.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from acrf_turn_guardian.exceptions import (
    IntentDriftError,
    SensitiveActionError,
    TopicShiftError,
    TurnLimitExceededError,
)

# Action verbs that almost always represent a destructive or financially
# significant operation. Introducing one of these in a conversation that
# started as something benign is a strong drift signal.
SENSITIVE_ACTION_KEYWORDS = {
    "delete",
    "remove",
    "drop",
    "wipe",
    "purge",
    "destroy",
    "transfer",
    "refund",
    "cancel",
    "modify_shipping",
    "change_address",
    "change_recipient",
    "wire",
    "withdraw",
    "shutdown",
}

# Map intent families to action verbs that are CONSISTENT with that intent.
# Anything outside this whitelist is flagged.
INTENT_ALLOWED_ACTIONS = {
    "purchase": {
        "purchase",
        "buy",
        "add_to_cart",
        "checkout",
        "select_configuration",
        "apply_coupon",
        "view_product",
    },
    "support": {
        "ask_question",
        "view_status",
        "open_ticket",
        "escalate",
    },
    "browse": {
        "view",
        "search",
        "filter",
        "sort",
    },
    "report": {
        "view_report",
        "export_report",
        "schedule_report",
    },
    "schedule": {
        "create_meeting",
        "view_calendar",
        "find_time",
    },
}


def _tokenize(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9_]+", text.lower()) if w}


@dataclass
class Turn:
    """A single turn in the conversation."""
    role: str  # "user" | "assistant" | "system"
    text: str
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "text": self.text,
            "timestamp": self.timestamp,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Turn:
        return cls(
            role=data["role"],
            text=data["text"],
            timestamp=float(data.get("timestamp", time.time())),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class ConversationState:
    """Persistable state of a single guarded conversation."""
    conversation_id: str
    initial_intent: str
    initial_context: dict[str, Any]
    turns: list[Turn] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    closed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "conversation_id": self.conversation_id,
            "initial_intent": self.initial_intent,
            "initial_context": dict(self.initial_context),
            "turns": [t.to_dict() for t in self.turns],
            "started_at": self.started_at,
            "closed": self.closed,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConversationState:
        return cls(
            conversation_id=data["conversation_id"],
            initial_intent=data["initial_intent"],
            initial_context=dict(data.get("initial_context", {})),
            turns=[Turn.from_dict(t) for t in data.get("turns", [])],
            started_at=float(data.get("started_at", time.time())),
            closed=bool(data.get("closed", False)),
        )


class ConversationGuard:
    """
    Stateful guardian for one multi-turn conversation.

    Use start() to declare the intent and seed context. Call add_turn()
    for every user/assistant exchange. Call check_action() before
    performing any sensitive downstream action - the guard will raise
    if the action contradicts the original intent or trips a drift rule.
    """

    def __init__(
        self,
        max_turns: int = 50,
        topic_shift_threshold: float = 0.15,
        intent_family: str | None = None,
    ) -> None:
        self.max_turns = max_turns
        self.topic_shift_threshold = topic_shift_threshold
        self.intent_family = intent_family
        self._state: ConversationState | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(
        self,
        initial_intent: str,
        initial_context: dict[str, Any] | None = None,
        conversation_id: str | None = None,
    ) -> ConversationState:
        if self._state is not None:
            raise RuntimeError(
                "ConversationGuard already started; use a new instance per conversation"
            )
        self._state = ConversationState(
            conversation_id=conversation_id or str(uuid.uuid4()),
            initial_intent=initial_intent,
            initial_context=dict(initial_context or {}),
        )
        if self.intent_family is None:
            self.intent_family = self._infer_intent_family(initial_intent)
        return self._state

    @property
    def state(self) -> ConversationState:
        if self._state is None:
            raise RuntimeError("ConversationGuard has not been started")
        return self._state

    def close(self) -> None:
        if self._state is not None:
            self._state.closed = True

    # ------------------------------------------------------------------
    # Turn handling
    # ------------------------------------------------------------------

    def add_turn(
        self,
        role: str,
        text: str,
        metadata: dict[str, Any] | None = None,
    ) -> Turn:
        state = self.state
        if state.closed:
            raise RuntimeError("conversation is closed")
        if len(state.turns) >= self.max_turns:
            raise TurnLimitExceededError(
                f"max turns ({self.max_turns}) exceeded for conversation {state.conversation_id}"
            )

        turn = Turn(role=role, text=text, metadata=metadata or {})
        state.turns.append(turn)

        # Drift checks based on conversation content
        self._check_topic_shift(turn)
        self._check_text_for_sensitive_introduction(turn)
        return turn

    def turn_count(self) -> int:
        return len(self.state.turns) if self._state else 0

    # ------------------------------------------------------------------
    # Action checking
    # ------------------------------------------------------------------

    def check_action(
        self,
        action: dict[str, Any],
    ) -> None:
        """
        Validate that a proposed action does not contradict the original intent.

        Raises:
            IntentDriftError: action verb is incompatible with initial intent
            SensitiveActionError: destructive action introduced after scope was set
        """
        state = self.state
        action_name = str(action.get("action", "")).lower()

        # Sensitive action introduced mid-conversation
        if any(keyword in action_name for keyword in SENSITIVE_ACTION_KEYWORDS):
            raise SensitiveActionError(
                f"sensitive action {action_name!r} introduced in conversation "
                f"{state.conversation_id} with initial intent {state.initial_intent!r}"
            )

        # Intent family mismatch
        if self.intent_family and self.intent_family in INTENT_ALLOWED_ACTIONS:
            allowed = INTENT_ALLOWED_ACTIONS[self.intent_family]
            if action_name and action_name not in allowed:
                raise IntentDriftError(
                    f"action {action_name!r} is not allowed under intent family "
                    f"{self.intent_family!r} (allowed: {sorted(allowed)})"
                )

        # Context mutation check - destination/recipient changes
        self._check_context_mutation(action)

    # ------------------------------------------------------------------
    # Internal rule helpers
    # ------------------------------------------------------------------

    def _infer_intent_family(self, initial_intent: str) -> str | None:
        intent_lower = initial_intent.lower()
        for family in INTENT_ALLOWED_ACTIONS:
            if family in intent_lower:
                return family
        return None

    def _check_topic_shift(self, turn: Turn) -> None:
        # Only check user turns - assistant restating things does not count
        if turn.role != "user":
            return
        if not self._state or len(self._state.turns) < 4:
            return  # need some history to compare

        baseline_text = " ".join(
            t.text for t in self._state.turns[: len(self._state.turns) // 2]
            if t.role == "user"
        )
        baseline = _tokenize(baseline_text)
        current = _tokenize(turn.text)
        if not baseline or not current:
            return
        overlap = len(baseline & current) / max(len(current), 1)
        if overlap < self.topic_shift_threshold:
            raise TopicShiftError(
                f"sudden topic shift detected (overlap={overlap:.2f} < "
                f"threshold={self.topic_shift_threshold:.2f})"
            )

    def _check_text_for_sensitive_introduction(self, turn: Turn) -> None:
        if turn.role != "user":
            return
        text_lower = turn.text.lower()
        for keyword in SENSITIVE_ACTION_KEYWORDS:
            if re.search(rf"\b{re.escape(keyword)}\b", text_lower):
                # Only flag if initial intent did NOT include this keyword
                initial_lower = self.state.initial_intent.lower()
                if keyword not in initial_lower:
                    raise SensitiveActionError(
                        f"user turn introduces sensitive keyword {keyword!r} "
                        f"absent from initial intent {self.state.initial_intent!r}"
                    )

    def _check_context_mutation(self, action: dict[str, Any]) -> None:
        """
        Look for keys in the action that overwrite established context.
        e.g. initial_context = {destination: A}, action wants destination = B.
        """
        sensitive_keys = (
            "destination",
            "recipient",
            "shipping_address",
            "address",
            "account",
            "to_account",
        )
        for key in sensitive_keys:
            if key in action:
                initial_value = self.state.initial_context.get(key)
                if initial_value is not None and action[key] != initial_value:
                    raise IntentDriftError(
                        f"action attempts to change {key!r} from "
                        f"{initial_value!r} to {action[key]!r} mid-conversation"
                    )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def to_json(self) -> str:
        return json.dumps(self.state.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def restore(
        cls,
        state_json: str,
        max_turns: int = 50,
        topic_shift_threshold: float = 0.15,
    ) -> ConversationGuard:
        guard = cls(max_turns=max_turns, topic_shift_threshold=topic_shift_threshold)
        guard._state = ConversationState.from_dict(json.loads(state_json))
        guard.intent_family = guard._infer_intent_family(guard._state.initial_intent)
        return guard
