"""
SessionManager module.

Tracks multiple ConversationGuard instances by conversation_id and
persists them to a JSON file. Useful when an agent platform handles
many concurrent conversations and needs to look one up by id.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from acrf_turn_guardian.conversation import ConversationGuard, ConversationState
from acrf_turn_guardian.exceptions import ConversationNotFoundError


@dataclass
class SessionManager:
    max_turns: int = 50
    topic_shift_threshold: float = 0.15
    _guards: dict[str, ConversationGuard] = field(default_factory=dict)

    def start(
        self,
        initial_intent: str,
        initial_context: dict[str, Any] | None = None,
        conversation_id: str | None = None,
    ) -> ConversationGuard:
        guard = ConversationGuard(
            max_turns=self.max_turns,
            topic_shift_threshold=self.topic_shift_threshold,
        )
        state = guard.start(
            initial_intent=initial_intent,
            initial_context=initial_context,
            conversation_id=conversation_id,
        )
        self._guards[state.conversation_id] = guard
        return guard

    def get(self, conversation_id: str) -> ConversationGuard:
        guard = self._guards.get(conversation_id)
        if guard is None:
            raise ConversationNotFoundError(
                f"unknown conversation: {conversation_id}"
            )
        return guard

    def close(self, conversation_id: str) -> None:
        guard = self.get(conversation_id)
        guard.close()

    def discard(self, conversation_id: str) -> None:
        self._guards.pop(conversation_id, None)

    def conversation_ids(self) -> list[str]:
        return sorted(self._guards.keys())

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_turns": self.max_turns,
            "topic_shift_threshold": self.topic_shift_threshold,
            "conversations": [
                guard.state.to_dict() for guard in self._guards.values()
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionManager:
        manager = cls(
            max_turns=int(data.get("max_turns", 50)),
            topic_shift_threshold=float(data.get("topic_shift_threshold", 0.15)),
        )
        for raw in data.get("conversations", []):
            state = ConversationState.from_dict(raw)
            guard = ConversationGuard(
                max_turns=manager.max_turns,
                topic_shift_threshold=manager.topic_shift_threshold,
            )
            guard._state = state
            guard.intent_family = guard._infer_intent_family(state.initial_intent)
            manager._guards[state.conversation_id] = guard
        return manager

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))

    @classmethod
    def load(cls, path: str | Path) -> SessionManager:
        return cls.from_dict(json.loads(Path(path).read_text()))
