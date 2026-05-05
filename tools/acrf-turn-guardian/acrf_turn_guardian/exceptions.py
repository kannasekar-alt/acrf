"""Exceptions raised by acrf-turn-guardian."""


class TurnGuardError(Exception):
    """Base exception for all turn guardian errors."""


class IntentDriftError(TurnGuardError):
    """Raised when a proposed action contradicts the initial conversation intent."""


class TurnLimitExceededError(TurnGuardError):
    """Raised when conversation has exceeded the configured maximum turn count."""


class TopicShiftError(TurnGuardError):
    """Raised when a sudden topic shift is detected mid-conversation."""


class SensitiveActionError(TurnGuardError):
    """Raised when a sensitive operation is introduced after initial scope was set."""


class ConversationNotFoundError(TurnGuardError):
    """Raised when an operation references an unknown conversation id."""
