"""Exceptions raised by acrf-semantic-guard."""


class SemanticGuardError(Exception):
    """Base exception for all semantic guard errors."""


class SemanticThreatError(SemanticGuardError):
    """Raised when a semantic threat is detected in an instruction."""

    def __init__(self, message: str, threats: list[dict] | None = None) -> None:
        super().__init__(message)
        self.threats = threats or []
