"""Exceptions raised by acrf-identity."""


class AgentIdentityError(Exception):
    """Base exception for all agent identity errors."""


class InvalidSignatureError(AgentIdentityError):
    """Raised when a message signature does not verify against the sender public key."""


class AgentNotTrustedError(AgentIdentityError):
    """Raised when verifying a message from an agent not in the trust store."""


class AgentRevokedError(AgentIdentityError):
    """Raised when verifying a message from a revoked agent."""


class MessageExpiredError(AgentIdentityError):
    """Raised when a message timestamp is too old (replay protection)."""


class NonceReusedError(AgentIdentityError):
    """Raised when a message nonce has been seen before (replay protection)."""
