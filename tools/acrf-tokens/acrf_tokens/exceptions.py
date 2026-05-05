"""Exceptions raised by acrf-tokens."""


class TokenError(Exception):
    """Base exception for all token errors."""


class InvalidTokenError(TokenError):
    """Raised when a token is malformed or its signature does not verify."""


class TokenExpiredError(TokenError):
    """Raised when a token has passed its expires_at time."""


class TokenRevokedError(TokenError):
    """Raised when a token has been revoked."""


class TokenScopeError(TokenError):
    """Raised when a required scope is not present in the token."""
