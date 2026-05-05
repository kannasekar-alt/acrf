"""Exceptions raised by acrf-safety-shield."""


class SafetyShieldError(Exception):
    """Base exception for all safety shield errors."""


class PrivilegeError(SafetyShieldError):
    """Raised when a non-admin credential tries to modify safety state."""


class InsufficientApprovalsError(SafetyShieldError):
    """Raised when a high-risk change does not have enough admin approvals."""


class InvalidAdminCredentialError(SafetyShieldError):
    """Raised when an admin credential signature does not verify."""


class UnknownAdminError(SafetyShieldError):
    """Raised when an admin credential is not in the trusted set."""
