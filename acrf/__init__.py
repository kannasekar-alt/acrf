"""
ACRF - Agent Communication Risk Framework

A structured risk methodology for securing agent-to-agent (A2A)
communications. Ten risk dimensions, severity-scored and defense-paired,
covering the trust failures that emerge when autonomous AI agents
talk to each other.

See https://github.com/kannasekar-alt/acrf for documentation.
"""

from acrf.core.assessment import Assessment
from acrf.core.loader import load_system
from acrf.core.models import (
    Action,
    Agent,
    AssessmentResult,
    BlastRadius,
    Channel,
    DimensionResult,
    Domain,
    DomainResult,
    Evidence,
    EvidenceArtifact,
    MaturityLevel,
    RiskDimension,
    System,
    TrustBoundary,
)

__version__ = "0.1.0"
__all__ = [
    # Core model types
    "Action",
    "Agent",
    "BlastRadius",
    "Channel",
    "Evidence",
    "EvidenceArtifact",
    "System",
    "TrustBoundary",
    # Enums and result types
    "RiskDimension",
    "Domain",          # backward-compat alias
    "MaturityLevel",
    "AssessmentResult",
    "DimensionResult",
    "DomainResult",    # backward-compat alias
    # Assessment and loading
    "Assessment",
    "load_system",
]
