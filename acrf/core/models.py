"""Data models for ACRF system descriptions and assessment results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class RiskDimension(str, Enum):
    """The ten ACRF risk dimensions for agent-to-agent communication security.

    Each dimension is cross-mapped to OWASP Agentic Top 10 (ASI) and
    OWASP MCP Top 10, scored with AIVSS (AI Vulnerability Severity Scoring),
    and paired with a concrete defense pattern.
    """

    IMPLICIT_TRUST = "implicit_trust"
    NO_STANDARD_IDENTITY = "no_standard_identity"
    MCP_SERVER_SPRAWL = "mcp_server_sprawl"
    MEMORY_POISONING = "memory_poisoning"
    SUPPLY_CHAIN_TOXICITY = "supply_chain_toxicity"
    CONFIG_EXECUTION_VECTORS = "config_execution_vectors"
    MULTI_TURN_DEFENSE_COLLAPSE = "multi_turn_defense_collapse"
    CASCADING_FAILURE_BLINDNESS = "cascading_failure_blindness"
    SEMANTIC_BYPASS = "semantic_bypass"
    SAFETY_CONTROLS_NOT_SELF_PROTECTING = "safety_controls_not_self_protecting"

    @property
    def display_name(self) -> str:
        return _DIMENSION_METADATA[self]["display_name"]

    @property
    def short_code(self) -> str:
        return _DIMENSION_METADATA[self]["short_code"]

    @property
    def acrf_id(self) -> str:
        """The ACRF identifier, e.g. 'ACRF-01'."""
        return _DIMENSION_METADATA[self]["acrf_id"]

    @property
    def owasp_agentic(self) -> str:
        """Cross-mapping to OWASP Agentic Top 10 (ASI)."""
        return _DIMENSION_METADATA[self]["owasp_agentic"]

    @property
    def owasp_mcp(self) -> str:
        """Cross-mapping to OWASP MCP Top 10."""
        return _DIMENSION_METADATA[self]["owasp_mcp"]

    @property
    def aivss_score(self) -> float:
        """AIVSS severity score (0.0–10.0)."""
        return _DIMENSION_METADATA[self]["aivss_score"]

    @property
    def aivss_severity(self) -> str:
        """AIVSS severity label: Critical (>=9.0), High (>=7.0), etc."""
        score = self.aivss_score
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        return "Low"

    @property
    def defense_pattern(self) -> str:
        """Recommended defense pattern."""
        return _DIMENSION_METADATA[self]["defense_pattern"]


# Kept as module-level dict for clean separation of data from logic.
_DIMENSION_METADATA: dict[RiskDimension, dict] = {
    RiskDimension.IMPLICIT_TRUST: {
        "display_name": "Implicit Trust Between Agents",
        "short_code": "IT",
        "acrf_id": "ACRF-01",
        "owasp_agentic": "ASI07 Insecure Inter-Agent",
        "owasp_mcp": "MCP07 Insufficient Auth",
        "aivss_score": 9.2,
        "defense_pattern": "Warrant delegation, mTLS, signed Agent Cards",
    },
    RiskDimension.NO_STANDARD_IDENTITY: {
        "display_name": "No Standard Agent Identity",
        "short_code": "SI",
        "acrf_id": "ACRF-02",
        "owasp_agentic": "ASI03 Identity & Privilege",
        "owasp_mcp": "MCP01 Token Mismanagement",
        "aivss_score": 9.0,
        "defense_pattern": "Agent Naming Service, OAuth 2.1, scoped tokens",
    },
    RiskDimension.MCP_SERVER_SPRAWL: {
        "display_name": "MCP Server Sprawl",
        "short_code": "SS",
        "acrf_id": "ACRF-03",
        "owasp_agentic": "ASI04 Supply Chain Vulns",
        "owasp_mcp": "MCP09 Shadow MCP Servers",
        "aivss_score": 8.4,
        "defense_pattern": "Agent inventory, mcp-scan, AIBOM",
    },
    RiskDimension.MEMORY_POISONING: {
        "display_name": "Memory Poisoning",
        "short_code": "MP",
        "acrf_id": "ACRF-04",
        "owasp_agentic": "ASI06 Memory & Context",
        "owasp_mcp": "MCP06 Intent Flow Subversion",
        "aivss_score": 9.1,
        "defense_pattern": "Namespace isolation, contextual integrity",
    },
    RiskDimension.SUPPLY_CHAIN_TOXICITY: {
        "display_name": "Supply Chain Toxicity",
        "short_code": "SC",
        "acrf_id": "ACRF-05",
        "owasp_agentic": "ASI04 Supply Chain Vulns",
        "owasp_mcp": "MCP03, MCP04 Tool Poisoning",
        "aivss_score": 9.3,
        "defense_pattern": "Lock dependency versions, skill-scanner",
    },
    RiskDimension.CONFIG_EXECUTION_VECTORS: {
        "display_name": "Config Files = Execution Vectors",
        "short_code": "CE",
        "acrf_id": "ACRF-06",
        "owasp_agentic": "ASI05 Unexpected Code Exec",
        "owasp_mcp": "MCP05 Command Injection",
        "aivss_score": 8.7,
        "defense_pattern": "Sandboxing, read-only configs",
    },
    RiskDimension.MULTI_TURN_DEFENSE_COLLAPSE: {
        "display_name": "Multi-Turn Defense Collapse",
        "short_code": "MT",
        "acrf_id": "ACRF-07",
        "owasp_agentic": "ASI01 Goal Hijack",
        "owasp_mcp": "MCP06 Intent Flow Subversion",
        "aivss_score": 9.4,
        "defense_pattern": "Deterministic intermediaries, session limits",
    },
    RiskDimension.CASCADING_FAILURE_BLINDNESS: {
        "display_name": "Cascading Failure Blindness",
        "short_code": "CF",
        "acrf_id": "ACRF-08",
        "owasp_agentic": "ASI08 Cascading Failures",
        "owasp_mcp": "MCP08 Lack of Audit",
        "aivss_score": 8.5,
        "defense_pattern": "Circuit breakers, agent-aware SIEM",
    },
    RiskDimension.SEMANTIC_BYPASS: {
        "display_name": "Semantic Bypass",
        "short_code": "SB",
        "acrf_id": "ACRF-09",
        "owasp_agentic": "ASI09 Human-Agent Trust",
        "owasp_mcp": "MCP10 Context Over-Sharing",
        "aivss_score": 8.6,
        "defense_pattern": "Guardian agents, intent validation",
    },
    RiskDimension.SAFETY_CONTROLS_NOT_SELF_PROTECTING: {
        "display_name": "Safety Controls Not Self-Protecting",
        "short_code": "SP",
        "acrf_id": "ACRF-10",
        "owasp_agentic": "ASI10 Rogue Agents",
        "owasp_mcp": "MCP02 Privilege Escalation",
        "aivss_score": 9.5,
        "defense_pattern": "Least agency, immutable guardrails",
    },
}


# --- Backward-compatibility alias ---
# Early versions of ACRF used "Domain" for the enum name. Keep the alias so
# that any downstream code or plugin that imports Domain still works.
Domain = RiskDimension


class MaturityLevel(int, Enum):
    """The 0-4 ACRF maturity scale."""

    NONE = 0
    INITIAL = 1
    DEFINED = 2
    MANAGED = 3
    OPTIMIZED = 4


class BlastRadius(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Action:
    """An action invocable over an agent-to-agent channel."""

    name: str
    blast_radius: BlastRadius
    reversible: bool = True


@dataclass
class Agent:
    """An agent participating in the system."""

    id: str
    name: str
    role: str
    identity_scheme: str | None = None
    operates_on_behalf_of: str | None = None


@dataclass
class Channel:
    """A communication channel between two agents."""

    id: str
    sender: str
    receiver: str
    transport: str
    message_format: str | None = None
    crosses_trust_boundary: bool = False
    synchronous: bool = True
    actions: list[Action] = field(default_factory=list)


@dataclass
class TrustBoundary:
    id: str
    name: str
    description: str | None = None


@dataclass
class EvidenceArtifact:
    """A single piece of evidence supporting a control objective."""

    control_objective: str
    artifact: str
    description: str | None = None


@dataclass
class Evidence:
    """Evidence supplied for a single risk dimension."""

    claimed_level: MaturityLevel
    artifacts: list[EvidenceArtifact] = field(default_factory=list)

    def artifacts_for(self, control_objective: str) -> list[EvidenceArtifact]:
        return [a for a in self.artifacts if a.control_objective == control_objective]


@dataclass
class System:
    """A complete ACRF system description."""

    acrf_version: str
    name: str
    description: str
    agents: list[Agent]
    channels: list[Channel]
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    evidence: dict[RiskDimension, Evidence] = field(default_factory=dict)
    owner: str | None = None
    assessment_date: str | None = None

    def agent_by_id(self, agent_id: str) -> Agent | None:
        return next((a for a in self.agents if a.id == agent_id), None)

    def cross_boundary_channels(self) -> list[Channel]:
        return [c for c in self.channels if c.crosses_trust_boundary]

    def high_blast_radius_actions(self) -> list[tuple[Channel, Action]]:
        result = []
        for channel in self.channels:
            for action in channel.actions:
                if action.blast_radius in (BlastRadius.HIGH, BlastRadius.CRITICAL):
                    result.append((channel, action))
        return result


@dataclass
class DimensionResult:
    """The result of assessing a single risk dimension."""

    dimension: RiskDimension
    claimed_level: MaturityLevel
    awarded_level: MaturityLevel
    gaps: list[str]
    notes: list[str] = field(default_factory=list)

    # Backward-compatibility alias
    @property
    def domain(self) -> RiskDimension:
        return self.dimension


# Backward-compatibility alias
DomainResult = DimensionResult


@dataclass
class AssessmentResult:
    """The full result of an ACRF assessment."""

    system_name: str
    acrf_version: str
    assessment_date: str | None
    dimension_results: list[DimensionResult]
    remediation_backlog: list[str]

    # Backward-compatibility alias
    @property
    def domain_results(self) -> list[DimensionResult]:
        return self.dimension_results

    def get(self, dimension: RiskDimension) -> DimensionResult:
        return next(r for r in self.dimension_results if r.dimension == dimension)

    def overall_score(self) -> float:
        """Mean of awarded levels across all assessed dimensions."""
        if not self.dimension_results:
            return 0.0
        return sum(r.awarded_level for r in self.dimension_results) / len(
            self.dimension_results
        )

    def summary(self) -> str:
        lines = [f"ACRF Assessment  - {self.system_name}"]
        lines.append(f"Methodology v{self.acrf_version}")
        if self.assessment_date:
            lines.append(f"Assessed: {self.assessment_date}")
        lines.append("")
        for r in self.dimension_results:
            marker = "=" if r.awarded_level == r.claimed_level else "▼"
            lines.append(
                f"  [{marker}] {r.dimension.acrf_id} {r.dimension.display_name:45s} "
                f"AIVSS {r.dimension.aivss_score}  "
                f"claimed {r.claimed_level.value}  awarded {r.awarded_level.value}"
            )
        lines.append("")
        lines.append(f"Overall mean: {self.overall_score():.2f}")
        return "\n".join(lines)
