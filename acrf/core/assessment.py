"""The ACRF assessment engine.

Evaluates a system description against the ten ACRF risk dimensions,
each cross-mapped to OWASP Agentic Top 10 and OWASP MCP Top 10 with
AIVSS severity scoring.
"""

from __future__ import annotations

from acrf.core.models import (
    AssessmentResult,
    DimensionResult,
    Evidence,
    MaturityLevel,
    RiskDimension,
    System,
)

# ---------------------------------------------------------------------------
# Control-objective codes per dimension
#
# Each dimension has four control objectives (level 1 → level 4).  An
# assessment awards the highest level whose required objectives all have at
# least one evidence artifact.  See docs/methodology.md for full definitions.
# ---------------------------------------------------------------------------

# fmt: off
LEVEL_REQUIREMENTS: dict[tuple[RiskDimension, int], list[str]] = {
    # ACRF-01  Implicit Trust Between Agents
    (RiskDimension.IMPLICIT_TRUST, 1): ["IT-1"],
    (RiskDimension.IMPLICIT_TRUST, 2): ["IT-1", "IT-2"],
    (RiskDimension.IMPLICIT_TRUST, 3): ["IT-1", "IT-2", "IT-3"],
    (RiskDimension.IMPLICIT_TRUST, 4): ["IT-1", "IT-2", "IT-3", "IT-4"],

    # ACRF-02  No Standard Agent Identity
    (RiskDimension.NO_STANDARD_IDENTITY, 1): ["SI-1"],
    (RiskDimension.NO_STANDARD_IDENTITY, 2): ["SI-1", "SI-2"],
    (RiskDimension.NO_STANDARD_IDENTITY, 3): ["SI-1", "SI-2", "SI-3"],
    (RiskDimension.NO_STANDARD_IDENTITY, 4): ["SI-1", "SI-2", "SI-3", "SI-4"],

    # ACRF-03  MCP Server Sprawl
    (RiskDimension.MCP_SERVER_SPRAWL, 1): ["SS-1"],
    (RiskDimension.MCP_SERVER_SPRAWL, 2): ["SS-1", "SS-2"],
    (RiskDimension.MCP_SERVER_SPRAWL, 3): ["SS-1", "SS-2", "SS-3"],
    (RiskDimension.MCP_SERVER_SPRAWL, 4): ["SS-1", "SS-2", "SS-3", "SS-4"],

    # ACRF-04  Memory Poisoning
    (RiskDimension.MEMORY_POISONING, 1): ["MP-1"],
    (RiskDimension.MEMORY_POISONING, 2): ["MP-1", "MP-2"],
    (RiskDimension.MEMORY_POISONING, 3): ["MP-1", "MP-2", "MP-3"],
    (RiskDimension.MEMORY_POISONING, 4): ["MP-1", "MP-2", "MP-3", "MP-4"],

    # ACRF-05  Supply Chain Toxicity
    (RiskDimension.SUPPLY_CHAIN_TOXICITY, 1): ["SC-1"],
    (RiskDimension.SUPPLY_CHAIN_TOXICITY, 2): ["SC-1", "SC-2"],
    (RiskDimension.SUPPLY_CHAIN_TOXICITY, 3): ["SC-1", "SC-2", "SC-3"],
    (RiskDimension.SUPPLY_CHAIN_TOXICITY, 4): ["SC-1", "SC-2", "SC-3", "SC-4"],

    # ACRF-06  Config Files = Execution Vectors
    (RiskDimension.CONFIG_EXECUTION_VECTORS, 1): ["CE-1"],
    (RiskDimension.CONFIG_EXECUTION_VECTORS, 2): ["CE-1", "CE-2"],
    (RiskDimension.CONFIG_EXECUTION_VECTORS, 3): ["CE-1", "CE-2", "CE-3"],
    (RiskDimension.CONFIG_EXECUTION_VECTORS, 4): ["CE-1", "CE-2", "CE-3", "CE-4"],

    # ACRF-07  Multi-Turn Defense Collapse
    (RiskDimension.MULTI_TURN_DEFENSE_COLLAPSE, 1): ["MT-1"],
    (RiskDimension.MULTI_TURN_DEFENSE_COLLAPSE, 2): ["MT-1", "MT-2"],
    (RiskDimension.MULTI_TURN_DEFENSE_COLLAPSE, 3): ["MT-1", "MT-2", "MT-3"],
    (RiskDimension.MULTI_TURN_DEFENSE_COLLAPSE, 4): ["MT-1", "MT-2", "MT-3", "MT-4"],

    # ACRF-08  Cascading Failure Blindness
    (RiskDimension.CASCADING_FAILURE_BLINDNESS, 1): ["CF-1"],
    (RiskDimension.CASCADING_FAILURE_BLINDNESS, 2): ["CF-1", "CF-2"],
    (RiskDimension.CASCADING_FAILURE_BLINDNESS, 3): ["CF-1", "CF-2", "CF-3"],
    (RiskDimension.CASCADING_FAILURE_BLINDNESS, 4): ["CF-1", "CF-2", "CF-3", "CF-4"],

    # ACRF-09  Semantic Bypass
    (RiskDimension.SEMANTIC_BYPASS, 1): ["SB-1"],
    (RiskDimension.SEMANTIC_BYPASS, 2): ["SB-1", "SB-2"],
    (RiskDimension.SEMANTIC_BYPASS, 3): ["SB-1", "SB-2", "SB-3"],
    (RiskDimension.SEMANTIC_BYPASS, 4): ["SB-1", "SB-2", "SB-3", "SB-4"],

    # ACRF-10  Safety Controls Not Self-Protecting
    (RiskDimension.SAFETY_CONTROLS_NOT_SELF_PROTECTING, 1): ["SP-1"],
    (RiskDimension.SAFETY_CONTROLS_NOT_SELF_PROTECTING, 2): ["SP-1", "SP-2"],
    (RiskDimension.SAFETY_CONTROLS_NOT_SELF_PROTECTING, 3): ["SP-1", "SP-2", "SP-3"],
    (RiskDimension.SAFETY_CONTROLS_NOT_SELF_PROTECTING, 4): ["SP-1", "SP-2", "SP-3", "SP-4"],
}
# fmt: on


def _dimension_criticality(system: System) -> dict[RiskDimension, float]:
    """Compute per-dimension criticality weights for a given system.

    The AIVSS score provides the baseline weight.  System-specific signals
    (cross-boundary channels, high-blast-radius / irreversible actions) add
    additional weight to the dimensions most affected.
    """
    # Start with AIVSS-proportional base weight (normalized to ~1.0 range).
    base: dict[RiskDimension, float] = {}
    for dim in RiskDimension:
        base[dim] = dim.aivss_score / 9.0  # 9.0 as anchor keeps weights near 1.0

    # Systems with cross-boundary channels: elevate trust and identity dims.
    if system.cross_boundary_channels():
        base[RiskDimension.IMPLICIT_TRUST] += 0.5
        base[RiskDimension.NO_STANDARD_IDENTITY] += 0.5
        base[RiskDimension.SEMANTIC_BYPASS] += 0.3

    # High-blast-radius actions: elevate supply chain, config, and safety dims.
    high_risk = system.high_blast_radius_actions()
    if high_risk:
        base[RiskDimension.SUPPLY_CHAIN_TOXICITY] += 0.5
        base[RiskDimension.SAFETY_CONTROLS_NOT_SELF_PROTECTING] += 0.5
        base[RiskDimension.MULTI_TURN_DEFENSE_COLLAPSE] += 0.5

    # Irreversible high-blast-radius actions: further elevate safety controls.
    irreversible_high = [(c, a) for c, a in high_risk if not a.reversible]
    if irreversible_high:
        base[RiskDimension.SAFETY_CONTROLS_NOT_SELF_PROTECTING] += 0.5
        base[RiskDimension.CASCADING_FAILURE_BLINDNESS] += 0.3

    return base


class Assessment:
    """Run an ACRF assessment against a loaded system."""

    def __init__(self, system: System):
        self.system = system

    def run(self) -> AssessmentResult:
        results = [self._assess_dimension(d) for d in RiskDimension]
        backlog = self._build_backlog(results)
        return AssessmentResult(
            system_name=self.system.name,
            acrf_version=self.system.acrf_version,
            assessment_date=self.system.assessment_date,
            dimension_results=results,
            remediation_backlog=backlog,
        )

    def _assess_dimension(self, dimension: RiskDimension) -> DimensionResult:
        evidence = self.system.evidence.get(dimension)
        claimed = evidence.claimed_level if evidence else MaturityLevel.NONE

        awarded_int = 0
        gaps: list[str] = []
        notes: list[str] = []

        # Walk levels 1..4; award the highest level whose requirements are met.
        for level in range(1, 5):
            required = LEVEL_REQUIREMENTS.get((dimension, level), [])
            missing = self._missing_objectives(evidence, required)
            if missing:
                gaps.append(
                    f"Level {level} requires evidence for {', '.join(required)}; "
                    f"missing: {', '.join(missing)}"
                )
                break
            awarded_int = level

        awarded = MaturityLevel(awarded_int)

        if awarded < claimed:
            notes.append(
                f"Claimed level {claimed.value} is not supported by available "
                f"evidence; awarded level {awarded.value}."
            )

        # Dimension-specific notes
        if (
            dimension == RiskDimension.IMPLICIT_TRUST
            and awarded >= MaturityLevel.DEFINED
            and self.system.cross_boundary_channels()
        ):
            notes.append(
                "System has cross-boundary channels; verify that IT-2 "
                "evidence covers external as well as internal trust delegation."
            )

        if (
            dimension == RiskDimension.SAFETY_CONTROLS_NOT_SELF_PROTECTING
            and awarded >= MaturityLevel.DEFINED
            and self.system.high_blast_radius_actions()
        ):
            notes.append(
                "System has high-blast-radius actions; verify that SP-2 "
                "evidence reflects immutable guardrails, not just policy checks."
            )

        if (
            dimension == RiskDimension.CASCADING_FAILURE_BLINDNESS
            and awarded >= MaturityLevel.INITIAL
            and len(self.system.channels) > 3
        ):
            notes.append(
                "System has multiple agent channels; verify that CF-1 "
                "evidence includes circuit-breaker coverage across all hops."
            )

        return DimensionResult(
            dimension=dimension,
            claimed_level=claimed,
            awarded_level=awarded,
            gaps=gaps,
            notes=notes,
        )

    @staticmethod
    def _missing_objectives(
        evidence: Evidence | None, required: list[str]
    ) -> list[str]:
        if evidence is None:
            return list(required)
        covered = {a.control_objective for a in evidence.artifacts}
        return [r for r in required if r not in covered]

    def _build_backlog(self, results: list[DimensionResult]) -> list[str]:
        criticality = _dimension_criticality(self.system)
        # Prioritize by (gap_size * criticality), descending.
        scored: list[tuple[float, DimensionResult]] = []
        for r in results:
            target = 4  # target level for backlog purposes
            gap_size = target - r.awarded_level.value
            if gap_size <= 0:
                continue
            priority = gap_size * criticality[r.dimension]
            scored.append((priority, r))

        scored.sort(key=lambda x: x[0], reverse=True)

        backlog: list[str] = []
        for priority, r in scored:
            next_level = r.awarded_level.value + 1
            required = LEVEL_REQUIREMENTS.get((r.dimension, next_level), [])
            missing = self._missing_objectives(
                self.system.evidence.get(r.dimension), required
            )
            label = f"{r.dimension.acrf_id} {r.dimension.display_name}"
            if missing:
                backlog.append(
                    f"{label}: advance from level "
                    f"{r.awarded_level.value} to {next_level} by providing "
                    f"evidence for {', '.join(missing)} "
                    f"(priority score {priority:.1f})"
                )
            else:
                backlog.append(
                    f"{label}: advance from level "
                    f"{r.awarded_level.value} to {next_level} "
                    f"(priority score {priority:.1f})"
                )
        return backlog
