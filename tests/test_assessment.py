"""Tests for the ACRF assessment engine."""

from __future__ import annotations

from pathlib import Path

from acrf.core.assessment import Assessment
from acrf.core.loader import load_system
from acrf.core.models import (
    Action,
    Agent,
    BlastRadius,
    Channel,
    Evidence,
    EvidenceArtifact,
    MaturityLevel,
    RiskDimension,
    System,
)

EXAMPLE = Path(__file__).parent.parent / "examples" / "travel-booking-agents.yaml"


def _minimal_system(
    evidence: dict[RiskDimension, Evidence] | None = None,
    channels: list[Channel] | None = None,
) -> System:
    default_channels = [
        Channel(
            id="ch1",
            sender="a",
            receiver="b",
            transport="https",
            actions=[Action(name="do", blast_radius=BlastRadius.LOW)],
        )
    ]
    return System(
        acrf_version="0.1",
        name="Test",
        description="Test system",
        agents=[
            Agent(id="a", name="A", role="orchestrator"),
            Agent(id="b", name="B", role="service_agent"),
        ],
        channels=channels or default_channels,
        evidence=evidence or {},
    )


def test_all_dimensions_score_zero_without_evidence():
    result = Assessment(_minimal_system()).run()
    for r in result.dimension_results:
        assert r.awarded_level == MaturityLevel.NONE
        assert r.claimed_level == MaturityLevel.NONE
    assert result.overall_score() == 0.0


def test_evidence_for_it1_awards_level_1():
    evidence = {
        RiskDimension.IMPLICIT_TRUST: Evidence(
            claimed_level=MaturityLevel.INITIAL,
            artifacts=[EvidenceArtifact(control_objective="IT-1", artifact="x")],
        )
    }
    result = Assessment(_minimal_system(evidence=evidence)).run()
    it = result.get(RiskDimension.IMPLICIT_TRUST)
    assert it.awarded_level == MaturityLevel.INITIAL


def test_missing_prerequisite_caps_level():
    # Claim level 3 but only provide IT-2 and IT-3 evidence (missing IT-1).
    evidence = {
        RiskDimension.IMPLICIT_TRUST: Evidence(
            claimed_level=MaturityLevel.MANAGED,
            artifacts=[
                EvidenceArtifact(control_objective="IT-2", artifact="x"),
                EvidenceArtifact(control_objective="IT-3", artifact="y"),
            ],
        )
    }
    result = Assessment(_minimal_system(evidence=evidence)).run()
    it = result.get(RiskDimension.IMPLICIT_TRUST)
    # Level 1 requires IT-1, which is missing.
    assert it.awarded_level == MaturityLevel.NONE
    assert any("IT-1" in gap for gap in it.gaps)


def test_claim_above_evidence_produces_note():
    evidence = {
        RiskDimension.IMPLICIT_TRUST: Evidence(
            claimed_level=MaturityLevel.OPTIMIZED,
            artifacts=[EvidenceArtifact(control_objective="IT-1", artifact="x")],
        )
    }
    result = Assessment(_minimal_system(evidence=evidence)).run()
    it = result.get(RiskDimension.IMPLICIT_TRUST)
    assert it.awarded_level == MaturityLevel.INITIAL
    assert it.claimed_level == MaturityLevel.OPTIMIZED
    assert any("not supported" in note for note in it.notes)


def test_full_evidence_awards_level_4():
    evidence = {
        RiskDimension.IMPLICIT_TRUST: Evidence(
            claimed_level=MaturityLevel.OPTIMIZED,
            artifacts=[
                EvidenceArtifact(control_objective=co, artifact=co)
                for co in ["IT-1", "IT-2", "IT-3", "IT-4"]
            ],
        )
    }
    result = Assessment(_minimal_system(evidence=evidence)).run()
    it = result.get(RiskDimension.IMPLICIT_TRUST)
    assert it.awarded_level == MaturityLevel.OPTIMIZED


def test_bundled_example_scoring():
    system = load_system(EXAMPLE)
    result = Assessment(system).run()

    # Implicit Trust: IT-1, IT-2, IT-3 → level 3
    assert result.get(RiskDimension.IMPLICIT_TRUST).awarded_level == MaturityLevel.MANAGED
    # No Standard Identity: SI-1, SI-2, SI-3 → level 3
    assert result.get(RiskDimension.NO_STANDARD_IDENTITY).awarded_level == MaturityLevel.MANAGED
    # MCP Server Sprawl: SS-1 → level 1
    assert result.get(RiskDimension.MCP_SERVER_SPRAWL).awarded_level == MaturityLevel.INITIAL
    # Memory Poisoning: MP-1 → level 1
    assert result.get(RiskDimension.MEMORY_POISONING).awarded_level == MaturityLevel.INITIAL
    # Supply Chain: SC-1, SC-2 → level 2
    assert result.get(RiskDimension.SUPPLY_CHAIN_TOXICITY).awarded_level == MaturityLevel.DEFINED
    # Config Execution: CE-1, CE-2 → level 2
    assert result.get(RiskDimension.CONFIG_EXECUTION_VECTORS).awarded_level == MaturityLevel.DEFINED
    # Multi-Turn: MT-1 → level 1
    assert (
        result.get(RiskDimension.MULTI_TURN_DEFENSE_COLLAPSE).awarded_level
        == MaturityLevel.INITIAL
    )
    # Cascading Failure: CF-1, CF-2 → level 2
    assert (
        result.get(RiskDimension.CASCADING_FAILURE_BLINDNESS).awarded_level
        == MaturityLevel.DEFINED
    )
    # Semantic Bypass: SB-1 → level 1
    assert result.get(RiskDimension.SEMANTIC_BYPASS).awarded_level == MaturityLevel.INITIAL
    # Safety Controls: SP-1 → level 1
    assert (
        result.get(RiskDimension.SAFETY_CONTROLS_NOT_SELF_PROTECTING).awarded_level
        == MaturityLevel.INITIAL
    )


def test_backlog_prioritizes_higher_criticality_dimension():
    # System with a critical irreversible action should push safety-related
    # dimensions up the priority list.
    channels = [
        Channel(
            id="ch1",
            sender="a",
            receiver="b",
            transport="https",
            actions=[
                Action(name="transfer_funds", blast_radius=BlastRadius.CRITICAL, reversible=False)
            ],
        )
    ]
    result = Assessment(_minimal_system(channels=channels)).run()

    # Safety Controls Not Self-Protecting (AIVSS 9.5 + high-blast bonus)
    # should be near the top of the backlog.
    assert result.remediation_backlog
    safety_positions = [
        i for i, item in enumerate(result.remediation_backlog)
        if "Safety Controls" in item
    ]
    assert safety_positions, "Safety Controls should appear in backlog"
    assert safety_positions[0] <= 2, "Safety Controls should be in top 3"


def test_safety_controls_note_appears_when_warranted():
    # When the system has high-blast-radius actions AND reaches level >= 2 for
    # ACRF-10, the assessor should see a note about immutable guardrails.
    channels = [
        Channel(
            id="ch1",
            sender="a",
            receiver="b",
            transport="https",
            actions=[
                Action(name="book_flight", blast_radius=BlastRadius.HIGH, reversible=False)
            ],
        )
    ]
    evidence = {
        RiskDimension.SAFETY_CONTROLS_NOT_SELF_PROTECTING: Evidence(
            claimed_level=MaturityLevel.DEFINED,
            artifacts=[
                EvidenceArtifact(control_objective="SP-1", artifact="x"),
                EvidenceArtifact(control_objective="SP-2", artifact="y"),
            ],
        )
    }
    system = _minimal_system(evidence=evidence, channels=channels)
    result = Assessment(system).run()
    sp = result.get(RiskDimension.SAFETY_CONTROLS_NOT_SELF_PROTECTING)
    assert sp.awarded_level == MaturityLevel.DEFINED
    assert any("immutable" in note for note in sp.notes)


def test_summary_is_renderable():
    result = Assessment(_minimal_system()).run()
    text = result.summary()
    assert "ACRF Assessment" in text
    assert "ACRF-01" in text
    assert "Implicit Trust" in text


def test_ten_dimensions_are_assessed():
    """Every assessment should produce results for all 10 risk dimensions."""
    result = Assessment(_minimal_system()).run()
    assert len(result.dimension_results) == 10
    assessed_dims = {r.dimension for r in result.dimension_results}
    assert assessed_dims == set(RiskDimension)


def test_backward_compat_domain_results_alias():
    """The .domain_results alias should still work for backward compatibility."""
    result = Assessment(_minimal_system()).run()
    assert result.domain_results is result.dimension_results
    for r in result.domain_results:
        assert r.domain is r.dimension
