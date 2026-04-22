"""Tests for the system description loader."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from acrf.core.loader import SystemDescriptionError, load_system
from acrf.core.models import BlastRadius, MaturityLevel, RiskDimension

EXAMPLE = Path(__file__).parent.parent / "examples" / "travel-booking-agents.yaml"


def test_loads_bundled_example():
    system = load_system(EXAMPLE)
    assert system.name == "Travel Booking Multi-Agent System"
    assert system.acrf_version == "0.1"
    assert len(system.agents) == 5
    assert len(system.channels) == 4
    assert {a.id for a in system.agents} == {
        "concierge",
        "flight-agent",
        "hotel-agent",
        "car-agent",
        "deal-finder",
    }


def test_example_evidence_is_parsed():
    system = load_system(EXAMPLE)
    it = system.evidence[RiskDimension.IMPLICIT_TRUST]
    assert it.claimed_level == MaturityLevel.MANAGED
    assert {a.control_objective for a in it.artifacts} == {"IT-1", "IT-2", "IT-3"}


def test_example_cross_boundary_channel_is_flagged():
    system = load_system(EXAMPLE)
    cross = system.cross_boundary_channels()
    assert len(cross) == 1
    assert cross[0].id == "ch-concierge-deals"


def test_high_blast_radius_actions_are_enumerated():
    system = load_system(EXAMPLE)
    high = system.high_blast_radius_actions()
    # book_flight, book_hotel, book_car are all high
    action_names = {a.name for _, a in high}
    assert action_names == {"book_flight", "book_hotel", "book_car"}
    for _, action in high:
        assert action.blast_radius == BlastRadius.HIGH


def test_missing_file_raises(tmp_path):
    with pytest.raises(SystemDescriptionError, match="File not found"):
        load_system(tmp_path / "does-not-exist.yaml")


def test_missing_required_field_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        textwrap.dedent(
            """\
            acrf_version: "0.1"
            system:
              name: "X"
              description: "Y"
            agents: []
            # channels missing
            """
        )
    )
    with pytest.raises(SystemDescriptionError, match="channels"):
        load_system(bad)


def test_channel_references_unknown_agent_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        textwrap.dedent(
            """\
            acrf_version: "0.1"
            system:
              name: "X"
              description: "Y"
            agents:
              - id: a
                name: A
                role: orchestrator
            channels:
              - id: ch1
                sender: a
                receiver: ghost
                transport: https
            """
        )
    )
    with pytest.raises(SystemDescriptionError, match="ghost"):
        load_system(bad)


def test_invalid_blast_radius_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        textwrap.dedent(
            """\
            acrf_version: "0.1"
            system:
              name: "X"
              description: "Y"
            agents:
              - id: a
                name: A
                role: orchestrator
              - id: b
                name: B
                role: service_agent
            channels:
              - id: ch1
                sender: a
                receiver: b
                transport: https
                actions:
                  - name: do_thing
                    blast_radius: apocalyptic
            """
        )
    )
    with pytest.raises(SystemDescriptionError, match="blast_radius"):
        load_system(bad)


def test_invalid_claimed_level_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        textwrap.dedent(
            """\
            acrf_version: "0.1"
            system:
              name: "X"
              description: "Y"
            agents:
              - id: a
                name: A
                role: orchestrator
              - id: b
                name: B
                role: service_agent
            channels:
              - id: ch1
                sender: a
                receiver: b
                transport: https
            evidence:
              implicit_trust:
                claimed_level: 9
            """
        )
    )
    with pytest.raises(SystemDescriptionError, match="claimed_level"):
        load_system(bad)


def test_unknown_dimension_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        textwrap.dedent(
            """\
            acrf_version: "0.1"
            system:
              name: "X"
              description: "Y"
            agents:
              - id: a
                name: A
                role: orchestrator
              - id: b
                name: B
                role: service_agent
            channels:
              - id: ch1
                sender: a
                receiver: b
                transport: https
            evidence:
              vibes_dimension:
                claimed_level: 2
            """
        )
    )
    with pytest.raises(SystemDescriptionError, match="vibes_dimension"):
        load_system(bad)


def test_malformed_yaml_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("not: valid: yaml: [")
    with pytest.raises(SystemDescriptionError):
        load_system(bad)


def test_invalid_agent_role_raises(tmp_path):
    """Agent role must be one of the schema-defined enum values."""
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        textwrap.dedent(
            """\
            acrf_version: "0.1"
            system:
              name: "X"
              description: "Y"
            agents:
              - id: a
                name: A
                role: hacker
            channels:
              - id: ch1
                sender: a
                receiver: a
                transport: https
            """
        )
    )
    with pytest.raises(SystemDescriptionError, match="role"):
        load_system(bad)


def test_invalid_operates_on_behalf_of_raises(tmp_path):
    """operates_on_behalf_of must be one of the schema-defined enum values."""
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        textwrap.dedent(
            """\
            acrf_version: "0.1"
            system:
              name: "X"
              description: "Y"
            agents:
              - id: a
                name: A
                role: orchestrator
                operates_on_behalf_of: everyone
            channels:
              - id: ch1
                sender: a
                receiver: a
                transport: https
            """
        )
    )
    with pytest.raises(SystemDescriptionError, match="operates_on_behalf_of"):
        load_system(bad)


def test_operates_on_behalf_of_is_optional(tmp_path):
    """operates_on_behalf_of is optional; omitting it should not raise."""
    ok = tmp_path / "ok.yaml"
    ok.write_text(
        textwrap.dedent(
            """\
            acrf_version: "0.1"
            system:
              name: "X"
              description: "Y"
            agents:
              - id: a
                name: A
                role: orchestrator
            channels:
              - id: ch1
                sender: a
                receiver: a
                transport: https
            """
        )
    )
    system = load_system(ok)
    assert system.agents[0].operates_on_behalf_of is None
