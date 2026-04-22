"""Tests for report rendering."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acrf.core.assessment import Assessment
from acrf.core.loader import load_system
from acrf.core.report import render, to_json, to_markdown

EXAMPLE = Path(__file__).parent.parent / "examples" / "travel-booking-agents.yaml"


@pytest.fixture()
def result():
    return Assessment(load_system(EXAMPLE)).run()


def test_markdown_includes_header_and_table(result):
    md = to_markdown(result)
    assert md.startswith("# ACRF Assessment  -")
    assert "| # | Risk Dimension | AIVSS | Claimed | Awarded |" in md
    assert "Implicit Trust Between Agents" in md
    assert "Remediation backlog" in md


def test_markdown_mentions_all_dimensions(result):
    md = to_markdown(result)
    for dim_name in [
        "Implicit Trust Between Agents",
        "No Standard Agent Identity",
        "MCP Server Sprawl",
        "Memory Poisoning",
        "Supply Chain Toxicity",
        "Config Files = Execution Vectors",
        "Multi-Turn Defense Collapse",
        "Cascading Failure Blindness",
        "Semantic Bypass",
        "Safety Controls Not Self-Protecting",
    ]:
        assert dim_name in md


def test_markdown_includes_cross_mappings(result):
    md = to_markdown(result)
    assert "OWASP Agentic" in md
    assert "OWASP MCP" in md
    assert "AIVSS" in md
    assert "Defense pattern" in md


def test_json_is_valid_and_structured(result):
    payload = json.loads(to_json(result))
    assert payload["acrf_version"] == "0.1"
    assert payload["system_name"] == "Travel Booking Multi-Agent System"
    assert len(payload["dimension_results"]) == 10
    for dr in payload["dimension_results"]:
        assert "acrf_id" in dr
        assert "dimension" in dr
        assert "owasp_agentic" in dr
        assert "owasp_mcp" in dr
        assert "aivss_score" in dr
        assert "claimed_level" in dr
        assert "awarded_level" in dr
        assert 0 <= dr["claimed_level"] <= 4
        assert 0 <= dr["awarded_level"] <= 4
    assert isinstance(payload["remediation_backlog"], list)


def test_render_dispatches_on_format(result):
    assert render(result, format="markdown").startswith("# ACRF Assessment")
    json.loads(render(result, format="json"))  # should not raise


def test_render_unknown_format_raises(result):
    with pytest.raises(ValueError, match="Unknown format"):
        render(result, format="xml")  # type: ignore[arg-type]
