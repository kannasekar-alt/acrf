"""Tests for the ACRF CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acrf.cli.main import main

EXAMPLE = Path(__file__).parent.parent / "examples" / "travel-booking-agents.yaml"


def test_validate_prints_ok(capsys):
    rc = main(["validate", str(EXAMPLE)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "valid ACRF system description" in out


def test_validate_rejects_bad_file(capsys, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("not: valid: yaml: [")
    rc = main(["validate", str(bad)])
    assert rc == 2


def test_assess_prints_summary(capsys):
    rc = main(["assess", str(EXAMPLE)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "ACRF Assessment" in out
    assert "ACRF-01" in out
    assert "Implicit Trust" in out
    assert "Remediation backlog" in out


def test_report_markdown_to_stdout(capsys):
    rc = main(["report", str(EXAMPLE), "--format", "markdown"])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.startswith("# ACRF Assessment")


def test_report_json_to_file(tmp_path, capsys):
    out_file = tmp_path / "out.json"
    rc = main(["report", str(EXAMPLE), "--format", "json", "-o", str(out_file)])
    assert rc == 0
    data = json.loads(out_file.read_text())
    assert data["system_name"] == "Travel Booking Multi-Agent System"
    assert len(data["dimension_results"]) == 10


def test_no_args_exits_nonzero(capsys):
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code != 0


def test_validate_rejects_invalid_role(capsys, tmp_path):
    """validate should fail (rc=2) for a file with an agent role not in the schema enum."""
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "acrf_version: '0.1'\n"
        "system:\n  name: X\n  description: Y\n"
        "agents:\n  - id: a\n    name: A\n    role: hacker\n"
        "channels:\n  - id: ch1\n    sender: a\n    receiver: a\n    transport: https\n"
    )
    rc = main(["validate", str(bad)])
    assert rc == 2


def test_validate_catches_schema_violation_missing_required(capsys, tmp_path):
    """validate should fail (rc=2) when top-level required fields are absent."""
    pytest.importorskip("jsonschema")  # skip if jsonschema not installed
    bad = tmp_path / "bad.yaml"
    # Missing 'agents' and 'channels'  - valid YAML but fails JSON Schema.
    bad.write_text(
        "acrf_version: '0.1'\n"
        "system:\n  name: X\n  description: Y\n"
    )
    rc = main(["validate", str(bad)])
    assert rc == 2
