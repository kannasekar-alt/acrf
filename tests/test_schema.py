"""Tests that the JSON Schema for system descriptions is valid and accepts the example."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

SCHEMA_PATH = Path(__file__).parent.parent / "specs" / "system-description.schema.json"
EXAMPLE = Path(__file__).parent.parent / "examples" / "travel-booking-agents.yaml"


def test_schema_is_valid_json():
    schema = json.loads(SCHEMA_PATH.read_text())
    assert schema["title"] == "ACRF System Description"
    assert "properties" in schema


def test_example_validates_against_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA_PATH.read_text())
    example = yaml.safe_load(EXAMPLE.read_text())
    jsonschema.validate(instance=example, schema=schema)


def test_schema_rejects_missing_top_level_field():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA_PATH.read_text())
    bad = {"acrf_version": "0.1", "system": {"name": "x", "description": "y"}}
    # Missing agents and channels.
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=bad, schema=schema)
