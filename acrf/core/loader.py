"""Loader for ACRF system description files (YAML or JSON)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

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
    TrustBoundary,
)


class SystemDescriptionError(ValueError):
    """Raised when a system description file cannot be loaded."""


# Enum values from the JSON Schema (specs/system-description.schema.json).
# Kept here as frozensets so the loader and schema stay in sync.
_VALID_ROLES: frozenset[str] = frozenset(
    {"orchestrator", "tool_user", "service_agent", "third_party"}
)
_VALID_OPERATES_ON_BEHALF_OF: frozenset[str] = frozenset(
    {"user", "service", "unattended"}
)


def load_system(path: str | Path) -> System:
    """Load a system description from a YAML or JSON file."""
    path = Path(path)
    if not path.exists():
        raise SystemDescriptionError(f"File not found: {path}")

    text = path.read_text(encoding="utf-8")

    try:
        if path.suffix in (".yaml", ".yml"):
            data = yaml.safe_load(text)
        elif path.suffix == ".json":
            data = json.loads(text)
        else:
            # Try YAML first (superset of JSON), then JSON as fallback.
            try:
                data = yaml.safe_load(text)
            except yaml.YAMLError:
                data = json.loads(text)
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise SystemDescriptionError(f"Malformed system description: {exc}") from exc

    if not isinstance(data, dict):
        raise SystemDescriptionError("Top-level document must be a mapping.")

    return _build_system(data)


def _build_system(data: dict[str, Any]) -> System:
    _require(data, "acrf_version", str)
    _require(data, "system", dict)
    _require(data, "agents", list)
    _require(data, "channels", list)

    system_block = data["system"]
    _require(system_block, "name", str)
    _require(system_block, "description", str)

    agents = [_build_agent(a) for a in data["agents"]]
    channels = [_build_channel(c) for c in data["channels"]]
    trust_boundaries = [_build_trust_boundary(tb) for tb in data.get("trust_boundaries", [])]
    evidence = _build_evidence(data.get("evidence", {}))

    _validate_channel_references(channels, agents)

    return System(
        acrf_version=str(data["acrf_version"]),
        name=system_block["name"],
        description=system_block["description"],
        owner=system_block.get("owner"),
        assessment_date=system_block.get("assessment_date"),
        agents=agents,
        channels=channels,
        trust_boundaries=trust_boundaries,
        evidence=evidence,
    )


def _build_agent(data: dict[str, Any]) -> Agent:
    _require(data, "id", str)
    _require(data, "name", str)
    _require(data, "role", str)

    role = data["role"]
    if role not in _VALID_ROLES:
        raise SystemDescriptionError(
            f"Agent {data.get('id', '?')!r} has invalid role {role!r}; "
            f"must be one of {sorted(_VALID_ROLES)}"
        )

    operates_on_behalf_of = data.get("operates_on_behalf_of")
    if operates_on_behalf_of is not None and operates_on_behalf_of not in _VALID_OPERATES_ON_BEHALF_OF:
        raise SystemDescriptionError(
            f"Agent {data.get('id', '?')!r} has invalid operates_on_behalf_of "
            f"{operates_on_behalf_of!r}; must be one of "
            f"{sorted(_VALID_OPERATES_ON_BEHALF_OF)}"
        )

    return Agent(
        id=data["id"],
        name=data["name"],
        role=role,
        identity_scheme=data.get("identity_scheme"),
        operates_on_behalf_of=operates_on_behalf_of,
    )


def _build_channel(data: dict[str, Any]) -> Channel:
    _require(data, "id", str)
    _require(data, "sender", str)
    _require(data, "receiver", str)
    _require(data, "transport", str)

    actions = [_build_action(a) for a in data.get("actions", [])]
    return Channel(
        id=data["id"],
        sender=data["sender"],
        receiver=data["receiver"],
        transport=data["transport"],
        message_format=data.get("message_format"),
        crosses_trust_boundary=bool(data.get("crosses_trust_boundary", False)),
        synchronous=bool(data.get("synchronous", True)),
        actions=actions,
    )


def _build_action(data: dict[str, Any]) -> Action:
    _require(data, "name", str)
    _require(data, "blast_radius", str)
    try:
        blast = BlastRadius(data["blast_radius"])
    except ValueError as exc:
        raise SystemDescriptionError(
            f"Invalid blast_radius {data['blast_radius']!r}; must be one of "
            f"{[b.value for b in BlastRadius]}"
        ) from exc
    return Action(
        name=data["name"],
        blast_radius=blast,
        reversible=bool(data.get("reversible", True)),
    )


def _build_trust_boundary(data: dict[str, Any]) -> TrustBoundary:
    _require(data, "id", str)
    _require(data, "name", str)
    return TrustBoundary(
        id=data["id"],
        name=data["name"],
        description=data.get("description"),
    )


def _build_evidence(data: dict[str, Any]) -> dict[RiskDimension, Evidence]:
    result: dict[RiskDimension, Evidence] = {}
    for key, block in data.items():
        try:
            dimension = RiskDimension(key)
        except ValueError as exc:
            raise SystemDescriptionError(
                f"Unknown evidence dimension {key!r}; must be one of "
                f"{[d.value for d in RiskDimension]}"
            ) from exc
        if not isinstance(block, dict):
            raise SystemDescriptionError(f"Evidence for {key!r} must be a mapping.")

        level_value = block.get("claimed_level", 0)
        if not isinstance(level_value, int) or level_value < 0 or level_value > 4:
            raise SystemDescriptionError(
                f"Evidence for {key!r} has invalid claimed_level {level_value!r} "
                f"(must be integer 0-4)."
            )

        artifacts = [_build_artifact(a) for a in block.get("artifacts", [])]
        result[dimension] = Evidence(
            claimed_level=MaturityLevel(level_value),
            artifacts=artifacts,
        )
    return result


def _build_artifact(data: dict[str, Any]) -> EvidenceArtifact:
    _require(data, "control_objective", str)
    _require(data, "artifact", str)
    return EvidenceArtifact(
        control_objective=data["control_objective"],
        artifact=data["artifact"],
        description=data.get("description"),
    )


def _validate_channel_references(channels: list[Channel], agents: list[Agent]) -> None:
    agent_ids = {a.id for a in agents}
    for c in channels:
        if c.sender not in agent_ids:
            raise SystemDescriptionError(
                f"Channel {c.id!r} references unknown sender agent {c.sender!r}."
            )
        if c.receiver not in agent_ids:
            raise SystemDescriptionError(
                f"Channel {c.id!r} references unknown receiver agent {c.receiver!r}."
            )


def _require(data: dict[str, Any], key: str, expected_type: type) -> None:
    if key not in data:
        raise SystemDescriptionError(f"Missing required field: {key!r}")
    if not isinstance(data[key], expected_type):
        raise SystemDescriptionError(
            f"Field {key!r} must be of type {expected_type.__name__}, "
            f"got {type(data[key]).__name__}."
        )
