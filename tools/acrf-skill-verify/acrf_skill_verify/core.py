"""
acrf-skill-verify core module.

Implements ACRF-05 defense pattern: supply chain toxicity.

The pattern:
1. Maintain a registry of approved skills with their expected SHA-256 hash
2. Before installing or executing any skill, hash its actual content
3. Compare actual hash to expected hash from the registry
4. Refuse to load tampered or unregistered skills - fail closed

Also supports a blocklist of known-malicious skill names for additional defense.
"""
import hashlib
import json
from pathlib import Path


class SkillIntegrityError(Exception):
    """Raised when skill integrity verification fails."""


def compute_hash(content: bytes) -> str:
    """Compute SHA-256 hash of skill content."""
    digest = hashlib.sha256(content).hexdigest()
    return f"sha256:{digest}"


def hash_file(skill_path: str | Path) -> str:
    """Compute SHA-256 hash of a skill file."""
    path = Path(skill_path)
    return compute_hash(path.read_bytes())


def hash_directory(skill_dir: str | Path) -> str:
    """
    Compute deterministic SHA-256 hash of an entire skill directory.

    Hashes file contents in sorted order to ensure deterministic output
    regardless of filesystem ordering.
    """
    path = Path(skill_dir)
    if not path.is_dir():
        raise ValueError(f"Not a directory: {skill_dir}")

    hasher = hashlib.sha256()
    files = sorted(p for p in path.rglob("*") if p.is_file())
    for file_path in files:
        relative = file_path.relative_to(path).as_posix()
        hasher.update(relative.encode())
        hasher.update(b"\x00")
        hasher.update(file_path.read_bytes())
        hasher.update(b"\x00")

    return f"sha256:{hasher.hexdigest()}"


class SkillRegistry:
    """
    Registry of approved skills with expected hashes and blocklist.

    Use this to maintain your organization's allowlist of vetted skills.
    Persist the registry to JSON for use across processes.
    """

    def __init__(self) -> None:
        self._approved: dict[str, str] = {}
        self._blocklist: set[str] = set()

    def register(self, skill_name: str, expected_hash: str) -> None:
        """Register an approved skill with its expected hash."""
        if skill_name in self._blocklist:
            raise SkillIntegrityError(
                f"Cannot register {skill_name}: skill is on the blocklist"
            )
        self._approved[skill_name] = expected_hash

    def block(self, skill_name: str) -> None:
        """Add a skill name to the blocklist."""
        self._blocklist.add(skill_name)
        self._approved.pop(skill_name, None)

    def is_blocked(self, skill_name: str) -> bool:
        return skill_name in self._blocklist

    def expected_hash(self, skill_name: str) -> str | None:
        return self._approved.get(skill_name)

    def to_dict(self) -> dict:
        return {
            "approved": dict(self._approved),
            "blocklist": sorted(self._blocklist),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SkillRegistry":
        registry = cls()
        registry._approved = dict(data.get("approved", {}))
        registry._blocklist = set(data.get("blocklist", []))
        return registry

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))

    @classmethod
    def load(cls, path: str | Path) -> "SkillRegistry":
        data = json.loads(Path(path).read_text())
        return cls.from_dict(data)


def verify_skill(
    skill_name: str,
    skill_content: bytes | str | Path,
    registry: SkillRegistry,
) -> tuple[bool, str]:
    """
    Verify a skill against the registry.

    Args:
        skill_name: Name of the skill to verify
        skill_content: Either raw bytes, a file path, or a directory path
        registry: SkillRegistry containing approved hashes and blocklist

    Returns:
        Tuple of (is_valid, reason). reason is empty when valid.
    """
    if registry.is_blocked(skill_name):
        return False, f"Skill is on the blocklist: {skill_name}"

    expected = registry.expected_hash(skill_name)
    if not expected:
        return False, f"Skill not registered: {skill_name}"

    if isinstance(skill_content, bytes):
        actual = compute_hash(skill_content)
    else:
        path = Path(skill_content)
        if not path.exists():
            return False, f"Skill content not found: {skill_content}"
        actual = hash_directory(path) if path.is_dir() else hash_file(path)

    if actual != expected:
        return False, (
            f"Skill integrity check failed for {skill_name}. "
            f"Expected: {expected[:32]}... "
            f"Got: {actual[:32]}... "
            f"Skill may be tampered or malicious."
        )

    return True, ""


def install_safe(
    skill_name: str,
    skill_content: bytes | str | Path,
    registry: SkillRegistry,
) -> str:
    """
    Verify a skill before installation. Fail closed.

    Returns the verified hash on success.
    Raises SkillIntegrityError on any verification failure.
    """
    valid, reason = verify_skill(skill_name, skill_content, registry)
    if not valid:
        raise SkillIntegrityError(reason)

    if isinstance(skill_content, bytes):
        return compute_hash(skill_content)
    path = Path(skill_content)
    return hash_directory(path) if path.is_dir() else hash_file(path)
