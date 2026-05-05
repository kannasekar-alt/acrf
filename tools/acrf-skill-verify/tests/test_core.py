"""Tests for acrf_skill_verify.core"""

import pytest
from acrf_skill_verify import (
    SkillIntegrityError,
    SkillRegistry,
    compute_hash,
    hash_directory,
    hash_file,
    install_safe,
    verify_skill,
)


def test_compute_hash_is_deterministic():
    h1 = compute_hash(b"hello world")
    h2 = compute_hash(b"hello world")
    assert h1 == h2
    assert h1.startswith("sha256:")


def test_compute_hash_differs_for_different_content():
    h1 = compute_hash(b"hello")
    h2 = compute_hash(b"hello!")
    assert h1 != h2


def test_hash_file(tmp_path):
    f = tmp_path / "skill.py"
    f.write_text("print(\"hello\")")
    digest = hash_file(f)
    assert digest.startswith("sha256:")


def test_hash_directory_is_deterministic(tmp_path):
    d = tmp_path / "skill"
    d.mkdir()
    (d / "main.py").write_text("a")
    (d / "config.json").write_text("{}")
    h1 = hash_directory(d)
    h2 = hash_directory(d)
    assert h1 == h2


def test_hash_directory_differs_when_content_changes(tmp_path):
    d = tmp_path / "skill"
    d.mkdir()
    (d / "main.py").write_text("a")
    h1 = hash_directory(d)
    (d / "main.py").write_text("b")
    h2 = hash_directory(d)
    assert h1 != h2


def test_hash_directory_rejects_file_path(tmp_path):
    f = tmp_path / "not_a_dir.txt"
    f.write_text("x")
    with pytest.raises(ValueError):
        hash_directory(f)


def test_registry_register_and_lookup():
    reg = SkillRegistry()
    reg.register("customer-insights-mcp", "sha256:abc123")
    assert reg.expected_hash("customer-insights-mcp") == "sha256:abc123"
    assert reg.expected_hash("other") is None


def test_registry_block():
    reg = SkillRegistry()
    reg.block("malicious-mcp")
    assert reg.is_blocked("malicious-mcp")
    assert not reg.is_blocked("other")


def test_registry_block_removes_from_approved():
    reg = SkillRegistry()
    reg.register("skill", "sha256:abc")
    reg.block("skill")
    assert reg.expected_hash("skill") is None
    assert reg.is_blocked("skill")


def test_registry_cannot_register_blocked_skill():
    reg = SkillRegistry()
    reg.block("malicious")
    with pytest.raises(SkillIntegrityError):
        reg.register("malicious", "sha256:abc")


def test_registry_save_and_load(tmp_path):
    reg = SkillRegistry()
    reg.register("a", "sha256:111")
    reg.register("b", "sha256:222")
    reg.block("evil")

    path = tmp_path / "registry.json"
    reg.save(path)

    loaded = SkillRegistry.load(path)
    assert loaded.expected_hash("a") == "sha256:111"
    assert loaded.expected_hash("b") == "sha256:222"
    assert loaded.is_blocked("evil")


def test_verify_skill_passes_for_registered_match(tmp_path):
    skill = tmp_path / "skill.py"
    skill.write_text("legitimate code")

    reg = SkillRegistry()
    reg.register("good-skill", hash_file(skill))

    valid, reason = verify_skill("good-skill", skill, reg)
    assert valid is True
    assert reason == ""


def test_verify_skill_fails_when_tampered(tmp_path):
    skill = tmp_path / "skill.py"
    skill.write_text("legitimate code")

    reg = SkillRegistry()
    reg.register("good-skill", hash_file(skill))

    # Attacker tampers with the file
    skill.write_text("malicious code")

    valid, reason = verify_skill("good-skill", skill, reg)
    assert valid is False
    assert "integrity check failed" in reason


def test_verify_skill_fails_when_unregistered(tmp_path):
    skill = tmp_path / "skill.py"
    skill.write_text("code")

    reg = SkillRegistry()
    valid, reason = verify_skill("unknown", skill, reg)
    assert valid is False
    assert "not registered" in reason


def test_verify_skill_fails_when_blocked(tmp_path):
    skill = tmp_path / "skill.py"
    skill.write_text("code")

    reg = SkillRegistry()
    reg.block("malicious-skill")

    valid, reason = verify_skill("malicious-skill", skill, reg)
    assert valid is False
    assert "blocklist" in reason


def test_verify_skill_works_with_bytes():
    content = b"skill content"
    reg = SkillRegistry()
    reg.register("inline-skill", compute_hash(content))

    valid, reason = verify_skill("inline-skill", content, reg)
    assert valid is True


def test_verify_skill_works_with_directory(tmp_path):
    d = tmp_path / "skill"
    d.mkdir()
    (d / "main.py").write_text("a")
    (d / "config.json").write_text("{}")

    reg = SkillRegistry()
    reg.register("dir-skill", hash_directory(d))

    valid, reason = verify_skill("dir-skill", d, reg)
    assert valid is True


def test_install_safe_returns_hash_when_valid(tmp_path):
    skill = tmp_path / "skill.py"
    skill.write_text("legitimate")

    reg = SkillRegistry()
    expected = hash_file(skill)
    reg.register("good", expected)

    digest = install_safe("good", skill, reg)
    assert digest == expected


def test_install_safe_raises_when_tampered(tmp_path):
    skill = tmp_path / "skill.py"
    skill.write_text("legitimate")

    reg = SkillRegistry()
    reg.register("good", hash_file(skill))

    skill.write_text("malicious")

    with pytest.raises(SkillIntegrityError):
        install_safe("good", skill, reg)


def test_install_safe_raises_when_unregistered():
    reg = SkillRegistry()
    with pytest.raises(SkillIntegrityError) as exc_info:
        install_safe("unknown", b"x", reg)
    assert "not registered" in str(exc_info.value)


def test_install_safe_raises_when_blocked():
    reg = SkillRegistry()
    reg.block("malicious")
    with pytest.raises(SkillIntegrityError) as exc_info:
        install_safe("malicious", b"x", reg)
    assert "blocklist" in str(exc_info.value)


def test_verify_skill_handles_missing_file(tmp_path):
    reg = SkillRegistry()
    reg.register("missing", "sha256:abc")
    valid, reason = verify_skill("missing", tmp_path / "does_not_exist.py", reg)
    assert valid is False
    assert "not found" in reason
