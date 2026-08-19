"""
Tests for instruction-surface write atom (AML.CS0051-shaped gap).

Author:  Landen Stecker
Date:    2026-07-12
Version: 1.0.0
"""

from __future__ import annotations

from pathlib import Path


from memory_governance import (
    ATOM_WRITE_INSTRUCTION,
    CTRL_NO_INSTRUCTION_WRITE,
    evaluate_instruction_surface_write,
    write_target_is_instruction_surface,
)
from triad_types import EffectRank, Polarity, Strength


def test_atom_control_edge_locked_shape():
    from memory_governance import MEMORY_ATOMS, MEMORY_CONTROLS, MEMORY_EDGES

    atom = next(a for a in MEMORY_ATOMS if a.atom_id == ATOM_WRITE_INSTRUCTION)
    assert atom.atom_type.value == "resource"
    ctrl = next(c for c in MEMORY_CONTROLS if c.control_id == CTRL_NO_INSTRUCTION_WRITE)
    assert ctrl.effect is EffectRank.BLOCK
    assert ctrl.severity.value == "high"
    assert ctrl.enforcement_mode.value == "monitor"
    assert "OWASP ASI06" in ctrl.framework_mappings
    assert "OWASP ASI01" in ctrl.framework_mappings
    assert "AML.CS0051" in " ".join(ctrl.framework_mappings)
    assert "AML.M0033" in " ".join(ctrl.framework_mappings)
    assert "NIST AI RMF GOVERN-1.1" in ctrl.framework_mappings
    assert "NIST AI RMF MEASURE-2.8" in ctrl.framework_mappings
    assert "NIST AI RMF MANAGE-2.4" in ctrl.framework_mappings
    edge = next(e for e in MEMORY_EDGES if e.atom_id == ATOM_WRITE_INSTRUCTION)
    assert edge.polarity is Polarity.CONTRADICTS
    assert edge.strength is Strength.STRONG
    assert "implements AML.M0033" in (atom.provenance.extracted_from or "")


def test_write_to_soul_fires(tmp_path: Path):
    hermes = tmp_path / "hermes"
    hermes.mkdir()
    (hermes / "SOUL.md").write_text("identity\n", encoding="utf-8")
    target = hermes / "SOUL.md"
    fired, coords = write_target_is_instruction_surface(
        str(target),
        hermes_home=hermes,
        cwd=tmp_path / "cwd",
    )
    assert fired is True
    assert coords.get("reason") == "write_target_is_instruction_surface"


def test_write_to_notes_abstains(tmp_path: Path):
    hermes = tmp_path / "hermes"
    notes = hermes / "notes"
    notes.mkdir(parents=True)
    target = notes / "ok.md"
    target.write_text("x\n", encoding="utf-8")
    fired, coords = write_target_is_instruction_surface(
        str(target),
        hermes_home=hermes,
        cwd=tmp_path / "cwd",
    )
    assert fired is False
    assert coords.get("reason") == "not_instruction_surface"


def test_canonicalize_failure_fail_closed(tmp_path: Path):
    hermes = tmp_path / "hermes"
    hermes.mkdir()
    fired, coords = write_target_is_instruction_surface(
        "path\x00evil",
        hermes_home=hermes,
        cwd=tmp_path,
    )
    assert fired is True
    assert coords.get("fail_closed") is True


def test_none_path_fail_closed(tmp_path: Path):
    fired, coords = write_target_is_instruction_surface(
        None,  # type: ignore[arg-type]
        hermes_home=tmp_path,
        cwd=tmp_path,
    )
    assert fired is True
    assert coords.get("fail_closed") is True


def test_skill_md_glob_fires(tmp_path: Path):
    hermes = tmp_path / "hermes"
    skill = hermes / "skills" / "evil" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("---\nname: evil\n---\n", encoding="utf-8")
    fired, _ = write_target_is_instruction_surface(
        str(skill),
        hermes_home=hermes,
        cwd=tmp_path,
    )
    assert fired is True


def test_agents_md_under_cwd_fires(tmp_path: Path):
    hermes = tmp_path / "hermes"
    hermes.mkdir()
    cwd = tmp_path / "proj"
    cwd.mkdir()
    agents = cwd / "AGENTS.md"
    agents.write_text("rules\n", encoding="utf-8")
    fired, _ = write_target_is_instruction_surface(
        str(agents),
        hermes_home=hermes,
        cwd=cwd,
    )
    assert fired is True


def test_evaluate_rolls_up_block(tmp_path: Path):
    hermes = tmp_path / "hermes"
    hermes.mkdir()
    soul = hermes / "SOUL.md"
    soul.write_text("x\n", encoding="utf-8")
    fired, coords, rollups, combined = evaluate_instruction_surface_write(
        str(soul),
        hermes_home=hermes,
        cwd=tmp_path,
    )
    assert fired is True
    assert combined is EffectRank.BLOCK
    assert any(r.control_id == CTRL_NO_INSTRUCTION_WRITE for r in rollups)
