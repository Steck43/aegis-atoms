"""
test_control_surface.py — Atom 3: write to declared control plane.

Author:  Landen Stecker
Date:    2026-07-13
"""
from __future__ import annotations

from pathlib import Path

from adversarial_suite import floor_coverage, run_suite, summarize
from triad_types import EffectRank


def test_suite_invariant_before_control_surface(tmp_path: Path):
    results = run_suite(tmp_path)
    c = floor_coverage(results)
    assert (c.covered, c.attack_total) == (7, 16)


def test_write_config_yaml_fires(tmp_path: Path):
    from memory_governance import write_target_is_control_surface

    home = tmp_path / ".hermes"
    home.mkdir()
    target = home / "config.yaml"
    target.write_text("plugins: {}\n", encoding="utf-8")
    fired, coords = write_target_is_control_surface(
        str(target), hermes_home=home, cwd=tmp_path
    )
    assert fired is True
    assert coords.get("reason") == "write_target_is_control_surface"


def test_write_soul_is_not_control_surface(tmp_path: Path):
    from memory_governance import write_target_is_control_surface

    home = tmp_path / ".hermes"
    home.mkdir()
    soul = home / "SOUL.md"
    soul.write_text("x", encoding="utf-8")
    fired, coords = write_target_is_control_surface(
        str(soul), hermes_home=home, cwd=tmp_path
    )
    assert fired is False
    assert coords.get("reason") == "not_control_surface"


def test_canonicalize_failure_fail_closed(tmp_path: Path):
    from memory_governance import write_target_is_control_surface

    fired, coords = write_target_is_control_surface(
        None, hermes_home=tmp_path, cwd=tmp_path
    )
    assert fired is True
    assert coords.get("fail_closed") is True


def test_control_is_block_no_approval():
    from memory_governance import MEMORY_CONTROLS, CTRL_NO_CONTROL_WRITE

    ctrl = next(c for c in MEMORY_CONTROLS if c.control_id == CTRL_NO_CONTROL_WRITE)
    assert ctrl.effect is EffectRank.BLOCK
    joined = " ".join(ctrl.framework_mappings)
    assert "OWASP ASI05" in joined
    assert "CVE-2026-25253" in joined


def test_suite_invariant_after_import(tmp_path: Path):
    results = run_suite(tmp_path)
    assert summarize(results)["tallies"]["CAUGHT-NAIVE"] == 7
    assert summarize(results)["tallies"]["FALSE-ALLOW"] == 8
