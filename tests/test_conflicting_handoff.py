"""CONFLICTING is the named box door. Dry only. Unset env is path-around-box."""

from __future__ import annotations

from triad_types import ControlRollup, EffectRank, RollupStatus


def test_unwired_without_env(monkeypatch) -> None:
    monkeypatch.delenv("AEGIS_CONFLICTING_HANDOFF", raising=False)
    from action_gating import conflicting_handoff_dry

    assert conflicting_handoff_dry() == "HANDOFF_UNWIRED"


def test_dry_ok(monkeypatch, tmp_path) -> None:
    script = tmp_path / "handoff.py"
    script.write_text("print('HANDOFF_OK CONFLICTING')\n", encoding="utf-8")
    monkeypatch.setenv("AEGIS_CONFLICTING_HANDOFF", str(script))
    from action_gating import conflicting_handoff_dry

    assert conflicting_handoff_dry() == "HANDOFF_OK"


def test_never_passes_launch(monkeypatch, tmp_path) -> None:
    script = tmp_path / "handoff.py"
    script.write_text(
        "import sys\n"
        "bad = '--launch' in sys.argv\n"
        "print('LAUNCH' if bad else 'HANDOFF_OK')\n"
        "raise SystemExit(1 if bad else 0)\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("AEGIS_CONFLICTING_HANDOFF", str(script))
    from action_gating import conflicting_handoff_dry

    assert conflicting_handoff_dry() == "HANDOFF_OK"


def test_denial_names_unwired_door(monkeypatch) -> None:
    monkeypatch.delenv("AEGIS_CONFLICTING_HANDOFF", raising=False)
    from action_gating import rollup_denial_message

    msg = rollup_denial_message(
        [
            ControlRollup(
                control_id="ctrl.test",
                status=RollupStatus.CONFLICTING,
                effect=EffectRank.ESCALATE,
                max_support_rank=2,
                max_contradiction_rank=3,
            )
        ]
    )
    assert msg is not None
    assert "HANDOFF_UNWIRED" in msg
    assert "CONFLICTING" in msg


def test_conflicting_rollup_invokes_dry_handoff(monkeypatch) -> None:
    """SYNTHETIC dual-polarity fixture: CONFLICTING denial names the door.

    Ad-hoc edges remain labeled SYNTHETIC. Organic prove is
    test_organic_conflicting_via_supports_edge.
    """
    import action_gating as ag
    from triad_types import (
        Control,
        Edge,
        EnforcementMode,
        MappingMethod,
        Polarity,
        Severity,
        Strength,
        rollup_control,
    )

    calls: list[str] = []
    monkeypatch.setattr(
        ag,
        "conflicting_handoff_dry",
        lambda: calls.append("dry") or "HANDOFF_OK",
    )

    ctrl = Control(
        control_id=ag.CTRL_SHELL,
        effect=EffectRank.BLOCK,
        severity=Severity.HIGH,
        precedence=100,
        enforcement_mode=EnforcementMode.MONITOR,
        framework_mappings=[],
    )
    synth_atom = "atoms.tool_invocation.SYNTHETIC_shell_schema_valid_for_probe"
    edges = [
        Edge(
            atom_id=ag.ATOM_SHELL_UNSANITIZED,
            control_id=ag.CTRL_SHELL,
            polarity=Polarity.CONTRADICTS,
            strength=Strength.STRONG,
            mapping_method=MappingMethod.RULE,
        ),
        Edge(
            atom_id=synth_atom,
            control_id=ag.CTRL_SHELL,
            polarity=Polarity.SUPPORTS,
            strength=Strength.MODERATE,
            mapping_method=MappingMethod.RULE,
        ),
    ]
    rollup = rollup_control(ctrl, edges, {ag.ATOM_SHELL_UNSANITIZED, synth_atom})
    assert rollup.status is RollupStatus.CONFLICTING

    msg = ag.rollup_denial_message([rollup])
    assert calls == ["dry"]
    assert msg is not None
    assert "CONFLICTING" in msg
    assert "[HANDOFF_OK]" in msg


def test_organic_conflicting_via_supports_edge(monkeypatch, tmp_path) -> None:
    """Production SUPPORTS + CONTRADICTS co-fire on argv-with-grammar."""
    import action_gating as ag

    script = tmp_path / "handoff.py"
    script.write_text("print('HANDOFF_OK CONFLICTING')\n", encoding="utf-8")
    monkeypatch.setenv("AEGIS_CONFLICTING_HANDOFF", str(script))

    firings, rollups, _combined = ag.evaluate_action_gating(
        "terminal",
        {"argv": ["sh", "-c", "echo $(whoami)"]},
        allowed_roots=["/tmp"],
        evaluation_id="organic-conflicting",
    )
    fired = {f.atom_id for f in firings}
    assert ag.ATOM_SHELL_UNSANITIZED in fired
    assert ag.ATOM_SHELL_ARGV_SCHEMA_VALID in fired

    shell = next(r for r in rollups if r.control_id == ag.CTRL_SHELL)
    assert shell.status is RollupStatus.CONFLICTING

    msg = ag.rollup_denial_message(rollups)
    assert msg is not None
    assert "CONFLICTING" in msg
    assert "HANDOFF_OK" in msg
