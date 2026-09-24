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

    Production ACTION_GATING_EDGES stay CONTRADICTS-only. Organic CONFLICTING
    remains unreachable until a Landen-ratified SUPPORTS edge lands. This
    fixture is labeled SYNTHETIC and must not be cited as organic.
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
    rollup = rollup_control(
        ctrl, edges, {ag.ATOM_SHELL_UNSANITIZED, synth_atom}
    )
    assert rollup.status is RollupStatus.CONFLICTING

    msg = ag.rollup_denial_message([rollup])
    assert calls == ["dry"]
    assert msg is not None
    assert "CONFLICTING" in msg
    assert "[HANDOFF_OK]" in msg
