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
