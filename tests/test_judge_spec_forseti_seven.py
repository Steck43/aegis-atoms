"""Forseti Spec v1 — seven failing-first tests (write before production code).

Source: CURSOR-JUDGE-SPEC.md sha256
82463E91CB5AA27A7BF1C6F8AF932B631702052CC6D00B176DAEF324C33DE1BA.
These tests encode the contract. They must fail until §1–2 land.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_01_bad_or_unknown_judge_outputs_escalate():
    """Bad/unknown outputs escalate — never become flag_for_review."""
    from judge_spec_v1 import map_model_answer_to_outcome

    for raw in (
        {"answer": "maybe"},
        {"answer": "allow"},
        {"answer": "block"},
        {"answers": ["yes", "no"]},
        {},
        None,
        "not-json",
    ):
        outcome = map_model_answer_to_outcome(raw)
        assert outcome == "ESCALATE", raw


def test_02_no_reason_code_on_allow_path_static():
    """Static: reason-code symbols never appear on a gate allow path."""
    allow_paths = [
        ROOT / "capability_gate_bridge.py",
        ROOT / "engine.py",
        ROOT / "__init__.py",
    ]
    # Prefer engine evaluate allow fall-through modules present in this roof.
    scanned = 0
    for path in allow_paths:
        if not path.is_file():
            continue
        scanned += 1
        text = path.read_text(encoding="utf-8")
        # Reason-code enum name must not be referenced on allow-return sites.
        assert "JudgeReasonCode" not in text
        # Stronger: dedicated module must exist and declare allow-path ban.
    ban = ROOT / "judge_reason_codes.py"
    assert ban.is_file(), "judge_reason_codes.py must exist"
    mod = ban.read_text(encoding="utf-8")
    assert "ALLOW_PATH_FORBIDDEN" in mod
    assert scanned >= 1


def test_03_atom_change_without_rubric_bump_fails_ci():
    """CI helper: atom catalog change without rubric hash bump is refused."""
    from judge_spec_v1 import assert_rubric_tracks_atoms

    # Simulate atom change with stale rubric pin.
    with pytest.raises(AssertionError):
        assert_rubric_tracks_atoms(
            atoms_commit="deadbeef",
            rubric_atoms_commit_pin="cafebabe",
        )


def test_04_missing_pinned_hash_fails():
    """G6 / receipt writer refuses missing required pins."""
    from judge_spec_v1 import require_g6_pins

    with pytest.raises(ValueError):
        require_g6_pins(
            {
                "model_snapshot": "x",
                # missing rubric_sha, prompt_sha, atoms_commit, sampling, effort, sdk
            }
        )


def test_05_slice_overlapping_heldout_refused():
    """Harness refuses a calibration slice that overlaps held-out."""
    from judge_spec_v1 import refuse_heldout_overlap

    held = {"a", "b", "c"}
    with pytest.raises(ValueError):
        refuse_heldout_overlap(slice_ids=["b", "d"], heldout_ids=held)


def test_06_agent_invoked_on_every_item_regression():
    """Regression: live agent compare must invoke the agent on every item."""
    from judge_spec_v1 import assert_agent_invoked_every_item

    rows = [
        {"id": "1", "agent_invoked": True},
        {"id": "2", "agent_invoked": False},
    ]
    with pytest.raises(AssertionError):
        assert_agent_invoked_every_item(rows)


def test_07_apply_cannot_arm_without_calibration_receipt():
    """apply cannot arm without a passing calibration receipt for current hashes."""
    from judge_spec_v1 import apply_arm_allowed

    assert (
        apply_arm_allowed(
            calibration_receipt_path=None,
            rubric_sha="x",
            prompt_sha="y",
            atoms_commit="z",
        )
        is False
    )
    # Empty / failing receipt also refuses.
    bad = ROOT / "receipts" / "raw" / "judge-spec" / "MISSING-CALIBRATION.json"
    assert (
        apply_arm_allowed(
            calibration_receipt_path=bad,
            rubric_sha="x",
            prompt_sha="y",
            atoms_commit="z",
        )
        is False
    )


def test_rubric_seed_has_frozen_examples_per_question():
    """Each rubric question carries one frozen positive and one frozen negative."""
    from judge_rubric_v1 import RUBRIC_QUESTIONS, rubric_sha256

    assert RUBRIC_QUESTIONS, "seed bank must not be empty"
    for q in RUBRIC_QUESTIONS:
        assert q["atom_id"]
        assert q["question"]
        assert q["positive_example"]
        assert q["negative_example"]
        assert q["positive_example"] != q["negative_example"]
    assert len(rubric_sha256()) == 64
