"""
test_irreversible_ops.py — Atom 1: declared irreversible operation membership.

Author:  Landen Stecker
Date:    2026-07-13
"""

from __future__ import annotations

from pathlib import Path


from adversarial_suite import floor_coverage, run_suite, summarize
from triad_types import EffectRank


def test_suite_invariant_before_irreversible_atom(tmp_path: Path):
    results = run_suite(tmp_path)
    s = summarize(results)
    assert s["tallies"] == {
        "CAUGHT-NAIVE": 7,
        "FALSE-ALLOW": 8,
        "FALSE-DENY": 1,
        "CORRECT-ALLOW": 1,
        "HALTED": 1,
    }
    c = floor_coverage(results)
    assert (c.covered, c.attack_total) == (7, 16)


def test_atom_carries_no_effect_or_framework():
    from irreversible_ops import IRREVERSIBLE_ATOMS

    atom = IRREVERSIBLE_ATOMS[0]
    assert (
        atom.atom_id == "atoms.tool_invocation.operation_in_declared_irreversible_set"
    )
    assert "effect" not in atom.__dataclass_fields__
    assert "framework_mappings" not in atom.__dataclass_fields__


def test_control_is_require_approval_not_block():
    from irreversible_ops import IRREVERSIBLE_CONTROLS

    ctrl = IRREVERSIBLE_CONTROLS[0]
    assert ctrl.effect is EffectRank.REQUIRE_APPROVAL
    joined = " ".join(ctrl.framework_mappings)
    assert "OWASP ASI02" in joined
    assert "OWASP LLM06:2025" in joined
    assert "AML.T0053" in joined
    assert "AML.T0086" in joined


def test_delete_file_fires():
    from irreversible_ops import evaluate_irreversible_operation

    fired, coords = evaluate_irreversible_operation("delete_file", {"path": "/tmp/x"})
    assert fired is True
    assert coords.get("normalized_operation") == "delete"
    assert coords.get("reason") == "operation_in_declared_irreversible_set"


def test_read_file_does_not_fire():
    from irreversible_ops import evaluate_irreversible_operation

    fired, coords = evaluate_irreversible_operation("read_file", {"path": "/tmp/x"})
    assert fired is False
    assert coords.get("reason") == "not_irreversible"


def test_terraform_destroy_fires():
    from irreversible_ops import evaluate_irreversible_operation

    fired, coords = evaluate_irreversible_operation(
        "terminal", {"command": "terraform destroy -auto-approve"}
    )
    assert fired is True
    assert coords.get("normalized_operation") == "terraform_destroy"


def test_rm_recursive_force_fires():
    from irreversible_ops import evaluate_irreversible_operation

    fired, coords = evaluate_irreversible_operation(
        "terminal", {"command": "rm -rf /var/data"}
    )
    assert fired is True
    assert coords.get("normalized_operation") == "rm_recursive_force"


def test_unparseable_operation_fail_closed():
    from irreversible_ops import evaluate_irreversible_operation

    fired, coords = evaluate_irreversible_operation("", None)
    assert fired is True
    assert coords.get("fail_closed") is True
    assert coords.get("reason") == "operation_unparseable"


def test_each_yaml_entry_cites_incident():
    from irreversible_ops import load_irreversible_operations, DEFAULT_IRREVERSIBLE_PATH

    cfg = load_irreversible_operations(DEFAULT_IRREVERSIBLE_PATH)
    ops = cfg["operations"]
    assert isinstance(ops, list) and len(ops) >= 5
    for entry in ops:
        assert entry.get("id")
        assert entry.get("incident_source"), entry
        assert entry.get("match")


def test_evaluate_rollup_require_approval():
    from irreversible_ops import evaluate_irreversible_ops

    fired, coords, rollups, combined = evaluate_irreversible_ops(
        "drop_table", {"table": "users"}
    )
    assert fired is True
    assert combined is EffectRank.REQUIRE_APPROVAL


def test_suite_invariant_with_module_imported(tmp_path: Path):
    """Importing the module must not move the 18-case distribution."""
    import irreversible_ops  # noqa: F401

    results = run_suite(tmp_path)
    s = summarize(results)
    assert s["tallies"]["CAUGHT-NAIVE"] == 7
    assert s["tallies"]["FALSE-ALLOW"] == 8
    c = floor_coverage(results)
    assert (c.covered, c.attack_total) == (7, 16)
