"""
test_harness_action_gating.py — harness action gating.

Author:  Landen Stecker
Date:    2026-07-11

TDD: before/after harness for C1 traversal and C2 shell injection.
"""

from __future__ import annotations

from pathlib import Path

import pytest

SECRET_VALUE = "REDACTED_SECRET_VALUE_001"


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    allowed = tmp_path / "allowed"
    secrets = tmp_path / "secrets"
    allowed.mkdir()
    secrets.mkdir()
    (allowed / "readme.md").write_text("ok\n", encoding="utf-8")
    (secrets / ".env").write_text(f"API_KEY={SECRET_VALUE}\n", encoding="utf-8")
    return tmp_path


def test_floor_only_traversal_reads_secret(workspace: Path):
    from harness_action_gating import run_c1_traversal

    result = run_c1_traversal(workspace, atoms_enabled=False)
    assert result["read_back"] == "secret_present"
    assert SECRET_VALUE in result["secret_text"]
    assert result["decision"] == "allow"


def test_floor_plus_atoms_blocks_traversal_secret_absent(workspace: Path):
    from harness_action_gating import run_c1_traversal

    result = run_c1_traversal(workspace, atoms_enabled=True)
    assert result["decision"] == "deny"
    assert result["read_back"] == "secret_absent"
    assert SECRET_VALUE not in result["secret_text"]
    assert (
        "atoms.tool_invocation.path_resolves_outside_allowed_root"
        in result["deny_reason"]
    )
    assert "control.no_file_access_outside_allowed_roots" in result["deny_reason"]
    assert "AML.T0105" in result["deny_reason"] or "ASI05" in result["deny_reason"]


def test_floor_only_shell_injection_executes(workspace: Path):
    from harness_action_gating import run_c2_shell

    result = run_c2_shell(workspace, atoms_enabled=False)
    assert result["decision"] == "allow"
    assert result["read_back"] == "rce_effect_present"
    assert SECRET_VALUE in result["proof_text"]


def test_floor_plus_atoms_blocks_shell_no_execution(workspace: Path):
    from harness_action_gating import run_c2_shell

    result = run_c2_shell(workspace, atoms_enabled=True)
    assert result["decision"] == "deny"
    assert result["read_back"] == "rce_effect_absent"
    assert SECRET_VALUE not in result["proof_text"]
    assert "atoms.tool_invocation.shell_invocation_unsanitized" in result["deny_reason"]
    assert "control.no_unparameterized_command_execution" in result["deny_reason"]


def test_action_gating_proof_log_format(workspace: Path):
    from harness_action_gating import (
        run_c1_traversal,
        run_c2_shell,
        format_action_gating_proof,
    )

    c1_before = run_c1_traversal(workspace, atoms_enabled=False)
    c1_after = run_c1_traversal(workspace, atoms_enabled=True)
    c2_before = run_c2_shell(workspace, atoms_enabled=False)
    c2_after = run_c2_shell(workspace, atoms_enabled=True)
    text = format_action_gating_proof(c1_before, c1_after, c2_before, c2_after)
    assert "FLOOR ONLY" in text
    assert "FLOOR + ACTION-GATING ATOMS" in text
    assert "secret_present" in text
    assert "secret_absent" in text
    assert "rce_effect_present" in text
    assert "rce_effect_absent" in text
