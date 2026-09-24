"""Triad honesty contracts for observe-tune (Task 9).

TRIAD_PARTIAL until legacy catalog effect-on-atom is closed. These tests
lock the typed action-gating shape and name the residual catalog debt.
"""

from __future__ import annotations

from action_gating import (
    ACTION_GATING_ATOMS,
    ACTION_GATING_CONTROLS,
    ACTION_GATING_EDGES,
    ATOM_SHELL_ARGV_SCHEMA_VALID,
    ATOM_SHELL_UNSANITIZED,
    CTRL_SHELL,
)
from triad_types import Polarity

# Dest-named residual: live bundle active atom.* rows with nested control.effect.
# Keep in sync with TRIAD-HONESTY-INVENTORY-2026-09-24.md (live bundle census).
LEGACY_CATALOG_EFFECT_ON_ATOM_RESIDUALS: frozenset[str] = frozenset(
    {
        "atom.resource.write_hermes_plugins_tree",
        "atom.resource.write_hermes_identity_hot",
        "atom.resource.write_hermes_secrets",
        "atom.resource.write_hermes_cron_store",
        "atom.resource.write_hermes_config",
        "atom.action.terminal_mutate_hermes_runtime",
        "atom.action.git_push_shared_remote",
        "atom.resource.write_public_surface",
        "atom.resource.write_vault_canon_protocol",
        "atom.resource.write_atom_catalog",
        "atom.resource.read_hermes_secrets",
        "atom.condition.confidential_tag_in_clean_export",
        "atom.action.memory_identity_write",
        "atom.resource.write_hermes_aegis_skills",
    }
)


def test_armed_surfaces_use_edge_polarity_not_atom_effect() -> None:
    for atom in ACTION_GATING_ATOMS:
        assert not hasattr(atom, "effect") or getattr(atom, "effect", None) is None
        assert not hasattr(atom, "polarity")

    for ctrl in ACTION_GATING_CONTROLS:
        assert ctrl.effect is not None
        assert ctrl.control_id

    for edge in ACTION_GATING_EDGES:
        assert edge.polarity in (Polarity.CONTRADICTS, Polarity.SUPPORTS)
        assert edge.strength is not None
        assert edge.atom_id
        assert edge.control_id


def test_legacy_catalog_effect_on_atom_is_residual_named() -> None:
    # Honest grade remains TRIAD_PARTIAL while this set is non-empty.
    assert len(LEGACY_CATALOG_EFFECT_ON_ATOM_RESIDUALS) == 14
    for atom_id in LEGACY_CATALOG_EFFECT_ON_ATOM_RESIDUALS:
        assert atom_id.startswith("atom.")
        assert not atom_id.startswith("atoms.")


def test_supports_edge_pairs_shell_control() -> None:
    supports = [
        e for e in ACTION_GATING_EDGES if e.atom_id == ATOM_SHELL_ARGV_SCHEMA_VALID
    ]
    assert len(supports) == 1
    assert supports[0].control_id == CTRL_SHELL
    assert supports[0].polarity is Polarity.SUPPORTS

    contra = [
        e
        for e in ACTION_GATING_EDGES
        if e.atom_id == ATOM_SHELL_UNSANITIZED and e.control_id == CTRL_SHELL
    ]
    assert len(contra) == 1
    assert contra[0].polarity is Polarity.CONTRADICTS
