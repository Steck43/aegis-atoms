"""
test_cie_observation_aggregate.py — cie observation aggregate.

Author:  Landen Stecker
Date:    2026-07-11

TDD: CIE aggregate collects confidence / ambiguity / trust_domain (sensing).
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

COMPOUNDING = Path(__file__).resolve().parents[2] / "aegis-compounding"
sys.path.insert(0, str(COMPOUNDING))

from aggregate import aggregate_period  # noqa: E402
from ingest import Signal  # noqa: E402


def _sig(atom_id: str, **payload) -> Signal:
    rec = {
        "record_type": "firing",
        "firing_id": payload.get("firing_id", "f"),
        "atom_id": atom_id,
        "effect": payload.get("effect", "block"),
        "enforced": payload.get("enforced", False),
        "session_id": payload.get("session_id", "s1"),
        "confidence": payload.get("confidence"),
        "ambiguity": payload.get("ambiguity"),
        "trust_domain": payload.get("trust_domain"),
        "severity": payload.get("severity", "high"),
        "evaluation_id": payload.get("evaluation_id", "s1:c1"),
    }
    # Drop Nones so old-log lines can omit fields.
    rec = {k: v for k, v in rec.items() if v is not None}
    return Signal(
        signal_id=rec["firing_id"],
        ts=datetime(2026, 7, 11, tzinfo=timezone.utc),
        kind="atom_firing",
        session_id=rec["session_id"],
        payload=rec,
        source_file="test",
    )


def test_aggregate_collects_confidence_distribution_per_atom():
    # This distribution is how the escalation threshold gets set later — from where
    # benign and malicious firings actually cluster, not from a guessed number.
    signals = [
        _sig("atoms.injection.indirect_marker", confidence=0.55, ambiguity="contradicted",
             trust_domain="retrieved_content", firing_id="a"),
        _sig("atoms.injection.indirect_marker", confidence=0.78, ambiguity="contradicted",
             trust_domain="retrieved_content", firing_id="b"),
        _sig("atoms.injection.indirect_marker", confidence=0.30, ambiguity="contradicted",
             trust_domain="user_input", firing_id="c"),
        _sig("atoms.tool_invocation.path_resolves_outside_allowed_root",
             confidence=1.0, ambiguity="contradicted", trust_domain="tool_output",
             firing_id="d"),
    ]
    since = datetime(2026, 7, 1, tzinfo=timezone.utc)
    until = datetime(2026, 7, 30, tzinfo=timezone.utc)
    agg = aggregate_period(signals, since, until)
    content = agg.atom_firings["atoms.injection.indirect_marker"]
    assert "confidence_samples" in content
    assert len(content["confidence_samples"]) == 3
    assert content["confidence_min"] == pytest.approx(0.30)
    assert content["confidence_max"] == pytest.approx(0.78)
    assert content["confidence_mean"] == pytest.approx((0.55 + 0.78 + 0.30) / 3)
    structural = agg.atom_firings[
        "atoms.tool_invocation.path_resolves_outside_allowed_root"
    ]
    assert structural["confidence_min"] == 1.0
    assert structural["confidence_max"] == 1.0


def test_aggregate_collects_ambiguity_breakdown():
    signals = [
        _sig("atom.x", confidence=1.0, ambiguity="contradicted",
             trust_domain="tool_output", firing_id="1"),
        _sig("atom.x", confidence=1.0, ambiguity="conflicting",
             trust_domain="tool_output", firing_id="2"),
        _sig("atom.x", confidence=1.0, ambiguity="contradicted",
             trust_domain="retrieved_content", firing_id="3"),
    ]
    since = datetime(2026, 7, 1, tzinfo=timezone.utc)
    until = datetime(2026, 7, 30, tzinfo=timezone.utc)
    agg = aggregate_period(signals, since, until)
    ax = agg.atom_firings["atom.x"]
    assert ax["ambiguity"]["contradicted"] == 2
    assert ax["ambiguity"]["conflicting"] == 1
    assert ax["trust_domains"]["tool_output"] == 2
    assert ax["trust_domains"]["retrieved_content"] == 1


def test_aggregate_old_log_without_observation_fields_still_parses():
    """Defensive: historical firings missing the new fields must not break CIE."""
    signals = [
        _sig("atom.legacy", firing_id="old"),  # no confidence/ambiguity/trust_domain
    ]
    # Force payload to omit observation keys entirely.
    signals[0].payload.pop("confidence", None)
    signals[0].payload.pop("ambiguity", None)
    signals[0].payload.pop("trust_domain", None)
    since = datetime(2026, 7, 1, tzinfo=timezone.utc)
    until = datetime(2026, 7, 30, tzinfo=timezone.utc)
    agg = aggregate_period(signals, since, until)
    legacy = agg.atom_firings["atom.legacy"]
    assert legacy["count"] == 1
    assert legacy["confidence_samples"] == []
    assert legacy["ambiguity"] == {}
    assert legacy["trust_domains"] == {}
