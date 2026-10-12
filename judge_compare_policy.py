"""Fail-closed consult policy for JUDGE-COMPARE scripted-call shadow runs."""

from __future__ import annotations

# Only these classified tracks may skip the compare-arm judge consultation.
_BENIGN_TRACKS = frozenset({"normal", "honest_mistake"})

EFFECT_RANK = {
    None: 0,
    "allow": 0,
    "monitor": 1,
    "human_review": 2,
    "block": 3,
}


def force_consult_for_track(track: str | None) -> bool:
    """Consult unless the track is explicitly classified as benign."""
    key = str(track or "").strip().lower().replace("-", "_")
    return key not in _BENIGN_TRACKS


def widens(off_effect: str | None, on_effect: str | None) -> bool:
    """True when the on-arm effect is weaker than the off-arm effect."""
    if off_effect not in EFFECT_RANK:
        raise ValueError(f"unknown off_effect label: {off_effect!r}")
    if on_effect not in EFFECT_RANK:
        raise ValueError(f"unknown on_effect label: {on_effect!r}")
    return EFFECT_RANK[on_effect] < EFFECT_RANK[off_effect]
