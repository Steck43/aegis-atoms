"""Consult policy for JUDGE-COMPARE scripted-call shadow runs.

Paid live mount already sets judge_force_consult=False when a key is present.
The compare runner must not force-consult every pilot row; that produced the
pre-G6-regrade 500/500 flag_for_review artifact.
"""

from __future__ import annotations

# Tracks that must consult the judge on the compare arm (shadow subtract OK).
_CONSULT_TRACKS = frozenset({"attack", "ambiguous"})

EFFECT_RANK = {
    None: 0,
    "allow": 0,
    "monitor": 1,
    "human_review": 2,
    "block": 3,
}


def force_consult_for_track(track: str | None) -> bool:
    """Return True only for attack/ambiguous tracks.

    normal and honest_mistake stay on the paid-path abstain/allow behavior
    unless firings are already conflicting.
    """
    key = str(track or "").strip().lower().replace("-", "_")
    return key in _CONSULT_TRACKS


def widens(off_effect: str | None, on_effect: str | None) -> bool:
    """True when the on-arm effect is weaker than the off-arm effect."""
    return EFFECT_RANK.get(on_effect, 0) < EFFECT_RANK.get(off_effect, 0)
