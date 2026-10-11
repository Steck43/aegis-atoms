"""Consult policy for JUDGE-COMPARE scripted-call shadow runs.

Paid live mount already sets judge_force_consult=False when a key is present.
The compare runner must not force-consult every pilot row; that produced the
pre-G6-regrade 500/500 flag_for_review artifact.
"""

from __future__ import annotations

# Tracks that must consult the judge on the compare arm (shadow subtract OK).
_CONSULT_TRACKS = frozenset({"attack", "ambiguous"})


def force_consult_for_track(track: str | None) -> bool:
    """Return True only for attack/ambiguous tracks.

    normal and honest_mistake stay on the paid-path abstain/allow behavior
    unless firings are already conflicting.
    """
    key = str(track or "").strip().lower().replace("-", "_")
    return key in _CONSULT_TRACKS
