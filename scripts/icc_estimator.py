"""PRE-1: session-cluster ICC estimator (ANOVA) with a synthetic self-test."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class IccResult:
    icc: float
    n_sessions: int
    n_obs: int


def icc_anova(session_scores: list[list[float]]) -> IccResult:
    """One-way random-effects ICC from per-session score lists."""
    sessions = [list(s) for s in session_scores if s]
    if len(sessions) < 2:
        raise ValueError("need at least two sessions")
    n_sessions = len(sessions)
    n_obs = sum(len(s) for s in sessions)
    if n_obs <= n_sessions:
        raise ValueError("need repeated measures within sessions")
    grand = sum(x for s in sessions for x in s) / n_obs
    ssb = 0.0
    ssw = 0.0
    for s in sessions:
        mean = sum(s) / len(s)
        ssb += len(s) * (mean - grand) ** 2
        ssw += sum((x - mean) ** 2 for x in s)
    dfb = n_sessions - 1
    dfw = n_obs - n_sessions
    msb = ssb / dfb
    msw = ssw / dfw if dfw else 0.0
    # Unequal n: use average cluster size.
    n0 = n_obs / n_sessions
    denom = msb + (n0 - 1.0) * msw
    icc = 0.0 if denom == 0 else (msb - msw) / denom
    # Clamp numerical noise into [0, 1].
    icc = max(0.0, min(1.0, icc))
    return IccResult(icc=icc, n_sessions=n_sessions, n_obs=n_obs)
