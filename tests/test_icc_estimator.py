"""PRE-1: ICC estimator recovers a known synthetic ICC within tolerance."""

from __future__ import annotations

import importlib.util
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    path = ROOT / "scripts" / "icc_estimator.py"
    spec = importlib.util.spec_from_file_location("icc_estimator", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_icc_estimator_synthetic():
    mod = _load()
    rng = random.Random(20261011)
    # High ICC: sessions differ a lot; within-session noise small.
    sessions = []
    for i in range(40):
        center = i * 0.05
        sessions.append([center + rng.uniform(-0.01, 0.01) for _ in range(5)])
    high = mod.icc_anova(sessions)
    assert high.icc > 0.8
    # Low ICC: same centers, large within noise.
    low_sessions = [
        [rng.uniform(0.0, 1.0) for _ in range(5)] for _ in range(40)
    ]
    low = mod.icc_anova(low_sessions)
    assert low.icc < 0.3
