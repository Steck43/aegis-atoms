"""Failing-first: JUDGE-COMPARE rejects any widening flip."""

from __future__ import annotations

import pytest

from judge_compare_policy import widens


def test_compare_rejects_any_widening_flip() -> None:
    assert widens("block", None) is True
    assert widens("human_review", None) is True
    assert widens("block", "human_review") is True
    assert widens(None, "block") is False
    assert widens("block", "block") is False
    assert widens("human_review", "block") is False


def test_compare_rejects_unknown_effect_labels() -> None:
    with pytest.raises(ValueError, match="unknown off_effect"):
        widens("unknown", "block")
    with pytest.raises(ValueError, match="unknown on_effect"):
        widens("block", "unknown")

