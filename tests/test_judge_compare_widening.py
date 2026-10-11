"""Failing-first: JUDGE-COMPARE rejects any widening flip."""

from __future__ import annotations

from judge_compare_policy import widens


def test_compare_rejects_any_widening_flip() -> None:
    assert widens("block", None) is True
    assert widens("human_review", None) is True
    assert widens("block", "human_review") is True
    assert widens(None, "block") is False
    assert widens("block", "block") is False
    assert widens("human_review", "block") is False
