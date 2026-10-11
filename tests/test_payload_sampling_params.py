"""J7-4: claude-sonnet-5 payload never carries temperature or top_p."""

from __future__ import annotations

import judge_slot_sonnet as slot


def test_payload_sampling_params_allowed_for_model():
    assert slot.MODEL_ID == "claude-sonnet-5"
    assert not hasattr(slot, "TEMPERATURE")
    assert not hasattr(slot, "TOP_P")
    src = (slot.__file__ and open(slot.__file__, encoding="utf-8").read()) or ""
    # Creation site must not pass sampling kwargs for this model.
    assert "temperature=" not in src
    assert "top_p=" not in src


def test_price_table_matches_model_id():
    from judge_audit import SONNET5_PRICE_TABLE

    assert SONNET5_PRICE_TABLE.model_id == slot.MODEL_ID
