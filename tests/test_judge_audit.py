"""B1 — judge audit spine tests. No network."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from judge_audit import (
    SONNET5_PRICE_TABLE,
    AuditStore,
    ModelCallUsage,
    main,
    sample_record,
)


def test_model_call_requires_identity():
    with pytest.raises(TypeError, match="model_identity"):
        ModelCallUsage(
            model_identity="",
            tokens_in=1,
            tokens_out=1,
            thinking_tokens=0,
            latency_ms=1.0,
            estimated_cost_usd=0.0,
            actual_cost_usd=None,
        )


def test_cost_recomputable_from_tokens():
    pt = SONNET5_PRICE_TABLE
    # 1M in + 1M out + 0 thinking = $2 + $10 = $12 intro
    assert (
        pt.cost_usd(tokens_in=1_000_000, tokens_out=1_000_000, thinking_tokens=0)
        == 12.0
    )
    # thinking bills as output
    assert pt.cost_usd(tokens_in=0, tokens_out=0, thinking_tokens=1_000_000) == 10.0


def test_append_only_store(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    store = AuditStore(path)
    store.append(sample_record())
    store.append(sample_record())
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["record_type"] == "judge_cycle_audit"
    assert json.loads(lines[0])["model_call"]["model_identity"] == "claude-sonnet-5"


def test_cli_sample_dry_run(capsys):
    rc = main(["--json", "sample", "--dry-run"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["model_call"]["thinking_tokens"] == 90
    assert out["model_call"]["model_identity"]


def test_cli_price_table(capsys):
    rc = main(["--json", "price-table"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["introductory_through"] == "2026-08-31"
    assert out["input_usd_per_mtok"] == 2.0
    assert "platform.claude.com" in out["source"]


def test_cli_summary_missing_file_is_actionable(tmp_path: Path):
    with pytest.raises(SystemExit) as ei:
        main(["--path", str(tmp_path / "nope.jsonl"), "summary"])
    assert ei.value.code == 2
