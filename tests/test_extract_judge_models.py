"""J7-1: missing returned model field is MEASURED-GAP, never inferred."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    path = ROOT / "scripts" / "extract_judge_models.py"
    spec = importlib.util.spec_from_file_location("extract_judge_models", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_extract_reports_missing_field_as_gap(tmp_path: Path):
    mod = _load()
    raw = tmp_path / "raw.json"
    raw.write_text(
        json.dumps(
            {
                "models": {"judge": "claude-sonnet-5"},
                "rows": [{"id": "1", "usage": {"input": 1}}],
            }
        ),
        encoding="utf-8",
    )
    report = mod.extract_file(raw)
    assert report["gap"] == "MEASURED-GAP"
    # Must not invent a returned model from the requested pin alone.
    returned = [c.get("returned_model") for c in report["calls"]]
    assert all(r in (None, "") for r in returned) or report["missing_returned_model_count"] >= 1
