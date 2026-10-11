"""Judge Spec v1 harness contracts (CURSOR-JUDGE-SPEC.md).

Model answers yes / no / cannot_determine only. Code maps to outcomes.
Apply stays False until a passing calibration receipt pins current hashes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from judge_reason_codes import JudgeReasonCode
from judge_rubric_v1 import RUBRIC_ATOMS_COMMIT_PIN, rubric_sha256

REQUIRED_G6_PINS = (
    "model_snapshot",
    "rubric_sha",
    "prompt_sha",
    "atoms_commit",
    "sampling",
    "effort",
    "sdk",
)


def map_model_answer_to_outcome(raw: Any) -> str:
    """Map model payload to CONCUR / SUBTRACT / ESCALATE / HUMAN.

    Only exact single answers yes/no/cannot_determine are accepted.
    Everything else escalates (never silently becomes a flag).
    """
    if not isinstance(raw, dict):
        return "ESCALATE"
    answer = raw.get("answer")
    if not isinstance(answer, str):
        return "ESCALATE"
    key = answer.strip().lower()
    if key == "yes":
        # yes = violates → subtract path (code maps; model never says flag)
        return "SUBTRACT"
    if key == "no":
        return "CONCUR"
    if key == "cannot_determine":
        return "HUMAN"
    return "ESCALATE"


def assert_rubric_tracks_atoms(
    *, atoms_commit: str, rubric_atoms_commit_pin: str | None = None
) -> None:
    pin = rubric_atoms_commit_pin or RUBRIC_ATOMS_COMMIT_PIN
    if atoms_commit != pin:
        raise AssertionError(
            f"atom change {atoms_commit!r} without rubric bump (pin {pin!r})"
        )


def current_rubric_sha() -> str:
    return rubric_sha256()


def require_g6_pins(row: dict[str, Any]) -> None:
    missing = [k for k in REQUIRED_G6_PINS if not row.get(k)]
    if missing:
        raise ValueError(f"missing pinned hash fields: {missing}")


def refuse_heldout_overlap(*, slice_ids: list[str], heldout_ids: set[str]) -> None:
    overlap = set(slice_ids) & set(heldout_ids)
    if overlap:
        raise ValueError(f"slice overlaps held-out: {sorted(overlap)}")


def assert_agent_invoked_every_item(rows: list[dict[str, Any]]) -> None:
    missing = [r.get("id") for r in rows if not r.get("agent_invoked")]
    if missing:
        raise AssertionError(f"agent not invoked on items: {missing}")


def guard_agent_mode_rows(rows: list[dict[str, Any]]) -> None:
    """Rows-path guard: agent-mode batches must invoke the agent on every item."""
    if any(r.get("agent_mode") for r in rows):
        assert_agent_invoked_every_item(rows)


def apply_arm_allowed(
    *,
    calibration_receipt_path: Path | str | None,
    rubric_sha: str,
    prompt_sha: str,
    atoms_commit: str,
) -> bool:
    if not calibration_receipt_path:
        return False
    path = Path(calibration_receipt_path)
    if not path.is_file():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
        return False
    if data.get("status") != "PASS":
        return False
    pins = data.get("pins") or {}
    return (
        pins.get("rubric_sha") == rubric_sha
        and pins.get("prompt_sha") == prompt_sha
        and pins.get("atoms_commit") == atoms_commit
    )


def reason_code_for_escalate(kind: str) -> JudgeReasonCode:
    return {
        "refusal": JudgeReasonCode.REFUSAL,
        "timeout": JudgeReasonCode.TIMEOUT,
        "malformed": JudgeReasonCode.MALFORMED,
        "unknown": JudgeReasonCode.UNKNOWN,
        "multi_code": JudgeReasonCode.MULTI_CODE,
        "empty": JudgeReasonCode.EMPTY,
    }.get(kind, JudgeReasonCode.UNKNOWN)


def catalog_tip_commit(*, catalog_path: Path, repo_root: Path | None = None) -> str:
    """Return the last commit that touched the live atom catalog path."""
    import subprocess

    root = repo_root or Path(__file__).resolve().parent
    path = Path(catalog_path)
    if not path.is_file():
        raise AssertionError(f"catalog missing: {path}")
    rel = path.resolve().relative_to(root.resolve()).as_posix()
    proc = subprocess.run(
        ["git", "log", "-1", "--format=%H", "--", rel],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    tip = (proc.stdout or "").strip()
    if proc.returncode != 0 or not tip:
        raise AssertionError(f"cannot resolve catalog tip for {rel}: {proc.stderr}")
    # Shallow clones often return HEAD for every path. Refuse that as a tip
    # unless HEAD itself modified the catalog (real single-commit change).
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    head_sha = (head.stdout or "").strip()
    if tip == head_sha:
        touched = subprocess.run(
            ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", head_sha],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        names = {
            line.strip().replace("\\", "/")
            for line in (touched.stdout or "").splitlines()
            if line.strip()
        }
        if rel not in names:
            raise AssertionError(
                f"catalog tip collapsed to HEAD ({head_sha[:12]}) without a "
                f"catalog diff — deepen the git fetch (fetch-depth: 0)"
            )
    return tip


def assert_rubric_tracks_real_catalog(
    *, catalog_path: Path, repo_root: Path | None = None
) -> None:
    """Refuse when the live catalog tip and rubric pin disagree."""
    tip = catalog_tip_commit(catalog_path=catalog_path, repo_root=repo_root)
    assert_rubric_tracks_atoms(atoms_commit=tip)


def assert_reason_code_enum_sha(expected: str) -> None:
    from judge_reason_codes import REASON_CODE_ENUM_SHA256

    if REASON_CODE_ENUM_SHA256 != expected:
        raise AssertionError(
            f"reason-code enum hash drift: {REASON_CODE_ENUM_SHA256} != {expected}"
        )


def assert_cause_receipts_content_hash_disjoint(receipts_dir: Path) -> None:
    import hashlib

    paths = sorted(Path(receipts_dir).glob("JUDGE-CAUSE-0*.md"))
    if len(paths) < 6:
        raise AssertionError(f"expected six cause receipts, found {len(paths)}")
    seen: dict[str, str] = {}
    for path in paths:
        digest = hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        if digest in seen:
            raise AssertionError(
                f"content-hash collision: {path.name} and {seen[digest]}"
            )
        seen[digest] = path.name
