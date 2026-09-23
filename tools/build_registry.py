"""
Atom registry: one row per atom id defined in this repo, and which copies carry it.

Author:  Landen Stecker
Date:    2026-09-23
Version: 0.1.0
Summary: The catalog is copied. The public catalog, the public bundle, the vault
policy file and the live WSL plugin each hold their own version of the same
atoms, and the plane atoms live in code. This tool harvests every atom id this
repo defines, writes catalog/REGISTRY.tsv, and with --check compares every
reachable copy field by field. Drift is printed and exits 1. Stdlib only, so it
runs where pyyaml is absent; the catalog is parsed by indentation, which is
enough for its fixed shape.

Usage:
    python tools/build_registry.py            # write catalog/REGISTRY.tsv
    python tools/build_registry.py --check    # exit 1 on stale TSV or cross-copy drift
    python tools/build_registry.py --check --local-only   # skip vault and WSL

Row sources (the only ones): this repo's catalog/Aegis-Atoms-v0.yaml,
Aegis-Atoms-v0.bundle.yaml, and module-level ATOM_* string constants in the
repo's top-level .py files. Vault and WSL copies are read-only comparison
inputs; an id that exists only there is reported as drift, never written as a
row. 00-Private is never read.

Status column:
    enforced     catalog atom, enforcement_mode enforce, effect block/human_review
    observe      catalog atom that logs but does not hold: observe or monitor
                 mode, effect monitor, or status documented with no code detector
    implemented  code-resident plane atom: detector and control exist in code,
                 wired into engine.evaluate_tool_call behind an opt-in flag
"""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TSV = ROOT / "catalog" / "REGISTRY.tsv"
COLUMNS = ["atom_id", "status", "effect", "mode", "source", "copies"]

VAULT_CATALOG = Path(
    r"C:\Users\lande\Documents\Obsidian Vault\The_Boswell_Archive\Agent\Policy\Aegis-Atoms-v0.yaml"
)
WSL_ROOT = "~/.hermes/profiles/aegis/plugins/aegis-atoms"

# Local-only fence patterns live in catalog/.fence (gitignored). One regex per
# non-empty, non-# line. The public tree must not carry client-name literals.
# Missing or empty file: harvest skip matches nothing (public ids stay); redact
# and drift print fail closed by treating every id as fenced.
_FENCE_PATH = ROOT / "catalog" / ".fence"
_FENCE_NEVER = re.compile(r"(?!)")
_FENCE_ALWAYS = re.compile(r"(?s).+")

_ATOM_START = re.compile(r"^  - atom_id:\s*(\S+)\s*$")
_TOP_KEY = re.compile(r"^[A-Za-z_]+:")
_SECTION = re.compile(r"^    ([A-Za-z_]+):\s*(.*)$")
_FIELDS_TRACKED = ("status", "effect", "mode", "detector", "relaxations")


def _patterns_from_fence_file() -> list[str]:
    if not _FENCE_PATH.is_file():
        return []
    out: list[str] = []
    for raw in _FENCE_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def fence_skip() -> re.Pattern[str]:
    """Pattern used to omit ids from the public registry harvest."""
    pats = _patterns_from_fence_file()
    if not pats:
        return _FENCE_NEVER
    return re.compile("|".join(f"(?:{p})" for p in pats), re.IGNORECASE)


def fence_redact() -> re.Pattern[str]:
    """Pattern used when printing ids. Fail closed if the local file is absent."""
    pats = _patterns_from_fence_file()
    if not pats:
        return _FENCE_ALWAYS
    return re.compile("|".join(f"(?:{p})" for p in pats), re.IGNORECASE)


def __getattr__(name: str) -> re.Pattern[str]:
    # tests/test_registry.py reads build_registry._FENCE
    if name == "_FENCE":
        return fence_skip()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def redact(atom_id: str) -> str:
    return "<fenced-id>" if fence_redact().search(atom_id) else atom_id


# ---- catalog parsing ----------------------------------------------------------


def parse_catalog(text: str) -> dict[str, dict]:
    """Return {atom_id: {line, status, effect, mode, detector, relaxations}}."""
    atoms: dict[str, dict] = {}
    cur: dict | None = None
    section = None
    in_atoms = False
    for lineno, raw in enumerate(text.splitlines(), 1):
        if raw.lstrip().startswith("#") or not raw.strip():
            continue
        if raw.startswith("atoms:"):
            in_atoms = True
            continue
        if _TOP_KEY.match(raw):
            in_atoms = False
            cur = None
            continue
        if not in_atoms:
            continue
        m = _ATOM_START.match(raw)
        if m:
            cur = {
                "line": lineno,
                "status": "",
                "effect": "",
                "mode": "",
                "detector": [],
                "relaxations": [],
            }
            atoms[m.group(1)] = cur
            section = None
            continue
        if cur is None:
            continue
        s = _SECTION.match(raw)
        if s:
            section = s.group(1)
            if section == "status":
                cur["status"] = s.group(2).strip().strip('"')
            continue
        body = raw.strip()
        if section == "control":
            k, _, v = body.partition(":")
            if k == "effect":
                cur["effect"] = v.strip().strip('"')
            elif k == "enforcement_mode":
                cur["mode"] = v.strip().strip('"')
        elif section in ("detector", "relaxations"):
            cur[section].append(body.lstrip("- ").strip().strip('"').strip("'"))
    for a in atoms.values():
        a["detector"] = tuple(sorted(a["detector"]))
        a["relaxations"] = tuple(sorted(a["relaxations"]))
    return atoms


# ---- code harvesting -----------------------------------------------------------


def _const_map(tree: ast.Module) -> dict[str, tuple[str, int]]:
    out = {}
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            out[node.targets[0].id] = (node.value.value, node.lineno)
    return out


def _kw(call: ast.Call, name: str):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _resolve(node, consts):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name) and node.id in consts:
        return consts[node.id][0]
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def harvest_code(sources: dict[str, str]) -> dict[str, dict]:
    """{atom_id: {line (file:line), effect, mode}} from ATOM_* constants + Edge/Control calls."""
    atoms: dict[str, dict] = {}
    for fname, text in sorted(sources.items()):
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        consts = _const_map(tree)
        controls: dict[str, tuple[str, str]] = {}
        edges: list[tuple[str, str]] = []
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                continue
            if node.func.id == "Control":
                cid = _resolve(_kw(node, "control_id"), consts)
                eff = _resolve(_kw(node, "effect"), consts)
                mode = _resolve(_kw(node, "enforcement_mode"), consts)
                if cid:
                    controls[cid] = (str(eff or "").lower(), str(mode or "").lower())
            elif node.func.id == "Edge":
                aid = _resolve(_kw(node, "atom_id"), consts)
                cid = _resolve(_kw(node, "control_id"), consts)
                if aid and cid:
                    edges.append((aid, cid))
        for name, (val, lineno) in consts.items():
            if not name.startswith("ATOM_") or not re.fullmatch(r"atoms?\.[a-z_]+\.[a-z0-9_]+", val):
                continue
            effs = sorted({controls[c][0] for a, c in edges if a == val and c in controls})
            modes = sorted({controls[c][1] for a, c in edges if a == val and c in controls})
            atoms[val] = {
                "line": f"{fname}:{lineno}",
                "effect": "|".join(effs),
                "mode": "|".join(modes),
            }
    return atoms


def local_py_sources() -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(ROOT.glob("*.py"))}


# ---- copies -----------------------------------------------------------------------


def _wsl_cat(rel: str) -> str | None:
    try:
        proc = subprocess.run(
            ["wsl", "-e", "sh", "-c", f"cat {WSL_ROOT}/{rel}"],
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", errors="replace")


def load_copies(local_only: bool) -> tuple[dict[str, dict], dict[str, dict], list[str]]:
    """Return (catalog copies, code copies, skipped labels)."""
    cats: dict[str, dict] = {
        "pub_catalog": parse_catalog((ROOT / "catalog" / "Aegis-Atoms-v0.yaml").read_text(encoding="utf-8")),
        "pub_bundle": parse_catalog((ROOT / "Aegis-Atoms-v0.bundle.yaml").read_text(encoding="utf-8")),
    }
    local_src = local_py_sources()
    codes: dict[str, dict] = {"pub_code": harvest_code(local_src)}
    skipped: list[str] = []
    if local_only:
        return cats, codes, ["vault", "wsl_catalog", "wsl_bundle", "wsl_code"]
    if VAULT_CATALOG.is_file():
        cats["vault"] = parse_catalog(VAULT_CATALOG.read_text(encoding="utf-8"))
    else:
        skipped.append("vault")
    for label, rel in (("wsl_catalog", "catalog/Aegis-Atoms-v0.yaml"), ("wsl_bundle", "Aegis-Atoms-v0.bundle.yaml")):
        text = _wsl_cat(rel)
        if text is None:
            skipped.append(label)
        else:
            cats[label] = parse_catalog(text)
    # Compare the same module files the public repo defines atoms in.
    definers = sorted({v["line"].split(":")[0] for v in codes["pub_code"].values()})
    wsl_src = {}
    for fname in definers:
        text = _wsl_cat(fname)
        if text is not None:
            wsl_src[fname] = text
    if wsl_src:
        codes["wsl_code"] = harvest_code(wsl_src)
    else:
        skipped.append("wsl_code")
    return cats, codes, skipped


# ---- registry -------------------------------------------------------------------------


def _status(entry: dict, in_code: bool) -> str:
    if entry["mode"] == "enforce" and entry["effect"] in ("block", "human_review"):
        return "enforced"
    if in_code:
        return "implemented"
    return "observe"


def build_rows(cats: dict[str, dict], codes: dict[str, dict]) -> list[dict]:
    pub_cat, pub_bundle, pub_code = cats["pub_catalog"], cats["pub_bundle"], codes["pub_code"]
    ids = set(pub_cat) | set(pub_bundle) | set(pub_code)
    rows = []
    for aid in sorted(ids):
        if fence_skip().search(aid):
            continue
        sources = []
        if aid in pub_code:
            sources.append(pub_code[aid]["line"])
        if aid in pub_cat:
            sources.append(f"catalog/Aegis-Atoms-v0.yaml:{pub_cat[aid]['line']}")
        elif aid in pub_bundle:
            sources.append(f"Aegis-Atoms-v0.bundle.yaml:{pub_bundle[aid]['line']}")
        cat_entry = pub_cat.get(aid) or pub_bundle.get(aid)
        if cat_entry is not None:
            effect, mode = cat_entry["effect"], cat_entry["mode"]
            status = _status(cat_entry, aid in pub_code)
            if cat_entry["status"] == "documented" and aid not in pub_code:
                status = "observe"
        else:
            effect, mode = pub_code[aid]["effect"], pub_code[aid]["mode"]
            status = "implemented"
        copies = [lbl for lbl, d in list(cats.items()) + list(codes.items()) if aid in d]
        rows.append(
            {
                "atom_id": aid,
                "status": status,
                "effect": effect,
                "mode": mode,
                "source": ";".join(sources),
                "copies": ",".join(copies),
            }
        )
    return rows


def render(rows: list[dict]) -> str:
    lines = ["\t".join(COLUMNS)]
    lines += ["\t".join(r[c] for c in COLUMNS) for r in rows]
    return "\n".join(lines) + "\n"


def drift(cats: dict[str, dict], codes: dict[str, dict]) -> list[str]:
    out: list[str] = []
    for family, copies in (("catalog", cats), ("code", codes)):
        if len(copies) < 2:
            continue
        all_ids = set().union(*(set(d) for d in copies.values()))
        for aid in sorted(all_ids, key=redact):
            have = [lbl for lbl, d in copies.items() if aid in d]
            missing = [lbl for lbl in copies if lbl not in have]
            name = redact(aid)
            if missing:
                out.append(f"PRESENCE {family} {name}: in {','.join(have)}; missing from {','.join(missing)}")
            fields = _FIELDS_TRACKED if family == "catalog" else ("effect", "mode")
            for f in fields:
                vals = {lbl: copies[lbl][aid][f] for lbl in have}
                if len(set(vals.values())) <= 1:
                    continue
                if isinstance(next(iter(vals.values())), tuple):
                    union = set().union(*vals.values())
                    for item in sorted(union):
                        holders = [lbl for lbl, v in vals.items() if item in v]
                        if len(holders) != len(vals):
                            out.append(f"FIELD {family} {name} {f}: {item!r} only in {','.join(holders)}")
                else:
                    out.append(
                        f"FIELD {family} {name} {f}: "
                        + "; ".join(f"{lbl}={v or '-'}" for lbl, v in vals.items())
                    )
    return out


def _local_cols(text: str) -> list[tuple]:
    rows = [ln.split("\t") for ln in text.splitlines() if ln.strip()]
    return [tuple(r[:5]) for r in rows]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="exit 1 on stale TSV or cross-copy drift")
    ap.add_argument("--local-only", action="store_true", help="skip vault and WSL copies")
    args = ap.parse_args(argv)

    cats, codes, skipped = load_copies(args.local_only)
    rows = build_rows(cats, codes)
    text = render(rows)

    if not args.check:
        TSV.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {TSV.relative_to(ROOT)}: {len(rows)} rows")
        if skipped:
            print(f"SKIP unreachable copies: {','.join(skipped)}")
        return 0

    rc = 0
    compared = ",".join(list(cats) + list(codes))
    print(f"SCOPE compared: {compared}" + (f"; SKIP: {','.join(skipped)}" if skipped else ""))
    if not TSV.is_file():
        print("STALE catalog/REGISTRY.tsv missing; run without --check")
        rc = 1
    elif _local_cols(TSV.read_text(encoding="utf-8")) != _local_cols(text):
        print("STALE catalog/REGISTRY.tsv differs from a fresh harvest (atom_id..source)")
        rc = 1
    found = drift(cats, codes)
    for line in found:
        print(fence_redact().sub("<fenced>", line))
    if found:
        rc = 1
    print(f"SUMMARY rows={len(rows)} drift={len(found)} rc={rc}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
