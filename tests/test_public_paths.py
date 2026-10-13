"""Tracked files carry no home paths, host tokens, or IPv4 literals.

Enumeration is `git ls-files`, so gitignored files are not scanned. Env-file
paths are checked on tracked files under scripts/ and receipts/.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ENV_FILE_VAR = "ANTHROPIC_ENV_FILE"


def _home_sep() -> str:
    # One backslash, two backslashes (JSON text), or one forward slash.
    return r"(?:\\\\|\\|/)"


def _home_pattern() -> re.Pattern[str]:
    drive = "C:"
    users = "Users"
    sep = _home_sep()
    windows = re.escape(drive) + sep + users + sep
    mnt = re.escape("/mnt/c") + sep + users + sep
    home = "(?:^|[/\\\\])" + "home" + "[/\\\\]" + "[^/\\\\\\s\"'`]+"
    mac = "(?<![A-Za-z0-9])" + "/" + users + "/" + "[^/\\s\"'`]+"
    return re.compile("|".join((windows, mnt, home, mac)), re.IGNORECASE)


def _env_path_pattern() -> re.Pattern[str]:
    token = "." + "env"
    sep = "[/\\\\]" + re.escape(token) + r"\b"
    quoted = "[\"']" + re.escape(token) + "[\"']"
    return re.compile(sep + "|" + quoted)


def _ipv4_pattern() -> re.Pattern[str]:
    octet = r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    return re.compile(rf"\b(?:{octet}\.){{3}}{octet}\b")


_QUOTE_JOIN = re.compile(r"""(?s)['"]\s*(?:\+\s*)?['"]""")


def _host_tokens() -> list[tuple[str, str]]:
    """Forbidden host locators, built from pieces so this file does not contain them."""
    parts = (
        ("opt-aegis", ("/", "opt", "/", "aegis")),
        ("workspace", ("/", "work", "space")),
        ("host-pc", ("Land", "ens", "PC")),
        ("vault-name", ("Obs", "idian", " ", "Vault")),
    )
    return [(label, "".join(pieces)) for label, pieces in parts]


def _collapse_splits(text: str) -> str:
    """Join adjacent string literals so a path split across quotes is visible."""
    prev = None
    cur = text
    while cur != prev:
        prev = cur
        cur = _QUOTE_JOIN.sub("", cur)
    return cur


def _scan_text(rel: str, text: str, *, env: bool) -> list[str]:
    home = _home_pattern()
    env_path = _env_path_pattern()
    ipv4 = _ipv4_pattern()
    tokens = _host_tokens()
    collapsed = _collapse_splits(text)
    hits: list[str] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        folded = _collapse_splits(line)
        kinds: list[str] = []
        if home.search(line) or home.search(folded):
            kinds.append("home")
        if env and (env_path.search(line) or env_path.search(folded)):
            kinds.append("env")
        if ipv4.search(line) or ipv4.search(folded):
            kinds.append("ipv4")
        for label, token in tokens:
            if (
                token.casefold() in line.casefold()
                or token.casefold() in folded.casefold()
            ):
                kinds.append(label)
        if kinds:
            hits.append(f"{rel}:{line_no}:{'+'.join(kinds)}")
    if not hits:
        for label, token in tokens:
            if token.casefold() in collapsed.casefold():
                hits.append(f"{rel}:split:{label}")
        if home.search(collapsed):
            hits.append(f"{rel}:split:home")
        if ipv4.search(collapsed):
            hits.append(f"{rel}:split:ipv4")
    return hits


def _tracked_files() -> list[Path]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    paths: list[Path] = []
    for rel in raw.split(b"\0"):
        if not rel:
            continue
        path = ROOT / rel.decode()
        if path.is_file():
            paths.append(path)
    return paths


def _hits_for(paths: list[Path]) -> list[str]:
    hits: list[str] = []
    for path in paths:
        data = path.read_bytes()
        if b"\x00" in data:
            continue
        text = data.decode("utf-8", errors="replace")
        rel = path.relative_to(ROOT).as_posix()
        env = rel.startswith("scripts/") or rel.startswith("receipts/")
        hits.extend(_scan_text(rel, text, env=env))
    return hits


def test_tracked_files_have_no_public_path_leaks() -> None:
    hits = _hits_for(_tracked_files())
    assert hits == [], "public path leaks:\n" + "\n".join(hits)


def test_planted_escaped_windows_path_fails_the_scan() -> None:
    planted = ROOT / "tools" / "_planted_public_path.py"
    drive = "C:"
    users = "Users"
    two = "\\" * 2
    body = "p = " + '"' + drive + two + users + two + "x" + '"' + "\n"
    planted.write_text(body, encoding="utf-8")
    try:
        hits = _hits_for([planted])
        assert any("home" in hit for hit in hits), hits
    finally:
        planted.unlink(missing_ok=True)


def test_ipv4_pattern_matches_a_dotted_quad() -> None:
    addr = ".".join(["100", "72", "168", "92"])
    assert _ipv4_pattern().search(addr)


def test_split_literals_are_visible_to_the_scanner() -> None:
    left, right = "/opt", "/aegis"
    quote = '"'
    text = "x = " + quote + left + quote + " + " + quote + right + quote + "\n"
    hits = _scan_text("sample.py", text, env=False)
    assert any(hit.endswith(":opt-aegis") or ":opt-aegis" in hit for hit in hits)


def test_home_pattern_matches_json_escaped_windows_path() -> None:
    drive = "C:"
    users = "Users"
    two = "\\" * 2
    one = "\\"
    slash = "/"
    pattern = _home_pattern()
    escaped = drive + two + users + two + "name" + two + "pilot.jsonl"
    assert pattern.search(escaped)
    assert pattern.search(drive + one + users + one + "name")
    assert pattern.search(drive + slash + users + slash + "name")
    user_home = "".join(["/", "ho", "me", "/", "name", "/"])
    assert pattern.search(user_home)


def _load_script(relative: str):
    path = ROOT / relative
    saved = list(sys.path)
    spec = importlib.util.spec_from_file_location(path.stem + "_public_paths", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {relative}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = saved
    return module


def _refuse_without_env_file(
    relative: str, fn_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv(ENV_FILE_VAR, raising=False)
    module = _load_script(relative)
    monkeypatch.setattr(Path, "is_file", lambda self: False)
    with pytest.raises(SystemExit, match=f"{ENV_FILE_VAR} is unset"):
        getattr(module, fn_name)()


def test_compare_pilot_refuses_when_env_file_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _refuse_without_env_file(
        "scripts/run_judge_compare_pilot.py",
        "_load_anthropic_key",
        monkeypatch,
    )


def test_live_model_pin_refuses_when_env_file_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _refuse_without_env_file(
        "scripts/j1_live_model_pin.py",
        "_load_key",
        monkeypatch,
    )


def test_live_sample_refuses_when_env_file_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _refuse_without_env_file(
        "scripts/j3_live_sample.py",
        "_load_key",
        monkeypatch,
    )


def test_compare_pilot_reads_key_from_env_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    env_file = tmp_path / "provider.env"
    env_file.write_text("ANTHROPIC_API_KEY=test-key-not-secret\n", encoding="utf-8")
    monkeypatch.setenv(ENV_FILE_VAR, str(env_file))
    module = _load_script("scripts/run_judge_compare_pilot.py")

    def _only_named(self: Path) -> bool:
        return self == env_file

    monkeypatch.setattr(Path, "is_file", _only_named)
    assert module._load_anthropic_key() == "test-key-not-secret"


def test_receipt_path_is_relative_to_the_corpus(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    corpus = tmp_path / "corpus"
    pilot = corpus / "_frozen_unpack" / "pilot-500.jsonl"
    monkeypatch.setenv("JUDGE_COMPARE_CORPUS", str(corpus))
    module = _load_script("scripts/run_judge_compare_pilot.py")
    recorded = module._receipt_path(pilot)
    assert recorded == "_frozen_unpack/pilot-500.jsonl"
    assert "Users" not in recorded


def test_bound_prove_refuses_when_script_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AEGISBOX_BOUND_PROVE", raising=False)
    import __init__ as atoms

    evidence, code, err = atoms._bound_prove_on_aegisbox(
        tool_call_id="c",
        gate_decision_sha256="ab",
        atoms_result_sha256="cd",
    )
    assert evidence is None
    assert code == 2
    assert err is not None
    assert "AEGISBOX_BOUND_PROVE is unset" in err
    assert "Users" not in err
