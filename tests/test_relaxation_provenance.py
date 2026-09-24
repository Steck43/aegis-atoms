"""Relaxations are keyed on who wrote the session text, and never drop a decision.

Added 2026-09-23. A catalog relaxation lowers an atom's effect when a regex
matches the session text. In Hermes that text is the turn's user_message, and a
delegated child's user_message is the goal its parent model wrote. So a phrase
the parent read in a document could relax policy in the child. Two changes are
pinned here:

  (a) provenance: a relaxation applies only when the session origin is
      "human". delegate, cron, webhook and unknown origins never relax.
  (b) clamp: on an enforce-mode atom a downgrade to monitor becomes
      human_review, because the enforcing loop only acts on block and
      human_review. A monitor downgrade kept the firing and dropped the
      decision.

The relaxation patterns below are synthetic. No catalog trigger is quoted.

Frames:
  * unit population  -- every catalog atom x downgrade target x origin x text,
                        compared against a reference model of the intended rule
  * engine           -- the same through evaluate_tool_call with a fixture that
                        fires each catalog atom
  * hook             -- pre_llm_call's platform and sender_id reach the engine
                        as session_origin
"""

from __future__ import annotations

import copy
import random
import zlib
from pathlib import Path

import pytest

import engine
from engine import (
    EFFECT_RANK,
    SESSION_ORIGINS,
    AtomDef,
    _effective_effect,
    evaluate_tool_call,
    load_catalog,
    session_origin_from_hook,
)

ROOT = Path(__file__).resolve().parents[1]
ENV = {"HERMES_HOME": "/h", "OBSIDIAN_VAULT_PATH": "/vault"}
SYNTH_PATTERN = r"ZZ-SYNTH-[0-9]{3}"
SYNTH_TEXT = "please go ahead ZZ-SYNTH-417 thanks"
NON_HUMAN = sorted(SESSION_ORIGINS - {"human"})
# Strings a caller might pass that are not in SESSION_ORIGINS. Each must behave
# as unknown.
STRAY_ORIGINS = ["", "Human", "HUMAN", " human", "user", "operator", "subagent", "cli"]
DOWN_TARGETS = ["monitor", "human_review", "block", "", "allow", "none", "BLOCK"]


def _all_atoms() -> list[AtomDef]:
    pub = load_catalog(ROOT / "catalog" / "Aegis-Atoms-v0.yaml", ENV)
    bundle = load_catalog(ROOT / "Aegis-Atoms-v0.bundle.yaml", ENV)
    seen = {a.atom_id for a in pub.atoms}
    return pub.atoms + [a for a in bundle.atoms if a.atom_id not in seen]


def _with_relax(atom: AtomDef, relaxations: list) -> AtomDef:
    a = copy.deepcopy(atom)
    a.relaxations = relaxations
    return a


def _reference(atom: AtomDef, text: str, origin: str) -> tuple[str, str]:
    """The intended rule, written independently of engine._effective_effect."""
    import re

    base = str(atom.control.get("effect", "monitor"))
    mode = str(atom.control.get("enforcement_mode", "observe"))
    if origin != "human":
        return base, mode
    effect = base
    for r in atom.relaxations:
        if not isinstance(r, dict):
            continue
        pat = r.get("when_session_matches")
        if not pat or not re.search(pat, text):
            continue
        down = r.get("downgrade_effect")
        if down not in EFFECT_RANK:
            continue
        if mode == "enforce" and down == "monitor":
            down = "human_review"
        if EFFECT_RANK[down] < EFFECT_RANK.get(effect, 3):
            effect = down
    return effect, mode


ATOMS = _all_atoms()


def test_population_covers_every_catalog_atom():
    ids = {a.atom_id for a in ATOMS}
    assert len(ids) >= 14
    assert "atom.condition.confidential_tag_in_clean_export" in ids
    assert "atom.resource.write_hermes_aegis_skills" in ids


@pytest.mark.parametrize("atom", ATOMS, ids=lambda a: a.atom_id)
def test_unit_population_no_non_human_origin_lowers(atom: AtomDef):
    rng = random.Random(zlib.crc32(atom.atom_id.encode()))
    cases = 0
    for down in DOWN_TARGETS:
        for n_relax in (1, 2, 3):
            relax = [
                {"when_session_matches": SYNTH_PATTERN, "downgrade_effect": down}
                for _ in range(n_relax)
            ]
            a = _with_relax(atom, relax)
            base = (
                str(atom.control.get("effect", "monitor")),
                str(atom.control.get("enforcement_mode", "observe")),
            )
            for origin in NON_HUMAN + STRAY_ORIGINS:
                for text in (SYNTH_TEXT, "", "no token here", "ZZ-SYNTH-000" * 3):
                    assert _effective_effect(a, text, origin) == base, (
                        atom.atom_id,
                        down,
                        origin,
                    )
                    cases += 1
            # Random texts, some carrying the token.
            for _ in range(20):
                text = "".join(rng.choice("abZZ-SYNTH-0123456789 ") for _ in range(30))
                origin = rng.choice(NON_HUMAN + STRAY_ORIGINS)
                assert _effective_effect(a, text, origin) == base
                cases += 1
    assert cases > 500


@pytest.mark.parametrize("atom", ATOMS, ids=lambda a: a.atom_id)
def test_unit_population_human_matches_reference(atom: AtomDef):
    rng = random.Random(zlib.crc32(atom.atom_id.encode()) ^ 0x5A5A)
    for _ in range(200):
        relax = [
            {
                "when_session_matches": rng.choice([SYNTH_PATTERN, r"QQ-OTHER", ""]),
                "downgrade_effect": rng.choice(DOWN_TARGETS),
            }
            for _ in range(rng.randint(0, 3))
        ]
        a = _with_relax(atom, relax)
        text = rng.choice([SYNTH_TEXT, "QQ-OTHER", "", "unrelated"])
        got = _effective_effect(a, text, "human")
        assert got == _reference(a, text, "human"), (atom.atom_id, relax, text)
        # Never raises the effect, never leaves the lattice.
        base = str(atom.control.get("effect", "monitor"))
        assert got[0] in EFFECT_RANK
        assert EFFECT_RANK[got[0]] <= EFFECT_RANK[base]


@pytest.mark.parametrize(
    "atom",
    [a for a in ATOMS if a.control.get("enforcement_mode") == "enforce"],
    ids=lambda a: a.atom_id,
)
def test_clamp_enforce_atom_monitor_downgrade_becomes_human_review(atom: AtomDef):
    a = _with_relax(
        atom, [{"when_session_matches": SYNTH_PATTERN, "downgrade_effect": "monitor"}]
    )
    effect, mode = _effective_effect(a, SYNTH_TEXT, "human")
    base = str(atom.control.get("effect"))
    if base == "monitor":
        assert effect == "monitor"
    else:
        assert effect == "human_review"
    assert mode == "enforce"


@pytest.mark.parametrize(
    "atom",
    [a for a in ATOMS if a.control.get("enforcement_mode") == "observe"],
    ids=lambda a: a.atom_id,
)
def test_observe_atom_human_behaviour_is_unchanged(atom: AtomDef):
    # Observe atoms never decide, so the clamp does not touch them.
    a = _with_relax(
        atom, [{"when_session_matches": SYNTH_PATTERN, "downgrade_effect": "monitor"}]
    )
    assert _effective_effect(a, SYNTH_TEXT, "human") == ("monitor", "observe")


def test_default_origin_is_unknown_and_cannot_relax():
    atom = next(a for a in ATOMS if a.control.get("effect") == "block")
    a = _with_relax(
        atom, [{"when_session_matches": SYNTH_PATTERN, "downgrade_effect": "monitor"}]
    )
    assert _effective_effect(a, SYNTH_TEXT) == ("block", "enforce")


def test_bare_mapping_relaxation_loads_as_one_relaxation(tmp_path: Path):
    # The public bundle carries this shape. Iterating a dict yielded its keys.
    cat = tmp_path / "c.yaml"
    cat.write_text(
        "atoms:\n"
        "  - atom_id: a.x\n"
        "    status: active\n"
        "    detector: {kind: tool_memory_write}\n"
        "    relaxations:\n"
        f"        when_session_matches: '{SYNTH_PATTERN}'\n"
        "        downgrade_effect: monitor\n"
        "    control: {effect: block, enforcement_mode: enforce}\n",
        encoding="utf-8",
    )
    atom = load_catalog(cat, ENV).atoms[0]
    assert atom.relaxations == [
        {"when_session_matches": SYNTH_PATTERN, "downgrade_effect": "monitor"}
    ]
    assert _effective_effect(atom, SYNTH_TEXT, "human") == ("human_review", "enforce")
    assert _effective_effect(atom, SYNTH_TEXT, "delegate") == ("block", "enforce")


# --- engine path ------------------------------------------------------------

# One call that fires each catalog atom under ENV. Kept here rather than read
# from the adversarial matrix so this file stands alone.
FIRE = {
    "atom.resource.write_hermes_plugins_tree": (
        "write_file",
        {"path": "/h/plugins/x.py"},
    ),
    "atom.resource.write_hermes_identity_hot": ("write_file", {"path": "/h/SOUL.md"}),
    "atom.resource.write_hermes_secrets": ("write_file", {"path": "/h/.env"}),
    "atom.resource.write_hermes_cron_store": (
        "write_file",
        {"path": "/h/cron/jobs.json"},
    ),
    "atom.resource.write_hermes_config": ("write_file", {"path": "/h/config.yaml"}),
    "atom.action.terminal_mutate_hermes_runtime": (
        "terminal",
        {"command": "hermes cron edit 3"},
    ),
    "atom.action.git_push_shared_remote": (
        "terminal",
        {"command": "git push origin main"},
    ),
    "atom.resource.write_public_surface": ("write_file", {"path": "/work/README.md"}),
    "atom.resource.write_vault_canon_protocol": (
        "write_file",
        {"path": "/vault/Agent/Policy/x.md"},
    ),
    "atom.resource.read_hermes_secrets": ("read_file", {"path": "/work/.env"}),
    "atom.condition.confidential_tag_in_clean_export": (
        "write_file",
        {"path": "/work/resume/cv.md", "content": "CONFIDENTIAL draft"},
    ),
    "atom.action.memory_identity_write": (
        "memory",
        {"action": "add", "target": "user"},
    ),
    "atom.resource.write_atom_catalog": (
        "write_file",
        {"path": "/vault/Agent/Policy/Aegis-Atoms-v0.yaml"},
    ),
    "atom.resource.write_hermes_aegis_skills": (
        "write_file",
        {"path": "/h/skills/aegis-x/SKILL.md"},
    ),
}


def _engine_catalog(relax_down: str | None):
    pub = load_catalog(ROOT / "catalog" / "Aegis-Atoms-v0.yaml", ENV)
    bundle = load_catalog(ROOT / "Aegis-Atoms-v0.bundle.yaml", ENV)
    seen = {a.atom_id for a in pub.atoms}
    pub.atoms = pub.atoms + [a for a in bundle.atoms if a.atom_id not in seen]
    for a in pub.atoms:
        a.relaxations = (
            []
            if relax_down is None
            else [
                {"when_session_matches": SYNTH_PATTERN, "downgrade_effect": relax_down}
            ]
        )
    return pub


def test_fire_table_covers_every_catalog_atom():
    assert set(FIRE) == {a.atom_id for a in ATOMS}


@pytest.mark.parametrize("relax_down", ["monitor", "human_review"])
@pytest.mark.parametrize("origin", sorted(SESSION_ORIGINS) + ["", "operator"])
@pytest.mark.parametrize("atom_id", sorted(FIRE))
def test_engine_population_non_human_never_lowers(atom_id, origin, relax_down):
    tool, args = FIRE[atom_id]
    plain = evaluate_tool_call(
        _engine_catalog(None), tool, args, env=ENV, session_text=SYNTH_TEXT
    )
    relaxed = evaluate_tool_call(
        _engine_catalog(relax_down),
        tool,
        args,
        env=ENV,
        session_text=SYNTH_TEXT,
        session_origin=origin,
    )
    fired = {f.atom_id: f for f in relaxed.firings}
    assert atom_id in fired, "fixture no longer fires its atom"
    rank = lambda e: EFFECT_RANK.get(e or "monitor", 0)  # noqa: E731
    if origin != "human":
        assert relaxed.winning_effect == plain.winning_effect
        assert (
            fired[atom_id].effect
            == {f.atom_id: f for f in plain.firings}[atom_id].effect
        )
    else:
        # Lowered at most to human_review on an enforce atom that decided.
        assert rank(relaxed.winning_effect) <= rank(plain.winning_effect)
        if plain.winning_effect in ("block", "human_review"):
            assert relaxed.winning_effect in ("block", "human_review")
            assert relaxed.block_message


# --- hook path --------------------------------------------------------------

HERMES_PLATFORMS = [
    # gateway/config.py Platform values, read 2026-09-23.
    "local",
    "telegram",
    "discord",
    "whatsapp",
    "whatsapp_cloud",
    "slack",
    "signal",
    "mattermost",
    "matrix",
    "homeassistant",
    "email",
    "sms",
    "dingtalk",
    "api_server",
    "webhook",
    "msgraph_webhook",
    "feishu",
    "wecom",
    "wecom_callback",
    "weixin",
    "bluebubbles",
    "qqbot",
    "yuanbao",
    "relay",
    # AIAgent(platform=...) literals outside the gateway.
    "cli",
    "tui",
    "subagent",
    "cron",
    "curator",
    "gateway",
    "imessage",
    "",
]


@pytest.mark.parametrize("platform", HERMES_PLATFORMS)
@pytest.mark.parametrize("sender", ["", "12345", "webhook:github-hermes"])
def test_origin_inference_table(platform, sender):
    got = session_origin_from_hook(platform, sender)
    assert got in SESSION_ORIGINS
    if sender.startswith("webhook:"):
        assert got == "webhook"
    elif platform == "subagent":
        assert got == "delegate"
    elif platform == "cron":
        assert got == "cron"
    elif platform in ("webhook", "msgraph_webhook", "wecom_callback"):
        assert got == "webhook"
    elif platform in ("cli", "tui"):
        assert got == "human"
    elif platform in engine._HUMAN_PLATFORMS_MESSAGING:
        assert got == ("human" if sender else "unknown")
    else:
        assert got == "unknown"


def test_origin_inference_tolerates_none_and_case():
    assert session_origin_from_hook(None, None) == "unknown"
    assert session_origin_from_hook("CLI", None) == "human"
    assert session_origin_from_hook("Subagent", "") == "delegate"


def _plugin(monkeypatch, tmp_path):
    import importlib
    import sys

    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    init = importlib.import_module("__init__")
    home = tmp_path / "h"
    home.mkdir(parents=True, exist_ok=True)
    vault = tmp_path / "vault"
    vault.mkdir(parents=True, exist_ok=True)
    env = {
        "HERMES_HOME": str(home.resolve()),
        "OBSIDIAN_VAULT_PATH": str(vault.resolve()),
    }
    monkeypatch.setattr(
        init,
        "_load_atoms_entry",
        lambda: init.AtomsEntryConfig(mode="enforce", judge_enabled=False),
    )
    monkeypatch.setattr(init, "_resolve_vault", lambda: vault)
    monkeypatch.setattr(
        init, "_load_catalog_cached", lambda: _engine_catalog("monitor")
    )
    monkeypatch.setattr(init, "_build_env", lambda e=env: dict(e))
    monkeypatch.setattr(init, "_SESSION_TEXT", {})
    # Flow context is per session and process-global; another test can leave a
    # SECRET read on the same session id.
    monkeypatch.setattr(init, "_SESSION_FLOW", {})
    return init, home


@pytest.mark.parametrize(
    "platform,sender,origin",
    [
        ("cli", "", "human"),
        ("telegram", "42", "human"),
        ("telegram", "", "unknown"),
        ("subagent", "", "delegate"),
        ("cron", "", "cron"),
        ("webhook", "webhook:gh", "webhook"),
        ("api_server", "k", "unknown"),
    ],
)
def test_hook_threads_origin_to_the_engine(
    monkeypatch, tmp_path, platform, sender, origin
):
    init, home = _plugin(monkeypatch, tmp_path)
    seen = {}
    real = init.eng.evaluate_tool_call

    def capture(*a, **kw):
        seen.update(kw)
        return real(*a, **kw)

    monkeypatch.setattr(init.eng, "evaluate_tool_call", capture)
    init.pre_llm_call(
        session_id="s1",
        user_message=SYNTH_TEXT,
        conversation_history=[],
        is_first_turn=True,
        model="m",
        platform=platform,
        sender_id=sender,
    )
    out = init.pre_tool_call(
        "write_file",
        {"path": str(home / "SOUL.md")},
        task_id="t",
        session_id="s1",
    )
    assert seen["session_origin"] == origin
    assert seen["session_text"] == SYNTH_TEXT
    # SOUL.md is an enforce BLOCK atom relaxed to monitor in this catalog.
    assert out is not None and out["action"] == "block"
    if origin == "human":
        assert "Held by" in out["message"]
    else:
        assert "Blocked by" in out["message"]


def test_hook_without_sender_kwarg_is_not_human_on_messaging(monkeypatch, tmp_path):
    init, _home = _plugin(monkeypatch, tmp_path)
    init.pre_llm_call(
        session_id="s2",
        user_message=SYNTH_TEXT,
        conversation_history=[],
        is_first_turn=True,
        model="m",
        platform="discord",
    )
    assert init._session_entry("s2") == (SYNTH_TEXT, "unknown")
