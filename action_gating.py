"""
Action-gating surface: path-outside-root (C1) and unsanitized-shell (C2).

Author:  Landen Stecker
Date:    2026-07-11
Version: 1.0.0
Summary: Surface two, action gating. Two atoms at the tool-call boundary. C1 fires when a file path resolves outside its allowed root, the bubblewrap escape, the /proc/self/root synonym that beats a denylist by spelling. C2 fires when a command carries executable structure the schema does not permit, the Snowflake Cortex bypass, the process substitution that rode in behind an allowlisted cat. Both are structural. They fire at certainty, not confidence, and when they cannot tell, they deny.
"""

from __future__ import annotations

import os
import re
import shlex
import string
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NamedTuple
from uuid import uuid4

try:
    from .triad_types import (
        AtomDefinition,
        AtomType,
        Control,
        ControlRollup,
        Edge,
        EffectRank,
        EnforcementMode,
        MappingMethod,
        Polarity,
        Provenance,
        RollupStatus,
        Severity,
        Strength,
        TrustDomain,
        combine_control_rollups,
        parse_atom_firing,
        rollup_control,
    )
except ImportError:  # standalone / sys.path test import
    from triad_types import (
        AtomDefinition,
        AtomType,
        Control,
        ControlRollup,
        Edge,
        EffectRank,
        EnforcementMode,
        MappingMethod,
        Polarity,
        Provenance,
        RollupStatus,
        Severity,
        Strength,
        TrustDomain,
        combine_control_rollups,
        parse_atom_firing,
        rollup_control,
    )

# /proc/self/root is the Linux synonym for the real host root from inside a
# mount namespace. Matching on the raw string spelling misses it.
_PROC_ROOT_ALIASES = re.compile(r"(?:^|/)proc/(?:1|self)/root(?=/|$)")


ATOM_PATH_OUTSIDE = "atoms.tool_invocation.path_resolves_outside_allowed_root"
ATOM_SHELL_UNSANITIZED = "atoms.tool_invocation.shell_invocation_unsanitized"
CTRL_PATH = "control.no_file_access_outside_allowed_roots"
CTRL_SHELL = "control.no_unparameterized_command_execution"
# Handoff door: bounded wait. Hang or timeout → path-around-box, not a contains claim.
_HANDOFF_TIMEOUT_S = 5.0

_FRAMEWORKS_SHARED = [
    "OWASP LLM05:2025 Improper Output Handling",
    "OWASP ASI05 Unexpected Code Execution (RCE)",
    "MITRE ATLAS AML.T0050 (Command and Scripting Interpreter)",
    "MITRE ATLAS AML.M0033 (Input and Output Validation for AI Agent Components)",
    "NIST AI RMF GOVERN-1.1",
    "NIST AI RMF MEASURE-2.8",
    "NIST AI RMF MANAGE-2.4",
]

_FRAMEWORKS_C1 = _FRAMEWORKS_SHARED + [
    "MITRE ATLAS AML.T0105 (Escape to Host)",
]


ACTION_GATING_ATOMS: list[AtomDefinition] = [
    AtomDefinition(
        atom_id=ATOM_PATH_OUTSIDE,
        atom_type=AtomType.RESOURCE,
        predicate=(
            "the canonicalized target of a file operation resolves outside "
            "the declared allowed root"
        ),
        detector_ref=None,
        provenance=Provenance(
            source="AML.M0033",
            source_type="mitigation",
            extracted_from=(
                "implements AML.M0033; defends against AML.T0050 and AML.T0105"
            ),
        ),
        version="1.0.0",
    ),
    AtomDefinition(
        atom_id=ATOM_SHELL_UNSANITIZED,
        atom_type=AtomType.ACTION,
        predicate=(
            "the call carries executable structure where the schema permits none"
        ),
        detector_ref=None,
        provenance=Provenance(
            source="AML.M0033",
            source_type="mitigation",
            extracted_from="implements AML.M0033; defends against AML.T0050",
        ),
        version="1.0.0",
    ),
]


ACTION_GATING_CONTROLS: list[Control] = [
    Control(
        control_id=CTRL_PATH,
        effect=EffectRank.BLOCK,
        severity=Severity.HIGH,
        precedence=100,
        enforcement_mode=EnforcementMode.MONITOR,
        framework_mappings=list(_FRAMEWORKS_C1),
    ),
    Control(
        control_id=CTRL_SHELL,
        effect=EffectRank.BLOCK,
        severity=Severity.HIGH,
        precedence=100,
        enforcement_mode=EnforcementMode.MONITOR,
        framework_mappings=list(_FRAMEWORKS_SHARED),
    ),
]


ACTION_GATING_EDGES: list[Edge] = [
    Edge(
        atom_id=ATOM_PATH_OUTSIDE,
        control_id=CTRL_PATH,
        polarity=Polarity.CONTRADICTS,
        strength=Strength.STRONG,
        mapping_method=MappingMethod.RULE,
    ),
    Edge(
        atom_id=ATOM_SHELL_UNSANITIZED,
        control_id=CTRL_SHELL,
        polarity=Polarity.CONTRADICTS,
        strength=Strength.STRONG,
        mapping_method=MappingMethod.RULE,
    ),
]


def canonicalize_path(raw: str) -> str:
    """Fully resolve meaning: synonyms, .., symlinks, hardlink targets.

    Raises on malformed input so callers can fail closed.
    """
    if raw is None:
        raise ValueError("path is None")
    if not isinstance(raw, str):
        raise TypeError("path must be str")
    if "\x00" in raw:
        raise ValueError("NUL in path")
    text = raw.replace("\\", "/")
    if _PROC_ROOT_ALIASES.search(text):
        remainder = _PROC_ROOT_ALIASES.sub("", text)
        if not remainder.startswith("/"):
            remainder = "/" + remainder
        return str(Path(remainder).resolve())
    p = Path(raw)
    return str(p.resolve(strict=False))


def _is_under_root(resolved: str, root: str) -> bool:
    try:
        resolved_p = Path(resolved).resolve(strict=False)
        root_p = Path(root).resolve(strict=False)
        return resolved_p == root_p or root_p in resolved_p.parents
    except (OSError, ValueError, RuntimeError):
        return False


def _hardlink_identity_ambiguous(resolved: str) -> bool:
    """Hardlinks have no single path identity. nlink>1 is uncertain → fire.

    Path.resolve follows symlinks but not hardlinks, so an in-root name can
    still be the same inode as an out-of-root file. Fail closed on ambiguity.
    """
    p = Path(resolved)
    if not p.exists():
        return False
    try:
        return p.stat().st_nlink > 1
    except OSError:
        return True


def evaluate_path_outside_root(
    raw_path: str,
    *,
    allowed_roots: list[str],
) -> tuple[bool, dict[str, Any]]:
    """C1 predicate. True = fires (outside root or fail-closed)."""
    coords: dict[str, Any] = {
        "raw_path": raw_path,
        "allowed_roots": list(allowed_roots),
    }
    try:
        if not allowed_roots:
            raise ValueError("no allowed roots declared")
        resolved = canonicalize_path(raw_path)
        coords["resolved"] = resolved
        if _hardlink_identity_ambiguous(resolved):
            coords["hardlink_ambiguous"] = True
            return True, coords
        if any(_is_under_root(resolved, r) for r in allowed_roots):
            return False, coords
        return True, coords
    except Exception as exc:
        coords["fail_closed"] = True
        coords["error"] = type(exc).__name__
        return True, coords


# A write into a .git directory, or to a file named .git, can plant repo
# config (core.fsmonitor, diff.external, a gitdir pointer) or a hook, and the
# next git read on a covered row then runs it. A part counts as .git in any
# case and with trailing dots or spaces, which some filesystems drop.
_PATH_WRITE_TOOLS = frozenset({"write_file", "patch"})


def _is_git_part(part: str) -> bool:
    return part.rstrip(" .").casefold() == ".git"


def names_git_control(raw: str) -> bool:
    """True when the raw or resolved path has a .git part. Malformed is True."""
    try:
        text = raw.replace("\\", "/")
        if any(_is_git_part(x) for x in text.split("/")):
            return True
        resolved = canonicalize_path(raw)
    except Exception:
        return True
    return any(_is_git_part(x) for x in Path(resolved).parts)


# git also takes a directory with no .git name as a repository when it holds
# HEAD next to objects and refs, and then reads config from it, so core.bare
# false plus core.worktree and core.fsmonitor in a hand written config runs a
# program on git status. A written name counts in any case, with trailing dots
# or spaces stripped, like a .git part. A dir is probed by exact name with
# lexists, the same probe git makes, so it works where a parent is not listable.
_GITDIR_HEAD = "head"
_GITDIR_PEERS = ("config", "objects", "refs", "commondir")
_GITDIR_SIBLING_WRITES = frozenset(
    {"config", "commondir", "gitdir", "packed-refs", "config.worktree"}
)


def _git_name(part: str) -> str:
    return part.rstrip(" .").casefold()


def _present(path: Path, planned: frozenset[str]) -> bool:
    """On disk now, or named by the same call (a patch that adds it)."""
    return os.path.lexists(path) or str(path).casefold() in planned


def is_gitdir_shaped(directory: Path, planned: frozenset[str] = frozenset()) -> bool:
    """True when the dir holds HEAD and one of config, objects, refs, commondir.

    Stricter than git, which needs HEAD, objects and refs, so a partial plant
    counts too. planned holds the paths the same call writes, so a plant laid
    out in one patch is judged as it will be after the patch, not before.
    """
    if not _present(directory / "HEAD", planned):
        return False
    return any(_present(directory / n, planned) for n in _GITDIR_PEERS)


def _sibling_of_gitdir(directory: Path, planned: frozenset[str] = frozenset()) -> bool:
    if _present(directory / "HEAD", planned):
        return True
    return all(_present(directory / n, planned) for n in ("objects", "refs"))


def _self_and_parents(path: Path) -> list[Path]:
    return [path, *path.parents]


def gitdir_write_reason(raw: str, planned: frozenset[str] = frozenset()) -> str | None:
    """Why a write to raw would build or edit a repository with no .git part.

    HEAD is never written by a path tool. A config, commondir, gitdir or
    packed-refs beside HEAD, or beside both objects and refs, is denied, and so
    is any write under a dir that is already gitdir shaped (hooks, refs), and a
    relative config-like name whose dir the call does not show. Malformed input
    is a reason, so the caller fails closed.
    """
    try:
        text = raw.replace("\\", "/")
        resolved = Path(canonicalize_path(raw))
    except Exception:
        return "gitdir_not_inspectable"
    candidates = [Path(text), resolved]
    if any(_git_name(p.name) == _GITDIR_HEAD for p in candidates):
        return "gitdir_head"
    if not Path(text).is_absolute() and _git_name(Path(text).name) in (
        _GITDIR_SIBLING_WRITES
    ):
        # A relative name resolves against a harness cwd the call does not show.
        return "gitdir_relative"
    for p in candidates:
        if not p.is_absolute():
            continue
        if _git_name(p.name) in _GITDIR_SIBLING_WRITES and _sibling_of_gitdir(
            p.parent, planned
        ):
            return "gitdir_sibling"
        if any(is_gitdir_shaped(d, planned) for d in p.parents):
            return "gitdir_inside"
    return None


# git reads user config from HOME/.gitconfig and XDG_CONFIG_HOME/git/config
# (HOME/.config/git/config by default), and Hermes runs the terminal with HOME
# at {HERMES_HOME}/home, which is inside the roots. A core.fsmonitor written
# there ran a program on a covered git status. A login shell also sources the
# init files in HOME, and ssh reads HOME/.ssh (config ProxyCommand, rc,
# authorized_keys). So a path tool write to one of these names is control,
# wherever it lands and whatever the case or trailing dots and spaces.
_SHELL_INIT_NAMES = frozenset(
    {
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".bash_logout",
        ".profile",
        ".zshrc",
        ".zshenv",
        ".zprofile",
        ".zlogin",
        ".zlogout",
    }
)
_XDG_GIT_NAMES = frozenset({"config", "attributes"})


def home_control_reason(raw: str) -> str | None:
    """Why a write to raw edits git user config or a shell init file.

    The raw and the resolved path are both read, so a link in the roots that
    points at HOME/.gitconfig counts. git/config counts under a .config dir or
    under the XDG_CONFIG_HOME the host env names, not under any dir named git.
    Malformed input is a reason.
    """
    try:
        text = raw.replace("\\", "/")
        resolved = Path(canonicalize_path(raw))
    except Exception:
        return "home_control_not_inspectable"
    for p in (Path(text), resolved):
        name = _git_name(p.name)
        if name == ".gitconfig":
            return "home_git_config"
        if name in _SHELL_INIT_NAMES:
            return "shell_init"
        if any(_git_name(part) == ".ssh" for part in p.parts):
            return "ssh_control"
        if name in _XDG_GIT_NAMES and _git_name(p.parent.name) == "git":
            base = p.parent.parent
            if _git_name(base.name) == ".config" or _is_xdg_config_home(base):
                return "xdg_git_config"
    return None


def _is_xdg_config_home(directory: Path) -> bool:
    """True when directory is the XDG_CONFIG_HOME the host env names."""
    raw = os.environ.get("XDG_CONFIG_HOME")
    if not raw:
        return False
    try:
        return Path(canonicalize_path(raw)) == Path(canonicalize_path(str(directory)))
    except Exception:
        return True


# A Hermes patch in V4A mode names its files in the patch body, not in path.
# The header grammar is the one Hermes applies (tools/patch_parser.py
# parse_v4a_patch): split on LF, drop one trailing CR, re.match each line, so
# any whitespace run is allowed after the stars and between the words, and Move
# File names a source and a destination. Every line is read, not only the lines
# between Begin and End Patch, so the atoms see at least the files Hermes does.
# Codex "Move to:" is kept as a destination too.
_V4A_UPDATE = re.compile(r"\*\*\*\s*Update\s+File:\s*(.+)")
_V4A_ADD = re.compile(r"\*\*\*\s*Add\s+File:\s*(.+)")
_V4A_DELETE = re.compile(r"\*\*\*\s*Delete\s+File:\s*(.+)")
_V4A_MOVE = re.compile(r"\*\*\*\s*Move\s+File:\s*(.+?)\s*->\s*(.+)")
_V4A_MOVE_TO = re.compile(r"\*\*\*\s*Move\s+to:\s*(.+)")
_V4A_BEGIN = re.compile(r"^\*\*\*\s*Begin\s+Patch\s*$")
_V4A_END = re.compile(r"^\*\*\*\s*End\s+Patch\s*$")


class V4AHeaders(NamedTuple):
    """Files a V4A body names. writes are files it creates or changes."""

    paths: list[str]
    writes: list[str]
    unparsed: list[str]


def parse_v4a_headers(body: str) -> V4AHeaders:
    """Read every V4A file header the way Hermes does.

    A line that starts with *** and is not Begin Patch, End Patch or a header
    with a non-empty path is unparsed; the caller reads that call as UNKNOWN,
    since the atoms cannot say which file it touches.
    """
    paths: list[str] = []
    writes: list[str] = []
    unparsed: list[str] = []
    for raw_line in body.split("\n"):
        line = raw_line[:-1] if raw_line.endswith("\r") else raw_line
        if not line.startswith("***"):
            continue
        if _V4A_BEGIN.match(line) or _V4A_END.match(line):
            continue
        named: list[str] = []
        for rx in (_V4A_UPDATE, _V4A_ADD, _V4A_MOVE_TO):
            m = rx.match(line)
            if m:
                named.append(m.group(1).strip())
                writes.append(m.group(1).strip())
        m = _V4A_DELETE.match(line)
        if m:
            named.append(m.group(1).strip())
        m = _V4A_MOVE.match(line)
        if m:
            named.extend((m.group(1).strip(), m.group(2).strip()))
            writes.append(m.group(2).strip())
        if not named or not all(named):
            unparsed.append(line)
            continue
        paths.extend(named)
    return V4AHeaders(paths, [w for w in writes if w], unparsed)


def patch_body_reason(tool_name: str, args: dict[str, Any]) -> str | None:
    """Why a patch call body leaves it UNKNOWN, or None when every file is read.

    A patch arg that is not a string, a V4A mode call with no string body or no
    file header, and any unparsed *** line all fail closed. The path arg alone
    never makes a V4A call COVERED.
    """
    if tool_name != "patch":
        return None
    body = args.get("patch")
    v4a = args.get("mode") == "patch"
    if body is None:
        return "v4a_no_body" if v4a else None
    if not isinstance(body, str):
        return "v4a_body_not_inspectable"
    headers = parse_v4a_headers(body)
    if headers.unparsed:
        return "v4a_unparsed_header"
    if v4a and not headers.paths:
        return "v4a_no_file_header"
    return None


def write_targets(tool_name: str, args: dict[str, Any]) -> list[str]:
    """Every path a write_file or patch call names, including V4A headers."""
    out: list[str] = []
    path = args.get("path") or args.get("target")
    if isinstance(path, str):
        out.append(path)
    body = args.get("patch")
    if tool_name == "patch" and isinstance(body, str):
        out.extend(parse_v4a_headers(body).paths)
    return out


def _planned_writes(tool_name: str, args: dict[str, Any]) -> frozenset[str]:
    """Paths the call creates, and every parent dir of each, casefolded."""
    names: list[str] = []
    path = args.get("path") or args.get("target")
    if isinstance(path, str):
        names.append(path)
    body = args.get("patch")
    if tool_name == "patch" and isinstance(body, str):
        names.extend(parse_v4a_headers(body).writes)
    out: set[str] = set()
    for raw in names:
        forms = [Path(raw.replace("\\", "/"))]
        try:
            forms.append(Path(canonicalize_path(raw)))
        except Exception:
            pass
        for p in forms:
            out.update(str(x).casefold() for x in _self_and_parents(p))
    return frozenset(out)


def git_write_reason(tool_name: str, args: dict[str, Any]) -> tuple[str, str] | None:
    """(path, reason) for the first write target that plants git control.

    The gitdir shape is judged with every file the same call writes counted as
    present, so one patch that adds objects, refs, config and HEAD is denied.
    """
    planned = _planned_writes(tool_name, args)
    for target in write_targets(tool_name, args):
        if names_git_control(target):
            return target, "git_control"
        why = home_control_reason(target)
        if why is not None:
            return target, why
        why = gitdir_write_reason(target, planned)
        if why is not None:
            return target, why
    return None


# Argv is a closed per-binary schema, not a joined-string denylist. Joining
# tokens and scanning for shell punctuation missed flag-shaped escapes
# (tar --checkpoint-action, ssh -oProxyCommand) and nested interpreters
# (bash -c). The binary must be a bare basename on this map; each flag token
# (anything starting with '-') must be listed for that binary. Unknown binary
# or unknown flag means deny. Path-form binaries (/tmp/evil, ./tool) deny.
_ARGV_FLAG_ALLOWLIST: dict[str, frozenset[str]] = {
    "cat": frozenset({"-n", "-v", "-b", "-s", "-E", "-T", "-A"}),
    "ls": frozenset({"-l", "-a", "-la", "-al", "-h", "-1", "-R"}),
    "git": frozenset(
        {
            "-5",
            "-n",
            "-q",
            "-v",
            "--oneline",
            "--stat",
            "--name-only",
            "--format=%h",
            "--no-pager",
        }
    ),
    "echo": frozenset({"-n", "-e"}),
    "grep": frozenset({"-n", "-r", "-rn", "-i", "-l", "-c", "-E", "-F", "-v"}),
    "cp": frozenset({"-r", "-R", "-a", "-p", "-v", "-n"}),
    "curl": frozenset({"-I", "-L", "-f", "-s", "-S", "-o", "-O", "-A", "-H"}),
    "sleep": frozenset(),
    "tar": frozenset(
        {
            "-x",
            "-c",
            "-t",
            "-v",
            "-f",
            "-z",
            "-j",
            "-J",
            "-a",
            "-C",
            "-tf",
            "-tvf",
            "-xf",
            "-xvf",
            "-czf",
            "-xzf",
            "--list",
        }
    ),
    "ssh": frozenset({"-p", "-i", "-l", "-F", "-v", "-4", "-6", "-n", "-T"}),
    # Interpreters: no -c / -lc. Module and quiet flags only.
    "python": frozenset({"-m", "-q", "-u", "-V", "--version"}),
    "python3": frozenset({"-m", "-q", "-u", "-V", "--version"}),
    "bash": frozenset(),
    "sh": frozenset(),
}
_ARGV_TOKEN_STRUCTURE = re.compile(r"[;|&`$<>()\n\r]")


# A freeform command string runs under a shell, so a list of known shell
# constructs is never complete: it missed a trailing "&", a newline, an env
# prefix, brace expansion and heredocs. The string branch is an allowlist
# instead, in two steps. First, a plain command carries letters, digits, these
# few characters, spaces, and quoted runs that hold the same plain characters.
# Second, the plain string is split into tokens and held to the same per-binary
# argv schema as an argv list, so the binary and every flag must be listed.
_PLAIN_CHARS = frozenset(string.ascii_letters + string.digits + "_./:,@%+=-")
_QUOTE_CHARS = frozenset("'\"")
_NAMED_CONSTRUCTS = ("<(", ">(", "$(", "<<", ">>", "&&", "||")
_ENV_PREFIX = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")


def _construct_at(command: str, i: int) -> str:
    for name in _NAMED_CONSTRUCTS:
        if command.startswith(name, i):
            return name
    return command[i]


def _first_disallowed(command: str) -> str | None:
    """Name the first construct outside the plain set, or None if plain."""
    quote = None
    for i, c in enumerate(command):
        if quote is not None:
            if c == quote:
                quote = None
            elif c != " " and c not in _PLAIN_CHARS:
                return _construct_at(command, i)
        elif c in _QUOTE_CHARS:
            quote = c
        elif c != " " and c not in _PLAIN_CHARS:
            return _construct_at(command, i)
    if quote is not None:
        return f"unbalanced {quote}"
    first = command.strip().split(" ", 1)[0]
    m = _ENV_PREFIX.match(first)
    if m:
        return f"env_prefix:{m.group(0)}"
    return None


def _inspect_argv(argv: list[str]) -> dict[str, Any]:
    """Permit argv only when the binary and every flag are on the allowlist."""
    binary = argv[0]
    if "/" in binary or "\\" in binary:
        return {
            "structure": "argv_path_binary",
            "permitted": False,
            "argv": list(argv),
            "binary": binary,
        }
    allowed_flags = _ARGV_FLAG_ALLOWLIST.get(binary)
    if allowed_flags is None:
        return {
            "structure": "argv_unknown_binary",
            "permitted": False,
            "argv": list(argv),
            "binary": binary,
        }
    for token in argv[1:]:
        if _ARGV_TOKEN_STRUCTURE.search(token):
            return {
                "structure": "argv_token_structure",
                "permitted": False,
                "argv": list(argv),
                "token": token,
            }
        if token.startswith("-") and token not in allowed_flags:
            return {
                "structure": "argv_unknown_flag",
                "permitted": False,
                "argv": list(argv),
                "binary": binary,
                "flag": token,
            }
    return {"structure": None, "permitted": True, "argv": list(argv)}


def inspect_call_structure(call: str | dict[str, Any]) -> dict[str, Any]:
    """Inspect whether a call carries shell-executable structure.

    Permitted argv schema: {"argv": [binary, *args]} where binary is a bare
    basename on the per-binary flag allowlist and every flag token is listed
    for that binary. A freeform command string is permitted only when every
    character is on the plain list (see _first_disallowed) and its shlex
    tokens pass the same argv schema. A string that does not split is denied.
    """
    if isinstance(call, dict):
        if "argv" in call:
            argv = call["argv"]
            if not isinstance(argv, list) or not argv:
                raise ValueError("argv must be a non-empty list")
            if not all(isinstance(t, str) for t in argv):
                raise ValueError("argv tokens must be strings")
            return _inspect_argv(argv)
        if "command" in call:
            return inspect_call_structure(str(call["command"]))
        raise ValueError("call dict must carry argv or command")

    if not isinstance(call, str):
        raise TypeError("call must be str or dict")
    if "\x00" in call:
        raise ValueError("NUL in command")

    found = _first_disallowed(call)
    if found is not None:
        return {"structure": found, "permitted": False, "command": call}
    try:
        tokens = shlex.split(call, posix=True)
    except ValueError as exc:
        return {
            "structure": f"command_parse_error:{type(exc).__name__}",
            "permitted": False,
            "command": call,
        }
    if not tokens:
        return {"structure": None, "permitted": True, "command": call}
    info = _inspect_argv(tokens)
    info["command"] = call
    return info


# Shell coverage table. C2 permitted only says the binary and each flag are on
# the allowlist; positionals and subcommands pass unread, so C2 alone let
# interpreters, git config, tar option letters and curl header files through.
# A terminal call counts as COVERED only when every inspected surface matches
# one exact row here. Exact binary, exact subcommand, exact flags, positionals
# by a closed shape. No prefix match, no similarity. A binary or subcommand not
# listed is UNKNOWN and takes control.coverage_unknown.
# A row bounds the argv, not repo config on disk: a hook or core.fsmonitor in
# the repo still runs on git status. So a row covers only in a working dir
# inside allowed_roots that is not and does not sit under a gitdir shaped dir,
# no positional or working dir names a .git part, and C1 denies path tool
# writes into .git or that build a gitdir shape (HEAD, config beside HEAD).
# User config is not bounded by the row either, and Hermes puts HOME inside the
# roots, so C1 also denies writes to HOME/.gitconfig, git/config and shell init
# files. As a second wall the plugin pins, at register, into the host env a
# local terminal inherits: safe.bareRepository=explicit, so git refuses a bare
# repo it finds by discovery, and core.fsmonitor=false, core.hooksPath=/dev/null
# and core.pager=cat, so a program named in any config file does not run for
# those keys. Command line config wins over every file. A git row is COVERED
# only while each pin is the value git would read.
_SAFE_BARE_KEY = "safe.bareRepository"
_SAFE_BARE_VALUE = "explicit"
GIT_ENV_PINS: tuple[tuple[str, str], ...] = (
    (_SAFE_BARE_KEY, _SAFE_BARE_VALUE),
    ("core.fsmonitor", "false"),
    ("core.hooksPath", "/dev/null"),
    ("core.pager", "cat"),
)


def _config_count_pairs(environ: Any) -> list[tuple[str, str]]:
    raw = environ.get("GIT_CONFIG_COUNT", "0")
    try:
        count = max(int(raw), 0)
    except (TypeError, ValueError):
        count = 0
    return [
        (
            str(environ.get(f"GIT_CONFIG_KEY_{i}", "")),
            str(environ.get(f"GIT_CONFIG_VALUE_{i}", "")),
        )
        for i in range(count)
    ]


def _config_parameter_pairs(environ: Any) -> list[tuple[str, str]] | None:
    """GIT_CONFIG_PARAMETERS as (key, value) pairs, None when it does not split.

    git writes it as shell quoted 'key'='value' or 'key=value' entries; shlex
    joins either form into key=value.
    """
    raw = environ.get("GIT_CONFIG_PARAMETERS")
    if raw is None:
        return []
    try:
        tokens = shlex.split(str(raw), posix=True)
    except ValueError:
        return None
    return [(t.partition("=")[0], t.partition("=")[2]) for t in tokens]


def _last_value(pairs: list[tuple[str, str]], key: str) -> str | None:
    last = None
    for k, value in pairs:
        if k.casefold() == key.casefold():
            last = value
    return last


def git_pin_effective(environ: Any = None) -> bool:
    """True when git would read every GIT_ENV_PINS value from this env.

    git reads GIT_CONFIG_COUNT entries and then GIT_CONFIG_PARAMETERS, and the
    last value wins, so a host GIT_CONFIG_PARAMETERS setting all overrode the
    count pin. A PARAMETERS value that does not split is not effective.
    """
    if environ is None:
        environ = os.environ
    params = _config_parameter_pairs(environ)
    if params is None:
        return False
    pairs = _config_count_pairs(environ) + params
    return all(_last_value(pairs, key) == value for key, value in GIT_ENV_PINS)


def pin_git_harness_env(environ: Any) -> None:
    """Pin GIT_ENV_PINS in GIT_CONFIG_* and GIT_CONFIG_PARAMETERS.

    The count entries keep entries already there, and a pin that is already
    the last value there is not added again. A count that is not a
    non-negative integer is read as 0, since git rejects it anyway. Each pin is
    also appended to GIT_CONFIG_PARAMETERS, which git reads last, so a host
    value there cannot override it and a child env that resets
    GIT_CONFIG_COUNT to 0 still carries it. A PARAMETERS value that does not
    split is left alone; git refuses it.
    """
    pairs = _config_count_pairs(environ)
    count = len(pairs)
    for key, value in GIT_ENV_PINS:
        if _last_value(pairs, key) != value:
            environ[f"GIT_CONFIG_KEY_{count}"] = key
            environ[f"GIT_CONFIG_VALUE_{count}"] = value
            pairs.append((key, value))
            count += 1
    environ["GIT_CONFIG_COUNT"] = str(count)
    params = _config_parameter_pairs(environ)
    if params is None:
        return
    entries = [
        f"'{key}'='{value}'"
        for key, value in GIT_ENV_PINS
        if _last_value(params, key) != value
    ]
    if not entries:
        return
    prior = str(environ.get("GIT_CONFIG_PARAMETERS", "")).strip()
    environ["GIT_CONFIG_PARAMETERS"] = " ".join([prior, *entries] if prior else entries)


_POS_SHAPES: dict[str, re.Pattern[str]] = {
    # Relative path under the working dir: no leading / ~ . or -, no .. part.
    "rel_path": re.compile(r"(?:\.|[A-Za-z0-9_][A-Za-z0-9._/-]*)"),
    # Revision or relative path for git read commands.
    "git_rev": re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/~^-]*"),
    "word": re.compile(r"[A-Za-z0-9._,:@%+=/-]+"),
    "uint": re.compile(r"[0-9]{1,4}"),
}


class ShellCoverageRow(NamedTuple):
    row_id: str
    binary: str
    subcommand: str | None
    flags: frozenset[str]
    positional: str | None
    max_positionals: int = 0
    min_flags: int = 0


SHELL_COVERAGE_TABLE: tuple[ShellCoverageRow, ...] = (
    ShellCoverageRow(
        "git.status", "git", "status", frozenset({"-v", "-q"}), "rel_path", 8
    ),
    ShellCoverageRow(
        "git.log",
        "git",
        "log",
        frozenset({"-5", "-n", "--oneline", "--stat", "--name-only", "--format=%h"}),
        "git_rev",
        4,
    ),
    ShellCoverageRow(
        "git.diff", "git", "diff", frozenset({"--stat", "--name-only"}), "git_rev", 4
    ),
    ShellCoverageRow(
        "ls",
        "ls",
        None,
        frozenset({"-l", "-a", "-la", "-al", "-h", "-1"}),
        "rel_path",
        8,
    ),
    ShellCoverageRow("echo", "echo", None, frozenset({"-n"}), "word", 16),
    ShellCoverageRow("sleep", "sleep", None, frozenset(), "uint", 1),
    ShellCoverageRow(
        "python3.version", "python3", None, frozenset({"-V", "--version"}), None, 0, 1
    ),
    ShellCoverageRow(
        "python.version", "python", None, frozenset({"-V", "--version"}), None, 0, 1
    ),
)

# Terminal args that carry no command. Any other key may be run by a harness
# and was not inspected, so it leaves the call UNKNOWN.
_SHELL_PASSIVE_KEYS = frozenset(
    {"command", "argv", "timeout", "workdir", "background", "pty", "check_interval"}
)
_GIT_GLOBAL_FLAGS = frozenset({"--no-pager"})


def _match_row(tokens: list[str]) -> str | None:
    binary = tokens[0]
    rest = list(tokens[1:])
    if binary == "git":
        while rest and rest[0] in _GIT_GLOBAL_FLAGS:
            rest.pop(0)
    for row in SHELL_COVERAGE_TABLE:
        if row.binary != binary:
            continue
        body = rest
        if row.subcommand is not None:
            if not body or body[0] != row.subcommand:
                continue
            body = body[1:]
        flags = [t for t in body if t.startswith("-")]
        positionals = [t for t in body if not t.startswith("-")]
        if any(f not in row.flags for f in flags) or len(flags) < row.min_flags:
            continue
        if len(positionals) > row.max_positionals:
            continue
        if positionals:
            shape = _POS_SHAPES[row.positional or ""]
            if not all(
                shape.fullmatch(p) and ".." not in p.split("/") for p in positionals
            ):
                continue
            if any(_is_git_part(x) for p in positionals for x in p.split("/")):
                continue
        return row.row_id
    return None


def _workdir_bound(workdir: Any, allowed_roots: list[str] | None) -> str | None:
    """Return why a working dir leaves the call UNKNOWN, or None if bounded.

    Relative paths take the harness cwd, which the call does not show, so only
    an absolute path that resolves inside allowed_roots is bounded.
    """
    if not isinstance(workdir, str) or not workdir.strip():
        return "workdir_not_inspectable"
    if not allowed_roots:
        return "workdir_no_roots"
    if not workdir.replace("\\", "/").startswith("/"):
        return "workdir_relative"
    if names_git_control(workdir):
        return "workdir_git_control"
    try:
        resolved = canonicalize_path(workdir)
    except Exception:
        return "workdir_not_inspectable"
    if not any(_is_under_root(resolved, r) for r in allowed_roots):
        return "workdir_outside_roots"
    # git walks up from the working dir and takes the first dir that is gitdir
    # shaped as the repository, so every parent counts, not only the dir.
    for start in (Path(workdir), Path(resolved)):
        if any(is_gitdir_shaped(d) for d in _self_and_parents(start)):
            return "workdir_gitdir_shape"
    return None


def shell_call_coverage(
    args: Any, *, allowed_roots: list[str] | None = None, environ: Any = None
) -> tuple[str | None, str]:
    """Return (row ids, reason). Row ids None means the call is not COVERED.

    Every present surface (argv list and command string) must match a row,
    since a harness may run either. A call with neither surface, or with a
    surface that is not inspectable, is never COVERED. A call that names a
    working dir is COVERED only when that dir resolves inside allowed_roots.
    """
    if not isinstance(args, dict):
        return None, "args_not_mapping"
    for key in args:
        if key not in _SHELL_PASSIVE_KEYS:
            return None, f"unexpected_arg:{key}"
    if "workdir" in args:
        why = _workdir_bound(args["workdir"], allowed_roots)
        if why is not None:
            return None, why
    surfaces: list[list[str]] = []
    if "argv" in args:
        argv = args["argv"]
        if not isinstance(argv, list) or not argv:
            return None, "argv_not_inspectable"
        if not all(isinstance(t, str) for t in argv):
            return None, "argv_not_inspectable"
        surfaces.append(list(argv))
    if "command" in args:
        command = args["command"]
        if not isinstance(command, str) or not command.strip():
            return None, "command_not_inspectable"
        if "\x00" in command or _first_disallowed(command) is not None:
            return None, "command_structure"
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError:
            return None, "command_parse_error"
        if not tokens:
            return None, "command_not_inspectable"
        surfaces.append(tokens)
    if not surfaces:
        return None, "no_inspectable_command"
    rows: set[str] = set()
    for tokens in surfaces:
        row = _match_row(tokens)
        if row is None:
            return None, f"no_table_row:{tokens[0]}"
        rows.add(row)
    # A git row is bounded only while git would refuse a bare repo it finds by
    # discovery, which a later host env change can undo.
    if any(r.startswith("git.") for r in rows) and not git_pin_effective(environ):
        return None, "git_pin_not_effective"
    return ",".join(sorted(rows)), "table_row"


def evaluate_shell_unsanitized(
    call: str | dict[str, Any],
) -> tuple[bool, dict[str, Any]]:
    """C2 predicate. True = fires (unsanitized structure or fail-closed)."""
    coords: dict[str, Any] = {}
    try:
        info = inspect_call_structure(call)
        coords.update(info)
        if info.get("permitted"):
            return False, coords
        return True, coords
    except Exception as exc:
        coords["fail_closed"] = True
        coords["error"] = type(exc).__name__
        return True, coords


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_firing(
    atom_id: str,
    evaluation_id: str,
    coords: dict[str, Any],
    trust_domain: TrustDomain = TrustDomain.TOOL_OUTPUT,
):
    return parse_atom_firing(
        {
            "firing_id": str(uuid4()),
            "evaluation_id": evaluation_id,
            "atom_id": atom_id,
            "detection_confidence": 1.0,
            "source_coordinates": coords,
            "detector_version": None,
            "timestamp": _now_iso(),
            "trust_domain": trust_domain.value,
        }
    )


PATH_TOOLS = frozenset({"read_file", "write_file", "patch", "search_files"})
SHELL_TOOLS = frozenset({"terminal"})
_ARG_SUBSTITUTION = re.compile(r"(?:\$\(|`|<\(|>\()")
_CONTENT_ARG_KEYS = frozenset(
    {
        "content",
        "text",
        "body",
        "prompt",
        "message",
        "description",
        "notes",
        "old_string",
        "new_string",
        "patch",
        "code",
        "html",
    }
)


def evaluate_action_gating(
    tool_name: str,
    args: dict[str, Any],
    *,
    allowed_roots: list[str],
    evaluation_id: str = "unknown",
) -> tuple[list, list[ControlRollup], EffectRank]:
    """Run C1/C2 detectors, parse firings, roll up controls."""
    fired_ids: set[str] = set()
    firings = []

    if tool_name in PATH_TOOLS:
        path = args.get("path") or args.get("target")
        if isinstance(path, str):
            fires, coords = evaluate_path_outside_root(
                path, allowed_roots=allowed_roots
            )
            if fires:
                fired_ids.add(ATOM_PATH_OUTSIDE)
                firings.append(_make_firing(ATOM_PATH_OUTSIDE, evaluation_id, coords))
        body = args.get("patch")
        if (
            tool_name == "patch"
            and isinstance(body, str)
            and ATOM_PATH_OUTSIDE not in fired_ids
        ):
            # Every file a V4A body names, both ends of a move, gets full C1.
            for header_path in parse_v4a_headers(body).paths:
                fires, coords = evaluate_path_outside_root(
                    header_path, allowed_roots=allowed_roots
                )
                if fires:
                    coords["v4a_header"] = True
                    fired_ids.add(ATOM_PATH_OUTSIDE)
                    firings.append(
                        _make_firing(ATOM_PATH_OUTSIDE, evaluation_id, coords)
                    )
                    break
        if tool_name in _PATH_WRITE_TOOLS and ATOM_PATH_OUTSIDE not in fired_ids:
            hit = git_write_reason(tool_name, args)
            if hit is not None:
                target, why = hit
                coords = {
                    "raw_path": target,
                    "allowed_roots": list(allowed_roots),
                    "git_control": True,
                    "git_reason": why,
                }
                fired_ids.add(ATOM_PATH_OUTSIDE)
                firings.append(_make_firing(ATOM_PATH_OUTSIDE, evaluation_id, coords))

    if tool_name in SHELL_TOOLS:
        # Inspect every present surface. Prefer-argv alone let a clean argv mask
        # an unsafe command string (Hermes runs command; check must not ignore it).
        calls: list[str | dict[str, Any]] = []
        argv = args.get("argv")
        if isinstance(argv, list):
            calls.append({"argv": argv})
        command = args.get("command")
        if isinstance(command, str) and command:
            calls.append(command)
        if not calls:
            calls.append("")
        for call in calls:
            fires, coords = evaluate_shell_unsanitized(call)
            if fires:
                fired_ids.add(ATOM_SHELL_UNSANITIZED)
                firings.append(
                    _make_firing(ATOM_SHELL_UNSANITIZED, evaluation_id, coords)
                )
                break
    else:
        # J04 (CVE-2025-53967): the agent-visible half is executable substitution
        # in a NON-shell tool arg. Widening SHELL_TOOLS cannot see it, because that
        # branch reads argv/command and an MCP tool carries neither. Substitution
        # only; full shell-structure matching here would false-fire on ordinary
        # metacharacters (search_files pattern "foo|bar").
        for key, val in args.items():
            if key in _CONTENT_ARG_KEYS:
                continue
            if not isinstance(val, str):
                continue
            m = _ARG_SUBSTITUTION.search(val)
            if not m:
                continue
            fired_ids.add(ATOM_SHELL_UNSANITIZED)
            firings.append(
                _make_firing(
                    ATOM_SHELL_UNSANITIZED,
                    evaluation_id,
                    {
                        "structure": m.group(0),
                        "permitted": False,
                        "arg": key,
                        "command": val,
                    },
                )
            )
            break

    rollups = [
        rollup_control(ctrl, ACTION_GATING_EDGES, fired_ids)
        for ctrl in ACTION_GATING_CONTROLS
    ]
    combined = combine_control_rollups(rollups)
    return firings, rollups, combined


def strangler_observe_split(atom_id: str, *, observe: bool | None = None) -> str:
    """One-deny observe split for path-outside-root. Does not grow the catalog."""
    if observe is None:
        observe = os.environ.get("AEGIS_STRANGLER_OBSERVE", "") == "1"
    if atom_id == ATOM_PATH_OUTSIDE and observe:
        return "strangler-observe"
    return "legacy"


def denial_line(
    atom_id: str,
    control_id: str,
    framework_ids: list[str],
) -> str:
    """Pinned denial line naming atom, control, and framework ids."""
    fw = ", ".join(framework_ids)
    return f"[aegis-atoms] Blocked by {atom_id} via {control_id} (frameworks: {fw})"


def conflicting_handoff_dry() -> str:
    """Named box door. Dry only. Unset, missing, hang, or observe-skip → unwired."""
    raw = os.environ.get("AEGIS_CONFLICTING_HANDOFF", "").strip()
    if not raw:
        return "HANDOFF_UNWIRED"
    path = Path(raw)
    if not path.is_file():
        return "HANDOFF_UNWIRED"
    # Side-effect only under enforce. Observe names the door as unwired.
    mode = os.environ.get("AEGIS_ATOMS_MODE", "enforce").strip().lower()
    if mode != "enforce":
        return "HANDOFF_UNWIRED"
    try:
        proc = subprocess.run(
            [sys.executable, str(path), "CONFLICTING"],
            capture_output=True,
            text=True,
            check=False,
            timeout=_HANDOFF_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return "HANDOFF_UNWIRED"
    out = f"{proc.stdout or ''}{proc.stderr or ''}"
    if proc.returncode == 0 and "HANDOFF_OK" in out:
        return "HANDOFF_OK"
    return "HANDOFF_UNWIRED"


def rollup_denial_message(rollups: list[ControlRollup]) -> str | None:
    """Build public denial from CONTRADICTED/CONFLICTING rollups."""
    ctrl_by_id = {c.control_id: c for c in ACTION_GATING_CONTROLS}
    # Prefer CONTRADICTS when multiple edges share a control_id (legacy SUPPORTS peer).
    edge_by_ctrl: dict[str, Edge] = {}
    for e in ACTION_GATING_EDGES:
        if e.polarity is Polarity.CONTRADICTS or e.control_id not in edge_by_ctrl:
            edge_by_ctrl[e.control_id] = e
    parts: list[str] = []
    for r in rollups:
        if r.status is RollupStatus.CONTRADICTED and r.effect is EffectRank.BLOCK:
            ctrl = ctrl_by_id[r.control_id]
            edge = edge_by_ctrl[r.control_id]
            parts.append(
                denial_line(edge.atom_id, ctrl.control_id, ctrl.framework_mappings)
            )
        elif r.status is RollupStatus.CONFLICTING:
            door = conflicting_handoff_dry()
            parts.append(
                f"[aegis-atoms] Escalated by {r.control_id}: CONFLICTING support "
                f"and contradiction (cannot auto-decide) [{door}]"
            )
    if not parts:
        return None
    return " | ".join(parts)
