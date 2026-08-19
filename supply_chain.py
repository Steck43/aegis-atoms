"""
Supply-chain surface (Surface 4): tool integrity + undeclared egress.

Author:  Landen Stecker
Date:    2026-07-12
Version: 1.1.0
Summary: Surface four, supply chain. Two halves. Integrity catches a tampered
         tool. Egress catches a clean, verified tool calling somewhere it never
         declared — the Postmark BCC pattern. Together they govern the surface
         the other three miss by construction.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import yaml

from triad_types import (
    AtomDefinition,
    AtomType,
    Control,
    Edge,
    EffectRank,
    EnforcementMode,
    MappingMethod,
    Polarity,
    Provenance,
    Severity,
    Strength,
    TrustDomain,
    parse_atom_firing,
    rollup_control,
    combine_control_rollups,
    ControlRollup,
    RollupStatus,
)

ATOM_TOOL_INTEGRITY = "atoms.supply_chain.tool_integrity_unverified"
ATOM_UNEXPECTED_EGRESS = "atoms.supply_chain.unexpected_egress_check"
CTRL_NO_UNVERIFIED = "control.no_unverified_tool_invocation"
CTRL_NO_UNDECLARED_EGRESS = "control.no_undeclared_egress"

_FRAMEWORKS = [
    "OWASP ASI04 Agentic Supply Chain Vulnerabilities",
    "ATLAS AML.T0010.005",
    "ATLAS AML.T0011.002",
    "NIST AI RMF GOVERN-6.1",
    "NIST AI RMF MANAGE-3.1",
]

_FRAMEWORKS_EGRESS = [
    "OWASP ASI04 Agentic Supply Chain Vulnerabilities",
    "AML.CS0053 (Postmark MCP, case study)",
    "NIST AI RMF MANAGE-2.2",
]

# Destination-shaped arg keys (same role as path keys for C1).
_DEST_KEYS = frozenset(
    {"to", "bcc", "cc", "url", "host", "endpoint", "recipients", "from"}
)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DEFAULT_PORTS = frozenset({80, 443})

DEFAULT_BASELINE_PATH = Path(__file__).resolve().parent / "approved_tools.yaml"


SUPPLY_CHAIN_ATOMS: list[AtomDefinition] = [
    AtomDefinition(
        atom_id=ATOM_TOOL_INTEGRITY,
        atom_type=AtomType.SUBJECT,
        predicate=(
            "an invoked tool's identity, version, or declared metadata "
            "does not match its approved baseline"
        ),
        detector_ref=None,
        provenance=Provenance(
            source="ATLAS AML.CS0053/CS0054/CS0049",
            source_type="case_studies",
            extracted_from=(
                "defends AML.T0010.005 supply chain compromise: AI agent tool; "
                "AML.T0011.002 poisoned tool"
            ),
        ),
        version="1.0.0",
    ),
    AtomDefinition(
        # tool_integrity_unverified asks: was this tool tampered with. This asks a
        # different question: is a clean, verified tool calling somewhere it never
        # declared. Postmark (AML.CS0053) is the case — the tool was intact, it just
        # BCC'd the attacker. Integrity passes; the exfil still lands. Two halves of
        # one surface.
        atom_id=ATOM_UNEXPECTED_EGRESS,
        atom_type=AtomType.RESOURCE,
        predicate=(
            "an outbound network destination in a tool call is not in that "
            "tool's declared allowed destinations"
        ),
        detector_ref=None,
        provenance=Provenance(
            source="Atom Audit (Landen) + AML.CS0053 Postmark",
            source_type="design+case_study",
            extracted_from=(
                "catches the BCC exfiltration pattern; declared-behavior "
                "egress control; # TODO: pin exfil technique id against live ATLAS"
            ),
        ),
        version="1.0.0",
    ),
]


SUPPLY_CHAIN_CONTROLS: list[Control] = [
    Control(
        control_id=CTRL_NO_UNVERIFIED,
        effect=EffectRank.BLOCK,
        severity=Severity.CRITICAL,
        precedence=100,
        enforcement_mode=EnforcementMode.MONITOR,
        framework_mappings=list(_FRAMEWORKS),
    ),
    Control(
        control_id=CTRL_NO_UNDECLARED_EGRESS,
        effect=EffectRank.BLOCK,
        severity=Severity.HIGH,
        precedence=100,
        enforcement_mode=EnforcementMode.MONITOR,
        framework_mappings=list(_FRAMEWORKS_EGRESS),
    ),
]


SUPPLY_CHAIN_EDGES: list[Edge] = [
    Edge(
        atom_id=ATOM_TOOL_INTEGRITY,
        control_id=CTRL_NO_UNVERIFIED,
        polarity=Polarity.CONTRADICTS,
        strength=Strength.STRONG,
        mapping_method=MappingMethod.RULE,
    ),
    Edge(
        atom_id=ATOM_UNEXPECTED_EGRESS,
        control_id=CTRL_NO_UNDECLARED_EGRESS,
        polarity=Polarity.CONTRADICTS,
        strength=Strength.STRONG,
        mapping_method=MappingMethod.RULE,
    ),
]


def hash_description(description: str) -> str:
    """SHA-256 of the tool's declared description (UTF-8)."""
    if not isinstance(description, str):
        raise TypeError("description must be str")
    return hashlib.sha256(description.encode("utf-8")).hexdigest()


def load_baseline(path: Path | str) -> dict[str, dict[str, Any]]:
    """Load tool_id → {version, description_hash, ...} from a YAML manifest."""
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("baseline root must be a mapping")
    tools = raw.get("tools")
    if not isinstance(tools, dict):
        raise ValueError("baseline must contain a tools mapping")
    out: dict[str, dict[str, Any]] = {}
    for tool_id, entry in tools.items():
        if not isinstance(entry, dict):
            raise ValueError(f"baseline entry for {tool_id!r} must be a mapping")
        out[str(tool_id)] = dict(entry)
    return out


def evaluate_tool_integrity(
    tool_id: str,
    *,
    version: str | None,
    description: str | None,
    baseline_path: Path | str,
    content_hash: str | None = None,
) -> tuple[bool, dict[str, Any]]:
    """Predicate. True = fires (unverified / mismatch / fail-closed)."""
    # This surface is the one the other three miss by construction. In Postmark
    # (AML.CS0053) the call is legitimate, nothing is written, and there's no
    # injection pattern in the input — so action, memory, and content atoms all
    # stay silent. The attack is in the tool itself. So we check the tool's
    # provenance, not the call: identity, version, and declared-description hash
    # against an approved baseline. A poisoned update changes the hash and fires.
    coords: dict[str, Any] = {
        "tool_id": tool_id,
        "observed_version": version,
        "baseline_path": str(baseline_path),
    }
    try:
        # Unverifiable is unverified. If the baseline can't be read or the tool's
        # metadata can't be hashed, the atom fires. A tool we cannot check is not a
        # tool we trust.
        baseline = load_baseline(baseline_path)
        if description is None:
            raise ValueError("description is None")
        observed_desc_hash = hash_description(description)
        coords["observed_description_hash"] = observed_desc_hash

        entry = baseline.get(tool_id)
        if entry is None:
            coords["reason"] = "unlisted_tool"
            return True, coords

        approved_version = entry.get("version")
        approved_desc_hash = entry.get("description_hash")
        coords["approved_version"] = approved_version
        coords["approved_description_hash"] = approved_desc_hash

        if version is None:
            raise ValueError("version is None")
        if str(version) != str(approved_version):
            coords["reason"] = "version_mismatch"
            return True, coords

        # The docstring is an attack surface. Invariant Labs (AML.CS0054) hid a prompt
        # injection in a tool's description that executed when the tool was called. So
        # the baseline pins the description hash too, not just the version — a silently
        # edited docstring is a supply-chain compromise even at the same version.
        if approved_desc_hash is None:
            raise ValueError("approved description_hash missing")
        if observed_desc_hash != str(approved_desc_hash):
            coords["reason"] = "description_hash_mismatch"
            return True, coords

        approved_content = entry.get("content_hash")
        if approved_content is not None:
            if content_hash is None:
                raise ValueError("content_hash required by baseline")
            coords["approved_content_hash"] = approved_content
            coords["observed_content_hash"] = content_hash
            if str(content_hash) != str(approved_content):
                coords["reason"] = "content_hash_mismatch"
                return True, coords

        coords["reason"] = "baseline_matched"
        return False, coords
    except Exception as exc:
        coords["fail_closed"] = True
        coords["error"] = type(exc).__name__
        if not Path(baseline_path).is_file():
            coords["reason"] = "baseline_unreadable"
        else:
            coords["reason"] = "metadata_unverifiable"
        return True, coords


def _flatten_dest_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        parts = [p.strip() for p in value.split(",") if p.strip()]
        return parts
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for item in value:
            out.extend(_flatten_dest_values(item))
        return out
    raise ValueError(f"unsupported destination value type: {type(value).__name__}")


def extract_destinations(args: dict[str, Any]) -> list[str]:
    """Pull destination-like fields from tool-call args (C1-style extraction)."""
    if not isinstance(args, dict):
        raise TypeError("args must be a dict")
    raw: list[str] = []
    for key, val in args.items():
        if str(key).lower() not in _DEST_KEYS:
            continue
        raw.extend(_flatten_dest_values(val))
    return raw


def canonicalize_destination(raw: str) -> str:
    """Canonical form for membership. Never compare on the raw string.

    Canonicalize the destination before the membership check. A declared-host
    list is beaten by spelling otherwise: the same endpoint reached by IP, by a
    subdomain, or on an odd port reads as "undeclared" or sneaks in as "declared"
    depending on the string. Compare on the canonical form, never the raw arg.
    This is the C1 path-canonicalization lesson applied to network destinations.
    """
    if not isinstance(raw, str):
        raise TypeError("destination must be str")
    text = raw.strip()
    if not text:
        raise ValueError("empty destination")

    # URL-shaped
    if "://" in text or text.startswith("//"):
        parsed = urlparse(text if "://" in text else f"https:{text}")
        host = parsed.hostname
        if not host:
            raise ValueError("url missing host")
        port = parsed.port
        host_l = host.lower()
        try:
            host_l = str(ipaddress.ip_address(host_l))
        except ValueError:
            pass
        if port is not None and port not in _DEFAULT_PORTS:
            return f"{host_l}:{port}"
        return host_l

    # Email
    if "@" in text:
        candidate = text.lower()
        if not _EMAIL_RE.match(candidate):
            raise ValueError("unparseable email")
        return candidate

    # Bare host[:port] or IP
    host_part = text
    port: int | None = None
    if text.count(":") == 1 and not text.startswith("["):
        host_part, port_s = text.rsplit(":", 1)
        if port_s.isdigit():
            port = int(port_s)
        else:
            host_part = text
            port = None
    host_l = host_part.strip().lower().rstrip(".")
    if not host_l or " " in host_l:
        raise ValueError("unparseable host")
    try:
        host_l = str(ipaddress.ip_address(host_l))
    except ValueError:
        if not re.match(r"^[a-z0-9.*-]+$", host_l):
            raise ValueError("unparseable host")
    if port is not None and port not in _DEFAULT_PORTS:
        return f"{host_l}:{port}"
    return host_l


def _destination_declared(canonical: str, declared: set[str]) -> bool:
    if canonical in declared:
        return True
    # Wildcard: *.example.com covers foo.example.com, not example.com itself.
    # A bare parent without '*' never covers a subdomain.
    for entry in declared:
        if not entry.startswith("*."):
            continue
        suffix = entry[1:]  # .example.com
        if canonical.endswith(suffix) and canonical != entry[2:]:
            return True
    return False


def evaluate_unexpected_egress(
    tool_id: str,
    args: dict[str, Any],
    *,
    baseline_path: Path | str,
) -> tuple[bool, dict[str, Any]]:
    """Predicate. True = fires (undeclared / unparseable / fail-closed)."""
    coords: dict[str, Any] = {
        "tool_id": tool_id,
        "baseline_path": str(baseline_path),
    }
    try:
        baseline = load_baseline(baseline_path)
        entry = baseline.get(tool_id)
        if entry is None:
            # Unlisted tool with destinations is undeclared egress; without
            # destinations there is nothing to clear or deny here.
            raw_dests = extract_destinations(args)
            if not raw_dests:
                coords["reason"] = "no_destinations_observed"
                return False, coords
            coords["reason"] = "undeclared_destination"
            coords["undeclared"] = list(raw_dests)
            return True, coords

        declared_raw = entry.get("declared_destinations") or []
        if not isinstance(declared_raw, list):
            raise ValueError("declared_destinations must be a list")

        declared: set[str] = set()
        for d in declared_raw:
            declared.add(canonicalize_destination(str(d)))

        raw_dests = extract_destinations(args)
        if not raw_dests:
            coords["reason"] = "no_destinations_observed"
            return False, coords

        observed: list[str] = []
        undeclared: list[str] = []
        for raw in raw_dests:
            # A destination we cannot parse is a destination we cannot clear. Unparseable
            # egress fires. A swallowed parse error here is the fail-open hole: exfil to a
            # malformed-looking address would otherwise pass clean.
            can = canonicalize_destination(raw)
            observed.append(can)
            if not declared or not _destination_declared(can, declared):
                undeclared.append(can)

        coords["observed"] = observed
        coords["declared"] = sorted(declared)
        if undeclared:
            coords["undeclared"] = undeclared
            coords["reason"] = "undeclared_destination"
            return True, coords

        coords["reason"] = "all_destinations_declared"
        return False, coords
    except Exception as exc:
        coords["fail_closed"] = True
        coords["error"] = type(exc).__name__
        if not Path(baseline_path).is_file():
            coords["reason"] = "baseline_unreadable"
        else:
            coords["reason"] = "destination_unparseable"
        return True, coords


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_firing(atom_id: str, evaluation_id: str, coords: dict[str, Any]):
    return parse_atom_firing(
        {
            "firing_id": str(uuid4()),
            "evaluation_id": evaluation_id,
            "atom_id": atom_id,
            "detection_confidence": 1.0,
            "source_coordinates": coords,
            "detector_version": None,
            "timestamp": _now_iso(),
            "trust_domain": TrustDomain.TOOL_OUTPUT.value,
        }
    )


def evaluate_supply_chain(
    tool_name: str,
    *,
    version: str | None,
    description: str | None,
    baseline_path: Path | str | None = None,
    content_hash: str | None = None,
    evaluation_id: str = "unknown",
    args: dict[str, Any] | None = None,
    integrity_enabled: bool = True,
    egress_enabled: bool = True,
) -> tuple[list, list[ControlRollup], EffectRank]:
    """Run integrity and/or egress predicates; roll up supply-chain controls."""
    path = baseline_path if baseline_path is not None else DEFAULT_BASELINE_PATH
    firings = []
    fired_ids: set[str] = set()

    if integrity_enabled:
        fires, coords = evaluate_tool_integrity(
            tool_name,
            version=version,
            description=description,
            baseline_path=path,
            content_hash=content_hash,
        )
        if fires:
            fired_ids.add(ATOM_TOOL_INTEGRITY)
            firings.append(_make_firing(ATOM_TOOL_INTEGRITY, evaluation_id, coords))

    if egress_enabled and args is not None:
        eg_fires, eg_coords = evaluate_unexpected_egress(
            tool_name,
            args,
            baseline_path=path,
        )
        if eg_fires:
            fired_ids.add(ATOM_UNEXPECTED_EGRESS)
            firings.append(
                _make_firing(ATOM_UNEXPECTED_EGRESS, evaluation_id, eg_coords)
            )

    rollups = [
        rollup_control(ctrl, SUPPLY_CHAIN_EDGES, fired_ids)
        for ctrl in SUPPLY_CHAIN_CONTROLS
    ]
    combined = combine_control_rollups(rollups)
    return firings, rollups, combined


def denial_line(
    atom_id: str,
    control_id: str,
    framework_ids: list[str],
) -> str:
    fw = ", ".join(framework_ids)
    return f"[aegis-atoms] Blocked by {atom_id} via {control_id} (frameworks: {fw})"


def rollup_denial_message(rollups: list[ControlRollup]) -> str | None:
    ctrl_by_id = {c.control_id: c for c in SUPPLY_CHAIN_CONTROLS}
    edge_by_ctrl = {e.control_id: e for e in SUPPLY_CHAIN_EDGES}
    parts: list[str] = []
    for r in rollups:
        if r.status is RollupStatus.CONTRADICTED and r.effect is EffectRank.BLOCK:
            ctrl = ctrl_by_id[r.control_id]
            edge = edge_by_ctrl[r.control_id]
            parts.append(
                denial_line(edge.atom_id, ctrl.control_id, ctrl.framework_mappings)
            )
        elif r.status is RollupStatus.CONFLICTING:
            parts.append(
                f"[aegis-atoms] Escalated by {r.control_id}: CONFLICTING support "
                f"and contradiction (cannot auto-decide)"
            )
    if not parts:
        return None
    return " | ".join(parts)
