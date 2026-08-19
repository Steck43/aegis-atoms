#!/usr/bin/env bash
# Install aegis-atoms plugin + enable in config.yaml (default mode: observe).
#
# Stamps source commit into PROVENANCE + plugin.yaml. Refuses dirty trees.
# Fail-closed default in _read_plugin_mode(default="enforce") is intentional and
# unchanged — this script seeds observe on a clean install so humans are told.
set -euo pipefail

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/../engine.py" && -f "$SCRIPT_DIR/../__init__.py" ]]; then
  # Script lives in aegis-atoms/scripts/
  SRC="$(cd "$SCRIPT_DIR/.." && pwd)"
  HERMES_REPO="$(cd "$SRC/../.." && pwd)"
else
  # Script lives in hermes-agent/scripts/
  HERMES_REPO="${AEGIS_REPO:-$(cd "$SCRIPT_DIR/.." && pwd)}"
  SRC="$HERMES_REPO/aegis-plugins/aegis-atoms"
fi
DEST="$HERMES_HOME/plugins/aegis-atoms"
# Prefer an explicit venv; fall back to live Hermes venv (not HERMES_HOME scratch).
PY="${HERMES_VENV:-$HOME/.hermes/hermes-agent/venv}/bin/python"
CONFIG="$HERMES_HOME/config.yaml"
VAULT="${OBSIDIAN_VAULT_PATH:-/mnt/c/Users/lande/Documents/Obsidian Vault/The_Boswell_Archive}"
SKIP_SMOKE="${AEGIS_INSTALL_SKIP_SMOKE:-0}"

# Provenance is stamped from the source plugin tree's git, not a parent monorepo tip.
GIT_ROOT="$SRC"

log() { printf '→ %s\n' "$*"; }
die() { printf '✗ %s\n' "$*" >&2; exit 1; }

[[ -d "$SRC" ]] || die "Missing plugin source: $SRC"
[[ -d "$GIT_ROOT/.git" ]] || die "Source tree has no .git — cannot stamp provenance: $GIT_ROOT"

# Refuse dirty tree before any install side effects (stamp must match code).
if [[ -n "$(git -C "$GIT_ROOT" status --porcelain)" ]]; then
  die "Refusing install from dirty tree. Commit or stash first so PROVENANCE matches the code.
$(git -C "$GIT_ROOT" status --porcelain | head -40)"
fi

[[ -x "$PY" ]] || die "Hermes venv python not found: $PY"
[[ -f "$VAULT/Agent/Policy/Aegis-Atoms-v0.yaml" ]] || die "Vault catalog missing: $VAULT/Agent/Policy/Aegis-Atoms-v0.yaml"

COMMIT="$(git -C "$GIT_ROOT" rev-parse HEAD)"
BRANCH="$(git -C "$GIT_ROOT" rev-parse --abbrev-ref HEAD)"
STAMP_TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
ASSERTER="aegis-atoms@${COMMIT}"

log "Installing aegis-atoms → $DEST"
log "Provenance: branch=$BRANCH commit=$COMMIT ts=$STAMP_TS"
rm -rf "$HERMES_HOME/plugins/boswell-atoms" 2>/dev/null || true
mkdir -p "$DEST"

cp "$SRC/plugin.yaml" "$SRC/__init__.py" "$SRC/engine.py" "$DEST/"
shopt -s nullglob
for f in "$SRC"/*.py "$SRC"/*.yaml; do
  base="$(basename "$f")"
  case "$base" in
    plugin.yaml|__init__.py|engine.py|Aegis-Atoms-v0.bundle.yaml) continue ;;
    adversarial_suite.py|cs0051_replay.py|suite_session.py) continue ;;
  esac
  case "$base" in
    harness_*.py|test_*.py) continue ;;
  esac
  cp "$f" "$DEST/"
done
shopt -u nullglob

cp "$VAULT/Agent/Policy/Aegis-Atoms-v0.yaml" "$DEST/Aegis-Atoms-v0.bundle.yaml"

cat >"$DEST/PROVENANCE" <<EOF
# aegis-atoms install provenance — do not edit by hand
commit=$COMMIT
branch=$BRANCH
installed_at_utc=$STAMP_TS
source_repo=$GIT_ROOT
asserter=$ASSERTER
EOF

"$PY" - "$DEST/plugin.yaml" "$COMMIT" "$BRANCH" "$STAMP_TS" "$ASSERTER" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
commit, branch, ts, asserter = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
raw["provenance"] = {
    "commit": commit,
    "branch": branch,
    "installed_at_utc": ts,
    "asserter": asserter,
}
path.write_text(yaml.dump(raw, default_flow_style=False, sort_keys=False), encoding="utf-8")
print("plugin.yaml provenance stamped")
PY

chmod 644 "$DEST"/* 2>/dev/null || true

log "Syntax check"
"$PY" -m py_compile "$DEST/__init__.py" "$DEST/engine.py"

VERIFY="$HERMES_REPO/scripts/verify-aegis-atoms.py"
if [[ -f "$VERIFY" ]]; then
  log "Engine verify"
  "$PY" "$VERIFY" || die "verify-aegis-atoms.py failed"
fi

log "Enable plugin in config.yaml (seeded mode: observe)"
"$PY" <<PY
from pathlib import Path
import yaml

cfg_path = Path("$CONFIG")
raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) if cfg_path.exists() else {}
plugins = raw.setdefault("plugins", {})
enabled = plugins.setdefault("enabled", [])
entries = plugins.setdefault("entries", {})

if "boswell-atoms" in enabled:
    enabled[:] = ["aegis-atoms" if x == "boswell-atoms" else x for x in enabled]
if "boswell-atoms" in entries:
    entries["aegis-atoms"] = entries.pop("boswell-atoms")
if "boswell-atoms" in enabled:
    enabled.remove("boswell-atoms")

if "aegis-atoms" not in enabled:
    enabled.append("aegis-atoms")
# Seed observe on first install only. Existing mode (including enforce left as
# a P1 finding) is preserved via setdefault.
entries.setdefault("aegis-atoms", {"mode": "observe"})
cfg_path.write_text(yaml.dump(raw, default_flow_style=False, sort_keys=False), encoding="utf-8")
mode = (entries.get("aegis-atoms") or {}).get("mode")
print(f"aegis-atoms enabled (seeded/kept mode={mode!r})")
PY

if [[ "$SKIP_SMOKE" != "1" ]]; then
  log "Smoke: observe does not PEP-block; PROVENANCE stamped"
  HERMES_HOME="$HERMES_HOME" AEGIS_REPO="$HERMES_REPO" ASSERTER_EXPECT="$ASSERTER" "$PY" <<'PY'
import os
import sys
from pathlib import Path

home = os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")
os.environ["HERMES_HOME"] = home
repo = os.environ.get("AEGIS_REPO", "")
expect = os.environ["ASSERTER_EXPECT"]
if repo:
    sys.path.insert(0, repo)

prov = Path(home) / "plugins" / "aegis-atoms" / "PROVENANCE"
if not prov.is_file():
    raise SystemExit("FAIL: PROVENANCE missing after install")
text = prov.read_text(encoding="utf-8")
commit = expect.split("@", 1)[-1]
if f"commit={commit}" not in text:
    raise SystemExit(f"FAIL: PROVENANCE missing commit={commit}, got:\n{text}")
if f"asserter={expect}" not in text:
    raise SystemExit(f"FAIL: PROVENANCE missing asserter={expect}, got:\n{text}")

from hermes_cli.plugins import discover_plugins, get_pre_tool_call_block_message

discover_plugins(force=True)
msg = get_pre_tool_call_block_message(
    "write_file",
    {"path": f"{home}/plugins/test-block.txt", "content": "x"},
    session_id="atoms-install-test-observe",
)
if msg and "aegis-atoms" in msg:
    raise SystemExit(f"FAIL: observe install must not PEP-block, got: {msg!r}")
print("PASS: no PEP block under observe; PROVENANCE stamped:", expect)
PY
fi

log "Done. Restart gateway or new session for hook registration."
