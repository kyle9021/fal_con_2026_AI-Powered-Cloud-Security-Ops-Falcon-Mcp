#!/usr/bin/env bash
# Preflight check for the Falcon MCP harness.
#
# Answers, in order: is my tooling present, are my secrets stored safely, can I
# authenticate, and which API scopes am I actually missing? Every failure prints
# the specific next action rather than a generic error.
#
#   ./scripts/doctor.sh

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

problems=0
warnings=0

ok()   { printf '  [ ok ]  %s\n' "$1"; }
bad()  { printf '  [FAIL]  %s\n' "$1"; problems=$((problems + 1)); }
warn() { printf '  [warn]  %s\n' "$1"; warnings=$((warnings + 1)); }
note() { printf '          %s\n' "$1"; }

echo
echo "Falcon MCP harness -- preflight"
echo "==============================="
echo

# --- 1. Tooling -------------------------------------------------------------
echo "Tooling"
if command -v python3 >/dev/null 2>&1; then
  ok "python3 $(python3 -c 'import platform;print(platform.python_version())')"
else
  bad "python3 not found -- required by the hooks."
fi

if command -v uvx >/dev/null 2>&1; then
  ok "uvx present ($(uvx --version 2>/dev/null | head -1))"
elif command -v uv >/dev/null 2>&1; then
  warn "uv present but uvx not on PATH."
  note "Try: uv tool install falcon-mcp"
else
  bad "uv/uvx not found -- .mcp.json launches falcon-mcp with uvx."
  note "Install: curl -LsSf https://astral.sh/uv/install.sh | sh"
fi
echo

# --- 2. Credential hygiene --------------------------------------------------
# Checked before authentication on purpose: a working credential stored badly
# is still a finding.
echo "Credential hygiene"
ENV_FILE="${HARNESS_ENV_FILE:-.env}"

if [ ! -f "$ENV_FILE" ]; then
  bad "$ENV_FILE does not exist."
  note "Run: cp env.example .env && chmod 600 .env"
else
  ok "$ENV_FILE exists"

  perms=$(stat -f '%A' "$ENV_FILE" 2>/dev/null || stat -c '%a' "$ENV_FILE" 2>/dev/null)
  if [ "$perms" = "600" ] || [ "$perms" = "400" ]; then
    ok "permissions $perms (owner-only)"
  else
    bad "permissions are $perms -- other users on this machine can read your keys."
    note "Fix: chmod 600 $ENV_FILE"
  fi

  if grep -qE '^FALCON_CLIENT_SECRET=(your-client-secret)?$' "$ENV_FILE" 2>/dev/null; then
    bad "FALCON_CLIENT_SECRET is still the placeholder."
  fi

  # Read-only posture. Absent means the falcon-mcp default (false), which is
  # not what this harness recommends, so treat silence as a warning.
  if grep -qE '^FALCON_MCP_READ_ONLY=true' "$ENV_FILE" 2>/dev/null; then
    ok "FALCON_MCP_READ_ONLY=true (write tools never registered)"
  else
    warn "FALCON_MCP_READ_ONLY is not set to true."
    note "The server will expose write tools. The PreToolUse hook still blocks"
    note "them, but defence in depth means setting both."
  fi

  if grep -qE '^FALCON_MCP_MODULES=' "$ENV_FILE" 2>/dev/null; then
    mods=$(grep -E '^FALCON_MCP_MODULES=' "$ENV_FILE" | sed 's/^[^=]*=//' | tr -d "'\"")
    count=$(printf '%s' "$mods" | tr ',' '\n' | grep -c .)
    # An unknown module name is a hard startup failure, not a warning: the
    # server exits and you get no Falcon tools at all. Ask the installed
    # server what it accepts rather than hardcoding a list that will rot.
    valid=$(uvx falcon-mcp --modules __probe__ 2>&1 | sed -n 's/.*Available modules: //p' | tr -d ' ')
    if [ -n "$valid" ]; then
      unknown=""
      for m in $(printf '%s' "$mods" | tr ',' ' '); do
        printf '%s' ",$valid," | grep -q ",$m," || unknown="$unknown $m"
      done
      if [ -n "$unknown" ]; then
        bad "FALCON_MCP_MODULES names unknown module(s):$unknown"
        note "falcon-mcp REFUSES TO START on an unknown module name, so the"
        note "server would load zero tools. Valid names:"
        note "  $valid"
      else
        ok "module surface limited to $count module(s), all valid"
      fi
    else
      ok "module surface limited to $count module(s) (could not verify names)"
    fi
  else
    warn "FALCON_MCP_MODULES not set -- all 27 modules and 139 tools will load."
    note "This degrades tool selection and widens the surface unnecessarily."
  fi
fi

# Secrets must never be tracked by git.
if [ -d .git ]; then
  if git ls-files --error-unmatch .env >/dev/null 2>&1; then
    bad ".env IS TRACKED BY GIT. Treat those credentials as compromised."
    note "Rotate the API client in the Falcon console, then:"
    note "  git rm --cached .env"
  else
    ok ".env is not tracked by git"
  fi
fi
echo

# --- 3. Guardrail -----------------------------------------------------------
echo "Write guardrail"
if [ -x scripts/test-guardrail.sh ]; then
  if ./scripts/test-guardrail.sh >/dev/null 2>&1; then
    ok "guardrail tests pass"
  else
    bad "guardrail tests FAIL -- run ./scripts/test-guardrail.sh to see which."
  fi
else
  warn "scripts/test-guardrail.sh missing or not executable."
fi
echo

# --- 4. Falcon API reachability and scopes ----------------------------------
echo "Falcon API"
if [ ! -f "$ENV_FILE" ]; then
  warn "skipped -- no credentials file."
else
  python3 - "$ENV_FILE" <<'PYCHECK'
import sys, os, json, datetime as dt
sys.path.insert(0, "scripts")
from falcon_api import FalconClient, FalconError, load_dotenv

load_dotenv(sys.argv[1])
try:
    client = FalconClient(timeout=10.0)
except FalconError as exc:
    print(f"  [FAIL]  {exc}")
    sys.exit(1)

region = client.base_url
try:
    client.token
except FalconError as exc:
    print(f"  [FAIL]  {exc}")
    print("          Most common causes, in order:")
    print("            1. FALCON_BASE_URL is the wrong region for this tenant.")
    print("            2. The API client was revoked or the secret is stale.")
    print("            3. The key was created in a different CID.")
    sys.exit(1)

print(f"  [ ok ]  authenticated against {region}")

# Probe each capability the harness uses. A 403 means a missing scope; a 404
# usually means the feature is not licensed on this tenant. Both are survivable
# and worth telling the operator apart.
probes = [
    ("Alerts:READ",            "detections",      "/alerts/queries/alerts/v2",                    {"limit": 1}),
    ("Hosts:READ",             "hosts",           "/devices/queries/devices/v1",                  {"limit": 1}),
    ("Vulnerabilities:READ",   "Spotlight",       "/spotlight/queries/vulnerabilities/v1",        {"limit": 1, "filter": "status:'open'"}),
    ("Incidents:READ",         "incidents",       "/incidents/queries/incidents/v1",              {"limit": 1}),
    ("Falcon Container:READ",  "container images","/container-security/combined/vulnerabilities/v1", {"limit": 1}),
]
# The container probe must hit the path the MCP tools actually use
# (ReadCombinedVulnerabilities, per falconpy) — /queries/containers/v1 404s on
# tenants where image assessment works fine, and this footer gets copied verbatim
# into briefs, so a false negative here becomes a false statement there.

missing, unlicensed = [], []
for scope, label, path, params in probes:
    payload = client.get(path, params)
    status = payload.get("_status")
    if status in (401, 403):
        missing.append((scope, label))
        print(f"  [warn]  {label}: no access (needs {scope})")
    elif status == 404:
        unlicensed.append(label)
        print(f"  [warn]  {label}: not available on this tenant (HTTP 404)")
    elif status:
        print(f"  [warn]  {label}: HTTP {status}")
    else:
        total = client.total(payload)
        detail = f"{total} record(s) visible" if total is not None else "reachable"
        print(f"  [ ok ]  {label}: {detail}")

if missing:
    print()
    print("          Add these READ scopes to your API client, then re-run:")
    for scope, label in missing:
        print(f"            - {scope}  (for {label})")
if unlicensed:
    print()
    print("          Not licensed/enabled here, so the posture brief will skip them:")
    for label in unlicensed:
        print(f"            - {label}")

# Persist what this run discovered, so the finding outlives the shell.
#
# Without this the knowledge dies here, and the next session's model sees a 404,
# has no way to tell it from an empty result, and reports a confident zero. That
# is the single worst artifact this harness can produce: authoritative, wrong,
# and indistinguishable from good news. The SessionStart hook reads this file
# and lists these under "Not checked".
try:
    # cwd is the repo root: doctor.sh cds there before running anything.
    # __file__ does not exist in a stdin heredoc, so do not reach for it.
    cache = os.path.join(os.getcwd(), ".cache")
    os.makedirs(cache, exist_ok=True)
    with open(os.path.join(cache, "capabilities.json"), "w", encoding="utf-8") as handle:
        json.dump({
            "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "base_url": region,
            "unlicensed": unlicensed,
            "no_scope": [{"scope": s, "label": l} for s, l in missing],
        }, handle, indent=2)
        handle.write("\n")
except Exception:
    pass  # A cache write must never fail the preflight.
PYCHECK
  rc=$?
  [ "$rc" -ne 0 ] && problems=$((problems + 1))
fi
echo

# --- Verdict ----------------------------------------------------------------
echo "==============================="
if [ "$problems" -eq 0 ] && [ "$warnings" -eq 0 ]; then
  echo "Ready. Start Claude Code in this directory and ask your first question."
elif [ "$problems" -eq 0 ]; then
  echo "Usable, with $warnings warning(s) above. Nothing blocking."
else
  echo "$problems problem(s) and $warnings warning(s). Fix the [FAIL] lines first."
  exit 1
fi
echo
