#!/usr/bin/env python3
"""SessionStart hook -- the security posture brief.

This is the "pull-to-push inversion" from the talk. An analyst opens a terminal
and the harness tells them what matters before they type a single query.

What it reports:
  * CrowdScore (current, plus direction of travel)
  * New critical/high detections
  * Open critical vulnerabilities
  * Stale hosts (sensor not seen recently)

Design rules this hook follows, because it runs on every single session:
  * FAIL OPEN, ALWAYS. A posture brief is a convenience. If credentials are
    missing, the API is slow, or a scope is absent, the hook prints a short note
    and exits 0. It must never be the reason a session won't start.
  * BUDGETED. Hard wall-clock budget; the whole thing is skipped if it can't
    finish in time.
  * CACHED. Results are cached briefly so opening five sessions in a row does
    not mean five rounds of API calls.
  * READ-ONLY. Uses the GET-only client in scripts/falcon_api.py.

Output goes to stdout, which Claude Code injects into the session as context.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))

# Tunables. The budget is overridable because conference/hotel wifi genuinely
# needs a longer one; the cache TTL is an internal limit, not a knob.
#
# Ceiling: the SessionStart hook in settings.json has timeout 20, and the
# budget is checked *before* each call, so the last call can still add its
# 6s client timeout on top. Above ~14 here, Claude Code kills the hook first --
# and a killed hook writes no cache, so every session pays full cost again.
# Raising the budget past that means raising the hook timeout to match.
TIME_BUDGET_SECONDS = float(os.environ.get("HARNESS_BRIEF_BUDGET", "12"))
CACHE_TTL_SECONDS = 900  # 15 min
STALE_HOST_DAYS = int(os.environ.get("HARNESS_STALE_HOST_DAYS", "14"))
DETECTION_WINDOW_HOURS = int(os.environ.get("HARNESS_DETECTION_WINDOW_HOURS", "24"))
CACHE_PATH = os.path.join(REPO_ROOT, ".cache", "posture-brief.json")

started = time.monotonic()


def out_of_budget() -> bool:
    return (time.monotonic() - started) > TIME_BUDGET_SECONDS


def iso_ago(**delta: int) -> str:
    """UTC timestamp N hours/days back, in the format Falcon FQL expects."""
    moment = dt.datetime.now(dt.timezone.utc) - dt.timedelta(**delta)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def read_cache() -> str | None:
    try:
        with open(CACHE_PATH, encoding="utf-8") as handle:
            blob = json.load(handle)
        if time.time() - blob["written_at"] < CACHE_TTL_SECONDS:
            return blob["brief"]
    except Exception:
        pass
    return None


def write_cache(brief: str) -> None:
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        tmp = CACHE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump({"written_at": time.time(), "brief": brief}, handle)
        os.replace(tmp, CACHE_PATH)
    except Exception:
        pass  # Caching is best-effort by design.


def not_checked() -> list[str]:
    """What the last doctor.sh run found this tenant cannot answer.

    The brief only knows about the four things it probes itself. doctor.sh probes
    wider, and without this its findings die with that shell -- leaving a later
    session to see a 404, mistake it for an empty result, and report a confident
    zero. Naming the gap is the whole point.
    """
    try:
        with open(os.path.join(REPO_ROOT, ".cache", "capabilities.json"),
                  encoding="utf-8") as handle:
            blob = json.load(handle)
    except Exception:
        return []  # doctor.sh has not run. Silence beats a nag.

    gaps = list(blob.get("unlicensed") or [])
    gaps += [f"{e['label']} (needs {e['scope']})" for e in blob.get("no_scope") or []]
    if not gaps:
        return []
    return [
        f"- _Not checked, per doctor.sh on {blob.get('checked_at', '?')[:10]}: "
        + "; ".join(gaps)
        + ". A question about these has no answer here -- say so rather than "
        "reporting zero._"
    ]


def collect() -> list[str]:
    """Gather the four posture signals. Returns markdown lines."""
    from falcon_api import FalconClient, load_dotenv

    # HARNESS_ENV_FILE lets you keep credentials outside the repo entirely --
    # a shared path, a mounted secret, or a file your secret manager renders.
    # Defaults to ./.env, which .gitignore already excludes.
    env_file = os.environ.get("HARNESS_ENV_FILE") or os.path.join(REPO_ROOT, ".env")
    load_dotenv(env_file)
    client = FalconClient(timeout=6.0)

    lines: list[str] = []
    unavailable: list[str] = []

    # 1. CrowdScore -------------------------------------------------------
    if not out_of_budget():
        payload = client.get(
            "/incidents/combined/crowdscores/v1",
            {"sort": "timestamp.desc", "limit": 2},
        )
        if client.denied(payload):
            unavailable.append("CrowdScore (Incidents:READ, or not licensed)")
        else:
            scores = payload.get("resources") or []
            if scores:
                current = scores[0].get("score")
                trend = ""
                if len(scores) > 1 and isinstance(scores[1].get("score"), int) and isinstance(current, int):
                    delta = current - scores[1]["score"]
                    if delta > 0:
                        trend = f" (up {delta})"
                    elif delta < 0:
                        trend = f" (down {abs(delta)})"
                lines.append(f"- **CrowdScore:** {current}{trend}")

    # 2. New critical / high detections -----------------------------------
    if not out_of_budget():
        since = iso_ago(hours=DETECTION_WINDOW_HOURS)
        alert_filter = (
            f"created_timestamp:>'{since}'+status:'new'"
            "+(severity_name:'Critical',severity_name:'High')"
        )
        payload = client.get(
            "/alerts/queries/alerts/v2",
            {"filter": alert_filter, "limit": 1},
        )
        if client.denied(payload):
            unavailable.append("detections (Alerts:READ)")
        else:
            total = client.total(payload)
            if total is not None:
                flag = " <- triage these first" if total else ""
                lines.append(
                    f"- **New critical/high detections** (last {DETECTION_WINDOW_HOURS}h): "
                    f"{total}{flag}"
                )

    # 3. Open critical vulnerabilities ------------------------------------
    if not out_of_budget():
        payload = client.get(
            "/spotlight/queries/vulnerabilities/v1",
            {"filter": "status:'open'+cve.severity:'CRITICAL'", "limit": 1},
        )
        if client.denied(payload):
            unavailable.append("vulnerabilities (Spotlight Vulnerabilities:READ)")
        else:
            total = client.total(payload)
            if total is not None:
                lines.append(f"- **Open critical vulnerabilities:** {total}")

    # 4. Stale hosts -------------------------------------------------------
    if not out_of_budget():
        cutoff = iso_ago(days=STALE_HOST_DAYS)
        payload = client.get(
            "/devices/queries/devices/v1",
            {"filter": f"last_seen:<'{cutoff}'", "limit": 1},
        )
        if client.denied(payload):
            unavailable.append("hosts (Hosts:READ)")
        else:
            total = client.total(payload)
            if total is not None:
                lines.append(
                    f"- **Stale hosts** (not seen in {STALE_HOST_DAYS}d): {total}"
                )

    if unavailable:
        lines.append("- _Skipped: " + "; ".join(unavailable) + "_")
    return lines + not_checked()


def main() -> int:
    if os.environ.get("HARNESS_BRIEF_DISABLE", "").lower() in ("1", "true", "yes"):
        return 0

    cached = read_cache()
    if cached:
        print(cached)
        return 0

    try:
        lines = collect()
    except Exception as exc:  # noqa: BLE001 -- fail open on anything at all
        # One quiet line. Never a stack trace, never a blocked session.
        print(
            "## Falcon posture brief unavailable\n"
            f"- {exc}\n"
            "- Run `./scripts/doctor.sh` to diagnose. The session is otherwise fine."
        )
        return 0

    if not lines:
        print(
            "## Falcon posture brief\n"
            "- No signals returned. Run `./scripts/doctor.sh` to check API scopes."
        )
        return 0

    stamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    brief = "\n".join(
        [
            f"## Falcon posture brief — {stamp}",
            "",
            *lines,
            "",
            "_Pushed automatically by the SessionStart hook. Ask a follow-up in plain "
            "language, or run a skill: `/trace-vm-image`, `/image-sprawl`, `/posture-brief`._",
        ]
    )
    write_cache(brief)
    print(brief)
    return 0


if __name__ == "__main__":
    # Belt and braces: even an unexpected failure in main() must exit 0.
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001
        sys.exit(0)
