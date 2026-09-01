#!/usr/bin/env python3
"""PreToolUse hook -- default-deny guardrail for Falcon MCP tools.

Why default-deny on verbs, not a denylist of tool names
-------------------------------------------------------
Falcon MCP went from 24 tools to 141 in a year. Any handwritten list of
"dangerous tools" is out of date the moment the server is upgraded, and it fails
in the worst direction: a brand-new tool that contains a host or deletes a policy
would sail straight through.

So this hook inverts it. A Falcon tool is allowed only if its name begins with a
verb we know is read-only. Everything else is refused, including tools that did
not exist when this file was written. New read tools named with a normal verb
keep working; new write tools are blocked until someone opts in on purpose.

Opting in
---------
Set HARNESS_ALLOW_WRITES=true to permit write tools. That is a deliberate,
visible act -- Week 3 of the 30-day path, once you trust your playbooks. Even
then, ALWAYS_BLOCKED below stays blocked, because those operations are
destructive enough that they should be done by a human in the console.

The other job: clamping `limit`
-------------------------------
`docs/context-discipline.md` asks for `limit` 10-25. Asking is not enforcing, and
the cost of being ignored is asymmetric -- one Spotlight record with host_info and
cve facets is several KB, so a single `limit: 500` can consume the whole context
window and end the session. So this hook rewrites the parameter rather than
trusting the request, and tells the model it did.

The message matters as much as the clamp. A silently truncated result set is worse
than a large one, because the model reports the capped number as if it were the
total. `additionalContext` says the count is a floor.

Exit code is always 0; the decision is communicated via the JSON contract so the
model receives a readable explanation instead of an opaque failure.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import sys

FALCON_TOOL_PREFIX = "mcp__falcon-mcp__"

# Verbs that only ever read. A Falcon tool must carry one of these as its
# first or second name token to be allowed through in read-only mode.
READ_VERBS = frozenset(
    {
        "search",
        "get",
        "list",
        "show",
        "count",
        "check",
        "download",
        "investigate",
        "query",
        "describe",
        # Both verified read-only in falcon-mcp 0.17.0: every falcon_aggregate_*
        # tool and both falcon_preview_* tools carry readOnlyHint=True. Without
        # these, 11 legitimate read tools are refused -- including
        # falcon_aggregate_detections, which the posture brief uses to get a real
        # distribution instead of a hand tally of the first 25 rows.
        "aggregate",
        "preview",
    }
)

# Tools whose NAME reads like a query but which the server flags as a write.
# The verb allowlist trusts the name, so a name that lies needs saying out loud.
#
# falcon_search_cases is POST-based and carries readOnlyHint=False in 0.17.0.
# FALCON_MCP_READ_ONLY=true already stops it registering, but this hook is the
# independent second layer and must not rely on that.
MISLEADINGLY_NAMED_WRITES = frozenset({"search_cases"})

# The mirror image: read-only tools whose name contains an ALWAYS_BLOCKED token.
# Checked before the block list, so keep it to tools verified readOnlyHint=True.
#
# falcon_preview_quarantine_actions reports what a quarantine action *would* do
# and changes nothing. That is precisely the "describe the change instead of
# making it" behaviour the deny message below asks for, so blocking it would
# refuse the safe alternative to the thing being refused.
READ_ONLY_EXCEPTIONS = frozenset({"preview_quarantine_actions"})

# Refused even when HARNESS_ALLOW_WRITES=true. These either destroy data,
# cut hosts off the network, or run code on an endpoint -- do them in the
# console, with a human and a change ticket.
#
# Matched as whole underscore-separated tokens, never as substrings. That
# distinction matters: "contain" must not match falcon_count_kubernetes_
# CONTAINers, and "execute" must not match falcon_download_report_EXECUTion.
ALWAYS_BLOCKED_TOKENS = frozenset(
    {
        "contain",
        "containment",
        "quarantine",
        "delete",
        "remove",
        "execute",
        "kill",
        "uninstall",
        "revoke",
    }
)

# Multi-word operations, matched as phrases against the full tool name.
# Only phrases the token match above cannot catch belong here: "rtr_execute"
# and "lift_containment" are already covered by the "execute" and
# "containment" tokens.
ALWAYS_BLOCKED_PHRASES = ("run_command",)

# Ceiling on the number of records any one Falcon call may return.
#
# 0 means no clamping: the harness passes `limit` through untouched. Set
# HARNESS_MAX_LIMIT to turn the ceiling on -- 25 is what
# `docs/context-discipline.md` recommends. Note that the `crystallize` path
# exists precisely so bulk pagination happens in a script with no model
# attached, which is the reason a ceiling here is optional rather than required.
DEFAULT_MAX_LIMIT = 0


def max_limit() -> int:
    """The ceiling, or 0 to disable clamping entirely."""
    raw = os.environ.get("HARNESS_MAX_LIMIT", "").strip()
    if not raw:
        return DEFAULT_MAX_LIMIT
    try:
        return max(0, int(raw))
    except ValueError:
        # A typo must not silently remove the ceiling.
        return DEFAULT_MAX_LIMIT


def clamp(tool_input: dict) -> tuple[dict, str] | None:
    """Return (rewritten input, explanation), or None if nothing needs changing.

    Only `limit` is touched, and only downward. Every other parameter is passed
    through untouched -- `updatedInput` replaces the whole object, so anything
    dropped here would be silently dropped from the call.
    """
    ceiling = max_limit()
    if not ceiling:
        return None

    requested = tool_input.get("limit")
    # A bool is an int in Python, and `limit: true` is nonsense either way.
    if not isinstance(requested, int) or isinstance(requested, bool):
        return None
    if requested <= ceiling:
        return None

    return (
        {**tool_input, "limit": ceiling},
        f"limit clamped {requested} -> {ceiling} by the harness "
        f"(HARNESS_MAX_LIMIT). The result set is truncated, so any count you "
        f"derive from it is a FLOOR, not a total -- report it as "
        f"'{ceiling}+' and say it is capped. For a real total, run "
        f"scripts/falcon_api.py, which reads meta.pagination.total over REST.",
    )

AUDIT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    ".cache",
    "tool-audit.jsonl",
)


MAX_AUDIT_BYTES = 5 * 1024 * 1024  # 5 MB


def audit(tool: str, decision: str, reason: str) -> None:
    """Append-only local record of every governed decision.

    Deliberately records the tool name and decision but NOT the tool arguments,
    which routinely contain hostnames, user names and other tenant data.
    Rotates at 5 MB to prevent unbounded growth on active harnesses.
    """
    try:
        os.makedirs(os.path.dirname(AUDIT_PATH), exist_ok=True)
        if os.path.isfile(AUDIT_PATH) and os.path.getsize(AUDIT_PATH) > MAX_AUDIT_BYTES:
            rotated = AUDIT_PATH + ".1"
            if os.path.isfile(rotated):
                os.remove(rotated)
            os.rename(AUDIT_PATH, rotated)
        entry = {
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "tool": tool,
            "decision": decision,
            "reason": reason,
        }
        with open(AUDIT_PATH, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
    except Exception:
        pass  # Auditing must never break the session.


def decide(tool_name: str) -> tuple[str, str]:
    """Return (decision, reason). decision is 'allow' or 'deny'."""
    bare = tool_name[len(FALCON_TOOL_PREFIX):]
    # Tools are named falcon_<verb>_<subject>; strip the product prefix.
    action = (bare[len("falcon_"):] if bare.startswith("falcon_") else bare).lower()
    tokens = action.split("_")

    hit = next((phrase for phrase in ALWAYS_BLOCKED_PHRASES if phrase in action), None)
    if hit is None and action not in READ_ONLY_EXCEPTIONS:
        blocked = ALWAYS_BLOCKED_TOKENS.intersection(tokens)
        hit = sorted(blocked)[0] if blocked else None

    if hit is not None:
        return (
            "deny",
            f"'{tool_name}' performs a destructive or endpoint-altering action "
            f"(matched '{hit}'). The harness blocks these unconditionally. "
            "Do this in the Falcon console with human review, or summarise the "
            "change you would make and let the operator run it.",
        )

    # The verb is usually the first token, but some tools carry a module prefix
    # first (falcon_IDP_investigate_entity), so check the first two positions.
    if action not in MISLEADINGLY_NAMED_WRITES and any(token in READ_VERBS for token in tokens[:2]):
        return "allow", "read-only tool"

    if os.environ.get("HARNESS_ALLOW_WRITES", "").strip().lower() in ("1", "true", "yes", "on"):
        return "allow", "write tool permitted by HARNESS_ALLOW_WRITES"

    return (
        "deny",
        f"'{tool_name}' is not a recognised read-only Falcon tool, so the harness "
        "treats it as a write and refuses it by default. If you genuinely need it, "
        "set HARNESS_ALLOW_WRITES=true in your environment and explain why first. "
        "Otherwise, describe the change you would make instead of making it.",
    )


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0  # Malformed input: stay out of the way.

    tool_name = payload.get("tool_name") or ""

    # Only govern Falcon MCP tools. Everything else is someone else's business.
    if not tool_name.startswith(FALCON_TOOL_PREFIX):
        return 0

    decision, reason = decide(tool_name)
    audit(tool_name, decision, reason)

    if decision == "allow":
        clamped = clamp(payload.get("tool_input") or {})
        if clamped is None:
            # Stay silent so read-only work is not spammed with hook chatter.
            return 0
        updated_input, explanation = clamped
        audit(tool_name, "clamp", explanation)
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                        "updatedInput": updated_input,
                        "additionalContext": explanation,
                    }
                }
            )
        )
        return 0

    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        )
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        sys.exit(0)
