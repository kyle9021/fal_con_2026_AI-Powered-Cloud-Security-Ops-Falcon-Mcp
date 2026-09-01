#!/usr/bin/env python3
"""PostToolUse hook -- prompt-injection detection for Falcon MCP results.

Scans tool_result for injection patterns (directives, URI injection, encoded
payloads). Alerts operator via stderr and logs to .cache/injection-audit.jsonl.
Never blocks. Fail-open on any exception. Never logs full payloads or tenant data.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import os
import re
import sys

FALCON_TOOL_PREFIX = "mcp__falcon-mcp__"

DIRECTIVE_PATTERNS = re.compile(
    r"(?:ignore\s+previous|disregard|new\s+instructions|system\s+prompt|you\s+are\s+now)",
    re.IGNORECASE,
)
URI_PATTERN = re.compile(r"https?://[^\s\"']{10,}", re.IGNORECASE)
B64_PATTERN = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")

AUDIT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    ".cache",
    "injection-audit.jsonl",
)
MAX_AUDIT_BYTES = 5 * 1024 * 1024  # 5 MB


def audit(tool: str, pattern: str, snippet: str) -> None:
    """Append one finding. Snippet truncated to 100 chars, never full payload."""
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
            "pattern": pattern,
            "snippet": snippet[:100],
        }
        with open(AUDIT_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception:
        pass  # Auditing must never break the session.


def is_real_base64(text: str) -> bool:
    """True only if the blob decodes to non-ASCII bytes (not just a long ID)."""
    try:
        return not base64.b64decode(text, validate=True).isascii()
    except Exception:
        return False


def scan(tool_result: str) -> list[tuple[str, str]]:
    """Return (pattern_name, matched_text) for every hit."""
    findings: list[tuple[str, str]] = []
    for m in DIRECTIVE_PATTERNS.finditer(tool_result):
        findings.append(("directive", m.group()))
    for m in URI_PATTERN.finditer(tool_result):
        findings.append(("uri_injection", m.group()))
    for m in B64_PATTERN.finditer(tool_result):
        if is_real_base64(m.group()):
            findings.append(("encoded_payload", m.group()[:60] + "..."))
    return findings


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0  # Malformed input: stay out of the way.

    tool_name = payload.get("tool_name") or ""
    if not tool_name.startswith(FALCON_TOOL_PREFIX):
        return 0

    tool_result = payload.get("tool_result")
    if not isinstance(tool_result, str) or not tool_result:
        return 0

    findings = scan(tool_result)
    if not findings:
        return 0

    for pattern, matched in findings:
        audit(tool_name, pattern, matched)

    summary = ", ".join(f"{p}({s[:40]})" for p, s in findings[:5])
    print(
        f"[injection-detect] {len(findings)} suspicious pattern(s) in "
        f"{tool_name}: {summary}",
        file=sys.stderr,
    )
    # Alert, don't block -- hiding the finding from the operator is worse.
    print(json.dumps({"decision": "allow"}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        sys.exit(0)  # Fail open.
