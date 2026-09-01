# Architecture

## Purpose

This harness wires Claude Code to a CrowdStrike Falcon tenant via the
falcon-mcp server, behind a default-deny write guardrail. It ships six
investigation playbooks, a session-start posture brief, and a path from
ad-hoc query to scheduled tokenless script. Its users are security operators
and SEs who want to ask their Falcon estate a question in plain language and
get a sourced, auditable answer — not a chatbot that happens to have API
access.

## Data flow

```
                                 .env (chmod 600)
                                   |
                                   v
 Operator ──> Claude Code ──> PreToolUse hook ──> falcon-mcp ──> Falcon API
   |              |          (guard-falcon-       (read-only      (layer 4:
   |              |           writes.py)           mode)        API scopes)
   |              |               |                    |
   |              |          allow / deny              |
   |              |               |                    v
   |              |               └──── if allow ──> Response
   |              |                                    |
   |              v                                    v
   |         Model reasoning  <────────────────── Tool result
   |              |
   |              v
   |         falcon_report.py ──> findings/*.html
   |              |                 (no JS, no CDN, CSP default-src 'none',
   |              |                  chmod 0600, gitignored)
   |              v
   |         Evidence table
   |         (every query: filter sent, count returned,
   |          403 vs 404 vs empty vs data)
   |
   v
 /crystallize ──> crystallized/*.py
                  (direct REST, no model, no tokens,
                   same GET-only client, schedulable)
```

### Subagent fan-out (trace-vm-image, image-sprawl)

```
 Skill dispatch
   |
   +---> falcon-asset-resolver  (MCP only, no Bash/Write/network)
   |         absorbs 139 KB CSPM records, returns one line per asset
   |
   +---> falcon-query           (MCP only, no Bash/Write/network)
   |         runs one branch of a multi-query investigation
   |
   +---> falcon-query           (same, parallel branch)
   |
   v
 Parent merges, sorts, ranks, renders
```

The agents that handle the largest tenant payloads have the smallest tool
surface. Neither can exfiltrate what it reads.

## Component map

### .claude/hooks/

| File | Hook point | Role |
|------|-----------|------|
| `guard-falcon-writes.py` | PreToolUse | Default-deny allowlist of read verbs. Unconditionally blocks destructive tokens even when writes are unlocked. Exits 0 always; never blocks non-Falcon tools. |
| `posture-brief.py` | SessionStart | Pushes critical/high detections, open critical vulns, and stale hosts into initial context. Fails open: missing creds or slow API produces a one-liner, not a blocked session. |

### .claude/agents/

| File | Tool access | Role |
|------|------------|------|
| `falcon-asset-resolver.md` | `falcon_search_cspm_assets` only | Resolves instance/image IDs across AWS/Azure/GCP. Exists because one EC2 asset record is ~139 KB; the parent context cannot hold a cohort. |
| `falcon-query.md` | ~10 read-only Falcon tools | Runs one independent branch of a playbook. Returns counts and compact tables, not raw records. |

### .claude/skills/

| Skill | What | Why it exists |
|-------|------|---------------|
| `posture-brief` | On-demand deep posture summary | The hook version is shallow and budgeted; this is the full picture. |
| `trace-vm-image` | VM vulns traced to boot image, ranked by blast radius | The question "which AMI do I fix" requires joining Spotlight vulns to CSPM assets — multi-step, multi-cloud. |
| `image-sprawl` | One container detection to every running copy of that image | Answers "how exposed are we" after a container alert. |
| `crystallize` | Finished investigation to tokenless script + dashboard | Stops paying the discovery cost twice. Once the query is settled, the model is overhead. |
| `falcon-setup` | Guided first-run setup and diagnosis | Names the fix, not just the failure. |
| `skill-template` | Write your own playbook | The skill that matters most — nobody outside your team knows your 2am questions. |

### scripts/

| File | Role |
|------|------|
| `falcon_api.py` | stdlib-only, GET-only Falcon client. Used by hooks (which cannot call MCP) and crystallized scripts. Can use a separate, narrower credential via `HARNESS_ENV_FILE`. |
| `falcon_report.py` | Renders investigation data as self-contained HTML. No JS, no external refs, CSP `default-src 'none'`. |
| `doctor.sh` | Preflight: checks tooling, file perms, read-only posture, guardrail, then authenticates and probes each scope. Distinguishes 403/404/empty. |
| `test-guardrail.sh` | Proves the hook works. Regression-tests the "containers vs contain" substring bug. |
| `test-crystallized.py` | Offline: exercises the crystallized script with stub data, no credentials. |
| `test-render-parity.sh` | Byte-for-byte diff of rendered HTML against committed golden file. CSS edits become reviewable diffs. |
| `test-provenance.py` | Asserts every query is recorded in the evidence table, filters cannot drift, and 403 is never reported as "0 results". |
| `test-agents.py` | Validates subagent definitions: tool references match the server build, tool allowlists hold. Born from a bug where a skill called a tool the server did not expose. |

### crystallized/

| File | Role |
|------|------|
| `critical-vulns-by-image.py` | Direct REST script: critical vulns grouped by source image, ranked by blast radius. Uses the same GET-only client. No model, no tokens, schedulable via cron. |

### docs/

| File | Covers |
|------|--------|
| `security.md` | Trust boundaries, unlocking writes, credential handling, what is NOT protected |
| `api-scopes.md` | Module-to-scope mapping, read-only as default |
| `context-discipline.md` | Token arithmetic, payload traps, how investigations die |
| `parallelism.md` | Subagent dispatch, the dispatch ledger, honest merge discipline |
| `troubleshooting.md` | Real failures and their fixes |

## Trust boundaries

Four layers, one real boundary:

```
Layer   What                         Enforcement           Failure mode
-----   ----                         -----------           ------------
  1     Model                        None                  Steerable by input
  2     Harness (PreToolUse hook)    Verb allowlist +      New tool? Blocked
                                     destructive denylist   until allowlisted
  3     falcon-mcp server            READ_ONLY=true:       Write tools never
                                     writes never           registered — cannot
                                     registered             be called at all
  4     Falcon API scopes            Server-side           The real boundary:
                                                            survives bugs in
                                                            layers 1–3
```

**Layer 4 is the one that actually holds.** If the API client has no write
scope, nothing above can write regardless of prompt injection, model
steering, hook bugs, or server misconfiguration.

Layer 1 is explicitly not a boundary. Detection descriptions, filenames, and
container labels are attacker-influenced text entering the model's context.

Enforcement details:

- **Hook verb allowlist**: `search`, `get`, `list`, `show`, `count`, `check`,
  `download`, `investigate`, `query`, `describe`. Matches whole
  underscore-delimited tokens, not substrings (the "containers" lesson).
- **Unconditional denylist**: `contain`, `quarantine`, `delete`, `remove`,
  `execute`, `kill`, `uninstall`, `revoke`, `run_command`,
  `lift_containment`. Not configurable by design.
- **MCP read-only mode**: `FALCON_MCP_READ_ONLY=true` — 45 of 139 tools
  withheld at registration time.
- **Module restriction**: `FALCON_MCP_MODULES` limits to 5 of 27 modules —
  security AND quality (139 tool schemas degrade tool selection).
- **Credential isolation**: `.env` denied to model via settings.json;
  `chmod 600` enforced by doctor; hooks can use a separate narrower
  credential via `HARNESS_ENV_FILE`.
- **Output isolation**: `findings/` gitignored, written `0600`. Dashboards
  make no network requests.

## The crystallize escape hatch

MCP is the right interface for discovery: the model chooses tools, navigates
the data model, correlates across domains. But once an investigation is
settled — the query is known, the join is known, the ranking is known — the
model is pure overhead: tokens, latency, non-determinism.

`/crystallize` captures a finished investigation as a standalone Python
script that calls the Falcon REST API directly. The script:

- Uses `scripts/falcon_api.py` (stdlib `urllib`, GET-only, no dependencies)
- Runs with no model, no MCP server, no tokens
- Produces the same HTML dashboard via `scripts/falcon_report.py`
- Is safe to schedule via cron or CI
- Cannot write even with a broader credential (client is GET-only)
- Carries the same evidence table (every query, every filter, every status)

The trigger: you have run the same investigation three times and the queries
have not changed. At that point the model's contribution is choosing the
same tools it chose last time. Crystallize it, schedule it, move on.

## Key design decisions

### Three-way status classification

Every API probe returns one of three statuses, and confusing them is the
most dangerous thing this harness can do:

| Status | Meaning | Misread as |
|--------|---------|------------|
| **403** | Missing API scope — never asked | "0 results" — false assurance |
| **404** | Not licensed — capability absent | "0 results" — false assurance |
| **Empty result** | Asked and answered: genuinely zero | Correct |

The doctor, the hooks, the skills, and the evidence tables all preserve this
distinction. A 403 reported as "no findings" is how a security tool lies to
you.

### The four kinds of nothing

Dashboards carry an evidence table that records every query. Each row is one
of:

1. **Data returned** — the query worked and produced results
2. **Empty result** — the query worked, zero matches (a real answer)
3. **403 Forbidden** — scope not granted (NOT zero matches)
4. **Not checked** — the query was never made

A finding section that shows "0 critical vulnerabilities" must trace to a row
in the evidence table showing an actual query with an actual empty response.
If the row is absent or shows 403, the finding is false.
`test-provenance.py` enforces this.

### Default-deny verb allowlist

A denylist of dangerous tools fails in the worst direction: every new tool is
permitted until someone adds it. The tool inventory went from 24 to 139 in a
year. The allowlist of read verbs fails safe: `falcon_purge_everything` is
blocked on day one by a hook nobody updated.

### Evidence/provenance ledger

Every dashboard ends with receipts: one row per query actually made, the
exact FQL filter, the count returned, and the status. This is not logging —
it is the mechanism that lets someone verify a finding weeks later instead of
taking it on trust. The provenance test suite asserts that no query goes
unrecorded and that filters cannot silently drift from what was sent.
