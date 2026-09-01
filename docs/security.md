# Security model

This harness connects a language model to your security telemetry. That deserves
a clear account of what is protected, how, and what remains your
responsibility.

The guiding idea, and the one worth taking home: **MCP is a governed access
layer, not a new security system.** It does not grant new capability. It exposes
what your API client can already do, in a form a model can use. Every control
below is about making that exposure deliberate.

## The trust boundaries

There are four, and they fail differently:

```
 ┌────────────────────────────────────────────────────────────┐
 │ 1. The model (Claude)                                       │
 │    Chooses which tools to call. NOT a security boundary.    │
 ├────────────────────────────────────────────────────────────┤
 │ 2. The harness — settings.json + PreToolUse hook            │
 │    Default-deny on writes. The model cannot disable this.   │
 ├────────────────────────────────────────────────────────────┤
 │ 3. falcon-mcp — FALCON_MCP_READ_ONLY, MODULES, TOOLS        │
 │    Write tools are never registered. Nothing to call.       │
 ├────────────────────────────────────────────────────────────┤
 │ 4. The Falcon API — your API client's scopes                │
 │    The real boundary. Everything above is convenience.      │
 └────────────────────────────────────────────────────────────┘
```

Layer 4 is the one that actually holds. **If your API client has no write scope,
nothing in layers 1–3 can write, regardless of bugs, prompt injection, or
misconfiguration.** That is why [api-scopes.md](api-scopes.md) leads with read-only
scopes rather than treating them as an option. Layers 2 and 3 exist to catch
mistakes and reduce blast radius; layer 4 exists so that a failure in the others
is survivable.

Layer 1 is explicitly *not* a boundary. Models are steerable, and content they
read — a detection description, a filename, a container label — is untrusted
input. Do not build a control whose enforcement point is the model's good
judgement.

## Layer 3: server-side restriction

Set in `.env`:

```bash
FALCON_MCP_READ_ONLY=true
FALCON_MCP_MODULES=detections,hosts,spotlight,cloud,intel
```

`FALCON_MCP_READ_ONLY=true` means write tools are **never registered**. This is
stronger than blocking them: a tool that does not exist cannot be called,
cannot be hallucinated into existence, and cannot be reached by a cleverly
phrased request. In 0.17.0 that withholds 45 of the 139 tools.

`FALCON_MCP_MODULES` is both a security and a quality control. The server ships
27 modules and 139 tools. Loading all of them widens your surface *and*
measurably degrades tool selection — every tool schema consumes context, and a
model choosing among 139 options chooses worse than one choosing among 30. Load
what your workflows use.

Get the module name right: an unknown name is a **hard startup failure**, not a
warning. The server exits and you get no Falcon tools at all, which presents as
"MCP is broken" rather than "one word is wrong". `./scripts/doctor.sh` validates
your list against the installed server.

Two finer-grained options are available when you need them:

```bash
FALCON_MCP_TOOLS=falcon_search_detections,falcon_search_hosts   # allowlist
FALCON_MCP_EXCLUDE_TOOLS=falcon_add_ioc,falcon_remove_iocs       # denylist
```

Prefer the allowlist. A denylist is only as complete as your knowledge of the
tool inventory, and that inventory grows.

## Layer 2: the PreToolUse guardrail

`.claude/hooks/guard-falcon-writes.py` runs before every `mcp__falcon-mcp__*`
call and returns allow or deny.

**It is default-deny, and that design choice is the important part.** The hook
does not maintain a list of dangerous tools to block. It maintains a list of
recognised *read verbs* to allow — `search`, `get`, `list`, `show`, `count`,
`check`, `download`, `investigate`, `query`, `describe` — and denies everything
else.

The reason is arithmetic. falcon-mcp went from 24 tools to 139 in about a year. A
handwritten denylist of dangerous tools fails in the worst possible direction:
every new tool is permitted until someone remembers to add it. An allowlist of
read verbs fails safe — a new tool called `falcon_purge_everything` is blocked on
day one, by a hook nobody updated.

On top of that, a small set of tokens is blocked **unconditionally**, even when
writes are unlocked: `contain`, `quarantine`, `delete`, `remove`, `execute`,
`kill`, `uninstall`, `revoke`, plus phrases like `run_command` and
`lift_containment`. Containing a production host or executing a command on an
endpoint is not a step in an investigation; it is an incident response decision
with a human's name attached.

Matching is on whole underscore-delimited tokens, never substrings. This is not
pedantry — an early version denied `falcon_count_kubernetes_containers` because
"contain" appears inside "containers". `scripts/test-guardrail.sh` keeps that
case as a regression test.

Verify the hook yourself rather than trusting this page:

```bash
./scripts/test-guardrail.sh
```

The hook always exits 0 and never blocks non-Falcon tools. A hook that crashes
should not take your session with it.

## Unlocking writes, if you must

```bash
HARNESS_ALLOW_WRITES=true    # in .env
```

This permits non-destructive writes — creating an IOC, adding a custom IOA rule.
Destructive tools stay blocked; that list is not configurable by design.

Before you set it, three questions:

1. **Have you read the audit log?** `.cache/tool-audit.jsonl` records every
   decision. If you cannot describe what the model has been doing for the last
   two weeks, you are not ready to let it change things.
2. **Is the write reversible?** Adding an IOC is. Deleting a rule group is not.
3. **Would you let a new team member do this unsupervised on their first day?**
   The model has comparable context about your environment and less about your
   politics.

A reasonable progression: two weeks read-only, then writes in a non-production
CID, then production writes with the audit log reviewed weekly.

## Credential handling

- `.env` is gitignored, along with `.env.*`, `*.env`, `*credentials*`, `*secret*`,
  `*.pem`, `*.key` and `.netrc`. The template is named `env.example` — no leading
  dot — precisely so the blanket `.env*` rule needs no exception.
- `chmod 600 .env`. The doctor **fails** the run if the bits are wrong, because a
  world-readable credential file on a shared machine is a finding regardless of
  how good the rest of the setup is.
- `.claude/settings.json` denies the model read access to `.env`, `.env.*`,
  anything matching `*credentials*`, and `.cache/`. The model can use the
  credentials via the MCP server; it cannot read them.
- Keep credentials outside the repo entirely with `HARNESS_ENV_FILE=/path/to/creds`
  — useful when a secret manager renders the file, or when several projects share
  one credential.
- Never paste a secret into a chat. Transcripts get logged, summarised, and
  pasted into tickets.

If a credential is ever committed: rotate it in the console **first**, then clean
history. Rewriting history on an already-pushed secret without rotating it
accomplishes nothing — it has been cloned.

## Data handling

Investigation output is sensitive in a way that is easy to underrate. Hostnames,
cluster names, cloud account IDs and CVE inventories together constitute a map of
where you are weakest — more useful to an attacker than most of what you would
classify as confidential.

- `findings/`, `out/` and `*.remediation.sh` are gitignored.
- `.cache/` is gitignored: it holds posture counts and the audit log.
- The audit log records tool names and decisions, **not tool arguments**. Arguments
  routinely contain tenant data, and an audit log is exactly the sort of file
  people paste into a ticket to prove something worked.
- Generated remediation scripts are dry-run by default and require `--apply`.

## What this harness does not protect against

Stated plainly, because a security page that only lists strengths is marketing:

- **Prompt injection.** A detection description, filename or container label is
  attacker-influenced text that enters the model's context. Layer 2 constrains
  what injected instructions can *do* — no writes, no destructive tools — but it
  cannot stop a model being misled about what it read. Treat surprising findings
  as claims to verify, not facts.
- **Data exfiltration via the conversation.** The model can read your telemetry
  and you can copy it anywhere. No technical control here changes that.
- **A model that is confidently wrong.** Its output is analysis, not truth. The
  most dangerous failure is a missing scope reported as "no findings" — which is
  why the doctor distinguishes 403 from an empty result, and why the skills
  require an explicit "not checked" section.
- **Over-broad API scopes.** If your client has write scopes, layers 2 and 3 are
  all that stand between a misfire and a change to production. Fix this at
  layer 4.
- **Third-party plugins and MCP servers.** Anything you add can register its own
  hooks, skills and tools, inside this same session. Read what you install.

## A pragmatic starting posture

For a first two weeks that is defensible in a review:

1. Read-only API scopes — the four in [api-scopes.md](api-scopes.md).
2. `FALCON_MCP_READ_ONLY=true`.
3. `FALCON_MCP_MODULES` limited to what you use.
4. `chmod 600 .env`, verified by the doctor.
5. `HARNESS_ALLOW_WRITES` unset.
6. Review `.cache/tool-audit.jsonl` at the end of week one.

That is enough to do real work, and little enough to explain to your CISO in a
paragraph.
