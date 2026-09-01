# Falcon MCP Harness

A ready-to-run Claude Code workspace for CrowdStrike Falcon, built for the
Fal.Con session *AI-Powered Cloud Security Operations: Connecting the Falcon MCP
Server to Real-World Workflows*.

Clone it, add read-only API credentials, and ask your security estate a question
in plain language. **About ten minutes to a useful answer.**

It ships secure by default: read-only scopes, a default-deny write guardrail, and
a preflight check that refuses to pass if your credential file is
world-readable.

---

## Quick start

```bash
git clone <this-repo> falcon-mcp-harness
cd falcon-mcp-harness

cp env.example .env
chmod 600 .env
# edit .env: client ID, secret, and your region's base URL

./scripts/doctor.sh
```

Create the API client in the Falcon console under **Support and resources → API
clients and keys**, with four READ scopes: **Alerts, Hosts, Vulnerabilities,
Incidents**.

When the doctor is green, start Claude Code in this directory. A posture brief
appears before you type anything. Then try:

> How many hosts have not reported in over 14 days?

Pick a question you already know the roughly-right answer to. A surprise means
either the harness is misconfigured or you have just learned something true about
your estate — both worth knowing before you trust it with a real investigation.

**Requirements:** [Claude Code](https://claude.com/claude-code),
[uv](https://docs.astral.sh/uv/), Python 3.9+, and a Falcon API client.

---

## What you get

### Six playbooks

| Command | What it does |
|---|---|
| `/falcon-setup` | Guided setup and diagnosis |
| `/posture-brief` | Deep on-demand posture summary with next actions |
| `/trace-vm-image` | Traces AWS/Azure/GCP VM vulnerabilities back to the image they booted from, ranks by blast radius |
| `/image-sprawl` | From one container detection to every place that image runs |
| `/crystallize` | Turns a finished investigation into a tokenless API script + dashboard |
| `/skill-template` | Helps you write playbooks for your own recurring investigations |

The first four are useful on day one. `/crystallize` is what stops you paying the
discovery cost twice: once an investigation is settled, it becomes a plain script
that runs for free on a schedule. **And the last is the one that matters** —
nobody outside your team knows which questions you ask at 2am.

The two investigation playbooks render their results as a self-contained HTML
dashboard in `findings/` — no JavaScript, no CDN, no outbound request when opened,
which is what makes it safe to put on a projector.

Every dashboard ends with its own receipts: one row per query actually made, the
exact filter, and what came back — **including the queries that returned nothing
and the ones that were denied**. That last part is the whole point. An empty result
is what separates *no findings* from *never asked*, and a missing scope reported as
"0 results" is how a security tool produces false assurance. Where a conclusion
rests on reading one field out of one record, the dashboard quotes that record
verbatim rather than asserting what it said.

### A posture brief before you ask

`.claude/hooks/posture-brief.py` runs at session start and pushes the current
picture into context: CrowdScore and its direction, new critical and high
detections, the open critical vulnerability count, and hosts that have stopped
reporting.

It is deliberately shallow and strictly budgeted. It fails open — no credentials,
a missing scope, or a slow link produces a one-line note, never a blocked
session.

### A guardrail that fails safe

`.claude/hooks/guard-falcon-writes.py` runs before every Falcon tool call and is
**default-deny**.

It does not maintain a list of dangerous tools to block. It maintains a list of
recognised read verbs to allow, and denies everything else. The reason is
arithmetic: falcon-mcp went from 24 tools to 139 in about a year. A denylist fails
in the worst direction — every new tool permitted until someone remembers it. An
allowlist fails safe: a hypothetical `falcon_purge_everything` is blocked on day
one by a hook nobody updated.

Destructive operations — containment, quarantine, delete, command execution — stay
blocked even when writes are unlocked. Verify it yourself rather than taking this
paragraph's word for it:

```bash
./scripts/test-guardrail.sh
```

### A preflight that names the fix

`./scripts/doctor.sh` checks tooling, credential file permissions, the read-only
posture, the guardrail, and then authenticates and probes each capability. Every
failure prints the specific next action.

Critically, it distinguishes **403 (missing scope)** from **404 (not licensed)**
from **an empty result set (a correct answer)**. Confusing the first for the third
— reporting "no critical vulnerabilities" when the truth is "no Spotlight scope" —
is the most dangerous thing a harness like this can do.

---

## Security posture

Full detail in [docs/security.md](docs/security.md). The essentials:

**Four boundaries, and only one of them really holds.**

```
1. The model            — chooses tools. NOT a security boundary.
2. This harness         — default-deny hook. The model cannot disable it.
3. falcon-mcp           — FALCON_MCP_READ_ONLY: write tools never registered.
4. Your API scopes      — the real boundary. Everything above is convenience.
```

If your API client has no write scope, nothing above can write — regardless of
bugs, prompt injection, or misconfiguration. That is why
[docs/api-scopes.md](docs/api-scopes.md) treats read-only as the default rather
than an option.

Layer 1 is explicitly not a boundary. Content the model reads — a detection
description, a filename, a container label — is untrusted input. Never build a
control whose enforcement point is the model's good judgement.

**Defaults shipped:**

- `FALCON_MCP_READ_ONLY=true`
- `FALCON_MCP_MODULES` limited to five of 27 modules (security *and* quality — 139
  tool schemas crowd the context and measurably degrade tool selection)
- `.env` gitignored, `chmod 600` enforced by the doctor, unreadable by the model
- Investigation output in `findings/`, gitignored and written mode `0600` —
  hostnames, cluster names, account IDs and CVE inventories together are a map of
  where you are weakest
- Generated dashboards have no JavaScript, no external references and a
  `default-src 'none'` CSP; opening one makes no network request
- Crystallized scripts in `crystallized/` use the same GET-only client, so they
  cannot write even if you run them with a broader credential

**What it does not protect against**, stated plainly: prompt injection via
telemetry content, exfiltration through the conversation, a model that is
confidently wrong, over-broad API scopes you granted anyway, and third-party
plugins that register their own hooks and tools in this same session.

---

## The thing that will actually break your first investigation

Not authentication. Context exhaustion.

A single Falcon host record is ~8 KB of JSON. Twenty crowd out the model's
reasoning; two hundred end the session. And it does not announce itself — the
model quietly loses earlier findings and gets vaguer, usually right when the
correlation was about to pay off.

Filter server-side. Use facets instead of per-record follow-ups. Narrow the scope
rather than paginating. Counts are the awkward case: the MCP server strips
`meta.pagination.total`, so get a count outside the context window or report a
sampled number as a floor.

[docs/context-discipline.md](docs/context-discipline.md) has the arithmetic and
the known payload traps.

### Fanning out to subagents

Three playbooks run their independent steps concurrently in subagents. For
`/trace-vm-image` this is not only a speed win: one EC2 instance asset record is about
139 KB, so resolving a whole cohort in one context is impossible, and the playbook
used to cap its shortlist at 10–20 instances for that reason alone. A subagent
absorbs the payload and returns one line per instance, so the cap comes off.

Two narrow agents live in `.claude/agents/`. Neither has Bash, Write or any
network tool — the component handling the most raw tenant data cannot put it
anywhere. The write guardrail hook applies to their calls too.

[docs/parallelism.md](docs/parallelism.md) has the discipline that keeps a parallel
run honest: the dispatch ledger, why a subagent that failed is not a zero, and why
merged results must be sorted before they are ranked.

---

## Repository layout

```
.claude/
  settings.json              hook wiring + permission allow/deny
  agents/
    falcon-asset-resolver.md absorbs the 139 KB CSPM asset records
    falcon-query.md          runs one branch of a multi-query playbook
  hooks/
    posture-brief.py         SessionStart: push posture into context
    guard-falcon-writes.py   PreToolUse: default-deny write guardrail
  skills/                    the six playbooks
scripts/
  doctor.sh                  preflight and diagnosis
  test-guardrail.sh          proves the guardrail works
  test-crystallized.py       offline self-test, no credentials needed
  test-render-parity.sh      offline self-test: the renderer vs the golden HTML
  test-provenance.py         offline self-test: every number is traceable
  test-agents.py             offline self-test: subagent definitions and dispatches
  falcon_api.py              stdlib-only read-only client used by the hooks
  falcon_report.py           renders findings as a self-contained HTML dashboard
crystallized/                generated tokenless scripts (tracked: logic, not data)
tests/
  fixtures/report.json       hostile payloads for the renderer
  golden/report.html         the byte-for-byte rendering contract
findings/                    dashboards and investigation output (gitignored)
docs/
  security.md                trust boundaries, unlocking writes
  api-scopes.md              module → scope mapping
  context-discipline.md      keeping long investigations alive
  parallelism.md             subagent fan-out, and how it stays honest
  troubleshooting.md         real failures and their fixes
.mcp.json                    falcon-mcp server definition
env.example                  credential template (copy to .env)
WORKSHOP.md                  the full handout: demos, queries, 30-day path
```

`scripts/falcon_api.py` exists because hooks are shell and Python — they cannot
call MCP tools. It is GET-only and needs just four read scopes, so you can point
it at a separate, even more restricted credential with `HARNESS_ENV_FILE`.

`crystallized/` is where investigations go to become permanent. Those scripts use
the same GET-only client and no model at all — see [the crystallize
skill](.claude/skills/crystallize/SKILL.md). You can verify the whole rendering and
ranking path before you have credentials:

```bash
python3 scripts/test-crystallized.py
./scripts/test-render-parity.sh
python3 scripts/test-provenance.py
python3 scripts/test-agents.py
```

`test-render-parity.sh` feeds one committed fixture to the renderer and diffs the
output against a committed golden HTML file byte-for-byte, including the CSS. A
deliberate CSS edit therefore arrives as a reviewable HTML diff rather than passing
silently.

`test-provenance.py` is the less obvious one. Every dashboard this harness
produces carries an evidence table: one row per query actually made, including the
ones that returned nothing and the ones that were denied. That table is what lets
someone check a finding weeks later instead of taking it on trust — so it is
tested like a feature. `test-provenance.py` drives the crystallized script with a
stub client and asserts that no query goes unrecorded, that a recorded filter
cannot drift from the one that was sent, and that a `403` is never reported as
"0 results".

`test-agents.py` exists because of a bug that shipped: a skill instructed a call to
a Falcon tool this server build does not expose, which fails halfway through a live
demo and looks like a Falcon problem rather than a typo. It now also holds the
subagents to their tool allowlists, so nobody can quietly grant `Bash` to the agent
that reads the largest tenant payloads.

---

## Working through it

[WORKSHOP.md](WORKSHOP.md) is the full handout — both demos step by step, ten
starter questions, and the 30-day path:

- **Week 1 Connect** — read-only, daily use, then read the audit log
- **Week 2 Automate** — tune the brief until it tells you something new
- **Week 3 Codify** — turn your own recurring investigation into a skill
- **Week 4 Scale** — add modules deliberately, share skills, only then consider
  writes

---

## Notes and caveats

**Demo 1 works entirely inside Falcon.** CSPM asset records carry the
instance-to-image edge natively: on an `AWS::EC2::Instance` asset, the
`relationships[]` array contains an `AWS::EC2::Image` entry whose `resource_id`
is the AMI. No AWS CLI needed — the CLI is optional enrichment for image *names*
and creation dates.

**But that record is ~139 KB** (see `docs/context-discipline.md`), so the
crystallized script pre-fetches all instances once and builds an index locally
rather than querying per-instance. If your tenant has AWS Inspector enabled,
the `AWS::Inspector::Coverage` record for the same instance
also carries `amiId` at ~2.5 KB — fifty times cheaper for the same answer.

**Always pin `resource_type` when filtering CSPM assets.** Several asset types
share one `resource_id`, so filtering on an instance ID alone can silently return
a different kind of record than you meant.

**`configuration` on a CSPM asset is a JSON string, not an object.** It has to be
parsed before you can read `imageId` out of it.

**Demo 2 must be parameterised.** The image from the session demo will not exist
in your tenant. Give the playbook an image you actually run.

**One upstream defect to know:** `falcon_count_kubernetes_containers` returns a
payload its own schema rejects. Use `falcon_search_kubernetes_containers` and
count. Noted in the skill so you do not lose an hour to it.

**Tool descriptions sometimes carry wrong field names.** The Kubernetes containers
tool shows `cloud:'AWS'`; the correct field is `cloud_name`. Trust the
`falcon://.../fql-guide` resources over tool descriptions.

---

## Contributing

New skills are the most useful contribution — particularly investigations
specific to a sector or cloud posture. Use `/skill-template`, and please include
what the skill does *not* do and which decisions stay with a human.

Never include real tenant data in a contribution: no hostnames, cloud account
IDs, cluster names, CIDs or CVE inventories. Sanitised examples only.

---

## Licence and status

MIT — see [LICENSE](LICENSE).

Community workshop material, not a CrowdStrike or Anthropic product. Not
officially supported by either. The upstream MCP server is
[CrowdStrike/falcon-mcp](https://github.com/CrowdStrike/falcon-mcp); issues with
the server itself belong there.

Verified against a live Falcon tenant. Your tenant's licensed capabilities will
differ — `./scripts/doctor.sh` tells you which.
