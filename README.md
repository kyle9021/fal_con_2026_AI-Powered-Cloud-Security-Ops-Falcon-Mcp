# Falcon MCP Harness

> **Let AI reason. Make the system prove.**

A ready-to-run workspace for exploring a simple idea:

**Use AI where probabilistic reasoning creates value. Use deterministic systems where evidence, authorization, repeatability, and accountability matter.**

Built around the CrowdStrike Falcon MCP server for the Fal.Con session **AI-Powered Cloud Security Operations: Connecting the Falcon MCP Server to Real-World Workflows**.

Clone it, add read-only API credentials, and ask your security estate a question in plain language.

About ten minutes to a useful answer.

---

## The idea

AI is remarkably useful when a problem is difficult to express deterministically.

Ask:

> Which vulnerable VM images create the most downstream exposure across my cloud estate?

An agent can explore the problem, choose tools, correlate data, refine queries, and discover an investigation that would have been expensive to encode beforehand.

That's valuable.

But once we've figured out how to answer the question reliably, why ask a probabilistic system to rediscover the procedure every time?

**Crystallize it.**

Turn what was learned into deterministic automation with explicit inputs, repeatable queries, testable behavior, evidence, provenance, and an audit trail.

The pattern this repository explores is:

```text
Explore → Prove → Crystallize → Automate → Audit → Escalate → Learn
```

AI handles ambiguity and discovery.

Deterministic systems handle what can be explicitly enforced and verified.

Human expertise handles the places where the system encounters uncertainty, exceptions, consequential judgment, or something we haven't encoded yet.

Then what we learn can become part of the system.

---

## Design principles

### 1. The model is not a security boundary

The model can reason about which tools to use.

It does not decide what it is authorized to do.

This harness uses four layers:

```text
1. Model             chooses tools                 NOT a security boundary
2. Harness           default-deny write guardrail
3. Falcon MCP        write tools can be unregistered
4. API scopes        authoritative permission boundary
```

Only the last boundary really holds.

If the API client has no write scope, nothing above it can write—regardless of prompt injection, model behavior, bugs, or configuration mistakes elsewhere in the stack.

Content read by the model is also untrusted input.

A detection description, filename, container label, hostname, or other piece of telemetry can influence model behavior. It should never gain authority merely because an LLM read it.

> **Never build a control whose enforcement point is the model's good judgment.**

---

### 2. An answer is not evidence

A model saying something is true does not establish that it is true.

Every generated dashboard therefore carries its own receipts:

- every query actually executed
- the exact filter sent
- the result returned
- queries that returned nothing
- queries that were denied
- source records supporting conclusions derived from individual fields

This distinction matters:

```text
0 findings        ≠ failed to query
403 Forbidden     ≠ 0 findings
Not licensed      ≠ no exposure
Model conclusion  ≠ evidence
```

A security system that turns **"I couldn't look"** into **"nothing is wrong"** creates false assurance.

If the system cannot establish what it observed, it should not pretend to know.

---

### 3. Provenance is part of the result

Security conclusions should remain inspectable after the agent session is gone.

The useful questions are not only:

> What did the agent conclude?

They are also:

> **How do you know?**  
> **What did you actually query?**  
> **Where did the evidence come from?**  
> **Can someone else verify it?**

`test-provenance.py` treats those properties as testable behavior.

It drives a crystallized investigation with a stub client and asserts that:

- no query disappears from the evidence trail
- recorded filters match the filters actually sent
- denied queries remain visible
- a `403` can never silently become `"0 results"`

Where a conclusion depends on a field from a particular record, the dashboard can quote the source record rather than merely asserting what it contained.

The evidence trail isn't decoration.

It's part of the product.

---

### 4. Keep deterministic controls deterministic

LLMs are useful precisely because they can operate under ambiguity.

Authorization should not.

Neither should credential handling, policy enforcement, invariant checking, or the integrity of an audit record.

The goal isn't to make AI deterministic.

The goal is to put deterministic mechanisms around the parts of the system where determinism matters.

```text
Probabilistic reasoning
        ↓
Explicit evidence
        ↓
Deterministic controls
        ↓
Authorized action
        ↓
Verifiable result
```

Use AI where reasoning creates value.

Use software where repeatability creates value.

---

### 5. Don't pay the reasoning cost twice

The first investigation may require exploration.

The hundredth shouldn't.

`/crystallize` converts a completed investigation into a tokenless API script and self-contained dashboard.

```text
Question
   ↓
AI-assisted exploration
   ↓
Useful investigation
   ↓
Evidence + provenance
   ↓
/crystallize
   ↓
Deterministic script
   ↓
Scheduled execution
   ↓
Evidence + audit
   ↓
Exception when reality no longer fits the procedure
```

Once crystallized, the investigation runs without a model.

The generated scripts use the same GET-only client as the harness, so they cannot write even when run with broader credentials.

**AI discovers the procedure. Software repeats it.**

This is the architectural center of the project.

---

### 6. Failures are information

An automated system should preserve uncertainty rather than hide it.

A missing API scope is information.

An unsupported capability is information.

An unexpected schema is information.

A failed subagent is information.

Conflicting evidence is information.

None of those conditions means zero.

When the system encounters something it cannot deterministically resolve, that should become an explicit exception.

Sometimes another deterministic mechanism can handle it.

Sometimes AI can investigate it.

Sometimes it requires a person who understands the domain.

The important property is that the system **doesn't manufacture certainty.**

---

## Quick start

```bash
git clone <this-repo> falcon-mcp-harness
cd falcon-mcp-harness

cp env.example .env
chmod 600 .env

# Edit .env:
# - Falcon client ID
# - Falcon client secret
# - your region's base URL

./scripts/doctor.sh
```

Create the API client in the Falcon console under:

**Support and resources → API clients and keys**

Give it four **READ** scopes:

- Alerts
- Hosts
- Vulnerabilities
- Incidents

When `doctor.sh` is green, start Claude Code in this directory.

A posture brief appears before you type anything.

Then try:

> **How many hosts have not reported in over 14 days?**

Start with a question whose roughly correct answer you already know.

That's intentional.

Before trusting an agent to tell you something you don't know, establish whether the system can reliably tell you something you do.

A surprise means either the harness is misconfigured or you have learned something real about your estate.

Both are worth discovering before a consequential investigation.

### Requirements

- Claude Code
- `uv`
- Python 3.9+
- CrowdStrike Falcon API client

---

## What you get

### Six playbooks

| Command | What it does |
|---|---|
| `/falcon-setup` | Guided setup and diagnosis |
| `/posture-brief` | Deep on-demand posture summary with next actions |
| `/trace-vm-image` | Traces AWS/Azure/GCP VM vulnerabilities back to the image they booted from and ranks blast radius |
| `/image-sprawl` | Starts with one container detection and finds every place that image runs |
| `/crystallize` | Turns a finished investigation into a tokenless API script + dashboard |
| `/skill-template` | Helps encode your own recurring investigations as reusable playbooks |

The first four help investigate.

`/crystallize` stops you from paying the discovery cost repeatedly.

`/skill-template` is how you add the expertise specific to your environment.

Nobody outside your team knows which questions matter at 2 a.m.

---

## Evidence-backed dashboards

The investigation playbooks render results as self-contained HTML dashboards in `findings/`.

They contain:

- no JavaScript
- no CDN
- no external references
- no outbound network request when opened
- a `default-src 'none'` Content Security Policy

That makes them suitable for local review and safe to put on a projector without the dashboard itself calling anywhere.

More importantly, each dashboard ends with an evidence table:

```text
Query → Exact filter → Result
```

including unsuccessful and empty queries.

A result without its evidence trail is much harder to distinguish from a plausible model-generated explanation.

---

## A posture brief before you ask

`.claude/hooks/posture-brief.py` runs at session start and pushes a deliberately small snapshot into context:

- CrowdScore and direction
- new critical/high detections
- open critical vulnerability count
- hosts that stopped reporting

It is intentionally shallow and strictly budgeted.

It also fails open.

No credentials, a missing scope, or a slow connection produces a one-line note rather than blocking the session.

---

## A guardrail that fails safe

`.claude/hooks/guard-falcon-writes.py` runs before every Falcon tool call.

It is **default-deny**.

It does not maintain a list of dangerous tools to block.

It maintains a list of recognized read verbs to allow and denies everything else.

Why?

Because the upstream MCP server expanded from 24 tools to 139 in roughly a year.

With a denylist:

```text
new tool → allowed until somebody notices
```

With an allowlist:

```text
new tool → blocked until somebody deliberately allows it
```

A hypothetical `falcon_purge_everything` is therefore denied on day one by a guardrail that has never heard of it.

Destructive operations—including containment, quarantine, deletion, and command execution—remain blocked even when writes are unlocked.

Don't take the README's word for it:

```bash
./scripts/test-guardrail.sh
```

---

## Preflight that distinguishes "nothing" from "couldn't look"

`./scripts/doctor.sh` checks:

- required tooling
- credential file permissions
- read-only posture
- the write guardrail
- authentication
- required capabilities

Failures include a specific next action.

More importantly, the doctor distinguishes:

```text
403 → missing scope
404 → capability not licensed
200 + empty result → legitimate empty result
```

Those are three fundamentally different observations.

Reporting **"no critical vulnerabilities"** when the actual condition is **"no Spotlight scope"** is one of the most dangerous failure modes for a harness like this.

---

## Security posture

Full details are in `docs/security.md`.

The essentials:

```text
1. Model
   Chooses tools.
   NOT a security boundary.

2. Harness
   Default-deny hook.
   Model cannot disable it.

3. falcon-mcp
   FALCON_MCP_READ_ONLY prevents write tools from being registered.

4. API scopes
   The real authorization boundary.
```

If your API client has no write scope, nothing above it can grant itself write authority.

That's why `docs/api-scopes.md` treats read-only access as the default rather than an optional hardening step.

### Defaults shipped

- `FALCON_MCP_READ_ONLY=true`
- `FALCON_MCP_MODULES` restricted to five of 27 modules
- `.env` is gitignored
- `chmod 600` is enforced by `doctor.sh`
- credentials are unreadable by the model
- investigation output in `findings/` is gitignored and mode `0600`
- generated dashboards contain no JavaScript or external references
- dashboards use `default-src 'none'`
- crystallized scripts use a GET-only API client

The module restriction is both a security and reasoning decision.

139 tool schemas consume context and measurably degrade tool selection.

More capability is not automatically better capability.

### What this does not protect against

Stated plainly:

- prompt injection through telemetry content
- exfiltration through the conversation
- a model that is confidently wrong
- overly broad API scopes you granted anyway
- third-party plugins registering their own hooks or tools in the same session

The harness reduces specific risks.

It does not make the model trustworthy.

---

## The thing likely to break your first investigation

It probably won't be authentication.

It will be **context exhaustion**.

A single Falcon host record is roughly 8 KB of JSON.

Twenty begin crowding out reasoning.

Two hundred can end the session.

Worse, the failure is subtle.

The model doesn't necessarily announce:

> My context is degraded.

It starts losing earlier findings and becoming less precise—often just as the investigation becomes interesting.

### Context discipline

Prefer:

```text
server-side filtering
        ↓
facets / aggregation
        ↓
narrow result sets
        ↓
small evidence returned to the model
```

over:

```text
fetch everything
        ↓
put everything in context
        ↓
hope the model reasons over it correctly
```

Use facets instead of per-record follow-ups.

Narrow the scope instead of blindly paginating.

Counts require special care because the MCP server strips `meta.pagination.total`. Obtain the count outside the context window where possible, or report a sampled value explicitly as a floor.

See `docs/context-discipline.md` for the arithmetic and known payload traps.

---

## Fanning out to constrained subagents

Three playbooks execute independent work concurrently through subagents.

For `/trace-vm-image`, this isn't merely a speed optimization.

One EC2 instance asset record is roughly **139 KB**.

Resolving an entire cohort inside one model context is therefore impractical.

A narrow subagent can absorb the large record and return only the small piece of information the parent investigation needs.

Two constrained agents live in `.claude/agents/`.

Neither has:

- Bash
- Write
- arbitrary network tools

The component processing the largest volume of raw tenant data therefore has fewer ways to put that data somewhere else.

The write guardrail applies to their Falcon calls as well.

Parallel execution introduces its own correctness problems.

`docs/parallelism.md` covers:

- the dispatch ledger
- why a failed subagent is not a zero
- deterministic merging
- sorting before ranking
- keeping parallel investigations auditable

---

## Repository layout

```text
.claude/
  settings.json
  agents/
    falcon-asset-resolver.md
    falcon-query.md
  hooks/
    posture-brief.py
    guard-falcon-writes.py
  skills/
    ...

scripts/
  doctor.sh
  test-guardrail.sh
  test-crystallized.py
  test-render-parity.sh
  test-provenance.py
  test-agents.py
  falcon_api.py
  falcon_report.py

crystallized/
  generated deterministic investigations

tests/
  fixtures/report.json
  golden/report.html

findings/
  generated dashboards and investigation output
  gitignored

docs/
  security.md
  api-scopes.md
  context-discipline.md
  parallelism.md
  troubleshooting.md

.mcp.json
env.example
WORKSHOP.md
```

### Why `falcon_api.py` exists

Hooks are shell and Python.

They cannot call MCP tools directly.

`scripts/falcon_api.py` is therefore a stdlib-only, GET-only client used by the hooks.

It needs only four read scopes.

You can point it at a separate, even more restricted credential with `HARNESS_ENV_FILE`.

---

## Testing the deterministic parts

The important properties of this system should not require faith in the model.

Several tests run entirely offline:

```bash
python3 scripts/test-crystallized.py
./scripts/test-render-parity.sh
python3 scripts/test-provenance.py
python3 scripts/test-agents.py
```

### Crystallized behavior

`test-crystallized.py` verifies the deterministic investigation path without requiring live credentials.

### Rendering

`test-render-parity.sh` feeds a committed fixture into the renderer and compares the output byte-for-byte with a committed golden HTML file—including CSS.

A deliberate rendering change therefore becomes a reviewable diff rather than silently changing the output.

### Provenance

`test-provenance.py` verifies that:

- every query is represented
- recorded filters match actual filters
- denied queries remain denied
- a `403` never turns into `"0 results"`

### Agent definitions

`test-agents.py` exists partly because of a real failure.

A skill once instructed a call to a Falcon tool that the server build did not expose.

In a live demo, that looks like a Falcon failure rather than a typo.

The test now also verifies the subagents' tool allowlists so nobody can quietly give `Bash` to the component handling the largest tenant payloads.

Failures became tests.

That's the point.

---

## From exploration to deterministic automation

`crystallized/` is where useful investigations become permanent.

The transition is intentional:

```text
New question
     ↓
AI exploration + tool use
     ↓
Evidence-backed investigation
     ↓
Crystallize
     ↓
Deterministic automation
     ↓
 ┌───────────────┐
 ↓               ↓
expected      exception
state            │
 ↓               ↓
continue    investigate / learn
```

The objective is not to remove AI.

It's to **stop using AI where AI is no longer necessary.**

And when the deterministic procedure encounters reality it doesn't understand, the process can become exploratory again.

That creates a loop:

```text
reason → learn → encode → automate → observe → exception → reason
```

---

## Working through the workshop

`WORKSHOP.md` contains:

- both demos step by step
- ten starter questions
- a 30-day adoption path

### Week 1 — Connect

Start read-only.

Use it daily.

Read the audit trail.

Learn what the system actually does before increasing capability.

### Week 2 — Automate

Tune the posture brief until it reliably tells you something useful.

### Week 3 — Codify

Turn one recurring investigation from your environment into a reusable skill.

### Week 4 — Scale

Add modules deliberately.

Share useful skills.

Only then consider writes.

The progression is intentional:

```text
understand → trust → encode → automate → expand
```

Not:

```text
connect everything → grant write access → hope
```

---

## Notes and caveats

### VM image tracing

Demo 1 works entirely inside Falcon.

CSPM asset records contain the instance-to-image relationship natively.

For an `AWS::EC2::Instance`, `relationships[]` contains an `AWS::EC2::Image` entry whose `resource_id` is the AMI.

No AWS CLI is required.

The CLI is optional enrichment for image names and creation dates.

However, the asset record is roughly 139 KB.

The crystallized implementation therefore pre-fetches instances once and builds an index locally rather than querying individually for each instance.

If AWS Inspector is enabled, the `AWS::Inspector::Coverage` record for the same instance also contains `amiId` at roughly 2.5 KB—around fifty times cheaper for the same piece of information.

### Pin the resource type

Always specify `resource_type` when filtering CSPM assets.

Multiple asset types can share a `resource_id`.

Filtering only on an instance ID can therefore return a different kind of record than intended.

### `configuration` is encoded JSON

`configuration` on a CSPM asset is a JSON string, not an object.

Parse it before reading values such as `imageId`.

### Image sprawl is tenant-specific

Demo 2 must be parameterized.

The image used during the session will not exist in your tenant.

Give the playbook an image you actually run.

### Known upstream container-count issue

`falcon_count_kubernetes_containers` currently returns a payload that its own schema rejects.

Use:

```text
falcon_search_kubernetes_containers
```

and count the returned records instead.

### Prefer the FQL guides

Tool descriptions occasionally contain incorrect field names.

For example, the Kubernetes containers tool may show:

```text
cloud:'AWS'
```

while the correct field is:

```text
cloud_name
```

Prefer the `falcon://.../fql-guide` resources over tool descriptions when they disagree.

---

## Extending it

The most valuable addition is usually not another generic tool.

It's **your team's knowledge**.

Use:

```text
/skill-template
```

to encode recurring investigations specific to your environment.

A useful skill should document:

- what question it answers
- what evidence it requires
- what assumptions it makes
- what it does when data is unavailable
- what it cannot conclude
- what can be automated deterministically
- which decisions still require judgment

The goal isn't to encode certainty where none exists.

It's to convert repeatable expertise into repeatable systems while preserving the boundary of what remains unknown.

---

## Contributing

New skills are particularly useful—especially investigations specific to a sector, environment, or cloud posture.

Please include:

- what the skill does
- what it does **not** do
- required scopes
- expected evidence
- failure behavior
- which decisions remain outside the automation

Never include real tenant data:

- hostnames
- cloud account IDs
- cluster names
- customer IDs
- vulnerability inventories
- other identifiable environment data

Sanitized examples only.

---

## The broader experiment

This repository started as workshop material for connecting an AI agent to real security operations.

It has also become an experiment in a larger engineering question:

> **How do we get the benefits of probabilistic AI without making probabilistic behavior the foundation of trust?**

The working answer here is:

> **Let AI reason. Make the system prove.**

Use AI to explore ambiguity.

Require evidence for conclusions.

Keep authorization outside the model.

Preserve provenance.

Turn learned, repeatable procedures into deterministic automation.

Make failures visible.

Escalate what cannot safely be resolved.

Then learn from those exceptions and improve the system.

The hypothesis is not that AI should do less.

It's that **we can use AI more aggressively when the systems around it give us something stronger than trust.**

---

## License and status

MIT — see `LICENSE`.

Community workshop material, not a CrowdStrike or Anthropic product.

Not officially supported by either.

The upstream MCP server is `CrowdStrike/falcon-mcp`; issues with the server itself belong there.

Verified against a live Falcon tenant.

Your tenant's licensed capabilities will differ.

Run:

```bash
./scripts/doctor.sh
```

to determine which capabilities are available in yours.