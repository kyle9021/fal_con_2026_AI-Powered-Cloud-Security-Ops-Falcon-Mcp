---
name: skill-template
description: Helps you write a new Falcon skill of your own. Turns a repeatable investigation you already do by hand into a reusable playbook with the right structure, FQL, safety boundaries and context discipline. Use when asked to create a new skill, codify a runbook, or turn a workflow into something reusable.
---

# Write your own skill

This is the meta-skill. Its output is a new `SKILL.md`.

The two shipped playbooks — `/trace-vm-image` and `/image-sprawl` — are examples, not
the point. The point is that **your** organisation's recurring investigations
become as repeatable as those two. Nobody outside your team knows which questions
you ask at 2am.

## What makes something worth codifying

A good candidate has all four traits. Check honestly before writing anything:

1. **You have done it more than twice.** Codifying a one-off is waste.
2. **It is multi-step.** A single query is a query, not a skill. Skills earn
   their keep on the pivots between steps.
3. **The steps are stable but the inputs vary.** Same method, different image /
   cluster / CVE / account each time.
4. **Judgement is involved.** If it is purely mechanical, write a script — it
   will be faster, cheaper and deterministic. Skills are for work that needs
   interpretation between the steps.

If it fails test 4, stop and write a script. That is a real answer, not a
consolation prize.

## Where the file goes

```
.claude/skills/<your-skill-name>/SKILL.md
```

The directory name becomes the invocation: `.claude/skills/lateral-movement/`
is callable as `/lateral-movement`. Use lowercase and hyphens.

## The frontmatter is the load-bearing part

```markdown
---
name: your-skill-name
description: What it does, then when to use it. Include the phrases an operator would actually type.
---
```

`description` is the only part of your skill the model sees before deciding
whether to invoke it. Everything below the frontmatter is invisible until it is
already chosen. So:

- **Say what it does, then say when to use it.** Both halves matter.
- **Include the operator's words, not yours.** If people ask "is this CVE
  anywhere in prod", put that phrasing in the description. Matching happens
  against real language.
- **Be specific enough to exclude.** "Helps with security investigations" will
  fire on everything and be useless. Name the trigger conditions.

A vague description is the single most common reason a good skill never runs.

## The body: write for a capable colleague

You are writing instructions for a competent analyst who does not know your
environment. Not a script, and not a beginner's tutorial.

A structure that works, adapted from the shipped skills:

```markdown
# <What this accomplishes>

## The idea behind this playbook
Why this approach beats the obvious one. Two or three sentences. This is what
lets the model adapt when reality does not match your steps.

## Context discipline
Which calls return large payloads, and what to keep from each.

## Step 1 — <establish scope>
## Step 2 — <gather>
## Step 3 — <pivot>
## Step 4 — <rank or correlate>

## Report back
The exact shape of the output.

## Evidence and provenance
Which queries get recorded, and which records get quoted verbatim.

## What this does not do
The boundary. Which actions require a human.
```

Guidance that reliably improves results:

- **Give the reasoning, not just the recipe.** "Group by digest, not tag, because
  tags are mutable" survives a changed API. "Group by digest" does not.
- **Put real FQL in.** Copy filters that you have actually run. Untested FQL in a
  skill is worse than none — it will be trusted.
- **Name the field names.** Half of all FQL failures are a wrong field name.
- **Say what to discard.** The most valuable line in a data-heavy skill is often
  "keep these four fields, drop the rest."
- **Define the output shape.** If you want a ranked table, show the table.
- **Write the failure paths.** What does an empty result mean here? What does a
  403 mean? Ambiguity there produces confidently wrong answers.

## Safety boundaries — write these in explicitly

The harness blocks write and destructive tools by default. Do not rely on that
alone; state the boundary inside the skill too, because skills get copied into
other people's harnesses that may be configured differently.

Every skill that touches production should say, in its own words:

- Which actions it will **draft but never execute**.
- Which decisions belong to a human, and which human.
- That its output lands in `findings/`, which is gitignored, and that anything it
  generates for a human to run is inert until that human chooses to run it.

If your skill genuinely needs a write tool, say so prominently at the top, name
the specific tool, and explain the failure mode if it is used wrongly. Do not
bury it in step 4.

## Evidence and provenance — the section people skip

Write this section into every skill. It is the one that decides whether the
skill's output survives contact with a sceptical audience.

An investigation produces a number. Somebody acts on it — reprioritises a
sprint, opens a change ticket, tells an executive that three images cause 66% of
the critical backlog. Weeks later, somebody asks where the number came from. If
the answer is "the model said so in a session that has since been closed", the
finding is unauditable, and an unauditable security finding gets quietly
discounted the first time it is inconvenient.

So state, inside the skill, that the output must carry its own receipts:

- **Every query gets recorded** via `report.query()` — the tool or endpoint, the
  exact filter, the limit, and what came back.
- **Zero-result queries get recorded too.** This is the part that gets dropped,
  and it is the most valuable row in the table: an empty result is what separates
  *no findings* from *never asked*. A coverage gap you probed for and a coverage
  gap you assumed look identical in prose and completely different in an evidence
  table.
- **Failures get recorded as failures**, with their status. `403 -- missing scope`
  is not the same as `0 results`, and reporting the first as the second is how
  this harness would produce false assurance instead of honest noise.
- **The pivot gets quoted verbatim** via `report.code()`. If the skill's
  conclusion rests on reading one field out of one record — a relationship edge,
  a parsed `configuration` fragment, a digest — show that fragment. The
  difference between a report that *asserts* an instance boots from an image and
  one that *shows the edge it read* is the difference between being believed and
  being checked. Prefer being checked.
- **Show the rows behind the total**, not only the total. If the summary says 57
  findings have a public exploit, a table on the same page should let a reader
  count 57.

The habit that makes this cheap: **record each query at the moment you run it**,
while you still know why. Reconstructing provenance at write-up time is how it
gets skipped, and a half-remembered filter in an evidence table is worse than an
empty one.

## Metric consistency

Dashboard metrics must use the same counting basis so each number is a subset of
the one above. If the first tile says "227 distinct CVEs" and the next says
"1,074 ExPRT critical/high", the reader expects a subset — but 1,074 is a
per-image sum, not a distinct count. The numbers don't nest, the narrative breaks,
and the dashboard loses credibility.

Pick **distinct values** as the default basis. Chain metrics via the `note` field:
`note=f"of {total_cves} distinct CVEs"`. See `crystallize/SKILL.md` for the full
rule and the trap that prompted it.

## Data handling

Your skill will handle hostnames, cloud account IDs, cluster names and CVE
inventories. That combination is a map of where you are weakest.

- Investigation output goes to `findings/` or `out/`. Both are gitignored.
- Never instruct the model to include raw tenant data in something shareable.
- If a skill produces something meant to leave the building, add an explicit
  redaction step. Do not assume it will happen.

## Test it before you trust it

Four passes, in order:

1. **The happy path.** Does it produce the output shape you specified?
2. **The empty path.** Run it against something that genuinely does not exist.
   Does it report "not found" clearly, or does it invent a plausible answer?
   This pass catches more bugs than the first.
3. **The wrong path.** Ask a question the skill should *not* handle. Does it
   decline, or does an over-broad `description` drag it in?
4. **The provenance path.** Pick a number off the finished output at random and
   try to trace it to a recorded query. If you cannot — and you are the person who
   just ran the investigation — nobody else ever will.

Then hand it to a colleague who did not write it. If they need to ask you what a
step means, the skill is not finished — that clarification will not be available
at 2am.

## Starting points

Investigations that codify well, from the patterns that keep recurring:

- **CVE exposure sweep** — one CVE ID, every affected asset, ranked by internet
  exposure and business criticality.
- **New-host onboarding audit** — hosts first seen in the last 7 days that are
  missing expected policies, tags or sensor versions.
- **Detection-to-owner routing** — new detections mapped to team ownership via
  host tags or cloud account, so triage skips the "whose is this" step.
- **Stale sensor sweep** — hosts that stopped reporting, grouped by cloud account
  and OS, to separate decommissioned assets from genuine blind spots.
- **Public exposure review** — publicly exposed cloud assets cross-referenced
  against open critical findings.

Pick the one you did most recently by hand. That is your first skill.
