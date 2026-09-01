# Running a playbook in parallel

Several playbooks in this harness have steps that do not depend on each other.
Those steps can run concurrently in subagents, which makes an investigation
faster and — for `/trace-vm-image` specifically — makes an investigation possible that
otherwise runs out of context.

This document is the shared discipline. The skills reference it rather than
repeating it, because getting parallelism subtly wrong produces a report that is
confidently incomplete, which is worse than a slow one.

Read `docs/context-discipline.md` first if you have not. Parallelism is a
consequence of that document, not an alternative to it.

## The two reasons to fan out

**Speed.** Six sequential Falcon queries at a couple of seconds each are slower
than one round of three subagents. On a live demo in front of an audience, this is
the difference between a playbook that lands and one that stalls.

**Context.** This is the bigger win and it applies to exactly one place today.
One CSPM instance record is ~139 KB (see `docs/context-discipline.md`). A
subagent absorbs the payload and returns sixty bytes, so the shortlist cap that
earlier versions imposed "because of context" can come off.

## When fan-out costs more than it saves

Dispatching a subagent is not free: it is a fresh context that must be given the
scope, must load its own instructions, and reports back through a summary. For
work that is one cheap call, that overhead is larger than the call.

**Do not dispatch a subagent for a single `limit: 1` count.** It is slower than
calling the tool directly, and it inserts a summarisation step between you and a
number you could have read yourself.

The rule of thumb: fan out when a branch is **either** several dependent calls
**or** one call with a very large payload. One small call stays inline.

Grouping matters too. Six independent counts should be three subagents doing two
each, not six doing one each — the dispatch overhead is paid per agent, and the
merge gets harder the more pieces it has.

## Concurrency cap

**Send at most 5 subagents at once**, in a single message so they actually run
concurrently. More than that and the Falcon API starts returning `429`, which
turns a fast investigation into a slow one with gaps in it. If you have twelve
instances to resolve, that is three rounds of four, not one round of twelve.

A `429` is an `error`, not a zero — see below.

## The dispatch ledger

**Every ID you dispatch must come back either resolved or explicitly unresolved,
and you must reconcile the two lists before you report.**

Write down what you sent. When the results come in, subtract. Anything in the
difference did not fail loudly — it vanished, either because a subagent dropped it
or because it returned prose instead of the format you asked for. A vanished ID is
invisible in the final table, which is the failure mode parallelism introduces and
serial execution does not.

The difference is not an internal detail. It is a `report.gap()` line:

> 3 of 47 instances could not be resolved to an image and are absent from this
> ranking.

A reader who knows the ranking covers 44 of 47 instances can act on it. A reader
who thinks it covers all 47 cannot.

## A subagent that failed is not a zero

The same rule that governs API responses governs subagent results. Four outcomes
look alike in a merged table and mean completely different things:

| Outcome | Means |
|---|---|
| Returned `count=0`, or `state=none` | **An answer.** Nothing there. |
| Returned `denied` | A missing scope or unlicensed module. Stable. |
| Returned `error` | Transient — a `429` or a `5xx`. Worth one retry. |
| Returned nothing usable, or never returned | A dispatch failure. Not evidence of anything. |

Merging any of the last three into the first is how a coverage gap gets published
as a clean result. If a branch of a posture brief came back `denied`, the brief
says "not established by this run" for that section — it does not say zero, and it
does not quietly omit the section, because an absent section reads as "nothing to
report" to everyone who sees it.

**Never fabricate or predict a pending agent's results.** If a subagent has not
reported yet, you do not know what it found. Wait for it, or report it as
unresolved. Writing the number you expect is the single most damaging thing you can
do in a parallel playbook, because it is indistinguishable from a real finding.

## Sort the merged results before you rank

Parallel results arrive in whatever order the subagents finish, which varies
between runs of the identical investigation. If your ranking has any
order-dependent tie-break — including the implicit "first one I saw wins" — the
same tenant produces a different table each time.

So: **merge everything, sort explicitly on the ranking keys with a named final
tie-break, then rank.** The tie-break must be a field, usually the identifier
ascending, never arrival order.

This is not tidiness. `/crystallize` claims that the script it generates
reproduces the investigation's ranking, and `scripts/test-crystallized.py` holds
the crystallized script to a deterministic sort for exactly this reason. An
arrival-order tie-break in the interactive playbook makes that claim false, and the
disagreement will surface as a failed parity check or, worse, as two different
answers in front of an audience.

## What to tell the operator

Say that you fanned out, and how far — "resolving 18 instances in 6 batches of 3".
It explains a pause, and it tells a reader of the transcript that the numbers came
from several sources that had to be reconciled.

Then report the ledger reconciliation, even when it is clean: "18 dispatched, 18
resolved" is a sentence that earns the ranking its credibility.

## The agents

Two definitions live in `.claude/agents/`:

| Agent | Tools | For |
|---|---|---|
| `falcon-asset-resolver` | CSPM asset search only | Absorbing the 139 KB instance records. Max **3 IDs** per dispatch. |
| `falcon-query` | Read-only Falcon searches | One branch of a multi-query playbook. |

Both are deliberately narrow. `falcon-asset-resolver` has no Bash, Write, Read or
WebFetch at all — the component that handles the largest volume of raw tenant data
in this harness is structurally unable to write it to disk or send it anywhere.
That is a cheap property to have and an expensive one to add back later.

The `PreToolUse` hook in `.claude/hooks/guard-falcon-writes.py` applies to subagent
tool calls as well as your own, so the write guard is not weakened by fanning out.
The agents' tool allowlists are the first layer and the hook is the second; neither
is relied on alone.
