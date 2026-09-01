---
name: crystallize
description: Turns a finished MCP investigation into a standalone Python script that calls the Falcon API directly — no model, no tokens, no MCP server — and renders an HTML dashboard. Use after an investigation has produced an answer worth having again, or when asked to automate, schedule, productionise or "make this repeatable" / "run this every morning".
---

# Crystallize an investigation into a tokenless script

## The idea behind this playbook

An MCP investigation spends tokens on two different things: deciding **which
questions to ask**, and **fetching the answers**. Only the first needs a model.

Once you know the question sequence, the answer is just a query. Re-running the
same investigation through a model every morning pays the discovery cost forever
for a discovery you already made.

So this playbook converts a finished investigation into a plain script:

| | MCP investigation | Crystallized script |
|---|---|---|
| Cost per run | Tens of thousands of tokens | Zero |
| Runs on a schedule | Awkward | `cron`, CI, anywhere |
| Output varies run to run | Yes, it is a model | No, it is arithmetic |
| Security review | "What might it ask?" | "Here are four GET requests" |
| Handles a novel question | Yes — this is the point | No |

The model's contribution is not thrown away. It is **preserved as the ranking
logic**, in code, where a colleague can read and argue with it.

## When to crystallize, and when not to

The test is one question: **if you ran this investigation again next month, would
you ask the same things in the same order?**

Crystallize when:

- The query sequence is stable and only the data changes.
- The judgement has collapsed into arithmetic — "rank by instances × distinct
  CVEs, promote anything exploitable" is a formula now.
- You want it on a schedule, or in front of someone who will not run Claude Code.

**Do not** crystallize when each run needs a fresh decision about what to chase
next, or when the second question's *shape* depends on the first answer in a way
you cannot write as an `if`. That is exactly what the MCP path is for. A script
that pretends to have judgement is worse than no script, because its output looks
equally confident when the situation has changed underneath it.

Say so plainly if the investigation fails this test. "This one should stay
interactive, and here is why" is a correct outcome for this playbook.

## What this needs

Nothing beyond the repo and Python 3.9+. The generated script imports
`scripts/falcon_api.py` (stdlib-only, GET-only) and `scripts/falcon_report.py`
(the dashboard renderer). **It does not use the MCP server at all** — that is the
entire point. No `pip install`, no FalconPy at runtime.

Read scopes: exactly the ones the original investigation used, and no more.
Crystallizing is not an opportunity to widen access.

## Step 1 — Establish what you are crystallizing

Before writing anything, state back to the operator, and get agreement on:

1. **The question**, in one sentence, as an executive would ask it.
2. **The exact MCP calls** the investigation made that mattered — tool, filter,
   facet, limit. Discard the exploratory dead ends; they are not part of the
   answer.
3. **The scope** — and whether it should be fixed or configurable.
4. **The numbers the investigation produced.** Write them down. They are your
   acceptance test in Step 5.

If the investigation is still in progress, or produced a result the operator has
not yet accepted, stop. Crystallizing a wrong answer just makes it repeatable.

## Step 2 — Translate MCP tools into REST endpoints

Every `falcon_*` MCP tool is a wrapper over one or two REST calls. **FQL filter
strings transfer verbatim** — that is the part you do not have to re-derive.

These are verified against the FalconPy endpoint spec, not assumed:

| MCP tool | Method and path |
|---|---|
| `falcon_search_vulnerabilities` | `GET /spotlight/combined/vulnerabilities/v1` |
| `falcon_search_kubernetes_containers` | `GET /container-security/combined/containers/v1` |
| `falcon_search_images_vulnerabilities` | `GET /container-security/combined/vulnerabilities/v1` |
| `falcon_search_detections` | `GET /alerts/combined/alerts/v1` |
| `falcon_search_hosts` | `GET /devices/combined/devices/v1` |
| `falcon_search_cspm_assets` | **two steps** — see below |

### Discovering the ones not listed

Do not guess an endpoint path. Guessed paths 404, and a 404 is
indistinguishable from "not licensed" (see `docs/troubleshooting.md`). FalconPy
ships a machine-readable spec of every endpoint; grep it:

```bash
# Locate FalconPy's endpoint spec (it arrives via uv's cache, or pip)
SPEC=$(find ~/.cache/uv ~/.local /usr/local/lib -maxdepth 8 -type d -name _endpoint -path '*falconpy*' 2>/dev/null | head -1)

# Find the path for a service
grep -rhoE '"/spotlight[a-z0-9/_-]*"' "$SPEC" | sort -u

# And the query parameters a given endpoint actually accepts
grep -n '"name":' "$SPEC/_spotlight_vulnerabilities.py"
```

Prefer a `combined` path where one exists: it returns full records in one call,
which is what the MCP tool was doing for you.

### Two things the spec tells you that the MCP tool hides

**`facet` is an array at the REST layer.** The MCP tool accepts exactly one
facet, so `facet: host_info` collapses the `cve` object to `{"id": ...}`. The REST
endpoint declares `facet` as `collectionFormat: multi`, so a crystallized script
can request both:

```
GET /spotlight/combined/vulnerabilities/v1?filter=...&facet=host_info&facet=cve
```

The script is **strictly more capable than the MCP path** here — one call gives
you the host *and* the severity, rating and KEV flag. Take advantage of it.

**CSPM assets are two calls, not one.** There is no combined endpoint:

```
GET /cloud-security-assets/queries/resources/v1?filter=<fql>&limit=...   -> resource IDs
GET /cloud-security-assets/entities/resources/v1?ids=<id>&ids=<id>...    -> full records
```

Batch **at most 100 IDs** per entities call. The API offers a POST variant for up
to 500, but `falcon_api.py` is deliberately GET-only — it contains no code path
that can write to your tenant. Staying under 100 keeps that property, and that is
worth more than the round trip you save.

This two-step is also *why* those records are enormous: there is no server-side
field projection. Extract what you need and drop the record in the same loop —
never accumulate them in a list.

## Step 3 — Write the script

Write to `crystallized/<question-slug>.py`. That directory is **committable on
purpose**, so keep it that way:

> **No tenant data in the script.** Account IDs, hostnames, cluster names and
> instance IDs are tenant-identifying. Read them from the environment with
> harmless defaults, so the logic can be shared and reviewed while the specifics
> stay in `.env`. The script is the reusable asset; the data is not.

```python
ACCOUNTS = [a for a in os.environ.get("HARNESS_SCOPE_ACCOUNTS", "").split(",") if a]
SEVERITY = os.environ.get("HARNESS_SEVERITY", "CRITICAL")
```

Structure it in this order — it makes the whole thing reviewable top to bottom:

1. **Docstring**: the question, the scopes needed, the date, and which
   investigation it came from.
2. **Config block**: every tunable constant, read from env, at the top.
3. **Fetch functions**, one per endpoint, each handling its own pagination.
4. **Pure functions** for aggregation and ranking — no I/O, so they can be
   reasoned about and tested.
5. **`build_report()`** assembling the dashboard.
6. **`main()`** with `--dry-run`.

### Four requirements that are not style preferences

**Paginate with `after`, and cap it.** Offset pagination drifts while data
changes underneath you; token pagination does not. Always impose a hard page
ceiling so a filter that matches more than you expected cannot run for an hour:

```python
def fetch_all(client, path, params, max_pages=20):
    after, seen = None, []
    for _ in range(max_pages):
        page = client.get(path, {**params, "after": after})
        if client.denied(page):
            return None                      # None means "could not determine"
        seen.extend(page.get("resources", []))
        after = (page.get("meta") or {}).get("pagination", {}).get("after")
        if not after:
            return seen
    return seen                              # truncated -- report it as a gap
```

**Never turn a denial into a zero.** `falcon_api.py` gives you
`FalconClient.denied()` for 401/403/404. On a denial, pass `None` to
`report.metric()` and add a `report.gap()` saying which signal was unavailable
and why. The renderer prints `None` as "unavailable" in grey, visibly different
from a real `0`. A dashboard reporting "0 critical vulnerabilities" because the
API client lacks Spotlight scope is the most dangerous artifact this repo can
produce.

**Metrics must use the same counting basis.** Pick **distinct values** and stick
to it for all metrics in a row. Each metric should be a subset of the one above
— chain them via the `note` field: `note=f"of {total_cves} distinct CVEs"`.
Mixing distinct counts with per-image sums produces numbers that don't nest and
narratives that contradict themselves.

**Report truncation as a gap.** If you hit the page ceiling or the result count
equals your limit, the answer is partial. Say so on the dashboard.

**`--dry-run` must print the requests and make none.** This is how a security
reviewer sees exactly what the script does without granting it credentials.

### Cross-cloud patterns (when your script touches CSPM)

Any crystallized script that resolves cloud instances to images will hit these.
They are not edge cases — they are the default path for Azure and GCP.

**Pre-fetch and index, don't query per-instance.** Paginate all CSPM instances
once per cloud, extract the 5 fields you need, discard the ~139 KB record, build
a local lookup dict. Resolution becomes a dict lookup — zero API calls for
thousands of instances. See `docs/context-discipline.md` for the payload trap.

**Instance ID format differs per cloud.**

| Cloud | Spotlight gives | CSPM indexes by | Resolution path |
|---|---|---|---|
| AWS | `i-xxx` | Same | Direct match |
| Azure standalone VM | VM GUID | ARM path | Construct from host API `zone_group + hostname` |
| Azure AKS/VMSS node | VM GUID | VMSS VM path (no hostname) | Extract VMSS name from hostname → parent VMSS → `Microsoft.Compute/images` edge |
| GCP Standard | numeric ID | URL with project NAME | Regex map number→name from pre-fetched resource_ids |
| GCP Autopilot | numeric ID | Not in CSPM | Managed by Google, not inventoried as compute instances |

**Azure `imageReference` is nested.** The image identity is at
`configuration.properties.creationData.imageReference.id` inside the disk entity
(`configuration` is a JSON string — parse before reading).

**`active:true` is the cross-cloud "running" filter.** `instance_state` values
differ per cloud (see table above). Use `active:true` for coverage denominators.

**Hosts entity API: 100 IDs per GET.** Sending more returns HTTP 400 silently
(`falcon_api.py` returns `{"_status": 400, "errors": [...]}`). Batch at 100.

**CSPM `managed_by:'Sensor'` does not reflect GCP sensor state.** GCP instances
show `Unmanaged` in CSPM even when the Hosts API confirms a sensor is deployed.
Use the Hosts API for GCP sensor counts.

**Account ID masking.** Default to masked output (`--unmask` flag to show full
IDs) so dashboards are safe for presentations and shared reviews.

**Per-instance resolution evidence.** Every instance row should carry its
resolution method (direct match, ARM path, VMSS parent, GCP URL, disk hop) so an
auditor can trace how each row was mapped. Store in resolved metadata and render
as a table column.

**Verify with Falcon MCP tools, not Python simulations.** Debug data mapping
with live `falcon_search_cspm_assets` calls — the live data is the authority.

**Check the service architecture before reporting a gap.** When a path doesn't
resolve, a different resource type or relationship chain usually reaches the
image — AKS nodes trace through the parent VMSS, GCP through the disk.

### Exit codes, so it can be a gate

| Code | Meaning |
|---|---|
| `0` | Ran; nothing above threshold |
| `1` | Could not run — auth, network, config |
| `2` | Ran; findings above threshold |

Distinguishing 1 from 2 is what lets CI fail a build on findings without failing
it on an expired credential.

## Step 4 — Render the dashboard

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from falcon_report import Report

report = Report(
    "Critical vulnerabilities by base image",
    subtitle="Which images to rebuild, most leverage first",
    scope=scope_description,          # be specific; a reader must know what was asked
)
report.metric("Blast radius", 572, note="VMs running these 16 images", tone="critical")
report.metric("VMs with sensor", 40, note="of 572 total — the visible slice")
report.metric("Exploitable CVEs", exploitable_count, note="of N ExPRT — fix these first")
report.gap("Azure: 204 VMs in CSPM, 0 vulnerability findings -- unsensored, so "
           "unassessed rather than clean. Nothing below covers them.")
report.table("Ranked images", ["Image", "Instances", "CVEs"], rows, numeric=[1, 2])
report.text("Leverage", "Rebuilding 3 of 47 images retires 128 of 195 findings.")
html_path, json_path = report.save("critical-by-image")
```

Output lands in `findings/`, which is **gitignored** — it names your weaknesses.
The HTML is a single self-contained file: no JavaScript, no CDN, no outbound
request when opened, everything HTML-escaped, written mode 600. It opens over
`file://` and prints to PDF cleanly, which is what makes it demo-safe.

**Sort rows before passing them in.** There is no client-side sorting, by design
— the ranking is a decision the investigation made, not a puzzle for the reader.

Lead the dashboard with the metric that *is* the finding. If the answer is "three
images cause 66% of this", the reader should not have to work that out from a
table.

### The script must record its own provenance

A crystallized script runs unattended. It has to explain itself — and it can do
that better than any chat transcript, because **the script emits the filter it
actually sent**, not one someone remembered sending.

Never retype the filter as a string literal in the `report.query()` call. Pass
the same variable and the two cannot disagree.

Provenance checklist for scheduled dashboards:

- Every endpoint the script calls gets a `report.query()` row — including
  empty results and failures (`returned="403 -- missing Spotlight scope"`)
- `report.code()` one verbatim excerpt of the record shape the script depends
  on — the relationship edge, the parsed config fragment
- Per-instance resolution evidence in the instance detail table (resolution
  method column)

## Step 5 — Verify it reproduces the investigation

This is the step that makes the artifact trustworthy, and it is not optional.

```bash
python3 crystallized/<name>.py --dry-run     # shows the requests, makes none
python3 crystallized/<name>.py               # real run
```

Then **compare its numbers against the ones you wrote down in Step 1.** They
should match, or every difference should have an explanation you can state.

If they disagree and you cannot say why, the translation is wrong. Fix it or say
so — do not ship it. A script that quietly disagrees with the investigation that
justified it is worse than no script, because it will be believed.

Legitimate reasons for a difference, all of which belong in the report:

- Time has passed and the tenant changed.
- The MCP run was truncated and the script paginates further — the script is more
  complete, and the original number was the wrong one.
- You now request multiple facets, so a field the MCP run could not see is
  populated.

## Step 6 — Hand it over

Report back:

1. **Path to the script**, and the one-line question it answers.
2. **Verification result** — did it reproduce the investigation's numbers?
3. **Path to the dashboard**, with the reminder that `findings/` is gitignored
   and the output should not be committed or emailed casually.
4. **Scopes it needs** and the env vars it reads.
5. **How to schedule it**, if wanted:

```cron
# 07:15 daily. Writes a dated dashboard to findings/.
15 7 * * * cd /path/to/harness && /usr/bin/python3 crystallized/<name>.py >> findings/cron.log 2>&1
```

6. **What it will not notice.** A crystallized script answers one question
   forever. It cannot tell you the question stopped being the right one. Say
   which change in the environment would invalidate it — a new cloud account, a
   different image pipeline, a renamed tag convention — so someone knows when to
   come back and re-investigate interactively.

## What this playbook must not do

- **No writes.** The generated script uses the GET-only client. Do not add a POST
  path, do not have it open tickets, do not have it change tenant state. If
  automation should act, that is a separate, reviewed, explicitly-approved piece
  of work — not a side effect of making a report repeatable.
- **No credentials in the script.** They come from the environment via
  `load_dotenv`, exactly as everything else in this repo does.
- **No tenant data in `crystallized/`.** If the logic genuinely cannot be
  expressed without a specific account ID, that value belongs in `.env` and the
  script reads it.
- **Do not delete or rewrite the skill it came from.** The interactive playbook
  stays: it is how the next novel question gets answered.
