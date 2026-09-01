---
name: trace-vm-image
description: Strategic vulnerability management. Finds cloud VMs carrying critical vulnerabilities across AWS, Azure and GCP, traces those vulnerabilities back to the image they booted from (AMI, Azure image reference, GCP source image), ranks images by blast radius, and renders an evidence-backed dashboard. Use when asked to prioritise cloud vulnerability work, find the root cause of repeated CVEs across a fleet, or answer "where did this vulnerability come from".
---

# Trace cloud VMs back to the image they booted from

## The idea behind this playbook

A list of 200 vulnerable VMs is a to-do list. A list of 3 bad images is a fix.

Most critical vulnerabilities on cloud instances were not introduced on the
instance. They were inherited from the image it booted from. Patch the instances
and you fix today's fleet; the next autoscaling event reintroduces the same CVE.
Fix the image and every future instance inherits the fix.

So this playbook always drives toward the same question: **what is the smallest
set of images I can rebuild to retire the largest number of critical findings?**

## Check for an existing script first

**For a tenant-wide, multi-account, or CSPM-onboarding/coverage question,
run `crystallized/critical-vulns-by-image.py` before starting Step 1.** It
already resolves every cloud's instance-to-image chain end to end (AWS, Azure's
disk hop, GCP's disk hop) and already tallies a per-cloud coverage table with a
`denied`/`errored`/`no_provider`/`unresolved` split — which is exactly the
built-in, honest way to answer "is cloud X onboarded to CSPM". Every instance
carrying a finding is resolved by default (see `HARNESS_MAX_INSTANCES` in its
docstring if you need to bound a run on an unusually large tenant).

Hand-rolling the same investigation live through Steps 2-4 below, one instance
at a time, is slower and — because a human questioner cannot see how thin a
manually-sampled shortlist is — tends to produce a report that reads as
hedge-heavy and incomplete even when the underlying data is fine. Reserve the
manual MCP path for genuinely small, already-scoped investigations (a handful
of instances, one account) or for a question this script does not yet answer.

```bash
python3 crystallized/critical-vulns-by-image.py
# read the fresh findings/critical-vulns-by-image-<date>.{html,json}
```

## What this needs

**The Falcon MCP server and nothing else.** Every step completes using
`falcon_search_vulnerabilities`, `falcon_search_cspm_assets`, and
`falcon_search_hosts` (needed for Azure/GCP key construction). No cloud
CLI — image names and build dates come from Falcon too.

Step 3 dispatches the `falcon-asset-resolver` subagent defined in
`.claude/agents/`, which uses the same MCP server and needs nothing further. It is
what lets this playbook rank a whole cohort rather than a sample; see
`docs/parallelism.md`.

One optional path appears in Step 3: a `jq` extraction for unusually long
shortlists, which needs `scripts/falcon_api.py` and therefore a populated `.env`
in the repo. That file is often absent — the MCP server may be getting its
credentials from the ambient environment instead — so **check before relying on
it**, and fall back to the subagent fan-out. The playbook produces a complete
ranked answer either way; say which route you took.

Scopes required: **Vulnerabilities** (Read), **Cloud Security API Assets** (Read),
and **Hosts** (Read — needed for Azure/GCP host API lookups to construct CSPM
keys). Without Cloud Security API Assets, you will get the vulnerability list
and be unable to resolve a single image.

## Before you start

Read `docs/context-discipline.md` if you have not. The short version, because it
determines whether this playbook succeeds or dies halfway through:

- A single Falcon host record is several kilobytes of JSON. Twenty of them will
  crowd out your reasoning; two hundred will end the session.
- Always filter server-side and pull the narrowest set of records you can.
- Aggregate as you go. Keep running tallies, not raw payloads.

Then read `docs/parallelism.md`. This playbook's Step 3 fans out to subagents, and
that document holds the rules that keep a parallel run from producing a
confidently incomplete answer — the dispatch ledger above all.

## Step 1 — Establish the scope

Ask the operator (or infer from their request) two things:

- **Scope:** whole tenant, one cloud account, one region, or one tag such as
  `Environment=Production`?
- **Threshold:** critical only, or critical plus high?

Do not skip this. "All critical vulnerabilities everywhere" is rarely the real
question, and an unscoped query on a large tenant returns tens of thousands of
records.

**Then name the clouds before you measure any of them.** Spotlight findings come
from the sensor. CSPM inventory is agentless. A cloud with instances but no
sensor produces *zero findings*, which means it never appears in anything you
group by provider — and a missing row reads as "they don't run that cloud", not
as "this report cannot see that cloud". Nothing errors, nothing is denied, and
the omission is invisible in the output.

So ask CSPM what exists, once per cloud, before Step 2. Three queries per cloud,
all from the same CSPM endpoint so the numbers are comparable:

```
falcon_search_cspm_assets
  filter: resource_type:'AWS::EC2::Instance'
  limit:  1
  → pagination.total = total VMs in CSPM inventory

  filter: resource_type:'AWS::EC2::Instance'+active:true
  limit:  1
  → pagination.total = active VMs (the real denominator)

  filter: resource_type:'AWS::EC2::Instance'+managed_by:'Sensor'
  limit:  1
  → pagination.total = VMs with Falcon sensor (the numerator)
```

Repeat for `Microsoft.Compute/virtualMachines` and
`compute.googleapis.com/Instance`. Use `active:true` for the denominator — not
`instance_state:'running'`, which differs per cloud (AWS `running`, Azure
`VM running`, GCP `RUNNING`). The `managed_by:'Sensor'` filter works for AWS
and Azure but **does not reflect GCP sensor state** — GCP instances show
`Unmanaged` in CSPM even when the Hosts API confirms a sensor. Use the Hosts
API (`service_provider:'GCP'`) for GCP sensor counts.

## Step 2 — Pull critical vulnerabilities with host context

Use `falcon_search_vulnerabilities` with the `host_info` facet, which attaches
the affected asset to each finding so you do not need a second lookup per host.

```
filter: status:'open'+cve.severity:'CRITICAL'
facet:  host_info
limit:  200
sort:   created_timestamp.desc
```

Narrow it as the scope demands. Every filter below is verified against the
Spotlight FQL guide — the field names matter, and the near-miss versions fail
silently by returning nothing:

| Intent | Add to filter |
|---|---|
| High ExPRT rating | `+cve.exprt_rating:['HIGH','CRITICAL']` |
| Known exploited (CISA KEV) | `+cve.is_cisa_kev:true` |
| Any known exploit exists | `+cve.exploit_status_to_include:['90']` |
| A specific CVE | `+cve.id:['CVE-2025-12345']` |
| Recently discovered | `+created_timestamp:>'2026-08-01T00:00:00Z'` |
| Internet-facing assets only | `+host_info.internet_exposure:'Yes'` |
| Business-critical assets only | `+host_info.asset_criticality:['Critical','High']` |

Four traps in this specific API:

- **The ExPRT field is `cve.exprt_rating`, not `exprt_rating`.** The bare form is
  not a field and matches nothing.
- **`cve.id` requires brackets.** `cve.id:'CVE-2025-12345'` is wrong;
  `cve.id:['CVE-2025-12345']` is right.
- **The exploit field differs between filtering and reading.** You *filter* on
  `cve.exploit_status_to_include`; the value that comes *back* is
  `cve.exploit_status`, where `90` means a public exploit is available and `0`
  means none. Filtering on `cve.exploit_status` matches nothing.
- **Wildcards are unsupported in Spotlight FQL entirely.** No `*` anywhere, unlike
  every other module in this harness.

**There is no "cloud instances only" filter.** `host_info.service_provider` is
returned in the response but is *not* filterable — the same distinction that
hides the AMI (see Step 3). Filter on something that is supported, then drop
non-cloud assets yourself when you read the results: a finding with no
`host_info.instance_id` is not an instance you can trace to an image.

If the result set is at the limit, the answer is truncated. Say so, then narrow
the scope rather than paginating blindly — a partial ranking is worse than a
scoped one because it silently misleads the prioritisation.

**`facet` takes exactly one value.** You cannot request `host_info` and `cve` in
the same call. With `host_info`, the `cve` object collapses to just `{"id": ...}` —
no severity, no rating, no KEV flag, even though you filtered on them. Rely on
the filter for what you constrained, and on the top-level `exploitability`,
`risk_score` and `has_exploitability_conditions` fields, which *are* returned.

## Step 3 — Group findings by asset, then by image

From each finding, keep only these fields — all verified present in a real
`host_info` response. Discard the rest immediately:

- `cve.id` (the only `cve` subfield the `host_info` facet returns)
- `exploitability`, `risk_score` — top-level, not under `cve`
- `host_info.hostname`, `host_info.instance_id`
- `host_info.service_provider`, `host_info.service_provider_account_id`
- `host_info.asset_criticality`, `host_info.internet_exposure`

**Do not expect `host_info.zone_group`.** It exists on host records from
`falcon_search_hosts`, but not in the Spotlight `host_info` facet. Get the region
from the CSPM asset's `crn` in the lookup below instead — it is there, and it is
authoritative.

**Skip `host_info.groups` deliberately.** It is a full array of every host group
the asset belongs to, with IDs *and* names. One real record carried 39 of them,
and it dominated the size of the whole finding. Never keep it; never summarise it.

**The base image is in Falcon, for all three clouds.** You do not need the AWS
CLI, Azure CLI or `gcloud` for this. CSPM asset records carry the
instance-to-image edge natively — but the payload is a trap, and the three
clouds do not put the edge in the same place.

**From each CSPM asset resolution**, keep these additional fields beyond the image
edge — they are essential for the instance detail table:

- `account_id`, `account_name` — who owns this instance
- `region` — where it runs (not in Spotlight `host_info`)
- `active` (bool) — whether CSPM considers the asset live
- `cloud_context.instance_state` or `cloud_context.host.state` — the instance's
  current state: `running`, `stopped`, `terminated`. Prefer `instance_state`;
  fall back to `host.state`; fall back to `active` as a boolean.

A stopped instance still carries its vulnerabilities and can be restarted. A
terminated instance appeared in findings because the sensor reported before it
died. Both belong in the table — the **Status** column tells the operator which
are running and which are not, so they can prioritise accordingly.

**Read `reference-cloud-lookup.md` in this skill's directory before your first
`falcon_search_cspm_assets` call.** It carries the per-cloud lookup shapes, the
139 KB payload trap, the subagent fan-out batching, and the image-name
resolution. Guessing any of that costs more context than reading it.

## Step 3b — Count total instances per image (blast radius)

The ranked table needs two counts per image: **VMs with sensor findings** and
**total VMs running this image**. The crystallized script counts deployments
during its pre-fetch pass. For manual MCP investigations, query the image's own
CSPM record (`resource_type:'AWS::EC2::Image'+resource_id:'<ami-id>'`) and count
its `relationships[]` entries with `resource_type: 'AWS::EC2::Instance'`. For
Azure VMSS images, the parent VMSS's `Microsoft.Compute/images` relationship
carries the image ID, and the VMSS VMs are its children.

Report both numbers. An image with 3 sensor-visible VMs but 200 deployed VMs
is a very different priority than one with 3 of 3.

## Step 4 — Rank by blast radius

Build two tables. The first is the ranked image table:

| Image | Cloud | Account ID | Account Name | Region | Name | Built | Deployed instances | Instances w/ findings | Distinct CVSS-critical CVEs | ExPRT crit/high | Exploit available | Flags |
|---|---|---|---|---|---|---|---|---|---|---|---|---|

When an image spans multiple accounts or regions (e.g. a shared AMI used in both
prod and dev), comma-separate the values in those columns.

The second is the **instance detail table** — every instance traced to an image,
with its resource ID:

| Instance ID | Instance Name | Account ID | Account Name | Region | Status | Image | Cloud | CVEs | ExPRT crit/high | Flags | Resolution path |
|---|---|---|---|---|---|---|---|---|---|---|

**Status** is the instance's current state from CSPM: `running`, `stopped`, or
`terminated`. A stopped instance still carries its vulnerabilities and can be
restarted at any time — it belongs in the table. A terminated instance does not,
but if it appeared in findings it means the sensor reported on it before it died.
The CSPM asset record carries this in `cloud_context.instance_state` or
`cloud_context.host.state`; the top-level `active` boolean is the fallback.

**Account ID** and **Account Name** come from the CSPM asset's `account_id` and
`account_name` fields. These are essential for multi-account environments — an
instance ID alone is ambiguous without its account.

The instance detail table is what the operator actually hands to the platform team.
The image table is the executive summary; the instance table is the work order.
Include both. Collapse the instance table if it has more than 10 rows.

**Both tables must list CVE IDs, not just counts.** A count of "12 critical CVEs"
is a priority signal; the actual IDs (`CVE-2026-45447, CVE-2026-5435, ...`) are
what the platform team patches. Aggregate CVE IDs per image and per instance as a
comma-separated column. The CSV export (automatic from `report.save()`) makes
this directly importable into ticketing systems.

**`Cloud`** is the provider from Step 3's resolver — `AWS`, `Azure` or `GCP`. It is
what lets one ranked table hold all three clouds without the reader having to
infer which is which from the `Image` column's shape, and it is the column the
coverage table in Step 5 joins against.

**CVSS severity is not the workload. ExPRT rating is.** This is the single most
useful thing this playbook establishes, and it is worth stating explicitly in the
report. On a verified run, one image carried 76 CVSS-critical CVEs — of which 32
were ExPRT **LOW** and only 10 were ExPRT critical. CVSS overstated the urgent
work by about sevenfold. Report both numbers side by side so the reader sees the
gap rather than taking your word for it.

Rank by, in order:

1. **CVEs with a public exploit** (`cve.exploit_status` == `90`). One instance
   running an exploitable CVE outranks fifty instances with theoretical ones.
2. **Instances affected × distinct critical CVEs** — the blast radius.
3. **ExPRT critical/high count** as the tiebreak.

Two things worth calling out when you see them:

- **Asset role beats arithmetic.** A domain controller with 10 exploitable CVEs is
  not comparable to a stateless web node with 40. If `host_info` tells you what
  the asset is, say so — it will change the operator's ordering.
- **Instance age versus image age.** If instances are days old and the image is
  years old, patching the fleet is futile and the image is unambiguously the
  defect. That contrast is the argument that gets the rebuild funded.

Then state the leverage in one sentence an executive would repeat:

> Rebuilding 3 of 47 images retires 128 of 195 critical findings — 66% of the
> critical backlog from three changes.

## Step 5 — Render a dashboard, do not remediate

Produce a viewable artifact, not a wall of chat text. Use the renderer:

```python
import sys, os
sys.path.insert(0, "scripts")
from falcon_report import Report

report = Report(
    "Critical vulnerabilities by base image",
    subtitle="Which images to rebuild, most leverage first",
    scope="open + CVSS CRITICAL, <the scope you actually queried>",
)

# The answer, before any table. One image, one action, one number.
report.verdict(
    "Rebuild ami-<...> first. It carries 9 CVEs with a public exploit across "
    "12 instances -- 66% of the exploitable backlog from one image.",
    tone="critical",
)

# Tone is the reader's triage order, not decoration. Reserve `critical` for
# "someone can use this today" and leave the descriptive counts untoned.
#
# Metrics must use the same counting basis — distinct CVEs — so each number
# is a subset of the one above. Never mix distinct CVE counts with per-image
# sums; see crystallize/SKILL.md "Metrics must use the same counting basis."
report.metric("Distinct critical CVEs", 195, note="CVSS CRITICAL")
report.metric("ExPRT critical/high", 41, note="of 195 distinct CVEs", tone="high")
report.metric("Public exploit", 9, note="of 41 ExPRT — fix these first",
              tone="critical")
report.metric("On CISA KEV", 3, note="already used in the wild", tone="critical")
report.metric("Images implicated", 3)

report.gap("7 instances could not be traced to an image -- see the collapsed "
           "table below.")

report.table(
    "Ranked images",
    ["Risk", "Image", "Type", "Name", "Built", "Deployed", "With findings",
     "CVEs", "ExPRT crit/high", "Flags"],
    rows,
    numeric=[5, 6, 7, 8],
    bar=5,        # deployed instances -- the real blast radius
    accent=0,     # Risk tints the whole row's left edge
    badges=[9],   # flags become chips; a comma splits one cell into several
    mono=[1],     # image IDs/refs break anywhere rather than stretching the column
    rank=True,    # a # gutter, and row 1 emphasised
    note="Ranked by exploitation status first, then blast radius. "
         "'Deployed' = total instances in CSPM; 'With findings' = instances "
         "the sensor reported vulnerabilities on.",
)

# Instance detail -- the work order for the platform team
report.table(
    "Instance detail",
    ["Instance ID", "Instance Name", "Region", "Image", "Platform",
     "CVEs", "ExPRT crit/high", "Flags", "Risk factors"],
    instance_rows,
    mono=[0, 3],
    badges=[7, 8],
    collapsed=len(instance_rows) > 10,
    note="Every instance traced to a vulnerable image. Hand this to the "
         "platform team.",
)

# Instances that never resolved to an image, by cloud -- a real section,
# collapsed rather than a bare count in a gap() line. `collapsed=True` wraps
# the table in a closed <details>, right after the ranked table.
report.table(
    "Untraceable instances",
    ["Instance", "Cloud", "Reason"],
    untraceable_rows,
    mono=[0],
    collapsed=True,
)

# One row per cloud you probed in Step 1 -- including the ones that produced
# nothing. Build the rows from that list, never from the findings, or a cloud
# with no sensor drops out of the table and the omission is silent.
report.table(
    "Coverage by cloud",
    ["Cloud", "In CSPM inventory", "Findings", "Instances resolved"],
    coverage_rows,
    numeric=[2, 3],
    note="Inventory is CSPM (agentless, every onboarded account); findings are "
         "Spotlight (sensor only). Inventory present with zero findings means an "
         "unsensored fleet -- unassessed, not clean.",
)
html_path, json_path = report.save("critical-vulns-by-image")
```

Write it with Python via Bash — the aggregation stays out of your context. Output
goes to `findings/`, which is gitignored because a dashboard of where you are
weakest is not something to commit. The HTML is self-contained: no JavaScript, no
CDN, no outbound request when opened, mode 600. It opens over `file://`.

Two rules about that table, both learned the hard way:

- **An `accent` column must hold a single severity word** — `critical`, `high`,
  `medium`, `low` — and nothing else. That is why the table has a `Risk` column
  that exists only to be read by `accent`. A cell reading "critical (KEV)" matches
  no severity and the row silently loses its colour.
- **The `Risk` word and the `Flags` chips must be derived from the same evidence
  the ranking used.** A row tinted `critical` next to a chip reading "No known
  exploit" is a contradiction the reader can see, and it costs you the room.

Lead with the metric that *is* the finding. If CVSS-critical overstates the
workload sevenfold, the reader should see both numbers side by side without
having to derive it — which is what the tones above are for: the two red metrics
are the work, the untoned 195 is the number the ticket queue thinks is the work.

`verdict()` is set once. Setting it twice replaces it, so a report with two
verdicts has none — decide what the single action is before you call it.

**Every gap from Step 2 and Step 3 becomes a `report.gap()` call.** Untraceable
findings, unresolved instances, truncation, clouds with no CSPM accounts
onboarded. They render near the top, not in a footnote.

**A cloud Step 1 found in CSPM but Step 2 produced no findings for is a
`report.gap()`, not a quiet zero row.** Say the count and say what it means:
"Azure: 204 instances in CSPM, 0 vulnerability findings — unsensored, therefore
unassessed rather than clean. Nothing below covers them." That is the one failure
mode with no error to trip over, so it has to be stated in words.

### Show the evidence — this is not optional

A dashboard that asserts "246 findings from 2 images" is asking to be trusted. One
that shows the FQL, the graph edge and the CVE list is asking to be **checked**.
In front of a customer, only the second survives a sceptical question — and six
months later it is the only version anyone can audit. Somebody will eventually
ask "where did that number come from", and the answer cannot be "the model said
so in a chat window that has since been closed".

So every claim on the dashboard carries its receipt. The renderer has two methods
for exactly this, and both render below the analysis, under a rule:

```python
# Every query, in the order you ran it -- including the ones that returned nothing.
report.query("falcon_search_vulnerabilities",
             "status:'open'+cve.severity:'CRITICAL'+cve.exprt_rating:'CRITICAL'",
             limit=1000, returned="1000 (capped)",
             note="Returned exactly the limit, so this is a floor.")
report.query("falcon_search_cspm_assets",
             "resource_type:'AWS::EC2::Vpc'+account_id:'<account>'",
             limit=1, returned=0,
             note="No CSPM inventory at all -- the account is not onboarded.")

# The verbatim edge, so attribution is visibly read rather than inferred.
report.code("Evidence — the instance-to-image edge",
            "relationships[]: {resource_type: AWS::EC2::Image,\n"
            "                  resource_id: ami-...,\n"
            '                  relationship_name: "is attached to"}\n'
            "configuration (parsed): imageId = ami-...")
```

Four things belong in the evidence section of *this* playbook specifically:

1. **Every query, with what it returned.** Zero-result rows are evidence too —
   they are what separates "no findings" from "never asked", and they are how a
   reader knows a coverage gap was tested for rather than assumed.
2. **The instance-to-image edge, verbatim**, showing both the `relationships[]`
   entry and the parsed `configuration.imageId`. Two independent fields agreeing
   is why the attribution is a reading and not a guess. Say so.
3. **Every instance in the cohort, resolved or not** — not just the ones that
   worked. The unresolved rows are usually the larger share of the finding count,
   and dropping them silently converts a coverage gap into a clean-looking answer.
4. **The full urgent CVE list.** If the summary says 57 findings have a public
   exploit, that number must be countable from a table on the same page.

The discipline that makes this cheap: **record each query as you make it**, while
you still know why you made it. Reconstructing provenance at write-up time is how
it gets skipped, and a half-remembered filter in an evidence table is worse than
an empty one.

### Do not write a remediation script

Earlier versions of this playbook drafted one. Do not. Rebuilding an image is a
change-managed activity owned by the platform team, and a generated script full of
instance IDs, AMI IDs and owner names is a liability sitting in a working tree —
it invites exactly the accidental commit that `findings/` exists to prevent.

Hand over decisions instead:

- Which image to rebuild first, and why that one.
- Who owns it — reference the **tag key** (`cstag-owner`, `Environment`), not the
  person's name. Names are personal data and add nothing to a ranking.
- What the rollback is: keep the old image registered until the replacement is
  validated.
- What is out of scope and needs its own investigation.

### Offer to crystallize it

Check first whether `crystallized/critical-vulns-by-image.py` already answers
this question (see "Check for an existing script first" above) — do not
propose building what already exists.

If it doesn't, and the operator will want this answer again — weekly, or on a
schedule — say so and offer `/crystallize`. It converts this investigation into
a standalone script that hits the Falcon API directly with no model and no
tokens, and renders the same dashboard. Two things get better in the process:
the ~139 KB payload trap disappears entirely (nothing enters a context
window), and the REST endpoint accepts **multiple facets**, so `host_info` and
`cve` arrive together instead of one collapsing the other.

## Report back

Keep it to:

1. Scope actually queried, and whether results were truncated.
2. The ranked image table — with both deployed and findings-instance counts.
3. The instance detail table — every instance ID, name, region, image, and resolution path.
4. The one-sentence leverage statement.
5. Path to the dashboard, and the reminder that `findings/` is gitignored.
6. Anything you could not determine — unresolved accounts, clouds with no
   CSPM accounts onboarded, images with unknown deployment counts.

The instance detail table is what makes this actionable. An image table without
instance IDs is a recommendation; an image table with instance IDs is a work order.

State uncertainty explicitly. A prioritisation the operator wrongly believes is
complete is worse than one they know is partial.
