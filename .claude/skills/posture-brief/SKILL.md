---
name: posture-brief
description: On-demand security posture briefing. Assembles current detections, vulnerability backlog, sensor health and threat intelligence into a single prioritised summary with recommended next actions. Use when asked for a morning brief, a posture summary, "what should I look at today", or a status report for leadership.
---

# The posture brief

Assemble the picture first and lead with what changed, so the operator's attention
goes to judgement rather than navigation.

## This skill versus the automatic brief

The `SessionStart` hook in `.claude/hooks/posture-brief.py` counts four things on a
wall-clock budget and cannot reason about what it found. This skill runs when asked
and correlates — it can notice that the host with a new critical detection is also
the one carrying 40 unpatched CVEs. Start from whatever the hook printed rather
than re-fetching, and say what you are building on.

## Context discipline

Counts from `pagination.total`, examples at `limit: 3–10`, and extract the two or
three fields you need from each record. Record sizes vary by two orders of magnitude —
a container-image finding is a few hundred characters, a host record is ~13k — so the
right `limit` is per-tool, not a global default. Never paste a raw payload into the
brief. See `docs/context-discipline.md`.

### Active status is not optional

Every resource surfaced in the brief — host, cloud asset, container, instance — must
state whether it is currently active. A vulnerability on a stopped cloud instance and a
vulnerability on a running one are different priorities; a detection on a terminated
container is context, not an action item. The specific field varies by data source:

| Source | Field | Values |
|---|---|---|
| CSPM asset | `active` (FQL-filterable) | true / false — **the cross-cloud normaliser** |
| CSPM asset | `instance_state` (FQL-filterable) | varies per cloud: AWS `running`, Azure `VM running`, GCP `RUNNING` |
| CSPM asset | `managed_by` (FQL-filterable) | Sensor / Snapshot / Unmanaged (**does not reflect GCP sensor state** — use Hosts API for GCP) |
| K8s container | `running_status` | true / false |
| Host record | `status` + `last_seen` | normal / contained; stale if last_seen >14d |
| Cloud risk | `status` | Open / Resolved / Suppressed |

For cloud VM coverage, the denominator is active instances (`active:true`),
not total inventory. Sensor coverage = `managed_by:'Sensor'` / `active:true`
(except GCP — see table above). A stopped instance carries its vulnerabilities
but is not exposed until restarted.

When the brief names a specific resource (an instance ID, a hostname, a pod), say
whether it is active. When reporting counts, note how many are active vs inactive
if the data supports it. A count of 200 vulnerable instances where 180 are stopped
is a different finding than 200 running ones.

## Gather it

Ten queries, all cheap, all inline. Do not fan these out to subagents —
`docs/parallelism.md` is explicit that a single count is faster called directly than
handed to an agent, and most of these are counts.

Compute one absolute ISO 8601 timestamp for "24h ago" and reuse it, so the numbers
cover the same window and can be compared to yesterday's.

### "Not checked" requires a refusal you saw this run

A capability goes under **Not checked** only when *you called the tool during this
brief* and it refused — 403 (missing scope) or 404 (path absent on this tenant).
Quote the status you got.

Do **not** populate "Not checked" from any of these:

- the `SessionStart` hook's footer, which prints a cached `doctor.sh` verdict
- `scripts/doctor.sh` output from an earlier day
- a memory file, this skill, or anything else written before this run

Those are all claims about the past. Licensing changes, scopes get granted, and a
probe that 404s on one path does not mean the capability is absent — `doctor.sh`
probes `/container-security/queries/containers/v1`, which 404s here, while the MCP
container tools query different paths and return data fine. Generalising that one
404 into "container images not licensed" put a false statement in a brief in front
of an operator who knew better.

The failure is asymmetric, which is why the rule is absolute. Writing "not checked"
about a working capability hides real findings and reads as authoritative. Calling
the tool to find out costs one query. Call it.

**1. New high-severity detections** (`falcon_search_detections`)

```
filter: created_timestamp:>'<24h ago ISO8601>'+status:'new'+(severity_name:'Critical',severity_name:'High')
sort:   severity.desc
limit:  5
```

**`limit: 5`, not 25.** A detection record on this tenant runs ~10k characters, so 25
of them is a 240k-character payload that overflows the tool result, gets spilled to a
file, and costs you a recovery detour mid-brief. On stage that detour is the whole
demo. Five records is enough to quote a concrete example; the *distribution* comes
from the aggregations below, which is where it should come from anyway.

Keep: severity, tactic, hostname, timestamp. Drop the rest of each record.

**2. Where the detections cluster** (`falcon_aggregate_detections`) — five calls,
same filter, one `field` each:

```
filter: created_timestamp:>'<24h ago ISO8601>'+status:'new'
field:  tactic
field:  device.hostname
field:  severity_name
field:  assigned_to_name    (with missing: 'Unassigned')
field:  product
```

Aggregations return the real distribution across the whole window rather than the
handful of rows you happened to fetch, and they cost a few hundred characters each.
One host or one tactic accounting for most of the volume is a different brief than
the same count spread evenly, and clustered activity leads the brief — so getting
the denominator right matters.

The `assigned_to_name` call with `missing: 'Unassigned'` is the highest-value query
in this skill. It answers "has anyone actually picked these up" across every matching
alert instead of the five you fetched, and a single `Unassigned` bucket equal to the
total is a workflow failure worth leading the brief with — a different and more
urgent finding than "there are a lot of alerts."

The `product` aggregation shows the cloud-vs-endpoint split: `epp` (endpoint),
`idp` (identity), `ngsiem` (correlation), `mobile`, etc. When Kubernetes nodes or
cloud instances dominate the top-host list, the product breakdown tells you whether
those are sensor-level alerts or NG-SIEM correlations — different queues, different
responders.

If an aggregation is refused, tally by hand from the records step 1 returned and
**say the tally is capped at 5**. A hand tally of a truncated sample is a hint, not a
distribution.

**3a. Cloud groups** (`falcon_search_cloud_groups`)

```
limit: 100
```

Call this first. Cloud groups are the organisational hierarchy — they map accounts to
business units, environments, and impact levels. The brief needs this context to say
"14 critical risks in the Production / Finance group" rather than "14 critical risks
in account 248148904598." Cache the group-id → name/environment/business_impact mapping
for use in steps 3b and 4.

**3b. Cloud risks** (`falcon_search_cloud_risks`)

```
filter: (severity:'Critical',severity:'High')+status:'Open'
sort:   severity.desc
limit:  5
```

Cloud risks aggregate IOM and IOA findings into per-asset risk records and include
threat intelligence attribution. They are the cloud-native equivalent of detections
and deserve equal billing in the brief.

Report `pagination.total` for the headline count. From the 5 records extract:
severity, cloud_provider, asset_type, rule_name, account_name, account_id,
and **cloud_groups**. If `cloud_groups` is non-null, resolve the IDs via
`falcon_get_cloud_groups` to get group name, environment, and business_impact.

**Group the output as: cloud group → accounts → top rules.** The operator needs to
know which organisational boundary owns the risk. If cloud_groups is null on all
records, fall back to grouping by account_name alone and note that no cloud groups
are configured for these accounts.

If this is the first time running the query and you want the production-vs-dev split,
add a second call with `+groups.environment:'production'`. The gap between total and
production-only tells you how much risk lives in dev/staging accounts that nobody
patches.

**4. Vulnerability backlog — confirmed findings** (`falcon_search_vulnerabilities`)

The vulnerability backlog on this tenant is dominated by EASM "potential" findings —
banner-grab guesses on internet-facing assets with `confidence: 'potential'` and
`risk_score: 0`. Mixing these with confirmed sensor detections produces an
apples-to-oranges number that misleads in leadership reports. **Split the count.**

```
filter: status:'open'+cve.severity:'CRITICAL'+confidence:'confirmed'
limit:  3
```

This is the **headline number** — confirmed vulnerabilities found by a Falcon sensor
on a managed host. Report it as the primary backlog.

**4a. Vulnerability distribution by cloud group → account**

The Spotlight vulnerability API does not have cloud-group or cloud-account FQL fields
directly. To show the hierarchy the operator needs:

1. From the cloud groups cached in step 3a, iterate the top groups (by environment
   priority: production first, then staging, then dev).
2. For each group, use the account_ids from the group's selectors to filter
   vulnerabilities by `host_info.tags` if the accounts tag their hosts, or note the
   gap. If host tags are not usable, use the `aid` values from cloud risks that
   overlap with vulnerability hosts to build the mapping.
3. Alternatively — and often more practical — report the cloud-risk → account
   hierarchy from step 3b as the cloud-native vulnerability view, and note that
   Spotlight confirmed vulns are host-centric and don't carry cloud-group metadata.

The goal is: the operator sees "Production / Finance: 3 accounts, 42k critical vulns"
not an undifferentiated 602k. If the data doesn't support the full hierarchy, say so
and report what you can: per-platform (`host_info.platform_name`) or per-criticality
(`host_info.asset_criticality`) splits are always available and still useful.

**5. Urgent confirmed subset** — same call plus
`+cve.exprt_rating:['HIGH','CRITICAL']`. Actively exploited beats theoretically
severe, and the gap between 4 and 5 is the most useful number in the brief:
the difference between the confirmed backlog and the work that matters right now.

**6. EASM potential count (context, not headline)**

```
filter: status:'open'+cve.severity:'CRITICAL'+confidence:'potential'
limit:  1
```

Report `pagination.total` as a separate line: "N EASM potential findings excluded
from the above — banner-grab inferences on internet-facing assets, not confirmed
scanner detections." One record at `limit: 1` is enough to confirm the pattern
(`risk_score: 0`, `host_info.managed_by: 'Unmanaged'`). If leadership wants the EASM
findings tracked, they belong in a separate workflow with different SLAs, not mixed
into the sensor backlog.

**7. Sensor health** (`falcon_search_hosts`)

```
filter: last_seen:<'<14 days ago ISO8601>'
sort:   last_seen.asc
limit:  5
```

**`limit: 5`, not 25** — host records are the largest payload in this skill (~13k
characters each; 25 overflows the tool result outright). The count you report comes
from `pagination.total`. Sort ascending so the five you do see are the longest-silent
ones, which are the ones worth naming.

Hosts that stopped reporting are blind spots, and a blind spot is worse than a
known bad host because nothing will alert on it. Check the `platform_name` spread
across your five: mobile sensors dropping off and Linux nodes dropping off have
different root causes and belong in different queues, so say which you're looking at
rather than reporting one undifferentiated number.

**8. Unmanaged assets** (`falcon_search_unmanaged_assets`, `limit: 5`) — discovered
by a sensor on something else, with no sensor of their own. Same argument as 5, one
step further out: these have never been visible. Needs the `discover` module in
`FALCON_MCP_MODULES`; if the tool is absent, that is a configuration gap and goes
under **Not checked**.

Keep 7 and 8 even when the operator is in a hurry. They are the only findings that
are an absence, and an absence never announces itself.

**9. Container images** (`falcon_search_images_vulnerabilities`)

```
filter: cvss_score:>7
sort:   images_impacted.desc
limit:  10
```

These records are small, so 10 is affordable and the ranking is the point: one CVE in
a base layer shows up as thousands of `images_impacted`, which is a single fix with
enormous reach — a far better next step than any individual host patch. Read
`exploited_status_string` and prioritise `Actively used` over a higher CVSS that
nobody is using. Pair with `falcon_count_kubernetes_containers` for the running-
workload denominator.

**9a. Container operational context** (`falcon_search_kubernetes_containers`)

After identifying the top CVEs in 9, pick the highest-impact one (most
`images_impacted` with worst `exploited_status_string`) and query running containers
that carry it:

```
filter: cve_id:'<top CVE ID>'+running_status:true
sort:   last_seen.desc
limit:  10
```

From the results extract: `cloud_account_id`, `cloud_name`, `cloud_region`,
`cluster_name`, `namespace`, `pod_name`, `image_registry`, `image_repository`,
`image_tag`. This tells the operator **where the vulnerable image is actually
running** — not just that it exists in a registry.

Report as a table or grouped list:

```
Registry: <image_registry>/<image_repository>:<image_tag>
  Cloud: <cloud_name> / account <cloud_account_id>
  Cluster: <cluster_name> / namespace: <namespace>
  Running pods: <pod_name> (and N others)
```

If the top CVE spans multiple registries or clusters, group by registry first, then
by cluster. The operator needs to know: is this one registry feeding everything, or
are multiple registries carrying the same vulnerable base layer?

If `image_registry` is available in the image vulnerability record itself (the
`registry` FQL field), you can also filter step 9 by registry to show per-registry
vulnerability counts. The FQL guide confirms `registry` is a filterable field on
`falcon_search_images_vulnerabilities`.

This capability **works on this tenant** — verified 2026-08-29. If a stale note tells
you otherwise, re-read the "Not checked" rule above and call the tool.

**10. Threat intelligence**, only if there is a hook for it. If a detection names a
tactic or an actor, `falcon_search_actors` adds genuine context. Generic intel
attached to a brief with no hook for it reads as padding.

### There is no incidents module

falcon-mcp 0.17.0 removed it: `falcon_search_incidents` and `falcon_show_crowd_score`
do not exist, and naming `incidents` in `FALCON_MCP_MODULES` is a startup abort, not a
warning. Correlate from the detections in step 1 instead and say that is what you did.

There is no MCP tool for CrowdScore and no REST-based fallback in this harness.
If the `SessionStart` hook did not print a CrowdScore value, you have no way to
check it this run. Do not list it under **Not checked** unless you actually
attempted a call that was refused — a stale note from `doctor.sh` does not count.

### Counting through MCP

Every search tool returns `pagination.total` — the real count of matching records,
independent of your `limit`. Read it and report it. Totals in the hundreds of
thousands come back fine at `limit: 3`.

That is the whole reason the limits in this skill are small: the count and the
examples come from different parts of the same response, and only the examples cost
context. Never report a returned row count as the total, and never write "25+" — a
capped floor when the exact number was sitting in the same payload is a worse answer
than the number.

`pagination.total` is occasionally `null` when the API declines to count. Only then is
the row count a floor; say so explicitly, or get the real number from
`scripts/falcon_api.py` over raw REST.

## How to write it

Aim for something an operator reads in under ninety seconds.

```markdown
## Posture brief — <date>

**Bottom line:** <one sentence. The single most important fact.>

### Needs attention today
1. <finding> — <why it matters> — <suggested next step>
2. ...

### Cloud posture
- <n> open critical/high cloud risks across <providers>
  - **<Cloud Group Name>** (<environment>, <business_impact>):
    - <account_name> (<account_id>): <n> risks — top rule: <rule_name>
    - <account_name>: <n> risks — top rule: <rule_name>
  - **<Cloud Group Name>** or **Ungrouped accounts**:
    - ...
  - Production accounts: <n> risks (if checked)

### Container images
- <n> CVEs with CVSS >7 across <n> images; <n> running K8s containers total
- Worst base-layer CVE: <CVE-ID> (<description>, CVSS <score>, <exploited_status>)
  - <images_impacted> images, <containers_impacted> running containers
  - Registry: <image_registry>/<image_repository>:<image_tag>
  - Cloud: <cloud_name> / account <cloud_account_id>
  - Clusters: <cluster_name> / ns: <namespace> / pods: <pod_name> (+N)

### Vulnerability backlog (confirmed sensor findings only)
- <n> open critical vulnerabilities (confirmed by Falcon sensor)
  - By cloud group (if available):
    - <Group>: <n> critical across <m> accounts
  - Or by platform/criticality if cloud groups unavailable
- <n> with high/critical ExPRT rating (actively exploited)
- <n> EASM potential findings excluded — banner-grab inferences, not confirmed

### Blind spots
- <n> hosts not seen in 14+ days
- <n> unmanaged assets with no sensor

### Not checked
- <capability> — refused this run with <403 | 404> | nothing refused this run
```

Rules that make the difference between a brief and a data dump:

- **Lead with the bottom line.** If the operator reads one line, it must be the
  right one.
- **Rank by what is actionable now**, not by severity label. An unassigned critical
  detection outranks a larger vulnerability backlog.
- **Every item gets a suggested next step.** A finding without a next step is just
  news.
- **"Not checked" is for refusals you saw this run**, quoted with their status. If
  nothing refused you, the section is one line: "nothing refused this run." Omitting
  it reads as "all clear"; padding it with stale claims is worse — it reports working
  capabilities as gaps.
- **Numbers, not adjectives.** "47 hosts" beats "several hosts."
- **Never upgrade "not checked" into "not licensed."** Those are different claims and
  only one of them is yours to make.

## Offer the follow-through

End by offering the obvious next move and let the operator choose — "the detection
on the AKS node pool is the thread worth pulling; want me to trace which image it
came from?" That is `/image-sprawl`; for the vulnerability backlog it is
`/trace-vm-image`. The brief's job is to identify the thread; those skills pull it.
