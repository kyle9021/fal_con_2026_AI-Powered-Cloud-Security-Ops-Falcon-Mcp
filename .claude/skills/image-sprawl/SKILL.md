---
name: image-sprawl
description: Container incident triage. Starts from a high-severity detection in a Kubernetes cluster, identifies the container image behind it, then finds every other place that image is running across all clusters and clouds. Use when triaging a container or Kubernetes detection, or when asked "where else is this image running" / "what is our exposure to this image".
---

# From one detection to full image exposure

## The idea behind this playbook

A container detection looks like one compromised workload. It usually is not.

Containers are stamped from images, and images get reused — across namespaces,
across clusters, across clouds, by teams who have never met. So the operational
question is never "what happened on this pod". The pod is ephemeral; it may
already be gone. The question is **which image caused this, and where else is
that image running right now?**

That reframing is the entire value of this playbook. It converts a single alert
into a scoped blast radius.

## What this needs

**The Falcon MCP server and nothing else** — `falcon_search_detections`,
`falcon_search_kubernetes_containers` and `falcon_search_images_vulnerabilities`.
No `kubectl`, no cloud CLI, no cluster access. This runs entirely from Falcon's
own inventory, which is the point: it sees clusters you may not have credentials
for.

Scopes required: **Alerts** (Read), **Kubernetes Protection** (Read), and
**Falcon Container Image** (Read) for Step 4. Without Kubernetes Protection there
is no sprawl answer at all.

## Context discipline

Container inventory responses are large and repetitive. Before you start:

- Never fetch full container records for a broad filter. Filter server-side.
- Keep only the fields listed in each step. Discard the rest as you go.
- **Do not use `falcon_count_kubernetes_containers`.** On current builds it
  returns a payload the tool's own schema rejects, producing a pydantic
  `int_type` validation error. Use `falcon_search_kubernetes_containers` and
  count the results yourself. This is a known upstream defect, not your mistake.

Steps 3 and 4 are independent and run concurrently in `falcon-query` subagents —
see `docs/parallelism.md` for the rules that keep a parallel run honest, in
particular that a branch which came back `denied` is not a branch that came back
empty.

## Step 1 — Find the detection

There are **two different kinds of container detection**, and they need different
routes through this playbook. Establish which one you have before going further,
because the wrong route dead-ends.

### Route A — an image scan detection (`product:'cwpp'`)

These come from Falcon Cloud Security scanning images in a registry or CI
pipeline. They are the shortcut: the detection record already carries the image
identity, so **Step 2 is unnecessary — skip straight to Step 3.**

```
filter: product:'cwpp'
sort:   timestamp.desc
limit:  20
```

Keep `image_registry`, `image_repository`, `image_tag`, `image_digest`,
`detection_type`, `name`, `severity_name`, and `cwpp_image_combined_name`.

**Do not filter these by high severity.** Image scan findings — exposed
credentials, embedded secrets, misconfiguration — are frequently rated
`Informational` while being exactly what you want to chase. Filtering
`severity_name:'High'` on this route is how you conclude, wrongly, that there is
nothing to look at. Filter on `detection_type` or `name` instead if you need to
narrow.

### Route B — a runtime detection on a cluster node

A sensor detection on the host that happens to be a Kubernetes node. Here you do
need the Step 2 pivot, because the detection knows the node, not the image.

```
filter: (severity_name:'High',severity_name:'Critical')+status:'new'
sort:   timestamp.desc
limit:  20
```

**Do not scope this with a guessed hostname pattern.** Node naming is entirely
tenant-specific — EKS nodes look like `ip-10-0-1-42.ec2.internal`, AKS nodes
like `aks-nodepool1-00000000-vmss00000u`, and plenty of nodes match neither. A
pattern like `device.hostname:'aks-*'` returns zero on a tenant that has no AKS,
which reads as "no detections" rather than "wrong guess". If you need to know
which of your hosts are cluster nodes, ask the inventory instead — host records
carry `k8s_cluster_id`, and it is populated only on nodes.

Confirm with the operator which detection to pursue if several look plausible.
Pursuing the wrong one wastes the whole chain.

From the detection keep: detection ID, severity, tactic/technique, timestamp,
`agent_id`, `device.hostname`, and any process or file indicators. **`agent_id` is
the one that matters for Step 2.**

## Step 2 — Identify the image behind it

*Route A already has the image. Skip to Step 3.*

Pivot from the affected host into the container inventory. Join on the **agent
ID**, not the hostname:

```
falcon_search_kubernetes_containers
filter: agent_id:'<agent_id from step 1>'
limit:  50
```

**Why not the hostname.** `node_name` does often equal the host's `hostname`
exactly — verified on EKS. But it is a string join on a field that is not
normalised: the same AKS node was returned as both `...vmss00000U` and
`...vmss00000u` in the same inventory, differing only in case. `agent_id` is the
sensor's own identifier, present on both records, and it either matches or it
does not. Use `node_name:'<hostname>'` only as a fallback when the detection has
no agent ID, and if it returns nothing, try the other casing before concluding
the node is empty.

**FQL field-name warning.** Some tool description examples in this module are
wrong. The tool's own example shows `cloud:'AWS'`; the authoritative field is
`cloud_name`. Always read `falcon://cloud/kubernetes-containers/fql-guide`
before composing a filter here, and trust the guide over the tool description.

A node runs many containers, most of them platform infrastructure — pause
sandboxes, CSI drivers, log shippers. Narrow to the right one using the
detection's timestamp, pod name, or namespace, and be suspicious of a `kube-system`
answer. Then record the image identity:

- `image_repository`
- `image_tag`
- `image_digest`  ← this is the one that matters

Use the **digest**, not the tag, as the identity for Step 3 wherever it is
available. Tags are mutable: `:latest` on two clusters can be two different
images, and the same digest can wear several tags. If you only have a tag, say
so and treat the result as approximate.

**Digest formats differ between sources.** Container inventory records prefix the
digest (`sha256:a1b2c3d4…`); `cwpp` detection records give the bare hex (`a1b2c3d4…`).
Normalise before comparing or filtering, or an identical image will look like two.

## Steps 3 and 4 run at the same time

Once you have the image identity, the two remaining questions are independent:
*where else does this run* (Step 3) and *what is wrong with the image itself*
(Step 4). Neither needs the other's answer, so dispatch both `falcon-query`
subagents in **one message** and read the specifications below as the brief for
each:

```
Agent(subagent_type="falcon-query", prompt="<Step 3 brief: the sprawl search>")
Agent(subagent_type="falcon-query", prompt="<Step 4 brief: the image's CVEs>")
```

Two branches is a modest speed win. The real reason to do it is that Step 3 at
`limit: 500` returns a long, repetitive container inventory — the branch that reads
it should not be the one holding your reasoning. A subagent hands back the
aggregated table and the counts; the 500 records stay where they were read.

Give each brief the **normalised** digest and say which form you normalised to. A
subagent that has to guess whether to add the `sha256:` prefix will report a zero
for an image that is running in thirty places, and a zero is exactly the kind of
answer nobody questions.

Then apply `docs/parallelism.md`: if a branch comes back `denied` (no Kubernetes
Protection scope, or no Falcon Container Image licence) that is **not** a zero, and
the report says "not established by this run" for that section rather than dropping
it. A missing Step 4 with no explanation reads as "the image is clean".

## Step 3 — Find every other place that image runs

Now widen deliberately. Search the whole inventory for the same image:

```
falcon_search_kubernetes_containers
filter: image_repository:'<repo>'
limit:  500
```

If the repository name is long or you only have a fragment, use a contains
match — note the `*'*...*'` form, which is FQL's substring syntax:

```
filter: image_repository:*'*<fragment>*'
```

An empty result is a real answer, not a failure. It means the image is not
running anywhere the sensor can see. Report that plainly.

This is common and expected on Route A: an image scan detection fires against
something in a registry or CI pipeline that was never deployed, or is no longer
running. "This image carries exposed credentials and is not currently running
anywhere" is a genuinely useful finding — it says fix it before it ships, not
after. Do not present it as an inconclusive result.

Aggregate the results into counts. Do not paste the container list:

| Cluster | Namespace | Cloud / Account | Running containers | Image tags seen |
|---|---|---|---|---|

Flag two things specifically:
- **Tag drift** — the same repository running multiple digests. That means some
  workloads are already on a newer or older build than the one you triaged.
- **Cross-boundary sprawl** — the image running in more than one cloud account
  or cluster, which widens both the blast radius and the number of owners who
  must act.

## Step 4 — Assess the image itself

```
falcon_search_images_vulnerabilities
filter: repository:'<image_repository from Step 2>'
sort:   cvss_score.desc
limit:  50
```

The filterable fields on this endpoint (verified against the FQL guide):
`cve_id`, `cvss_score`, `severity`, `registry`, `repository`, `tag`,
`image_id`, `image_digest`, `container_running_status`, `cps_rating`.

Example filters:
- By repository: `repository:'crowdstrike/vulnapp'`
- By CVE: `cve_id:'CVE-2026-5435'`
- By registry + severity: `registry:'quay.io'+severity:'Critical'`
- Running containers only: `container_running_status:true+cvss_score:>7`

This answers whether the detection is a symptom of a known-vulnerable image or
something new. Note the `images_impacted` field — a high number means the
vulnerable layer is shared far beyond this one image.

## Step 5 — Report the exposure

Structure the answer so a responder can act inside a minute:

1. **What fired** — one sentence: detection, severity, cluster.
2. **The image** — repository, tag, digest.
3. **Blast radius** — N containers across M clusters and K accounts. Lead with
   this number; it is the finding.
4. **Tag drift and cross-account sprawl**, if present.
5. **Known vulnerabilities** in the image, worst first.
6. **What a human must decide** — see below.

### Render it as a dashboard

Sprawl is a table, and a table is easier to act on when it is not scrolling past
in a chat window. Produce a viewable artifact:

```python
import sys; sys.path.insert(0, "scripts")
from falcon_report import Report

report = Report(
    "Container image exposure",
    subtitle="<repository>@<digest>",
    scope="<what you actually searched>",
)

# The blast radius is the finding, so it is the verdict -- not a cell in row 3.
report.verdict(
    "This image is running in 34 containers across 4 clusters and 2 cloud "
    "accounts. Rotating the exposed credential requires coordinating with 2 "
    "account owners, not 1.",
    tone="critical",
)

# Metrics should nest: each number is a subset or breakdown of the one above.
# See crystallize/SKILL.md "Metrics must use the same counting basis."
report.metric("Running containers", 34, tone="critical")
report.metric("Clusters", 4, note="across 34 containers", tone="high")
report.metric("Cloud accounts", 2, note="widens the owner list", tone="high")
report.metric("Distinct digests seen", 3, note="tag drift")
report.gap("Registry scan coverage was not checked.")

report.table(
    "Where it runs",
    ["Cluster", "Namespace", "Cloud / Account", "Containers", "Running", "Tags seen"],
    rows,
    numeric=[3, 4],
    bar=3,        # containers -- so the worst cluster is visible, not counted
    rank=True,
    mono=[4],     # tags: long, and their exact bytes are the point
)
report.table(
    "Known vulnerabilities",
    ["Severity", "CVE", "CVSS", "Images impacted", "Flags"],
    cves,
    numeric=[2, 3],
    accent=0,     # a single severity word, nothing else -- see below
    mono=[1],
    badges=[4],   # "KEV", "Public exploit", "No known exploit"
)
report.table(
    "Detection triage — is the scanned image actually deployed?",
    ["Reported registry", "Image name", "Image tag", "Deployment state",
     "Detections", "Share"],
    triage_rows,
    numeric=[4],
    note="Cross-references detections against container inventory. "
         "'not deployed anywhere' means the digest exists in a registry scan "
         "but no running or stopped container matches it — fix before it ships, "
         "not after. 'iar' is Image Assessment at Runtime (always running by "
         "construction).",
)
html_path, _ = report.save("image-exposure")
```

Build the aggregation with Python via Bash so the container list never enters your
context. Output goes to `findings/`, which is gitignored — it names your clusters,
namespaces and accounts. The HTML is self-contained, has no JavaScript and makes
no outbound request when opened.

Note the column order in the second table: **`Severity` moved to position 0** so
`accent` can read it. An `accent` column must contain a single severity word —
`critical`, `high`, `medium`, `low` — and nothing else; a cell reading
`Critical (KEV)` matches no severity and the row silently loses its tint. Put the
qualifier in `badges` instead, which is what badges are for.

**An empty sprawl result still gets a dashboard.** "This image carries exposed
credentials and is running nowhere" is a finding worth showing someone. The
renderer says so explicitly rather than rendering a blank table.

### Show the evidence — this is not optional

"This image runs in 34 containers across 4 clusters" is a number someone will act
on, so it has to be checkable. Record the provenance as you go:

```python
report.query("falcon_search_detections", "product:'cwpp'+severity_name:'Critical'",
             limit=50, returned=0,
             note="Image-scan detections here are rated Informational, not "
                  "Critical -- filtering on severity returns nothing and reads "
                  "as 'no findings'. Shown so the empty result is not mistaken "
                  "for a clean image.")
report.query("falcon_search_kubernetes_containers",
             "image_digest:'a3f1c0…' (bare hex, no sha256: prefix)",
             limit=1000, returned=34)

report.code("Evidence — image identity, straight from the detection",
            "image_registry    <registry>\n"
            "image_repository  <repo>\n"
            "image_digest      a3f1c0…      <- bare hex here\n"
            "container inventory reports:  sha256:a3f1c0…\n"
            "Normalised before joining, or one image counts as two.")
```

Three things this playbook in particular must show:

1. **Every query, including the empty ones.** A `product:'cwpp'` search filtered
   to Critical returning zero is not "the image is clean" — it is the severity
   filter doing the wrong thing. Recording the query is what makes that visible
   instead of reassuring.
2. **The join key and any normalisation you applied.** Digests arrive bare-hex
   from detections and `sha256:`-prefixed from inventory; node names have come
   back in two casings from the same cluster. If your count depended on
   reconciling those, the dashboard says how.
3. **The container rows themselves**, not just the total. A reader who cannot see
   the 34 rows cannot tell whether one namespace accounts for 30 of them — which
   changes the remediation entirely.

### If they will want this again

Offer `/crystallize`. "Which images run in more than one cluster" is a standing
question, not a one-off — it converts cleanly into a scheduled script that needs
no model and no tokens, and renders the same dashboard every morning.

## What this playbook does not do

It does not contain hosts, kill pods, delete images, or patch anything. The
harness blocks those tools by default and that is intentional: containing a node
in a production cluster can take out a service, and that call belongs to whoever
carries the pager for it.

Instead, hand over decision-ready options:

- Rebuild the image from a patched base, or roll back to a known-good digest.
- Which namespaces to drain first, in dependency order.
- Whether to contain the originally affected node now, and who must approve it.
- The owners to notify for each cluster the image reaches.
