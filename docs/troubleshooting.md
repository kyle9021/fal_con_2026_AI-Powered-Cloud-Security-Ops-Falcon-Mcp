# Troubleshooting

Every entry here is a failure that actually happened while building and testing
this harness against a live tenant. Start with the doctor:

```bash
./scripts/doctor.sh
```

---

## Authentication

### 403 at the token endpoint

**The most common setup failure, and the biggest time sink.** Almost always the
wrong region in `FALCON_BASE_URL`. A perfectly valid credential pointed at the
wrong cloud fails identically to a revoked one.

```bash
FALCON_BASE_URL=https://api.crowdstrike.com          # US-1
FALCON_BASE_URL=https://api.us-2.crowdstrike.com     # US-2
FALCON_BASE_URL=https://api.us-3.crowdstrike.com     # US-3
FALCON_BASE_URL=https://api.eu-1.crowdstrike.com     # EU-1
FALCON_BASE_URL=https://api.laggar.gcw.crowdstrike.com   # US-GOV-1
FALCON_BASE_URL=https://api.us-gov-2.crowdstrike.mil     # US-GOV-2
```

Check the region in the Falcon console URL. If the region is right, then in order:
the client was revoked, the secret was truncated when copied, or the key belongs
to a different CID.

Confirm it is not the harness by testing the credential directly:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  "$FALCON_BASE_URL/oauth2/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "client_id=$FALCON_CLIENT_ID&client_secret=$FALCON_CLIENT_SECRET"
```

`201` is success. `403` from raw curl means the credential is genuinely bad — stop
debugging the harness.

### 401 rather than 403

Malformed credentials. Look for trailing whitespace, wrapping quotes, or a line
break pasted into the middle of the secret. `.env` values need no quotes.

---

## Tools return nothing

Three different situations look identical from the model's side. Getting them
confused is the most dangerous failure in this harness.

| Response | Meaning | Action |
|---|---|---|
| 401 / 403 | Missing scope | Add it — the doctor names it |
| 404 | Not licensed or enabled on this tenant | Nothing to fix |
| 200, empty results | **A correct answer.** No matching data | Report it as such |

**Never report a missing scope as "no findings."** "No critical vulnerabilities"
when the truth is "no Vulnerabilities:read scope" is how a harness produces
false assurance.

### A feature returns 404

Some features are not provisioned on every tenant. The posture brief skips
unavailable capabilities and says so. A 404 is not a permissions problem — no
scope will fix it.

### Empty results that should not be empty

Check, in order:

1. **Field name.** Half of all FQL problems. See the field-name warnings below.
2. **Quoting.** `status:'open'` — single quotes around values, always.
3. **Case.** Values are usually case-sensitive: `cve.severity:'CRITICAL'`, but
   `severity_name:'Critical'`. Inconsistent across modules; check the FQL guide.
4. **Time format.** ISO 8601 with `Z`: `'2026-08-01T00:00:00Z'`.
5. **Module loaded.** If the tool is not in `FALCON_MCP_MODULES`, it does not exist.

---

## FQL

### Wrong field names in tool descriptions

Real and confirmed: `falcon_search_kubernetes_containers` shows `cloud:'AWS'` in
its own example. The correct field is **`cloud_name`**.

The authoritative source is the FQL guide resource for the module:

```
falcon://cloud/kubernetes-containers/fql-guide
falcon://spotlight/vulnerabilities/fql-guide
falcon://hosts/search/fql-guide
falcon://incidents/search/fql-guide
```

**Read the guide, not the tool description.** When they disagree, the guide is
right.

### Contains / substring matching

The syntax is easy to get subtly wrong:

```
image_repository:*'*juice*'     # correct
image_repository:'*juice*'      # not a contains match
```

### Operator quick reference

```
+   AND            ,   OR             !   not equals
~   text match     *   wildcard       :>  greater than
field:['A','B']    in list
```

---

## Spotlight: pagination and nested fields

### `offset` is silently ignored, and the `after` token is unreachable over MCP

`falcon_search_vulnerabilities` accepts an `offset` parameter and appears to
honour it. It does not — page 2 returns the same records as page 1. The API
paginates with an opaque `after` token carried in
`meta.pagination.after`, and the MCP tool exposes no parameter to send it back.

The practical consequences:

- **A single MCP call is your whole result set.** Raise `limit` rather than
  attempting to page.
- **Past roughly 1,000 records the connection closes** mid-response. Treat ~1,000
  as the working ceiling and narrow the filter instead.
- If a result set hits the limit, **say the answer is truncated.** A partial
  ranking presented as complete is worse than a scoped one, because nobody knows
  to distrust it.

This is the single strongest argument for `/crystallize`: the REST API paginates
properly with the `after` token, so a crystallized script can read the full set
that the interactive session structurally cannot.

### KEV status is nested two levels down

The CISA Known Exploited Vulnerabilities flag is not a top-level field:

```
cve.cisa_info.is_cisa_kev        # correct
cve.is_cisa_kev                  # does not exist
is_cisa_kev                      # does not exist
```

Both wrong forms fail as an empty result rather than an error, which reads as
"nothing in our environment is on the KEV list" — a reassuring and false
conclusion. Related: `cve.exploit_status` is a number (`90` = a public exploit
exists), and `cve.exprt_rating` is a string.

### CVSS severity is not urgency

`cve.severity:'CRITICAL'` is the CVSS band. `cve.exprt_rating` is CrowdStrike's
assessment of whether it is actually being exploited. They disagree constantly,
and the gap is the whole point of prioritising: a live investigation found 76
CVSS-critical findings on one host of which 9 had a public exploit.

Rank on `exprt_rating` and `exploit_status`. Use `cve.severity` to scope, never to
prioritise.

---

## CSPM assets: four specific traps

The cloud asset inventory is the richest source in the harness and the easiest to
get wrong. All four of these were hit while building `/trace-vm-image`.

### A filter that looks right returns the wrong record type

Several asset types share a single `resource_id`. An EC2 instance ID also matches
that instance's `AWS::Inspector::Coverage` record, and possibly others.

```
# Ambiguous -- returns whichever type it finds first
filter: resource_id:'i-0123456789abcdef0'

# Correct -- always pin the type
filter: resource_type:'AWS::EC2::Instance'+resource_id:'i-0123456789abcdef0'
```

This fails quietly. You get a valid record, for the wrong thing.

### `configuration` is a JSON string, not an object

Both `configuration` and `supplementary_configuration` are serialized JSON
delivered as strings. They must be parsed before you can read anything out of
them, and a naive walk over the response's keys will step straight past their
contents.

That is how the AMI hides: `configuration.imageId` exists, but only after parsing.
For `AWS::Inspector::Coverage`, the string parses to a JSON *array*, and the AMI
sits at `[0].resourceMetadata.ec2.amiId`.

### One EC2 instance record is ~139 KB

About 35,000 tokens, for one instance. See
[context-discipline.md](context-discipline.md). Filter to specific instance IDs,
extract, discard. Never query the type unfiltered.

### A hit and a miss come back in different envelopes

`falcon_search_cspm_assets` does not return an empty list when nothing matches. A
hit and a miss are shaped differently:

```
hit   { "resources": [ {...} ] }
miss  { "resources": [], "meta": {...} }   -- or the resources key absent entirely
```

Code that reads `response["resources"][0]` works right up until the first miss,
then raises. Every access in this harness goes through
`.get("resources") or []` for that reason. A `KeyError` here is not a bug in your
filter — it *is* the empty answer, arriving in a shape you did not plan for.

### Where the AMI actually lives

For the record, since this is easy to conclude wrongly — **Falcon does have the
instance-to-AMI mapping.** It is not in the host record (`falcon_search_hosts`
returns `instance_id` but no image ID), and it is not in the CSPM *filterable*
field list. It is in the CSPM asset **payload**:

```
relationships[] where resource_type == "AWS::EC2::Image"
  → resource_id  = ami-...
  → crn          = aws|<account>|<region>|AWS::EC2::Image|ami-...

configuration (parse first) → imageId = ami-...
```

The filterable-field guide and the returned payload are different things. Not
finding a field in the FQL guide means you cannot *filter* on it, not that it is
absent.

---

## Kubernetes containers and image detections: the join traps

Everything here was observed on a live tenant while building `/image-sprawl`.
Every one of them produces a plausible wrong answer rather than an error.

### The same image has three different registry identities

One image, as reported by three different parts of Falcon:

```
container inventory        mcr.microsoft.com           <- no scheme
registry-scan detection    https://mcr.microsoft.com   <- scheme included
runtime-assessment         iar                         <- not a registry at all
```

`iar` is **Image Assessment at Runtime** — Falcon assessing an image it observed
running, rather than one it pulled from a registry. It appears in the
`image_registry` field, so a join on that field silently drops those findings, and
a report grouped by registry invents a registry called "iar".

**Never compare `image_registry` for equality.** Treat it as a label, and treat
`iar` as a scan source rather than a location.

### Digests are prefixed in one place and bare in the other

```
container inventory     image_digest = sha256:a1b2c3d4e5f6...
cwpp detection          image_digest = a1b2c3d4e5f6...
```

Strip `sha256:` before joining. On the tenant this was measured on, joining
without normalising matched **nothing**; after normalising, 4 of 12 running
digests matched. Zero and four are both believable numbers, which is exactly why
this fails quietly.

### Most registry-scan detections are for images nobody runs

Measured, on one component: 82 of 96 image-scan detections — **85%** — targeted
digests not deployed anywhere in the tenant. All 6 `iar` detections landed on
digests present in inventory, 4 of them running at that moment.

This is not a defect; it is what the two sources are for. Registry scanning covers
what *could* ship, runtime assessment covers what *is* running. But it means a
triage queue sorted by detection count spends most of its effort on undeployed
images. **Check sprawl before spending time on an image-scan finding.**

### `cluster_name` is not a usable key; `cluster_id` is

On the tenant measured: 102 container records, 9 distinct `cluster_id` values, and
only 7 apparent `cluster_name` values. The name was:

- **empty** on 35 of 102 records, spanning two different clusters, and
- **reused** — one name covered containers in both AWS and Azure.

Group on `cluster_id`. If you group on the name you will under-count clusters and
merge two clouds into one row, and both errors look like a tidy result.

### `cloud_region` is not always a region

On Azure/AKS records it carries the **node resource group**
(`MC_<rg>_<cluster>_<region>`). On AWS it carries an availability zone. Do not
label that column "region" without checking what is in it — it will be wrong for
one of your two clouds.

### `node_name` collides on case

Two nodes in a single inventory response differed only in the case of their final
character:

```
aks-nodepool1-00000000-vmss00000L
aks-nodepool1-00000000-vmss00000l
```

34 distinct `node_name` values became 32 after lowercasing. A string join on
`node_name` reports one node as two; a case-insensitive dedupe merges two real
nodes into one. Join on `agent_id` instead — present on 102 of 102 records here —
or `kac_agent_id` (93 of 102). Host records carry `k8s_cluster_id`, populated only
on nodes.

### Zero vulnerabilities does not mean zero findings

A record can carry `image_vulnerability_count: 0` alongside
`image_detection_count: 2`. Vulnerabilities and detections are separate counters:
misconfiguration, embedded secrets and posture findings arrive as detections and
never touch the vulnerability count.

An image reported as having no vulnerabilities can still be running as root, with
a writable root filesystem, on every node in nine clusters. A vulnerability-led
workflow calls that image clean.

### `image_has_been_assessed` distinguishes "clean" from "never scanned"

Null or false means no scan data exists — which renders as "no findings" in any
report that does not check the flag. On the tenant measured, 3 of 12 running
digests had never been assessed, carrying 11 running containers, and they were the
**newest** tags. The freshest deployment is the most likely to be unscanned.

Also note `image_assessed_at` is a **unix epoch integer**, not the ISO 8601 string
used almost everywhere else in the API.

### Image-scan detections are rated `Informational`

Covered in `/image-sprawl`, repeated here because it is the most costly mistake in
this module: filtering `product:'cwpp'` by `severity_name:'High'` or `'Critical'`
returns nothing on a tenant with real findings. Filter on `detection_type` or
`name` instead.

---

## Known upstream defects

### `falcon_count_kubernetes_containers` fails validation

Returns `[{'count': 345}]` while its schema declares `int`, producing a pydantic
`int_type` validation error. The count is correct; the tool cannot return it.

**Workaround:** use `falcon_search_kubernetes_containers` and count the results.

### `falcon_check_connectivity` reports failure while everything works

Observed returning a negative result on a tenant where every search tool
succeeded immediately afterwards. It probes something narrower than "can I reach
the API", so a false negative here says nothing about whether your credentials
work.

**Do not treat it as a gate.** If it fails, run an actual search — that is the
real test. `./scripts/doctor.sh` checks the token endpoint directly and is the
more trustworthy signal.

---

## Hooks

### The posture brief does not appear

By design it fails silently rather than blocking your session. To see why:

```bash
python3 .claude/hooks/posture-brief.py
```

Common causes: no `.env`; missing scopes (it will say which); the wall-clock
budget expired on a slow link (raise `HARNESS_BRIEF_BUDGET`); or a cached empty
result — clear `.cache/posture-brief.json` to force a refresh.

On conference or hotel wifi the budget is the usual culprit. `HARNESS_BRIEF_BUDGET=14`
is the practical maximum on the default config: the `SessionStart` hook in
`.claude/settings.json` has `timeout: 20`, and because the budget is checked
*before* each API call, the final call can still add its 6-second client timeout
on top. Set the budget higher than ~14 and Claude Code kills the hook mid-flight
— which writes no cache, so the next session pays the full cost over again. If
you want a longer budget, raise that hook timeout to match.

Disable it entirely with `HARNESS_BRIEF_DISABLE=true`.

### A tool I need is being denied

The guardrail is default-deny: anything that is not a recognised read verb is
blocked. Check the reasoning:

```bash
tail .cache/tool-audit.jsonl
```

- **A read tool wrongly denied** — that is a bug in the harness, not your setup.
  Its verb is missing from `READ_VERBS` in
  `.claude/hooks/guard-falcon-writes.py`. Add it, then add a case to
  `scripts/test-guardrail.sh`.
- **A write tool denied** — working as intended. Read
  [security.md](security.md) before setting `HARNESS_ALLOW_WRITES=true`.
- **A destructive tool denied** — stays blocked regardless of that setting.
  Containment and command execution belong to a human.

### Guardrail tests fail

```bash
./scripts/test-guardrail.sh
```

It prints which assertion failed. Two cases are regression tests for real bugs
and are worth understanding before you change the matching logic:

- `falcon_count_kubernetes_containers` must be **allowed** — "contain" appears
  inside "containers", which an early substring-matching version got wrong.
- `falcon_idp_investigate_entity` must be **allowed** — its read verb is the
  second token, not the first.

### I edited a skill and the change did nothing

Skills are read when the session starts. Editing a `SKILL.md` mid-session and then
invoking that skill runs the version Claude Code loaded at launch, not the one on
disk. Observed while building this harness, and easy to misread as "my edit was
wrong."

**Restart Claude Code after editing a skill.** The same applies to
`.claude/settings.json` hook wiring and `.mcp.json`.

---

## Sessions that degrade or die mid-investigation

Not a bug. You have exhausted the context window.

Symptoms: the model forgets earlier findings, repeats calls it already made, or
its answers get vaguer as the investigation goes on.

Read [context-discipline.md](context-discipline.md). The short version: filter
server-side, use facets instead of per-record follow-ups, and narrow the scope
rather than paginating through thousands of records. Counting is the awkward case —
the MCP server strips `meta.pagination.total`, so a count has to come from outside
the context window or be reported as a sampled floor.

---

## Setup

### `uvx: command not found`

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Then restart the shell. If `uv` is installed but `uvx` is not on `PATH`, try
`uv tool install falcon-mcp` and point `.mcp.json` at the installed binary.

### `.env` permissions failure

```bash
chmod 600 .env
```

The doctor treats this as a failure, not a warning. On a shared machine, a
644 credential file is readable by every other account on the box.

### `.env` is tracked by git

The doctor will tell you. **Rotate the credential in the console first** — it has
been cloned by anyone who pulled. Then:

```bash
git rm --cached .env
```

Cleaning history without rotating accomplishes nothing.

---

## Still stuck

Include in a bug report: `./scripts/doctor.sh` output with credentials redacted,
the exact tool name and filter, and the last few lines of
`.cache/tool-audit.jsonl`. Redact hostnames, cloud account IDs and cluster names
before sharing — see the data-handling note in [security.md](security.md).
