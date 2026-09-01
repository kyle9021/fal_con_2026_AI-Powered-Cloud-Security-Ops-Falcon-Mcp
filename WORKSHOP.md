# Workshop handout

Everything from the session, in a form you can work through at your own pace.
Nothing here needs the session recording.

**Time to first useful answer: about ten minutes.**

---

## Part 1 — Connect (10 minutes)

```bash
git clone <this-repo> falcon-mcp-harness
cd falcon-mcp-harness
cp env.example .env
chmod 600 .env
```

Create a read-only API client in the Falcon console — **Support and resources →
API clients and keys** — and grant these READ scopes:

| Console scope label | Tools it unlocks | Needed for |
|---|---|---|
| **Alerts** | `falcon_search_detections`, `falcon_aggregate_detections`, `falcon_get_detection_details` | Detections, posture brief |
| **Hosts** | `falcon_search_hosts`, `falcon_get_host_details` | Host inventory, sensor health |
| **Vulnerabilities** | `falcon_search_vulnerabilities` | Spotlight CVEs, `/trace-vm-image` |
| **Falcon Container Image** | `falcon_search_kubernetes_containers`, `falcon_count_kubernetes_containers`, `falcon_search_images_vulnerabilities` | Container inventory, image vulns, `/image-sprawl` |
| **Cloud Security API Assets** | `falcon_search_cspm_assets` | Instance-to-image resolution, `/trace-vm-image` |
| **Cloud Security API Risks** | `falcon_search_cloud_risks` | Cloud risk posture in brief |
| **Cloud Groups V2** | `falcon_search_cloud_groups`, `falcon_get_cloud_groups` | Cloud group hierarchy in brief |
| **Cloud Security API Detections** | `falcon_search_iom_findings` | IOM findings |
| **Assets** | `falcon_search_unmanaged_assets`, `falcon_search_managed_assets`, `falcon_search_applications` | Unmanaged/managed assets, app inventory |

**Optional but recommended:**

| Console scope label | Tools it unlocks | Needed for |
|---|---|---|
| **Actors** (Falcon Intelligence) | `falcon_search_actors`, `falcon_get_mitre_report` | Threat actors, MITRE reports in brief |
| **Indicators** (Falcon Intelligence) | `falcon_search_indicators` | IOC search |
| **Reports** (Falcon Intelligence) | `falcon_search_reports` | Intelligence reports |
| **Cloud Security Policies** | `falcon_search_cspm_suppression_rules` | Suppression rule review |

Grant all nine required scopes before the workshop. The posture brief runs at
session start and touches most of them — a missing scope produces a "not checked"
gap, not an error, but a brief full of gaps is not the opening you want.

Demo 3 (`/crystallize`) needs no additional scope — it reuses whichever ones the
investigation it crystallizes already used.

Console scope labels vary between tenant versions and regions. If a name above
doesn't match exactly, look for the closest match on the same product.
`./scripts/doctor.sh` is the authority — it probes each capability against your
live tenant.

Full detail in [docs/api-scopes.md](docs/api-scopes.md).

Put the client ID, secret and your region's base URL into `.env`. The region is
the single most common setup mistake; the table is in `env.example`.

> **Best practice:** In production, use a secret manager (1Password CLI, AWS
> Secrets Manager, HashiCorp Vault) instead of a `.env` file. Point the
> `--env-file` argument in `.mcp.json` to a wrapper script that fetches
> credentials at launch, or export them from your shell profile so they never
> touch disk. For the workshop, `.env` is fine — but do not commit it, and
> rotate the secret after the session.

Then verify before you do anything else:

```bash
./scripts/doctor.sh
```

Green means connected. Any failure prints the specific next action. If you get a
403, check the region first — a valid key pointed at the wrong cloud looks exactly
like a bad key.

Now start Claude Code in this directory. You should see a posture brief before
you type anything.

---

## Part 2 — The three demos

The first two are investigations. The third turns an investigation into something
that runs without you.

### Demo 1 — From a vulnerability list to a fix

```
/trace-vm-image
```

Or in your own words: *"Which of our cloud instances have critical
vulnerabilities, and which base images did they come from?"*

**The point of this demo.** A list of 200 vulnerable instances is a to-do list. A
list of 3 bad images is a fix. Patch the instances and the next autoscaling event
reintroduces the same CVE; fix the image and every future instance inherits the
fix.

What the playbook does:

1. Scopes the question — account, region or tag.
2. Pulls open critical vulnerabilities with the `host_info` facet, so each finding
   arrives with its affected asset attached.
3. Resolves instances to their base images.
4. Ranks images by blast radius: instances affected × distinct critical CVEs,
   with actively-exploited CVEs promoted regardless of count.
5. Renders the result as a self-contained HTML dashboard in `findings/`.

**It does not write a remediation script, on purpose.** Rebuilding an image is a
change-managed activity owned by whoever runs the platform, and a generated script
full of instance IDs, image IDs and owner names is a liability sitting in a working
tree. The playbook ends at a ranked, evidenced recommendation and names the
decisions that stay with a human.

**The dashboard is the demo artifact.** One HTML file, no JavaScript, no CDN
reference, `Content-Security-Policy: default-src 'none'`, everything HTML-escaped,
written mode `0600`. It makes no network request when you open it, which is what
makes it safe to put on a projector or hand to someone who was not in the room.
A matching `.json` lands beside it for anything downstream.

**The finding that changes the answer.** On a live tenant this demo returned 76
CVSS-critical CVEs on the top image. Of those, ExPRT rated 10 CRITICAL, 25 HIGH —
and **32 LOW**. Nine had a public exploit available. So the real queue was 10
items, not 76: **CVSS severity is not the workload, ExPRT rating is**, and the gap
between them was about sevenfold. Rank on `cve.exprt_rating` and
`cve.exploit_status`, and treat `cve.severity` as a filter, not a priority.

One more thing that inverts the obvious conclusion: on that tenant the instances
were one day old and the images were five years old. Patching instances would have
been pure motion.

**Where the image data comes from.** This runs entirely inside Falcon. CSPM asset
records carry the instance-to-image edge natively across all three clouds:
- **AWS:** `relationships[]` on the instance contains an `AWS::EC2::Image` entry
- **Azure:** the attached disk's `imageReference` config, or the parent VMSS's
  `Microsoft.Compute/images` relationship for AKS nodes
- **GCP:** the attached disk's `compute.googleapis.com/Image` relationship

For AWS specifically, the `resource_id` is the AMI, with account and region in
its CRN. The same value appears as `imageId` inside the asset's `configuration`
(a JSON *string* that needs parsing).

No cloud CLI is needed. Falcon carries image names too: query the image as its
own CSPM asset and the record has `name` and `creationDate`. Two caveats — that
record is about **20,000 tokens** because it
embeds the entire CSPM compliance mapping, so fetch one image at a time and keep
only those two fields; and an image on a live relationship edge may have no
`AWS::EC2::Image` asset at all, in which case the name is simply unresolvable and
you report the ID.

**The thing that will bite you.** One CSPM instance record is ~139 KB (~35k
tokens). See `docs/context-discipline.md` for the full trap. The short version:
never query instance entities unfiltered, and extract only the fields you need.

Two mitigations worth knowing:

- **Pin `resource_type` in every CSPM filter.** Several asset types share one
  `resource_id`, so filtering on an instance ID alone can return a different kind
  of record than you intended — a filter that looks correct, quietly answering a
  different question.
- **If your tenant has AWS Inspector enabled**, the `AWS::Inspector::Coverage`
  record for the same instance also carries `amiId` (under
  `resourceMetadata.ec2` in its `configuration` string) at about **2.5 KB** —
  fifty times cheaper for the same answer. Try it first; fall back to the
  `AWS::EC2::Instance` edge if it comes back without one. Expect it to be absent —
  a verified run against a live tenant found none at all.

### Demo 2 — From one detection to full exposure

```
/image-sprawl
```

Or: *"We have a high-severity detection on a Kubernetes node. Which image caused
it, and where else is that image running?"*

**The point of this demo.** A container detection looks like one compromised
workload. Containers are stamped from images, and images get reused across
namespaces, clusters, clouds and teams who have never met. The pod may already be
gone. The useful question is which image, and where else.

What the playbook does:

1. Finds the detection — and works out which of two kinds it is.
2. If it is an image scan finding (`product:'cwpp'`), the image is already named
   in the detection and this step is skipped. If it is a runtime detection on a
   cluster node, it pivots into the container inventory on the node's **agent ID**
   to identify the image.
3. Searches the whole inventory for that image — **by digest, not tag**, because
   `:latest` on two clusters can be two different images.
4. Reports the blast radius: N containers across M clusters and K accounts.
5. Flags tag drift and cross-account sprawl.
6. Checks the image's own known vulnerabilities.

Two things it will not do: contain hosts or kill pods. Containing a node in a
production cluster can take out a service, and that call belongs to whoever
carries the pager.

**Two things that will bite you here.**

Image scan detections are often rated `Informational` — exposed credentials in a
layer, a hardcoded key — while being exactly what you want to chase. Filtering
this route to High and Critical is how you conclude there is nothing to look at.

And do not scope the runtime route by guessing at node hostnames. Node naming is
tenant-specific: EKS gives you `ip-10-0-1-42.ec2.internal`, AKS gives you
`aks-nodepool1-…-vmss00000u`. A pattern like `aks-*` returns zero on a tenant with
no AKS, which reads as "no detections" rather than "wrong guess". The playbook
joins on agent ID instead, which is an exact match — the same AKS node came back
as both `vmss00000U` and `vmss00000u` in one inventory, so string joins on the
node name are genuinely unsafe.

**Parameterise it to your environment.** The image in the session demo will not
exist in your tenant. Give the playbook an image name you actually run.

An empty sprawl result is a real answer, incidentally. "This image has exposed
credentials and is not running anywhere" means fix it before it ships.

### Demo 3 — Make the investigation permanent

```
/crystallize
```

Or: *"I want this to run every morning without me."*

**The point of this demo.** The first two demos spend tokens to discover something.
Once discovered, the discovery is over — the filters are settled, the ranking rule
is decided, and re-running the model to reach the same conclusion is paying twice.
`/crystallize` reads a finished investigation out of the conversation and writes a
standalone Python script to `crystallized/` that calls the Falcon REST API
directly.

What that buys you:

- **Zero tokens and no model.** It runs in CI, in cron, on a box with no Claude.
- **Deterministic.** Same input, same output. That is a property you can hand to
  an auditor; a model's output is not.
- **Statically reviewable.** It is a diff. Your change process already knows what
  to do with a diff.
- **Sometimes strictly more capable than the MCP path.** `facet` is an array at the
  REST layer, so a script gets `host_info` *and* `cve` in one call where the MCP
  tool accepts only one. And the 139 KB payload trap simply evaporates — a script
  has no context window to exhaust, so it can count the whole result set instead of
  reporting a sampled floor.

The model's judgement does not disappear; it survives as the ranking function.
There is a worked example in
[crystallized/critical-vulns-by-image.py](crystallized/critical-vulns-by-image.py),
and you can verify the whole ranking and rendering path before you have
credentials:

```bash
python3 scripts/test-crystallized.py
./scripts/test-render-parity.sh
```

Exit codes are chosen so CI can act on them: `0` nothing above threshold, `2`
findings above threshold, `1` could not run. Distinguishing `1` from `2` is what
lets a build fail on findings without failing on an expired credential.

The acceptance test is the part not to skip: run the script and compare its numbers
against the investigation that justified it. A script that quietly disagrees with
that investigation is worse than no script, because it will be believed.

---

## Part 3 — Ten questions to start with

Type these in plain language. No FQL required — that is the point.

**Posture**
1. What changed in the last 24 hours that I should care about?
2. How many hosts have not reported in over 14 days, and which cloud accounts are
   they in?
3. Are there any unassigned critical detections right now?

**Vulnerabilities**
4. How many open critical vulnerabilities do we have, and how many are actively
   exploited?
5. Is CVE-YYYY-NNNNN present anywhere in our estate?
6. Which ten hosts carry the most critical findings?

**Cloud and containers**
7. Which container images are running in more than one cluster?
8. Do we have any publicly exposed cloud assets with open critical findings?

**Identity and intel**
9. Which privileged accounts have not been used in 90 days?
10. What do we know about the threat actor behind our most recent high-severity
    detection?

Question 2 is a good first one: you probably already know roughly what the answer
should be, so a surprise tells you something real — either the harness is
misconfigured, or you have just learned something true about your estate.

---

## Part 4 — Your 30-day path

### Week 1 — Connect

Get one connection working, read-only, and use it daily. No automation yet.

- `./scripts/doctor.sh` green.
- Ask the ten questions above. Note which ones your tenant cannot answer and why —
  missing scope or not licensed. Those are different problems.
- At the end of the week, read `.cache/tool-audit.jsonl`. That is your record of
  what an AI actually did with access to your security data. Before you expand
  anything, be able to describe it.

**Done when:** you have asked a question you would otherwise have clicked through
four consoles to answer.

### Week 2 — Automate the boring part

Move from pull to push. Stop asking for the same summary every morning.

- The `SessionStart` posture brief already does this. Tune it —
  `HARNESS_DETECTION_WINDOW_HOURS`, `HARNESS_STALE_HOST_DAYS` — until it reflects
  what your team actually cares about.
- Run `/posture-brief` for the deeper on-demand version.

**Done when:** the brief tells you something you did not already know, at least
once.

### Week 3 — Codify your own expertise

The shipped skills are examples. The value is your team's recurring
investigations becoming as repeatable as those two — and nobody outside your team
knows which questions you ask at 2am.

```
/skill-template
```

Pick the investigation you did most recently by hand. Four tests for whether it
is worth codifying: you have done it more than twice, it is multi-step, the steps
are stable while the inputs vary, and judgement is involved between steps. If
there is no judgement, write a script — it will be faster and deterministic.

**Done when:** a colleague runs your skill and gets a useful answer without
asking you what a step means.

### Week 4 — Scale carefully

- Add modules as workflows need them, one at a time, granting the matching read
  scope each time.
- Share skills with your team via the repo. Skills are text; they review like code.
- Take the one investigation you now run most often and crystallize it:

  ```
  /crystallize
  ```

  Then schedule it. A script in cron costs nothing per run, so the investigation
  you could justify doing weekly you can now afford daily. Review its diff the way
  you would review any other code that reads production data.
- Only now consider writes, and read `docs/security.md` first. A reasonable
  progression is two weeks read-only, then writes in a non-production CID, then
  production writes with the audit log reviewed weekly.

**Done when:** someone who was not in the room is using a skill someone else
wrote, and at least one finding reaches your team without anyone asking for it.

---

## Part 5 — Two things that will trip you up

### Context exhaustion

A single Falcon host record is ~8 KB of JSON. Twenty crowd out the model's
reasoning; two hundred end the session. The failure is not an error message — the
model quietly loses earlier findings and its answers get vaguer, usually right
when the correlation was about to pay off.

The fixes: filter server-side, use facets instead of per-record follow-ups, and
narrow the scope rather than paginating through thousands of records. When you
want a count, get it outside the context window — `meta.pagination.total` looks
like the answer but the MCP server strips it, so a count means either fetching the
records or piping them through `jq` in a Bash call.

Full detail in `docs/context-discipline.md`. This is the thing most likely to make
your first real investigation fail.

### Three different kinds of "nothing"

| Response | Meaning |
|---|---|
| 403 | Missing scope |
| 404 | Not licensed on this tenant |
| 200, empty | **A correct answer** |

Never let the first be reported as the third. "No critical vulnerabilities" when
the truth is "no Spotlight scope" is the most dangerous output this harness can
produce. The doctor separates them; the skills are required to include a "not
checked" section for exactly this reason.

---

## Where things live

See [Repository layout](README.md#repository-layout) in the README.

---

## The one idea worth taking home

MCP is a **governed access layer, not a new security system**. It grants no new
capability — it exposes what your API client can already do, in a form a model can
use.

Which means the interesting work is not the connection. It is deciding what to
expose, watching what gets done with it, and codifying the judgement your team
already has.
