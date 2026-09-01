# Reference — resolving an instance to its base image

Split out of `SKILL.md` Step 3 to keep the playbook's hot path short. Read this
once, before your first `falcon_search_cspm_assets` call. The three clouds do not
put the instance-to-image edge in the same place, and the payload is a trap.

### Which cloud, and where its image reference actually lives

`host_info.service_provider` on the finding tells you the cloud (bare
`"AWS"`, `"Azure"`, `"GCP"` — a clean literal, not a suffixed form like
`"AWS_EC2_V2"`). That decides which `resource_type` to pin for the instance
lookup:

| Cloud | Instance `resource_type` | Where the image reference lives |
|---|---|---|
| AWS | `AWS::EC2::Instance` | the instance's own `relationships[]` — one hop, done |
| Azure standalone VM | `Microsoft.Compute/virtualMachines` | the **attached disk's** `properties.creationData.imageReference.id` — one hop out |
| Azure AKS/VMSS | `Microsoft.Compute/virtualMachineScaleSets` | the **parent VMSS's** `Microsoft.Compute/images` relationship — extract VMSS name from hostname |
| GCP | `compute.googleapis.com/Instance` | the **attached disk's** `relationships[]` — one hop out |

**Only AWS's edge sits on the instance record itself.** Azure and GCP instance
records carry no image reference at all — checking the instance's own
`relationships[]`/`configuration` for one finds nothing, and that is not
"untraceable," it is "looked in the wrong record." Both need a second CSPM
call to the attached disk.

### Critical: instance ID format mismatch across clouds

Spotlight `host_info.instance_id` does NOT match CSPM `resource_id` for Azure
or GCP. The resolution path differs by cloud and by Azure resource type:

| Cloud | Spotlight ID | Resolution path |
|---|---|---|
| AWS | `i-xxx` | Direct CSPM lookup — `resource_id` matches |
| Azure standalone VM | VM GUID | Construct ARM path from host API (`subscription + zone_group + hostname`) |
| Azure AKS/VMSS node | VM GUID | Extract VMSS name from hostname → parent VMSS → `Microsoft.Compute/images` edge |
| GCP Standard | numeric ID | Construct URL from host API `zone_group` + project number→name map + hostname |
| GCP Autopilot | numeric ID | Not in CSPM inventory — untraceable |

**Azure AKS path (verified 2026-08-30):** AKS hostnames encode the VMSS name:
`aks-agentpool-35640463-vmss00001Q` → VMSS name is `aks-agentpool-35640463-vmss`
(everything before the instance suffix). Host API `zone_group` gives the resource
group. Construct: `/subscriptions/<sub>/resourcegroups/<rg>/providers/
microsoft.compute/virtualmachinescalesets/<vmss-name>`. The parent VMSS carries
a `Microsoft.Compute/images` relationship (e.g., `aksubuntu/images/
2404gen2containerd/versions/202608.14.0`). Skip the individual VMSS VM entity —
it has no hostname, no computerName, and no image edge.

**GCP project number→name map:** CSPM `account_id` uses `projects/<number>`,
`resource_id` uses `projects/<name>`. Build the map during the CSPM pre-fetch
by regex-extracting the name from resource_ids. Then construct the full URL:
`//compute.googleapis.com/projects/<name>/zones/<zone>/instances/<hostname>`.

**Hosts entity API limit:** 100 IDs per GET call. 150+ returns HTTP 400.

### Critical: `instance_state` values differ per cloud

| Cloud | `instance_state` value | FQL filter |
|---|---|---|
| AWS | `running` (lowercase) | `instance_state:'running'` |
| Azure | `VM running` | `instance_state:'VM running'` |
| GCP | `RUNNING` (uppercase) | `instance_state:'RUNNING'` |

Use `active:true` as the cross-cloud normalised filter for "is this VM live."

### Critical: GCP account ID prefix

CSPM indexes GCP accounts as `projects/<number>` (e.g. `projects/418489422081`).
Spotlight gives the bare number. Query CSPM with the `projects/` prefix or
the lookup returns 0 and reads as "account not registered."

### The lookup — AWS (one hop)

One instance per call, from your shortlist only:

```
falcon_search_cspm_assets
filter: resource_type:'AWS::EC2::Instance'+resource_id:'i-0123456789abcdef0'
limit:  1
```

Read the payload trap below before you make this call yourself. Past three
instances you should be dispatching it to subagents rather than running it in this
context — but you still need to know what the record contains, because you are
the one who has to judge whether what comes back is right.

**Always pin `resource_type`.** Several asset types share a single
`resource_id` — an instance ID also matches its `AWS::Inspector::Coverage`
record. Filtering on `resource_id` alone returns whichever type it happens to
find, so a filter that looks right returns the wrong kind of record. This
discipline matters even more once you are also fetching disk records below —
a disk ID and an instance ID never collide, but a sloppy filter on either one
still risks matching an unrelated asset type.

The AMI appears in two places in the response:

1. **`relationships[]`** — the entry where `resource_type` is
   `"AWS::EC2::Image"`. Its `resource_id` is the AMI, and its `crn` carries the
   provider, account and region:
   `aws|<account>|<region>|AWS::EC2::Image|ami-0123456789abcdef0`.
   This is the reliable one — a first-class graph edge, `relationship_name: "is
   attached to"`.
2. **`configuration` → `imageId`.** Note that `configuration` is a **JSON string,
   not an object** — it must be parsed before you can read it. It also yields
   `instanceId`, `instanceType` and `launchTime`.

Prefer the `relationships` edge. Use `configuration` only to corroborate.

Also grab `tags` from the asset while you have it. Owner, `Environment`,
`Project` and EKS cluster tags are what turn a ranked list into a list with
names against it — and you will not want to fetch this record twice.

### The lookup — Azure and GCP (two hops, via the disk)

Neither cloud's instance record carries the image reference, so the first
call is the same shape as AWS's but only gets you the disk:

```
falcon_search_cspm_assets
filter: resource_type:'Microsoft.Compute/virtualMachines'+resource_id:'<vm-id>'
limit:  1
```

```
falcon_search_cspm_assets
filter: resource_type:'compute.googleapis.com/Instance'+resource_id:'<instance-id>'
limit:  1
```

Read that instance's `relationships[]` for the disk edge —
`Microsoft.Compute/disks` for Azure, `compute.googleapis.com/Disk` for GCP —
and take its `resource_id`. Then issue a **second** call, pinned to the disk,
exactly as disciplined as the first:

```
falcon_search_cspm_assets
filter: resource_type:'Microsoft.Compute/disks'+resource_id:'<disk-id>'
limit:  1
```

```
falcon_search_cspm_assets
filter: resource_type:'compute.googleapis.com/Disk'+resource_id:'<disk-id>'
limit:  1
```

The two clouds then diverge in what the disk record gives you — confirmed
live, not assumed symmetric:

- **GCP**: the disk's own `relationships[]` carries a
  `compute.googleapis.com/Image` edge (`relationship_name: "is associated
  with"`) — the same first-class-edge shape as AWS, just one hop further out.
  Corroborate with the disk's `configuration.sourceImage` (a matching URL)
  and `configuration.sourceImageId`.
- **Azure standalone VMs**: the disk's image reference is at
  `configuration.properties.creationData.imageReference.id` — a full ARM path
  encoding publisher/offer/sku/version. The `configuration` field is a JSON
  string that must be parsed. Extract the identity via regex:
  `.../Publishers/<pub>/ArtifactTypes/VMImage/Offers/<offer>/Skus/<sku>/Versions/<ver>`
- **Azure AKS/VMSS nodes**: skip the individual VMSS VM and the disk entirely.
  Extract the VMSS name from the Spotlight hostname
  (`aks-agentpool-35640463-vmss00001Q` → `aks-agentpool-35640463-vmss`), construct
  the parent VMSS ARM path from the host API's `zone_group` (resource group) +
  subscription, and read the parent VMSS's `Microsoft.Compute/images` relationship.
  The parent VMSS carries the AKS node image (e.g.,
  `aksubuntu/images/2404gen2containerd/versions/202608.14.0`).

If the disk lookup itself comes back empty, or neither the edge nor the
config yields an image reference, the instance is untraceable — bucket it,
do not drop it (see Step 5's collapsed table).

**A separate, easily-confused field:** CSPM assets also carry `cloud_provider`
at the top level, used to filter *across* asset types by cloud
(`resource_type:'Microsoft.Compute/disks'+cloud_provider:'azure'`). Its
values are **lowercase** in this tenant (`"azure"`, `"gcp"`) even though the
MCP's own `fql-guide` resource shows capitalized examples — a second,
independent case-sensitivity trap, distinct from `host_info.service_provider`
above (which is a clean, non-lowercase literal) and from the `cloud:'AWS'`
vs. `cloud_name` field-naming trap noted elsewhere in this harness. Filtering
on the wrong case returns zero rows, not an error, so an empty result here is
easy to misread as "no Azure assets" when it is really "wrong case."

### The payload trap

One CSPM instance record is ~139 KB (~35k tokens). Full details in
`docs/context-discipline.md`. The short version: never query instance entities
without a `resource_id` filter, extract only the fields you need, and past three
instances fan out to subagents or use the pre-fetch architecture below.

### The pre-fetch architecture (crystallized script)

The crystallized script (`crystallized/critical-vulns-by-image.py`) uses a
fundamentally different approach than per-instance MCP lookups:

1. **Pre-fetch all CSPM instances** per cloud in one pass (paginate + batch entity
   fetch). Parses each 139 KB entity and discards it, keeping only ~100 bytes:
   the Spotlight-matchable key, image edge, account, region, and state.
2. **Build a cross-cloud lookup index** keyed by the identifier Spotlight uses:
   - AWS: `resource_id` (the `i-xxx` instance ID — matches Spotlight directly)
   - Azure standalone VM: full ARM `resource_id` (lowercased) — lookup constructs ARM from host API `zone_group + hostname`
   - Azure AKS/VMSS: parent VMSS ARM path — lookup extracts VMSS name from hostname
   - GCP: full `resource_id` URL — lookup constructs URL from host API `zone_group` + project number→name regex map + hostname
3. **Resolve locally** — dict lookups, zero API calls for the resolution phase.
4. **Deployment counts** are tallied from the same pre-fetched data (count image
   relationships per entity), eliminating the separate deployment scan.
5. **Azure/GCP disk hops** are done only for instances that matched in the index
   but had no image on the instance record — a much smaller set than all instances.

This architecture eliminates the per-instance resolution bottleneck (previously
9,700 individual API calls taking 15 minutes) and replaces it with ~70 batched
entity fetches (~90 seconds for 7,000 instances across all clouds).

### Fan out — for manual MCP investigations only

For manual MCP investigations with fewer than ~20 instances, dispatch
`falcon-asset-resolver` subagents as described in `docs/parallelism.md`. The
pre-fetch architecture above is the default for the crystallized script; the
subagent fan-out is for interactive sessions where you don't want to run the
full script.

### Resolving the image name

A bare `ami-0a1b2c3d…` or a GCP image URL means nothing to a human reading your
report, and Falcon can give you a real name for two of the three clouds:

- **AWS**: the AMI has its **own CSPM asset**, and its `configuration` carries
  `name` and `creationDate`:

  ```
  filter: resource_type:'AWS::EC2::Image'+resource_id:'ami-0123456789abcdef0'
  limit:  1
  ```

- **GCP**: the same shape, on `compute.googleapis.com/Image` instead — its own
  CSPM asset, with a `name`/creation-date pair in `configuration`. Look it up the
  same way, for ranked images only.

- **Azure needs no lookup at all.** Step 3 already composed the identity string
  (`publisher/offer/sku/version`) from the disk's `imageReference` while
  resolving the instance — that tuple *is* the name. There is no second
  `Microsoft.Compute/images` asset to fetch for this purpose; do not spend a
  call on one.

The build date is usually the most damning number in the whole report. An instance
launched yesterday from an image built five years ago tells you immediately that
patching the instance is futile — the image is the defect.

**AWS's and GCP's image records have their own payload trap: roughly 20,000
tokens for AWS's `AWS::EC2::Image`.** Not because of user-data, but because it
embeds the entire CSPM compliance mapping — CIS, NIST, PCI, FedRAMP, HITRUST,
SCF controls, both compliant and non-compliant. So this one fans out too:
`falcon-asset-resolver` with `mode: images` and up to 3 `<resource_type>\t<id>`
pairs per agent, for ranked images only. Keep just `name` and `creationDate`.

**An AMI or Custom Image may have no asset at all.** One referenced by a live
instance's relationship edge can be absent from CSPM inventory — deregistered,
shared from another account, or outside the scan scope. Report the name as
unresolved and move on; do not treat it as an error, and do not silently drop
the image from the ranking. It still backs a running instance. Falcon is the
only source this playbook uses for image identity, on all three clouds.
