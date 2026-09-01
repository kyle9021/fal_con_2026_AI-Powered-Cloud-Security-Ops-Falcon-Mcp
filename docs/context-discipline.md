# Context discipline

Security data is enormous and repetitive. This is the operational constraint that
decides whether a Falcon MCP workflow succeeds or dies two thirds of the way
through — and it is the one nobody warns you about.

## The problem, measured

A single Falcon host record is several kilobytes of JSON. Most of it is
irrelevant to any given question: full policy assignment blocks, dozens of host
group IDs, sensor configuration, timestamps in three formats.

The arithmetic is unforgiving:

| Call | Rough context cost |
|---|---|
| 1 host record | ~8 KB |
| 20 host records | ~160 KB — crowds out your reasoning |
| 200 host records | session over |

The failure mode is nasty because it is not an error. The model does not say "too
much data". It runs out of room to think, starts losing earlier findings, and its
answers quietly degrade at exactly the point in a long investigation where the
correlation was about to pay off.

## The rules

Rule 2 is the only one the harness *can* enforce for you, and it is off unless
you ask for it. Set `HARNESS_MAX_LIMIT` and `.claude/hooks/guard-falcon-writes.py`
applies it as a ceiling: a call asking for more has its `limit` rewritten downward
before it runs, and the model is told the resulting count is a floor rather than a
total. Unset — the default — nothing is clamped and every rule on this page is
discipline the model keeps on its own, which is why they are written down.

**1. Filter server-side. Always.**

Push every constraint into FQL. Never fetch broadly and filter in the model — the
data has already cost you the context by the time the model sees it.

```
# No
falcon_search_hosts(limit=500) → look for Windows ones

# Yes
falcon_search_hosts(filter="platform_name:'Windows'+last_seen:>'...'", limit=20)
```

**2. When you want a number, count it outside your context.**

The obvious move is `limit: 1` plus `meta.pagination.total`. **This does not work
through the MCP server.** Verified against a live tenant: the `falcon_*` search
tools return only `{"result": [...]}` — the `meta` envelope, and with it the
total, is stripped. The count is available over raw REST, and
`FalconClient.total()` in `scripts/falcon_api.py` reads it, but MCP callers cannot
see it.

So counting means either fetching the records, or getting the count without the
records reaching you. Prefer the second:

```bash
# The payload goes to jq, never to the model. Needs a populated .env.
python3 scripts/falcon_api.py ... | jq '.resources | length'
```

Failing that, sample deliberately and say so. `limit: 400` returning exactly 400
means the real number is *at least* 400 — report it as a floor, never as a total.
A count the operator believes is complete is worse than an honest lower bound.

This is also the strongest argument for `/crystallize`: a script counts the whole
result set for free, because nothing it fetches enters a context window at all.

**3. Use facets instead of second lookups.**

`falcon_search_vulnerabilities` with `facet: host_info` attaches the affected
asset to each finding. One call, already joined. Without it you are making N
follow-up calls and paying full host-record price for each.

**4. Extract, then discard.**

Decide what you need from a payload *before* you fetch it, take those fields, and
let the rest go. The most valuable instruction in a data-heavy skill is often
"keep these four fields, drop the rest."

**5. Aggregate as you go.**

Keep running tallies rather than raw records. If you are grouping 200 findings by
image, hold the group counts — not the 200 findings.

**6. Narrow the scope rather than paginating.**

If a result set hits your limit, the answer is truncated. Paginating through
10,000 records will exhaust the session before it produces an answer. Scope down
— one account, one region, one severity — and say what you scoped to.

A scoped answer is useful. A truncated answer presented as complete is worse than
no answer, because the operator acts on it.

**7. Trim the tool surface.**

`FALCON_MCP_MODULES` is a context control as much as a security one. Every
loaded tool's schema sits in context before you ask anything. 139 tools is a
meaningful tax on a budget you need for the investigation.

## Reading a large record once

Sometimes you genuinely need everything about one host. That is fine — fetch one,
extract what matters, and do not fetch a second "for comparison". Two full host
records to compare is nearly always three fields you could have compared from
search results.

## Known payload traps

Discovered the hard way against a live tenant:

- **`falcon_search_cspm_assets` on `AWS::EC2::Instance` is the worst offender in
  the whole surface.** One record is roughly **139 KB — about 35,000 tokens** —
  because it embeds the full AWS instance configuration plus
  `supplementary_configuration` with base64 user-data. At `limit: 20` that is
  ~700,000 tokens. Always filter to specific `resource_id`s, take the fields you
  need, and discard the record.

  Two ways to make it cheaper:
  - The `AWS::Inspector::Coverage` record for the same instance carries `amiId`
    and tags at about **2.5 KB** — fifty times less for the same answer — when
    AWS Inspector is enabled on the tenant. Expect it to be missing: a verified
    run found none at all, so treat it as a cheap thing to try, not a plan.
  - Extract outside the context window: fetch in a Bash call and pipe through
    `jq` so only the fields you want ever reach the model.

- **`AWS::EC2::Image` records are a second, separate trap: about 20,000 tokens
  each.** Not user-data this time — they embed the whole CSPM compliance mapping,
  every CIS / NIST / PCI / FedRAMP / HITRUST / SCF control, compliant *and*
  non-compliant. You usually want two fields out of it, `name` and `creationDate`.
  Fetch one AMI at a time and keep only those.

- **A query that matches nothing can cost more than one that works.** When a
  filter returns no results, several tools — `falcon_search_detections` is the
  one to watch — helpfully append their *entire* FQL guide to the response as a
  hint. That is roughly **10,000 tokens for a zero-result query.** Three bad
  guesses at a field name cost more context than the investigation itself.

  The practical consequence: read the `falcon://.../fql-guide` resource **once**,
  deliberately, and compose filters from it. Iterating by trial and error against
  the live API is the single most expensive debugging habit available to you, and
  it gets more expensive the more wrong you are.

- **`falcon_search_vulnerabilities` with `facet: host_info` carries
  `host_info.groups`** — every host group the asset belongs to, IDs and names.
  One real finding included 39 of them, and they dominated the record. Keep the
  handful of `host_info` fields you need and drop `groups` on sight.
- **`falcon_get_host_details` on many IDs.** The tool accepts up to 5000 IDs. Do
  not approach that. Above roughly 10 you should be asking whether search results
  would answer the question.
- **`falcon_count_kubernetes_containers` is broken.** It returns a payload its own
  schema rejects, producing a pydantic `int_type` validation error. Use
  `falcon_search_kubernetes_containers` and count. Not your bug.
- **Container inventory is highly repetitive.** Fifty containers from one
  deployment differ in a couple of fields. Aggregate immediately.
- **Intel reports are long-form prose.** Fetch a specific report deliberately, not
  as background colour.

## FQL that keeps responses small

```
+                    AND
,                    OR
!                    not equals
~                    case-insensitive text match
field:>'value'       greater than
field:*'*text*'      contains  (note both asterisks and the quoting)
field:['A','B']      in list
```

Two field-name warnings, both found in practice:

- Some tool descriptions carry **wrong example field names**. The Kubernetes
  containers tool shows `cloud:'AWS'`; the correct field is `cloud_name`. Read the
  `falcon://.../fql-guide` resource for the module and trust it over the tool
  description.
- A wrong field name usually returns an error, but an over-broad filter returns
  *everything*. The second failure is more expensive than the first.

## A worked comparison

**The expensive way** — 47 calls, several hundred KB, likely dies mid-run:

```
1. Search all hosts (limit 500)
2. For each host, get details
3. Look for the vulnerable ones
```

**The cheap way** — 1 call, one page of JSON:

```
falcon_search_vulnerabilities(
  filter="status:'open'+cve.severity:'CRITICAL'+cve.exprt_rating:'CRITICAL'",
  facet="host_info",
  limit=50,
)
```

Same question. The difference is entirely in where the filtering happened.
