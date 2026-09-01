#!/usr/bin/env python3
"""Which base images carry our critical vulnerabilities, ranked by leverage.

Crystallized from the `/trace-vm-image` investigation. Answers one question:
**what is the smallest set of images we can rebuild to retire the largest number
of critical findings?**

Runs with no model, no tokens and no MCP server. Two REST services:

  GET /spotlight/combined/vulnerabilities/v1        (scope: Vulnerabilities read)
  GET /cloud-security-assets/queries/resources/v1   (scope: CSPM registration read)
  GET /cloud-security-assets/entities/resources/v1  (scope: CSPM registration read)

Note what changes by leaving MCP behind:

  * **The payload trap evaporates.** One AWS::EC2::Instance asset record is ~139 KB
    and would consume ~35,000 tokens of a model's context. Here it is parsed and
    discarded inside a loop, so its size is irrelevant. The constraint that shapes
    the interactive playbook simply does not apply.
  * **Both facets at once.** The MCP tool accepts one facet; this endpoint accepts
    an array, so each finding arrives with host *and* CVE detail together.

Scope comes from the environment, never from this file -- account IDs are
tenant-identifying and this script is meant to be committable and reviewable:

  HARNESS_SCOPE_ACCOUNTS   comma-separated cloud account IDs (default: all)
  HARNESS_EXPRT_ONLY       1/true/yes to filter to ExPRT HIGH/CRITICAL only (default: off)
  HARNESS_MAX_PAGES        page ceiling per query partition (default: 0 = unlimited)
  HARNESS_MAX_INSTANCES    cap on CSPM instance resolution (default: 0 = unlimited)
  HARNESS_RESOLVE_WORKERS  thread pool size for CSPM resolution (default: 10)

Exit codes:

  0  ran to completion; nothing exploitable
  1  did not run, or did not complete -- bad credentials, no scope, or a 429/5xx
     partway through. A partial answer that is *reported* as partial still exits 1,
     because a scheduler must not record it as a clean pass.
  2  ran to completion; findings with a public exploit or a CISA KEV listing
  3  --dry-run only: printed the requests, made none. Deliberately not 0, so a
     scheduler entry with a stray --dry-run cannot pass for a clean run.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))

from falcon_api import FalconClient, FalconError, load_dotenv  # noqa: E402
from falcon_report import Report  # noqa: E402

log = logging.getLogger("trace-vm-image")

_DEVICE_ID_RE = re.compile(r"^[0-9a-f]{32}$")

SPOTLIGHT = "/spotlight/combined/vulnerabilities/v1"
CSPM_QUERY = "/cloud-security-assets/queries/resources/v1"
CSPM_ENTITIES = "/cloud-security-assets/entities/resources/v1"

SEVERITY = "CRITICAL"
ACCOUNTS = [a.strip() for a in os.environ.get("HARNESS_SCOPE_ACCOUNTS", "").split(",") if a.strip()]
EXPRT_ONLY = os.environ.get("HARNESS_EXPRT_ONLY", "").strip().lower() in ("1", "true", "yes")
MASK_ACCOUNTS = True  # set False by --unmask
MAX_PAGES = int(os.environ.get("HARNESS_MAX_PAGES", "0"))
MAX_INSTANCES = int(os.environ.get("HARNESS_MAX_INSTANCES", "0"))
PAGE_SIZE = 400

# CSPM resolution can mean hundreds of sequential GETs on a large tenant. A
# bounded thread pool keeps that fast without ever letting resolution outrun a
# reasonable request rate.
RESOLVE_WORKERS = int(os.environ.get("HARNESS_RESOLVE_WORKERS", "10"))


# ExPRT ratings that represent real, prioritisable work. CVSS severity alone
# overstates the workload substantially -- that finding is why this ranking leads
# with ExPRT rather than cve.severity.
ACTIONABLE_RATINGS = {"CRITICAL", "HIGH"}


def mask_id(value):
    """Obfuscate an account/resource ID for stage-safe output. Shows first 4 chars."""
    if not MASK_ACCOUNTS or not value or value == "unknown":
        return value
    s = str(value)
    if len(s) <= 4:
        return s
    return s[:4] + "X" * (len(s) - 4)


# -- filters, defined once -------------------------------------------------
# Every filter this script sends is built here and nowhere else. The dry-run
# listing, the live request and the evidence table all read the same function,
# so a provenance table cannot drift from the query it claims to document. A
# retyped filter string in a report is worse than no report: it looks
# authoritative while being wrong.


def vuln_filter() -> str:
    filt = f"status:'open'+cve.severity:'{SEVERITY}'"
    if EXPRT_ONLY:
        filt += "+cve.exprt_rating:['HIGH','CRITICAL']"
    return filt


# The instance -> image chain, per cloud. Only AWS puts the image edge on the
# instance record; Azure and GCP need a second hop via the attached disk, and
# Azure has no image edge at all -- its identity is four fields parsed out of the
# disk's `imageReference`.
#
# Hardcoding AWS here is not a shortcut, it is a wrong answer that looks right:
# a GCP instance ID queried as AWS::EC2::Instance returns HTTP 200 with zero
# rows, which is indistinguishable from "this account is not onboarded to CSPM"
# unless the resource_type is pinned from the provider. An earlier version of
# this script did exactly that and silently dropped every non-AWS instance into
# the not-onboarded bucket.
CLOUDS = {
    "AWS": {
        "instance": "AWS::EC2::Instance",
        "disk": None,                       # image edge is on the instance
        "image": "AWS::EC2::Image",
    },
    "Azure": {
        "instance": "Microsoft.Compute/virtualMachines",
        "vmss_vm": "Microsoft.Compute/virtualMachineScaleSets/virtualMachines",
        "vmss": "Microsoft.Compute/virtualMachineScaleSets",
        "disk": "Microsoft.Compute/disks",
        "image": "Microsoft.Compute/images",
    },
    "GCP": {
        "instance": "compute.googleapis.com/Instance",
        "disk": "compute.googleapis.com/Disk",
        "image": "compute.googleapis.com/Image",
    },
}


def asset_filter(resource_type: str, resource_id: str) -> str:
    """Always pin resource_type: several asset types share one resource_id, so
    filtering on the ID alone can return an Inspector coverage record instead."""
    return f"resource_type:'{resource_type}'+resource_id:'{resource_id}'"


# -- the call ledger -------------------------------------------------------
# Appended to at the moment each request returns, by the code that made it.
# Recording provenance after the fact is how it gets skipped or misremembered;
# recording it here means empty results and failures are captured too, and those
# are the rows that matter most. An empty result is what separates "no findings"
# from "never asked", and a 403 recorded as a 0 is how a security report produces
# false assurance.
CALLS: list[dict] = []
_CALLS_LOCK = threading.Lock()


def record(endpoint, filt="", returned=None, limit=None, facet="", note=""):
    """Record one request. `returned` is a count, or a string for a failure."""
    with _CALLS_LOCK:
        CALLS.append({"endpoint": endpoint, "filter": filt, "returned": returned,
                  "limit": limit, "facet": facet, "note": note})


# One verbatim fragment of each record shape the script depends on, captured the
# first time it is read. When an API response shape changes a year from now, this
# is what tells the next person what the script expected to find.
EVIDENCE: dict[str, dict] = {}

# A denial and an empty result both mean "no image", and they mean completely
# different things to whoever reads the report. `None` cannot carry that
# difference, so denial gets its own sentinel.
DENIED = object()

# And a third thing that is neither: a 429 or a 5xx. It is tempting to lump these
# in with denial, but they are not stable -- the same query may succeed in a
# minute -- and it is far worse to lump them in with success. A response that
# falls through to `payload.get("resources") or []` contributes an empty list to
# the totals, so the report says "0 findings, fully paginated", adds no gap, and
# exits 0. Authoritative, wrong, and green in CI.
ERRORED = object()

# A fourth thing, and the one this script used to get wrong. The finding named a
# cloud with no chain in CLOUDS, so no lookup was ever attempted. That is not a
# denial, not an error, and emphatically not "no asset found" -- reporting it as
# the latter blames the tenant for a gap in this script.
NO_PROVIDER = object()


# -- fetching ---------------------------------------------------------------


def fetch_pages(client, path, params, max_pages=MAX_PAGES):
    """Token-paginate an endpoint. Returns `(state, resources, truncated)`.

    `state` is one of three strings, and the three-way split is the whole point:

      "ok"      -- HTTP 200. `resources` may be empty, and an empty list here is
                   a real answer: the question was asked and nothing came back.
      "denied"  -- 401/403/404. A missing scope or an unlicensed feature. Stable,
                   so it belongs in the report as a gap.
      "error"   -- 429 or 5xx. Transient. Neither an answer nor a denial.

    An earlier version of this function checked only `denied()`, so a 500 or a
    rate limit fell through to `resources.extend([])`, found no `after` token, and
    returned an empty list indistinguishable from a genuinely empty result. The
    report then read "0 findings", noted "fully paginated via the after token",
    raised no gap and exited 0.

    Note the mid-pagination case, which is the nastier half: if page 1 succeeds
    and page 2 errors, the partial data is real but incomplete, so it is returned
    with `truncated=True` rather than discarded or presented as whole.
    """
    resources, after, page_count = [], None, 0
    t0 = time.monotonic()
    while max_pages == 0 or page_count < max_pages:
        page_count += 1
        page = client.get(path, {**params, "after": after})
        if client.denied(page):
            log.warning("page %d: denied (401/403/404)", page_count)
            return "denied", None, False
        if client.errored(page):
            log.warning("page %d: error (429/5xx) after %.1fs, %d records so far",
                        page_count, time.monotonic() - t0, len(resources))
            return "error", (resources or None), bool(resources)
        batch = page.get("resources") or []
        resources.extend(batch)
        log.debug("page %d: +%d records (total %d)", page_count, len(batch), len(resources))
        if page_count % 25 == 0:
            log.info("page %d: %d records so far (%.1fs)", page_count, len(resources), time.monotonic() - t0)
        after = ((page.get("meta") or {}).get("pagination") or {}).get("after")
        if not after:
            log.info("fetched %d records in %d pages (%.1fs)",
                     len(resources), page_count, time.monotonic() - t0)
            return "ok", resources, False
    log.info("fetched %d records in %d pages (%.1fs, hit page ceiling)",
             len(resources), page_count, time.monotonic() - t0)
    return "ok", resources, True


def fetch_findings(client):
    """Open findings at the configured severity, with host and CVE detail.

    When EXPRT_ONLY is set, partitions into CRITICAL and HIGH streams and
    paginates them concurrently — roughly halving wall-clock time on large
    tenants. The partitions are disjoint (a finding has exactly one ExPRT
    rating), so no dedup is needed.
    """
    base = vuln_filter()

    if EXPRT_ONLY:
        partitions = [
            (f"{base}+cve.exprt_rating:'CRITICAL'", "ExPRT CRITICAL"),
            (f"{base}+cve.exprt_rating:'HIGH'", "ExPRT HIGH"),
        ]
    else:
        partitions = [(base, "all")]

    log.info("querying Spotlight: %s (%d partition%s)",
             base, len(partitions), "s" if len(partitions) > 1 else "")

    # Pre-warm auth token before fanning out
    _ = client.token

    all_resources = []
    any_denied = False
    any_errored = False
    any_truncated = False
    partition_notes = []

    def _paginate_partition(args):
        filt, label = args
        return label, filt, fetch_pages(client, SPOTLIGHT, {
            "filter": filt,
            "facet": ["host_info", "cve"],
            "limit": PAGE_SIZE,
            "sort": "created_timestamp|desc",
        })

    with ThreadPoolExecutor(max_workers=len(partitions)) as pool:
        results = list(pool.map(_paginate_partition, partitions))

    for label, filt, (state, resources, truncated) in results:
        if state == "denied":
            any_denied = True
            record(SPOTLIGHT, filt, returned="denied", facet="host_info, cve",
                   note=f"Partition {label}: denied.")
            continue
        if state == "error":
            any_errored = True
            n = len(resources) if resources else 0
            record(SPOTLIGHT, filt, returned=f"error ({n} partial)", facet="host_info, cve",
                   note=f"Partition {label}: 429/5xx mid-pagination.")
            if resources:
                all_resources.extend(resources)
                any_truncated = True
            continue
        n = len(resources) if resources else 0
        all_resources.extend(resources or [])
        if truncated:
            any_truncated = True
        partition_notes.append(f"{label}: {n}")
        record(SPOTLIGHT, filt, returned=n, facet="host_info, cve",
               limit=f"{PAGE_SIZE}/page" + (f", {MAX_PAGES} pages max" if MAX_PAGES else ""),
               note=f"Partition {label}." + (" Truncated." if truncated else " Complete."))

    log.info("Spotlight complete: %d findings across %d partition(s) (%s)",
             len(all_resources), len(partitions),
             ", ".join(partition_notes) if partition_notes else "none returned")

    if any_denied and not all_resources:
        return "denied", None, False
    if any_errored and not all_resources:
        return "error", None, False
    if any_errored:
        return "error", all_resources, True
    return "ok", all_resources, any_truncated



def parse_config(asset):
    """CSPM `configuration` is a JSON *string*, not an object. Parse or discard."""
    config = asset.get("configuration")
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except ValueError:
            config = {}
    return config if isinstance(config, dict) else {}


def edge(asset, resource_type):
    """The first relationship edge of a given type, or None."""
    for candidate in asset.get("relationships") or []:
        if candidate.get("resource_type") == resource_type:
            return candidate
    return None


def one_asset(client, resource_type, resource_id, empty_note, big_note=""):
    """Fetch exactly one pinned CSPM asset.

    Returns the asset dict, or DENIED / ERRORED / None. `None` means the asset
    genuinely does not exist -- HTTP 200 with zero rows -- and the caller must
    keep that distinct from the two sentinels.

    Batch size stays at 1 so the GET-only client remains sufficient; the POST
    variant would allow 500, but this client has no code path that can write.
    """
    filt = asset_filter(resource_type, resource_id)
    page = client.get(CSPM_QUERY, {"filter": filt, "limit": 1})
    if client.denied(page):
        record(CSPM_QUERY, filt, returned="denied -- CSPM scope unavailable", limit=1)
        log.debug("denied: %s %s", resource_type, resource_id)
        return DENIED
    if client.errored(page):
        record(CSPM_QUERY, filt, returned="error -- HTTP 429/5xx", limit=1,
               note="Transient. Unknown for a reason that says nothing about "
                    "the asset itself.")
        log.debug("error: %s %s", resource_type, resource_id)
        return ERRORED
    ids = page.get("resources") or []
    if not ids:
        record(CSPM_QUERY, filt, returned=0, limit=1, note=empty_note)
        return None
    record(CSPM_QUERY, filt, returned=len(ids), limit=1)

    detail = client.get(CSPM_ENTITIES, {"ids": ids[:1]})
    label = f"ids=1 ({resource_type})"
    if client.denied(detail):
        record(CSPM_ENTITIES, label, returned="denied -- CSPM scope unavailable")
        return DENIED
    if client.errored(detail):
        record(CSPM_ENTITIES, label, returned="error -- HTTP 429/5xx")
        return ERRORED
    assets = detail.get("resources") or []
    record(CSPM_ENTITIES, label, returned=len(assets), note=big_note)
    return assets[0] if assets else None


def azure_identity(config):
    """Extract the Azure image identity from a disk's configuration.

    The imageReference lives at two possible paths depending on the CSPM
    record shape:
      1. config.properties.creationData.imageReference.id (full ARM path)
      2. config.imageReference (publisher/offer/sku/version dict)

    Path 1 is the common case on this tenant. The ARM path encodes
    publisher/offer/sku/version in its segments — extract them via regex
    rather than relying on the dict keys."""
    # Path 1: properties.creationData.imageReference.id
    props = config.get("properties") or {}
    if isinstance(props, str):
        try:
            props = json.loads(props)
        except ValueError:
            props = {}
    cd = (props or {}).get("creationData") or {}
    if isinstance(cd, str):
        try:
            cd = json.loads(cd)
        except ValueError:
            cd = {}
    ir = (cd or {}).get("imageReference") or {}
    if isinstance(ir, str):
        try:
            ir = json.loads(ir)
        except ValueError:
            ir = {}
    img_id = (ir or {}).get("id") or ""
    if img_id:
        # Extract publisher/offer/sku/version from ARM path
        m = re.search(
            r"/Publishers/([^/]+)/ArtifactTypes/VMImage/Offers/([^/]+)/Skus/([^/]+)/Versions/([^/]+)",
            img_id, re.IGNORECASE)
        if m:
            return f"{m.group(1)}/{m.group(2)}/{m.group(3)}/{m.group(4)}"
        return img_id  # return raw id if regex doesn't match

    # Path 2: direct imageReference dict (legacy/alternative shape)
    reference = config.get("imageReference")
    if isinstance(reference, str):
        try:
            reference = json.loads(reference)
        except ValueError:
            reference = {}
    if not isinstance(reference, dict):
        return None
    parts = [reference.get(k) for k in ("publisher", "offer", "sku", "version")]
    return "/".join(str(p) for p in parts if p) or None



def resolve_image_name(client, provider, image_id):
    """Image name and build date. Returns `(state, meta)`.

    `state` is "ok", "denied" or "error", same three-way split as everywhere else.
    It is returned rather than folded into an empty dict because the label this
    function produces is cosmetic but the *reason* it is missing is not: "no such
    image asset" and "the API was rate-limiting us" both leave the Name column
    reading `unresolved`, and only one of them means the run is untrustworthy.

    Frequently there is genuinely no asset -- an image on a live relationship edge
    may have no asset of its own (deregistered, shared from another account, or
    outside the scan scope). That is an "ok" with no name.
    """
    spec = CLOUDS.get(provider) or {}
    resource_type = spec.get("image")
    if resource_type is None:
        # Azure only: the identity string was already composed from the disk's
        # imageReference while resolving the instance. Nothing left to look up.
        return "ok", {}

    asset = one_asset(
        client, resource_type, image_id,
        empty_note=(f"The image is on a live relationship edge but has no "
                    f"{resource_type} asset -- deregistered, shared from another "
                    "account, or outside the scan scope. The name is genuinely "
                    "unresolvable, which is not the same as absent."),
        big_note="~20 KB of CSPM compliance mapping for two wanted fields.")
    if asset is DENIED:
        return "denied", {}
    if asset is ERRORED:
        return "error", {}
    if asset is None:
        return "ok", {}
    config = parse_config(asset)
    return "ok", {"name": config.get("name"),
                  "created": config.get("creationDate")
                             or config.get("creationTimestamp")}


# -- pure aggregation -------------------------------------------------------


def group_by_instance(findings):
    """Collapse findings onto the cloud instances that can be traced to an image.

    A finding with no instance_id is not traceable to a base image. Those are counted
    separately rather than dropped silently -- they are still real findings, and
    a report that omits them without saying so is misleading.
    """
    instances, untraceable = defaultdict(lambda: {
        "hostname": None, "account": None, "provider": None, "aid": None, "cves": {},
    }), 0

    for finding in findings:
        host = finding.get("host_info") or {}
        instance_id = host.get("instance_id")
        if not instance_id:
            untraceable += 1
            continue
        cve = finding.get("cve") or {}
        entry = instances[instance_id]
        entry["hostname"] = entry["hostname"] or host.get("hostname")
        entry["account"] = entry["account"] or host.get("service_provider_account_id")
        entry["provider"] = entry["provider"] or host.get("service_provider")
        entry["aid"] = entry["aid"] or (
            finding.get("aid") if _DEVICE_ID_RE.match(finding.get("aid") or "") else None
        )
        if cve.get("id"):
            entry["cves"][cve["id"]] = {
                "exprt": (cve.get("exprt_rating") or "").upper(),
                # exploit_status 90 == a public exploit is available.
                "exploit": str(cve.get("exploit_status") or "0") == "90",
                "kev": bool((cve.get("cisa_info") or {}).get("is_cisa_kev")),
            }
    return instances, untraceable


def rank_images(images):
    """Blast radius first, then promote anything known to be exploited.

    One instance running a CVE on CISA's Known Exploited list outranks fifty
    instances with theoretical ones, so exploitation status is the primary key and
    KEV outranks a merely public exploit -- KEV means someone has already used it
    against someone else.
    """
    def key(item):
        data = item[1]
        return (
            1 if data["kev"] else 0,
            1 if data["exploitable"] else 0,
            len(data["instances"]) * len(data["cves"]),
            data["actionable"],
        )
    return sorted(images.items(), key=key, reverse=True)


def risk_label(image):
    """The single word that tints a row. Read off the evidence, not chosen.

    Note the ordering: KEV and a public exploit both mean critical because both
    are "someone can do this today". ExPRT critical/high without a known exploit
    is high -- real work, but not this hour's work.
    """
    if image["kev"] or image["exploitable"]:
        return "critical"
    if image["actionable"]:
        return "high"
    return "medium"


def flag_tokens(image):
    """Flags for the badge column, comma-joined -- the renderer splits them."""
    flags = []
    if image["kev"]:
        flags.append("KEV")
    if image["exploitable"]:
        flags.append("Public exploit")
    if not flags:
        flags.append("No known exploit")
    return ", ".join(flags)


def _resolve_disk_hop(client, provider, spec, cspm_resource_id):
    """Azure/GCP: the image edge is not on the instance record itself.

    Three chains handled here:
      Azure standalone VM → disk → imageReference (config parse)
      Azure VMSS VM → parent VMSS → Microsoft.Compute/images (relationship edge)
      GCP instance → disk → compute.googleapis.com/Image (relationship edge)
    """
    instance_asset = one_asset(
        client, spec["instance"] if "virtualmachinescalesets/virtualmachines" not in cspm_resource_id.lower()
        else spec.get("vmss_vm", spec["instance"]),
        cspm_resource_id,
        empty_note="Instance vanished between pre-fetch and disk-hop.",
        big_note="Re-fetch for image chain.")
    if not instance_asset or instance_asset is DENIED or instance_asset is ERRORED:
        return None

    # Azure VMSS VM: walk to parent VMSS for the image edge
    if provider == "Azure" and "virtualmachinescalesets/virtualmachines" in cspm_resource_id.lower():
        vmss_edge = edge(instance_asset, spec.get("vmss"))
        if not vmss_edge or not vmss_edge.get("resource_id"):
            return None
        vmss_asset = one_asset(
            client, spec["vmss"], vmss_edge["resource_id"],
            empty_note="Parent VMSS not found in CSPM.")
        if not vmss_asset or vmss_asset is DENIED or vmss_asset is ERRORED:
            return None
        img_edge = edge(vmss_asset, spec.get("image"))
        if img_edge:
            EVIDENCE.setdefault("edge", {
                "instance": cspm_resource_id,
                "resource_type": img_edge.get("resource_type"),
                "resource_id": img_edge.get("resource_id"),
                "relationship_name": img_edge.get("relationship_name"),
                "crn": img_edge.get("crn"),
            })
            return {"image": img_edge.get("resource_id")}
        # Fallback: parse VMSS config for imageReference
        vmss_config = parse_config(vmss_asset)
        vmp = vmss_config.get("virtualMachineProfile") or {}
        if isinstance(vmp, str):
            try:
                vmp = json.loads(vmp)
            except ValueError:
                vmp = {}
        sp = (vmp or {}).get("storageProfile") or {}
        if isinstance(sp, str):
            try:
                sp = json.loads(sp)
            except ValueError:
                sp = {}
        identity = azure_identity(sp)
        if identity:
            return {"image": identity, "name": identity}
        return None

    # Azure standalone VM: hop to disk for imageReference
    if provider == "Azure":
        disk_edge_entry = edge(instance_asset, spec["disk"])
        if not disk_edge_entry or not disk_edge_entry.get("resource_id"):
            return None
        disk = one_asset(
            client, spec["disk"], disk_edge_entry["resource_id"],
            empty_note="Disk named on instance edge but has no CSPM asset.")
        if not disk or disk is DENIED or disk is ERRORED:
            return None
        disk_config = parse_config(disk)
        identity = azure_identity(disk_config)
        if identity:
            return {"image": identity, "name": identity}
        return None

    # GCP: hop to disk for image edge
    disk_edge_entry = edge(instance_asset, spec["disk"])
    if not disk_edge_entry or not disk_edge_entry.get("resource_id"):
        return None
    disk = one_asset(
        client, spec["disk"], disk_edge_entry["resource_id"],
        empty_note="Disk named on instance edge but has no CSPM asset.")
    if not disk or disk is DENIED or disk is ERRORED:
        return None
    disk_config = parse_config(disk)
    found = edge(disk, spec["image"])
    if found:
        EVIDENCE.setdefault("edge", {
            "instance": cspm_resource_id,
            "resource_type": found.get("resource_type"),
            "resource_id": found.get("resource_id"),
            "relationship_name": found.get("relationship_name"),
            "crn": found.get("crn"),
        })
    return {"image": ((found or {}).get("resource_id")
                      or disk_config.get("sourceImageId")
                      or disk_config.get("sourceImage"))}


# -- assembly ---------------------------------------------------------------


def finish(report, code):
    """Attach the ledger and return. Every exit from build_report comes through
    here, including the failure exits.

    That is deliberate: the denial and error paths are exactly the ones a reader
    most needs the evidence table for, and an earlier version returned early
    without it -- so a report that said "scope unavailable" showed no queries at
    all, which is indistinguishable from a script that never tried.
    """
    for call in CALLS:
        report.query(call["endpoint"], call["filter"], returned=call["returned"],
                     facet=call["facet"], limit=call["limit"], note=call["note"])
    return report, code


def build_report(client):
    scope = f"open + CVSS {SEVERITY}"
    if EXPRT_ONLY:
        scope += " + ExPRT HIGH/CRITICAL"
    scope += f", accounts {', '.join(ACCOUNTS)}" if ACCOUNTS else ", whole CID"

    # CID is extracted from the JWT at auth time, before any GET
    cid_display = mask_id(client.cid) if client.cid else "unknown"

    report = Report(
        "Critical vulnerabilities by base VM image",
        subtitle=f"Source: CrowdStrike Falcon | CID: {cid_display}",
        scope=scope,
    )

    state, findings, truncated = fetch_findings(client)

    if state == "denied":
        report.verdict(
            "This run could not read Spotlight at all. Nothing here is a "
            "statement about your vulnerability posture.",
            tone="medium",
        )
        report.metric("Findings", None, note="Vulnerabilities scope unavailable")
        report.gap(
            "Spotlight returned 401/403/404. This is NOT a report of zero "
            "vulnerabilities -- the signal could not be read at all."
        )
        return finish(report, 1)

    if state == "error":
        report.gap(
            "Spotlight returned HTTP 429 or 5xx, so the vulnerability query did "
            "not complete. This is transient, not a denial and not a zero: the "
            "same query may succeed on the next run. Every count below is a floor "
            "derived from whatever arrived before the failure, and this run exits "
            "1 so a scheduler treats it as a failed run rather than a clean one."
        )
        if findings is None:
            report.verdict(
                "This run failed before it collected anything. Re-run it; do not "
                "read the absence of findings as an absence of risk.",
                tone="medium",
            )
            report.metric("Findings", None, note="Spotlight query failed (429/5xx)")
            return finish(report, 1)

    # An errored run stays exit 1 no matter what the partial data says. A run that
    # found exploitable images *and* failed halfway is still a failed run.
    hard_fail = state == "error"

    if ACCOUNTS:
        findings = [
            f for f in findings
            if ((f.get("host_info") or {}).get("service_provider_account_id") in ACCOUNTS)
        ]

    instances, untraceable = group_by_instance(findings)
    if truncated:
        report.gap(
            f"Stopped at the {MAX_PAGES}-page ceiling. More findings exist than "
            "were counted; treat every total here as a floor, not a total."
        )
    if untraceable:
        report.gap(
            f"{untraceable} findings had no instance_id and cannot be traced to an "
            "image. Non-cloud hosts, or cloud assets the sensor did not identify."
        )

    # Every instance with a finding is resolved, sorted by CVE count descending
    # so the most-vulnerable instances resolve first if capped.
    shortlist = sorted(instances.items(), key=lambda kv: len(kv[1]["cves"]), reverse=True)
    if MAX_INSTANCES and len(shortlist) > MAX_INSTANCES:
        total_before_cap = len(shortlist)
        log.info("capping CSPM resolution at %d of %d instances (HARNESS_MAX_INSTANCES)",
                 MAX_INSTANCES, total_before_cap)
        shortlist = shortlist[:MAX_INSTANCES]
        report.gap(
            f"CSPM resolution capped at {MAX_INSTANCES} of {total_before_cap} "
            "instances (HARNESS_MAX_INSTANCES). The remaining instances are excluded "
            "from the image ranking. The shortlist is sorted by CVE count, so the "
            "most-vulnerable instances are resolved first."
        )

    images, unresolved = defaultdict(lambda: {
        "instances": set(), "cves": {}, "accounts": set(), "account_names": set(),
        "regions": set(),
        "exploitable": 0, "kev": 0, "actionable": 0, "name": None, "created": None,
        "provider": None,
    }), []
    resolved_meta = {}  # instance_id -> {region, account, provider} from CSPM
    denied, errored, no_provider = [], [], defaultdict(int)

    # Per-cloud coverage, tallied as we go. Without this a run that resolved only
    # AWS looks exactly like a tenant that only runs AWS -- which is how this
    # script previously reported on 493 AWS hosts and stayed silent about 11,444
    # GCP ones. Coverage is a first-class output, not a debugging aid.
    coverage = defaultdict(lambda: {"findings": 0, "instances": 0, "resolved": 0,
                                    "inventory": None, "running": None,
                                    "sensored": None})
    # Seed a row for every cloud this script can trace, before counting anything.
    # Spotlight only sees sensored hosts, so a cloud with no sensor produces no
    # findings and would otherwise never become a key here -- and a missing row
    # reads as "you do not run that cloud". This tenant has 204 Azure VMs in CSPM
    # and zero Azure sensors: the honest output is an Azure row of zeros next to
    # an inventory count, not silence.
    for name in CLOUDS:
        _ = coverage[name]
    for finding in findings:
        host = finding.get("host_info") or {}
        coverage[host.get("service_provider") or "unidentified"]["findings"] += 1
    for _instance_id, data in instances.items():
        coverage[data.get("provider") or "unidentified"]["instances"] += 1

    # What CSPM knows about, independent of any finding. This is the denominator
    # that turns "we found nothing" into "we found nothing out of N".
    # Three counts per cloud: total inventory, running, and sensored — all from
    # CSPM so the numbers are comparable (same system, same scan).
    t_cov = time.monotonic()

    def _fetch_cloud_coverage(args):
        cname, cspec = args
        base_filt = f"resource_type:'{cspec['instance']}'"
        inv, run, sen = None, None, None
        page = client.get(CSPM_QUERY, {"filter": base_filt, "limit": 1})
        if client.denied(page) or client.errored(page):
            record(CSPM_QUERY, base_filt, returned="unavailable", limit=1,
                   note="Inventory count for the coverage table only.")
            return cname, inv, run, sen
        inv = client.total(page)
        record(CSPM_QUERY, base_filt, returned=inv if inv is not None else 0, limit=1,
               note=f"{cname} instance assets in CSPM, tenant-wide.")
        log.debug("%s inventory: %s", cname, inv)
        running_filt = base_filt + "+active:true"
        page = client.get(CSPM_QUERY, {"filter": running_filt, "limit": 1})
        if not client.denied(page) and not client.errored(page):
            run = client.total(page)
            record(CSPM_QUERY, running_filt, returned=run if run is not None else 0,
                   limit=1, note=f"{cname} active instances (active:true, cross-cloud).")
            log.debug("%s active: %s", cname, run)
        sensor_filt = base_filt + "+managed_by:'Sensor'"
        page = client.get(CSPM_QUERY, {"filter": sensor_filt, "limit": 1})
        if not client.denied(page) and not client.errored(page):
            sen = client.total(page)
            record(CSPM_QUERY, sensor_filt, returned=sen if sen is not None else 0,
                   limit=1, note=f"{cname} instances with Falcon sensor (CSPM managed_by).")
            log.debug("%s sensored: %s", cname, sen)
        return cname, inv, run, sen

    with ThreadPoolExecutor(max_workers=len(CLOUDS)) as pool:
        for cname, inv, run, sen in pool.map(_fetch_cloud_coverage,
                                              list(CLOUDS.items())):
            coverage[cname]["inventory"] = inv
            coverage[cname]["running"] = run
            coverage[cname]["sensored"] = sen

    log.info("coverage queries complete (%.1fs)", time.monotonic() - t_cov)

    # -- Pre-fetch CSPM instance inventory ---------------------------------
    # Instead of 9,700 individual CSPM lookups (one per Spotlight instance),
    # paginate all instances per cloud once and build a local index. This
    # eliminates the per-instance resolution phase entirely and solves the
    # cross-cloud ID format mismatch:
    #   AWS:   index by resource_id (i-xxx) — matches Spotlight directly
    #   Azure: index by hostname extracted from the ARM path tail
    #   GCP:   index by configuration.id (numeric) — matches Spotlight
    # One pass also gives us deployment counts per image (from relationships)
    # and image names (from the image edge), so the deployment scan and image
    # name resolution phases also collapse into this single fetch.

    _ = client.token  # pre-warm before threading

    # Per-cloud index: maps Spotlight's instance_id → extracted fields
    cspm_index = {}  # key = Spotlight identifier, value = extracted dict
    ami_deployment = defaultdict(int)  # image_id -> count of instances
    gcp_project_map = {}  # project number -> project name (from CSPM resource_ids)
    vmss_parent_images = {}  # vmss resource_id (lowercase) -> image_id

    def _prefetch_cloud(args):
        """Paginate one cloud's instances, fetch entities, return extracted rows."""
        cname, cspec = args
        rows = []
        image_counts = defaultdict(int)
        vmss_parents = {}  # vmss resource_id (lowercase) -> image_id from relationship
        # Azure has regular VMs, VMSS VMs (AKS nodes), and VMSS parents (carry the image edge)
        instance_types = [cspec["instance"]]
        if cspec.get("vmss_vm"):
            instance_types.append(cspec["vmss_vm"])
        if cspec.get("vmss"):
            instance_types.append(cspec["vmss"])

        t0 = time.monotonic()
        for inst_type in instance_types:
            base_filt = f"resource_type:'{inst_type}'"
            offset, batch_size = 0, 500
            type_fetched = 0
            log.info("pre-fetching %s %s from CSPM", cname, inst_type.rsplit('/', 1)[-1])

            while True:
                page = client.get(CSPM_QUERY, {"filter": base_filt, "limit": batch_size, "offset": offset})
                if client.denied(page):
                    return cname, "denied", [], {}, {}
                if client.errored(page):
                    return cname, "error", rows, dict(image_counts), dict(vmss_parents)
                ids = page.get("resources") or []
                if not ids:
                    break

                chunks = [ids[i:i + 100] for i in range(0, len(ids), 100)]

                def _fetch_chunk(chunk_ids):
                    detail = client.get(CSPM_ENTITIES, {"ids": chunk_ids})
                    return detail.get("resources") or []

                with ThreadPoolExecutor(max_workers=min(RESOLVE_WORKERS, len(chunks))) as pool:
                    for assets in pool.map(_fetch_chunk, chunks):
                        for asset in assets:
                            extracted = _extract_instance(cname, cspec, asset)
                            if extracted:
                                rows.append(extracted)
                            # Count deployments per image from relationships
                            img_type = cspec.get("image")
                            if img_type:
                                for rel in (asset.get("relationships") or []):
                                    if rel.get("resource_type") == img_type:
                                        image_counts[rel["resource_id"]] += 1
                            # Capture VMSS parent → image mapping
                            asset_rt = asset.get("resource_type") or ""
                            if asset_rt == cspec.get("vmss"):
                                rid = (asset.get("resource_id") or "").lower()
                                for rel in (asset.get("relationships") or []):
                                    if rel.get("resource_type") == cspec.get("image"):
                                        vmss_parents[rid] = rel.get("resource_id")
                                        break

                type_fetched += len(ids)
                log.debug("pre-fetched %d %s %s so far", type_fetched, cname,
                          inst_type.rsplit('/', 1)[-1])
                page_total = client.total(page)
                if page_total is not None and offset + len(ids) >= page_total:
                    break
                offset += len(ids)

            record(CSPM_QUERY, base_filt, returned=type_fetched,
                   note=f"{cname} {inst_type} pre-fetch.")
        log.info("pre-fetched %s: %d index entries, %d VMSS parents (%.1fs)",
                 cname, len(rows), len(vmss_parents), time.monotonic() - t0)
        return cname, "ok", rows, dict(image_counts), dict(vmss_parents)

    def _extract_instance(cname, cspec, asset):
        """Extract the Spotlight-matchable key and image edge from one CSPM entity."""
        config = parse_config(asset)
        cloud_ctx = asset.get("cloud_context") or {}
        host_ctx = cloud_ctx.get("host") or {}
        resource_id = asset.get("resource_id") or ""

        # The key Spotlight uses to identify this instance
        if cname == "AWS":
            spotlight_key = resource_id  # i-xxx, matches directly
        elif cname == "Azure":
            # Index by full ARM resource_id (lowercase). The lookup side constructs
            # the ARM path from the host API's zone_group + hostname.
            spotlight_key = resource_id.lower() if resource_id else None
        elif cname == "GCP":
            # Index by full resource_id (URL). The lookup side constructs the URL
            # from Spotlight's zone_group + hostname, using a project number→name
            # map built from regex on these same resource_ids.
            spotlight_key = resource_id if resource_id else None
        else:
            return None

        if not spotlight_key:
            return None

        # Extract the image edge
        image_id = None
        image_name = None
        resource_type = asset.get("resource_type") or ""
        if cname == "AWS" and cspec.get("disk") is None:
            # AWS: image edge on instance record
            img_edge = edge(asset, cspec["image"])
            image_id = (img_edge or {}).get("resource_id") or config.get("imageId")
            if img_edge and "edge" not in EVIDENCE:
                EVIDENCE["edge"] = {
                    "instance": resource_id,
                    "resource_type": img_edge.get("resource_type"),
                    "resource_id": img_edge.get("resource_id"),
                    "relationship_name": img_edge.get("relationship_name"),
                    "crn": img_edge.get("crn"),
                }
            if not EVIDENCE.get("config"):
                EVIDENCE["config"] = {k: config.get(k) for k in
                                      ("imageId", "instanceType", "launchTime")}
        elif cname == "Azure":
            if "virtualMachineScaleSets/virtualMachines" in resource_type.lower():
                # AKS VMSS VM: image is on parent VMSS, via relationship edge
                vmss_edge = edge(asset, cspec.get("vmss"))
                if vmss_edge and vmss_edge.get("resource_id"):
                    # Store parent VMSS ID — resolve image from it during disk-hop
                    image_id = None  # needs disk-hop to parent VMSS
            else:
                # Standalone Azure VM: needs disk hop for imageReference
                image_id = None
        elif cname == "GCP":
            # GCP: needs disk hop
            image_id = None

        return {
            "spotlight_key": spotlight_key,
            "resource_id": resource_id,
            "provider": cname,
            "account": asset.get("account_id"),
            "account_name": asset.get("account_name"),
            "region": asset.get("region"),
            "active": asset.get("active"),
            "instance_state": cloud_ctx.get("instance_state") or host_ctx.get("state"),
            "image": image_id,
            "image_name": image_name,
        }

    t_prefetch = time.monotonic()
    with ThreadPoolExecutor(max_workers=len(CLOUDS)) as pool:
        prefetch_results = list(pool.map(_prefetch_cloud, list(CLOUDS.items())))

    for cname, state, rows, img_counts, vmss_imgs in prefetch_results:
        if state == "denied":
            report.gap(f"CSPM pre-fetch denied for {cname}. No {cname} instances could be resolved.")
            continue
        if state == "error":
            hard_fail = True
            report.gap(f"CSPM pre-fetch errored (429/5xx) for {cname}. Partial data used.")
        for row in rows:
            key = row["spotlight_key"]
            cspm_index[key] = row
            # Build GCP project number→name map from resource_ids
            if cname == "GCP" and key:
                acct = row.get("account") or ""
                proj_num = acct.replace("projects/", "") if acct.startswith("projects/") else None
                m = re.match(r"//compute\.googleapis\.com/projects/([^/]+)/", key)
                if proj_num and m:
                    gcp_project_map[proj_num] = m.group(1)
        for img_id, count in img_counts.items():
            ami_deployment[img_id] += count
        vmss_parent_images.update(vmss_imgs)

    if vmss_parent_images:
        log.info("VMSS parent images: %d scale sets with image edges", len(vmss_parent_images))
    if gcp_project_map:
        log.info("GCP project map: %d number→name entries", len(gcp_project_map))

    log.info("CSPM pre-fetch complete: %d index entries, %d images with deployments (%.1fs)",
             len(cspm_index), len(ami_deployment), time.monotonic() - t_prefetch)

    # -- Resolve findings against the index --------------------------------
    # AWS: direct dict lookup by instance_id.
    # Azure: construct ARM path from host API (zone_group + hostname), lookup in index.
    # GCP: direct dict lookup by numeric instance_id.
    # Azure and GCP need one host API batch call to get zone_group.
    t_resolve = time.monotonic()

    # Batch-fetch host records for Azure and GCP instances to construct lookup keys
    cloud_aids = {}  # aid -> (instance_id, provider)
    azure_gcp_total = 0
    azure_gcp_with_aid = 0
    for instance_id, data in shortlist:
        prov = data.get("provider")
        if prov in ("Azure", "GCP"):
            azure_gcp_total += 1
            if data.get("aid"):
                azure_gcp_with_aid += 1
                cloud_aids[data["aid"]] = (instance_id, prov)
    if azure_gcp_total:
        log.info("Azure/GCP in shortlist: %d total, %d with device_id aid",
                 azure_gcp_total, azure_gcp_with_aid)

    constructed_keys = {}  # instance_id -> (key_type, key_value, host_meta)
    if cloud_aids:
        log.info("fetching %d Azure/GCP host records for key construction", len(cloud_aids))
        aids_list = list(cloud_aids.keys())
        for i in range(0, len(aids_list), 100):
            chunk = aids_list[i:i + 100]
            detail = client.get("/devices/entities/devices/v2", {"ids": chunk})
            host_results = detail.get("resources") or []
            log.debug("host API returned %d of %d requested", len(host_results), len(chunk))
            for d in host_results:
                aid = d.get("device_id", "")
                entry = cloud_aids.get(aid)
                if not entry:
                    continue
                iid, prov = entry
                zg = d.get("zone_group", "")
                hn = d.get("hostname", "")
                acct = d.get("service_provider_account_id", "")
                # Carry host metadata through to the resolution loop
                host_meta = {"account": acct, "hostname": hn, "zone_group": zg}

                if prov == "Azure" and zg and hn and acct:
                    vmss_match = re.match(r"^(.*-vmss)\d", hn, re.IGNORECASE)
                    if vmss_match:
                        vmss_name = vmss_match.group(1)
                        vmss_path = (f"/subscriptions/{acct}/resourcegroups/{zg}"
                                     f"/providers/microsoft.compute/"
                                     f"virtualmachinescalesets/{vmss_name}").lower()
                        vmss_image = vmss_parent_images.get(vmss_path)
                        if vmss_image:
                            host_meta["vmss_name"] = vmss_name
                            constructed_keys[iid] = ("vmss_direct", vmss_image, host_meta)
                        else:
                            log.debug("VMSS parent not found for %s: %s", hn, vmss_path[-70:])
                    else:
                        arm = (f"/subscriptions/{acct}/resourcegroups/{zg}"
                               f"/providers/microsoft.compute/virtualmachines/{hn}").lower()
                        constructed_keys[iid] = ("arm", arm, host_meta)

                elif prov == "GCP" and zg and hn:
                    # zone_group = "projects/660847187194/zones/europe-west3-a"
                    # Replace the project number with the project name from our map
                    zg_match = re.match(r"projects/(\d+)/zones/(.+)", zg)
                    if zg_match:
                        proj_num = zg_match.group(1)
                        zone = zg_match.group(2)
                        proj_name = gcp_project_map.get(proj_num)
                        if proj_name:
                            gcp_url = (f"//compute.googleapis.com/projects/{proj_name}"
                                       f"/zones/{zone}/instances/{hn}")
                            constructed_keys[iid] = ("gcp", gcp_url, host_meta)

        azure_constructed = sum(1 for v in constructed_keys.values() if v[0] in ("arm", "vmss_direct"))
        gcp_constructed = sum(1 for v in constructed_keys.values() if v[0] == "gcp")
        vmss_direct = sum(1 for v in constructed_keys.values() if v[0] == "vmss_direct")
        log.info("constructed keys: %d Azure (%d via VMSS parent), %d GCP, %d total",
                 azure_constructed, vmss_direct, gcp_constructed, len(constructed_keys))

    for instance_id, data in shortlist:
        provider = data.get("provider")
        spec = CLOUDS.get(provider)
        if spec is None:
            no_provider[provider or "unidentified"] += 1
            continue

        # Build the lookup key the same way the index was built
        if provider == "AWS":
            lookup_key = instance_id
            resolved = cspm_index.get(lookup_key)
            if not resolved:
                unresolved.append(instance_id)
                continue
        elif provider in ("Azure", "GCP"):
            key_entry = constructed_keys.get(instance_id)
            if not key_entry:
                unresolved.append(instance_id)
                continue
            key_type, key_value, host_meta = key_entry
            if key_type == "vmss_direct":
                # AKS node: image came from the parent VMSS, no index lookup needed
                image_id = key_value
                image = images[image_id]
                image["instances"].add(instance_id)
                acct = host_meta.get("account") or data.get("account")
                image["accounts"].add(acct)
                region = host_meta.get("zone_group", "")
                if region:
                    image["regions"].add(region)
                image["cves"].update(data["cves"])
                image["provider"] = image["provider"] or provider
                resolved_meta[instance_id] = {
                    "account": acct,
                    "provider": provider,
                    "image": image_id,
                    "region": region,
                    "active": True,
                    "instance_state": "running",
                    "resolution": f"VMSS parent: {host_meta.get('vmss_name', 'unknown')}",
                }
                coverage[provider]["resolved"] += 1
                continue
            # ARM path or GCP URL — look up in the CSPM index
            resolved = cspm_index.get(key_value)
            if not resolved:
                unresolved.append(instance_id)
                continue
        else:
            no_provider[provider or "unidentified"] += 1
            continue

        image_id = resolved.get("image")
        if not image_id:
            # Azure and GCP need a disk hop — the pre-fetch only got the instance.
            # Do the disk lookup now, only for matched instances (much smaller set).
            if provider in ("Azure", "GCP") and resolved.get("resource_id"):
                disk_result = _resolve_disk_hop(client, provider, spec, resolved["resource_id"])
                if disk_result:
                    image_id = disk_result.get("image")
                    if disk_result.get("name"):
                        resolved["image_name"] = disk_result["name"]

        if not image_id:
            unresolved.append(instance_id)
            continue

        # Determine resolution method for evidence trail
        if provider == "AWS":
            res_method = f"CSPM direct: resource_id={mask_id(instance_id)}"
        elif provider == "Azure" and key_entry and key_entry[0] == "arm":
            res_method = f"ARM path: {mask_id(key_entry[1][-40:] if len(key_entry[1]) > 40 else key_entry[1])} → disk hop"
        elif provider == "GCP" and key_entry and key_entry[0] == "gcp":
            res_method = f"GCP URL: {mask_id(key_entry[1][-40:] if len(key_entry[1]) > 40 else key_entry[1])} → disk hop"
        else:
            res_method = "index match → disk hop"

        image = images[image_id]
        image["instances"].add(instance_id)
        image["accounts"].add(resolved.get("account") or data.get("account"))
        if resolved.get("account_name"):
            image["account_names"].add(resolved["account_name"])
        if resolved.get("region"):
            image["regions"].add(resolved["region"])
        image["cves"].update(data["cves"])
        image["provider"] = image["provider"] or provider
        image["name"] = image["name"] or resolved.get("image_name")
        resolved_meta[instance_id] = {
            "region": resolved.get("region"),
            "account": resolved.get("account") or data.get("account"),
            "account_name": resolved.get("account_name"),
            "provider": provider,
            "image": image_id,
            "active": resolved.get("active"),
            "instance_state": resolved.get("instance_state"),
            "resolution": res_method,
        }
        coverage[provider]["resolved"] += 1

    log.info("index resolution complete: %d instances (%.1fs)",
             len(shortlist), time.monotonic() - t_resolve)

    # Image name resolution — still per-image, but only ~30-50 queries
    def _resolve_name(item):
        image_id, image = item
        return image_id, resolve_image_name(client, image["provider"], image_id)

    t_names = time.monotonic()
    log.info("resolving %d image names", len(images))
    with ThreadPoolExecutor(max_workers=max(1, min(RESOLVE_WORKERS, len(images) or 1))) as pool:
        name_results = dict(pool.map(_resolve_name, images.items()))
    log.info("image name resolution complete (%.1fs)", time.monotonic() - t_names)

    name_errors = 0
    for image_id, image in images.items():
        image["exploitable"] = sum(1 for c in image["cves"].values() if c["exploit"])
        image["kev"] = sum(1 for c in image["cves"].values() if c["kev"])
        image["actionable"] = sum(
            1 for c in image["cves"].values() if c["exprt"] in ACTIONABLE_RATINGS
        )
        name_state, meta = name_results[image_id]
        if name_state == "error":
            name_errors += 1
        image["name"] = image["name"] or meta.get("name")
        image["created"] = (meta.get("created") or "")[:10] or None

    # Deployment counts: AWS comes from the pre-fetch (instance→image relationship).
    # Azure and GCP don't carry that relationship on the instance entity, so for
    # non-AWS images, fall back to the traced-instances count (a floor, not the
    # full blast radius).
    for image_id, image in images.items():
        prefetch_count = ami_deployment.get(image_id)
        if prefetch_count is not None and prefetch_count > 0:
            image["deployed"] = prefetch_count
        elif image.get("provider") != "AWS":
            # Best available: count of instances we traced to this image
            image["deployed"] = len(image["instances"]) or None
        else:
            image["deployed"] = prefetch_count

    # A cloud CSPM inventories but Spotlight never mentions is the quietest way to
    # be wrong: nothing errored, nothing was denied, and the report simply has no
    # row for it. Spotlight findings come from the sensor, so this is an unsensored
    # fleet, not an empty one -- and unsensored means unassessed, which belongs in
    # the report rather than in the reader's head.
    invisible = [
        (name, tally["inventory"]) for name, tally in coverage.items()
        if tally["findings"] == 0 and (tally["inventory"] or 0) > 0
    ]
    if invisible:
        report.gap(
            "; ".join(f"{name}: {count} instances in CSPM, 0 vulnerability findings"
                      for name, count in invisible)
            + ". Spotlight only reports on hosts running the sensor, so these are "
            "unsensored -- and therefore unassessed, not clean. Nothing below covers "
            "them. Deploying the sensor is what makes them appear here."
        )
    if denied:
        report.gap(
            f"CSPM asset lookups were denied (401/403) for {len(denied)} instances. "
            "Their images could not be resolved. This is a missing scope, not an "
            "absent asset -- the vulnerability counts above stand, the ranking does not."
        )
    if errored:
        hard_fail = True
        report.gap(
            f"CSPM asset lookups failed with HTTP 429/5xx for {len(errored)} "
            "instances. Those instances are missing from the ranking below for a "
            "reason that has nothing to do with their images, so the ranking is "
            "incomplete in a way a re-run may fix. Distinct from the denials: a "
            "denial will still be a denial tomorrow."
        )
    if name_errors:
        report.gap(
            f"{name_errors} image name lookups hit HTTP 429/5xx, so some rows read "
            "'unresolved' because the API was unavailable rather than because the "
            "image has no asset. Cosmetic -- the ranking does not use the name."
        )
    if no_provider:
        detail = ", ".join(f"{name} ({count})" for name, count in
                           sorted(no_provider.items(), key=lambda kv: -kv[1]))
        report.gap(
            f"{sum(no_provider.values())} instances name a cloud this script has "
            f"no lookup chain for: {detail}. No query was attempted for them, so "
            "this is a limit of the script, NOT a finding about your tenant. Add "
            "the cloud to CLOUDS to include them."
        )

    # Count Azure VMSS nodes in the unresolved set — they're a known platform gap
    azure_vmss_unresolved = sum(
        1 for iid in unresolved
        if instances.get(iid, {}).get("provider") == "Azure"
        and ("vmss" in (instances.get(iid, {}).get("hostname") or "").lower()
             or "aks-" in (instances.get(iid, {}).get("hostname") or "").lower())
    )
    gcp_unresolved = sum(
        1 for iid in unresolved
        if instances.get(iid, {}).get("provider") == "GCP"
    )
    if azure_vmss_unresolved or gcp_unresolved:
        parts = []
        if azure_vmss_unresolved:
            parts.append(
                f"Azure VMSS/AKS nodes ({azure_vmss_unresolved}): parent VMSS "
                "did not carry a Microsoft.Compute/images relationship — "
                "image could not be resolved for these nodes"
            )
        if gcp_unresolved:
            parts.append(
                f"GCP instances ({gcp_unresolved}): GKE Autopilot nodes are "
                "managed by Google and not inventoried as individual compute "
                "instances in CSPM. Register GCP accounts with Standard GKE "
                "clusters or standalone VMs to enable tracing"
            )
        report.gap(
            "Unresolved cross-cloud instances: "
            + "; ".join(parts) + "."
        )
    if unresolved:
        # Diagnose WHY: collect accounts from unresolved instances, check which
        # are registered in CSPM.
        unresolved_accounts = defaultdict(lambda: {"count": 0, "provider": None})
        for iid in unresolved:
            data = instances.get(iid, {})
            acct = data.get("account") or "unknown"
            unresolved_accounts[acct]["count"] += 1
            unresolved_accounts[acct]["provider"] = (
                unresolved_accounts[acct]["provider"] or data.get("provider")
            )

        def _check_account_in_cspm(args):
            acct_id, info = args
            provider = info.get("provider")
            spec = CLOUDS.get(provider) if provider else None
            if not spec:
                return acct_id, None
            # GCP accounts in CSPM use "projects/<number>" prefix
            cspm_acct = f"projects/{acct_id}" if provider == "GCP" else acct_id
            filt = f"resource_type:'{spec['instance']}'+account_id:'{cspm_acct}'"
            page = client.get(CSPM_QUERY, {"filter": filt, "limit": 1})
            if client.denied(page) or client.errored(page):
                return acct_id, None
            return acct_id, client.total(page) or 0

        not_in_cspm = []
        in_cspm = []
        acct_items = [(a, v) for a, v in unresolved_accounts.items() if a != "unknown"]
        if acct_items:
            with ThreadPoolExecutor(max_workers=min(5, len(acct_items))) as pool:
                for acct_id, cspm_count in pool.map(_check_account_in_cspm, acct_items):
                    if cspm_count is None:
                        continue
                    entry = unresolved_accounts[acct_id]
                    if cspm_count == 0:
                        not_in_cspm.append((acct_id, entry["provider"], entry["count"]))
                    else:
                        in_cspm.append((acct_id, entry["provider"], entry["count"], cspm_count))

        if not_in_cspm:
            total_not = sum(c for _, _, c in not_in_cspm)
            report.gap(
                f"{total_not} of {len(unresolved)} unresolved VMs belong to "
                f"{len(not_in_cspm)} accounts not registered in CSPM. "
                "These accounts have sensors but no cloud registration — "
                "see the account table below for the full list."
            )
        if in_cspm:
            total_in = sum(c for _, _, c, _ in in_cspm)
            details = []
            for acct_id, provider, count, cspm_count in sorted(in_cspm, key=lambda x: -x[2]):
                if provider == "GCP":
                    details.append(f"{provider} {mask_id(acct_id)} ({count} VMs — likely GKE "
                                   "Autopilot nodes not inventoried as compute instances)")
                elif provider == "Azure":
                    details.append(f"{provider} {mask_id(acct_id)} ({count} VMs — likely AKS VMSS "
                                   "nodes whose parent VMSS lacks an image edge)")
                else:
                    details.append(f"{provider} {mask_id(acct_id)} ({count} VMs — instances may be "
                                   "terminated or not yet scanned by CSPM)")
            report.gap(
                f"{total_in} unresolved VMs belong to {len(in_cspm)} accounts that "
                "are registered in CSPM but could not be matched: "
                + "; ".join(details) + "."
            )
        remaining = len(unresolved) - sum(c for _, _, c in not_in_cspm) - sum(c for _, _, c, _ in in_cspm)
        if remaining > 0:
            report.gap(
                f"{remaining} unresolved VMs have no account ID or could not "
                "be checked against CSPM."
            )

    # Account CSPM registration status — one table, always rendered.
    all_finding_accounts = defaultdict(lambda: {"provider": None, "findings": 0,
                                                 "instances": 0, "resolved": 0})
    for finding in findings:
        host = finding.get("host_info") or {}
        acct = host.get("service_provider_account_id") or "unknown"
        all_finding_accounts[acct]["findings"] += 1
        all_finding_accounts[acct]["provider"] = (
            all_finding_accounts[acct]["provider"] or host.get("service_provider"))
    for iid, data in instances.items():
        acct = data.get("account") or "unknown"
        all_finding_accounts[acct]["instances"] += 1
        if iid in resolved_meta:
            all_finding_accounts[acct]["resolved"] += 1

    acct_rows = []
    for acct, info in sorted(all_finding_accounts.items(),
                              key=lambda kv: -kv[1]["findings"]):
        if acct == "unknown":
            continue
        registered = "Yes" if info["resolved"] > 0 else "No"
        acct_rows.append([
            mask_id(acct),
            info["provider"] or "unknown",
            info["findings"],
            info["instances"],
            info["resolved"],
            registered,
        ])

    if acct_rows:
        report.table(
            "Account CSPM registration status",
            ["Account ID", "Cloud", "Critical vuln findings", "VMs with findings",
             "Traced to image", "Registered in CSPM"],
            acct_rows,
            numeric=[2, 3, 4],
            bar=2,
            badges=[5],
            collapsed=len(acct_rows) > 10,
            note="Every cloud account that appeared in vulnerability findings. "
                 "'Registered in CSPM' = at least one VM from this account "
                 "resolved to a CSPM asset. Accounts marked 'No' have sensors "
                 "reporting vulnerabilities but no CSPM cloud registration — "
                 "register them to enable image tracing.",
        )

    ranked = rank_images(images)
    total_cves = len({c for i in images.values() for c in i["cves"]})
    # Count distinct CVEs with each property — not per-image sums, so the numbers
    # nest cleanly: total >= ExPRT >= exploitable >= KEV
    all_cves = {}
    for img in images.values():
        for cve_id, cve_data in img["cves"].items():
            existing = all_cves.get(cve_id)
            if existing is None:
                all_cves[cve_id] = dict(cve_data)
            else:
                existing["exploit"] = existing["exploit"] or cve_data["exploit"]
                existing["kev"] = existing["kev"] or cve_data["kev"]
                if cve_data["exprt"] in ACTIONABLE_RATINGS:
                    existing["exprt"] = cve_data["exprt"]
    total_exploitable = sum(1 for c in all_cves.values() if c["exploit"])
    total_kev = sum(1 for c in all_cves.values() if c["kev"])
    total_actionable = sum(1 for c in all_cves.values() if c["exprt"] in ACTIONABLE_RATINGS)
    total_instances = sum(len(i["instances"]) for i in images.values())
    total_deployed = sum(
        (i.get("deployed") or 0) for i in images.values() if isinstance(i.get("deployed"), int)
    )

    # -- the verdict: the sentence a reader should leave with -----------------
    # Tone is read off the findings, never chosen for effect. `ok` on a report
    # carrying gaps would be a lie told in CSS.
    if ranked:
        top_image, top = ranked[0]
        # Integer floor division, matching the renderer's bar arithmetic -- the
        # three languages this contract covers round differently, so nothing here
        # is allowed to round at all.
        share = (len(top["cves"]) * 100 // total_cves) if total_cves else 0
        lead = "Rebuild one image first: "
        if top["kev"]:
            lead += f"{top_image} carries {top['kev']} CVE(s) on CISA's Known Exploited list"
        elif top["exploitable"]:
            lead += f"{top_image} carries {top['exploitable']} CVE(s) with a public exploit"
        else:
            lead += f"{top_image} is the widest-blast-radius image"
        blast = f" Total footprint: {total_deployed} VMs across {len(images)} images." if total_deployed else ""
        report.verdict(
            f"{lead}, and rebuilding it retires {len(top['cves'])} of {total_cves} "
            f"distinct CVSS-{SEVERITY} CVEs ({share}%) across "
            f"{len(top['instances'])} of {total_instances} sensor-visible instances.{blast}",
            tone="critical" if (top["kev"] or top["exploitable"]) else "high",
        )
    elif findings:
        report.verdict(
            f"{len(findings)} finding(s) at CVSS {SEVERITY}, but none could be "
            "traced to a base image -- see the gaps above before concluding "
            "anything from this page.",
            tone="medium",
        )
    else:
        report.verdict(
            f"No open CVSS-{SEVERITY} findings on cloud instances in this scope. "
            "The queries ran and returned nothing, which is the good kind of "
            "nothing -- the evidence table below shows exactly what was asked.",
            tone="ok",
        )

    report.metric("VM images with critical CVEs", len(images))
    report.metric("VMs running these images", total_deployed or "?",
                  note=f"across {len(images)} images",
                  tone="critical" if total_deployed and total_deployed > total_instances * 2 else "high")
    report.metric("VMs with sensor", total_instances,
                  note=f"of {total_deployed or '?'} total — the visible slice")
    report.metric("Distinct CVEs", total_cves, note=f"CVSS {SEVERITY}")
    report.metric("ExPRT critical/high", total_actionable,
                  note=f"of {total_cves} distinct CVEs",
                  tone="high" if total_actionable else "")
    report.metric("Public exploit", total_exploitable,
                  note=f"of {total_actionable} ExPRT — fix these first",
                  tone="critical" if total_exploitable else "ok")
    report.metric("On CISA KEV", total_kev,
                  note="already used in the wild",
                  tone="critical" if total_kev else "ok")

    report.table(
        "Ranked images",
        ["Risk", "Image", "Cloud", "Account ID", "Account Name", "Region",
         "Name", "Built", "VMs running this image", "VMs with sensor",
         "CVEs", "CVE IDs", "ExPRT crit/high", "Flags"],
        [
            [
                risk_label(data),
                mask_id(image_id),
                data["provider"] or "unknown",
                ", ".join(sorted(mask_id(a) for a in data["accounts"] - {None})) or "unknown",
                ", ".join(sorted(data["account_names"])) or "unknown",
                ", ".join(sorted(data["regions"])) or "unknown",
                data["name"] or "unresolved",
                data["created"] or "unknown",
                data.get("deployed") if data.get("deployed") is not None else "?",
                len(data["instances"]),
                len(data["cves"]),
                sorted(data["cves"].keys()),
                data["actionable"],
                flag_tokens(data),
            ]
            for image_id, data in ranked
        ],
        numeric=[8, 9, 10, 12],
        bar=8,        # deployed -- the real blast radius, drawn to scale
        accent=0,     # Risk tints the whole row's left edge
        badges=[13],
        mono=[1],  # image IDs break anywhere
        details=[11],  # CVE IDs: pivot-drill, one CVE per line
        rank=True,
        note="Ranked by exploitation status first (KEV, then public exploit), "
             "then instances x distinct CVEs. "
             "'VMs running this image' = total instances in CSPM inventory booted "
             "from this image (AWS: from instance-to-image relationship; "
             "Azure/GCP: falls back to traced-instance count — a floor, not the "
             "full blast radius, because the image relationship is on the disk or "
             "VMSS parent, not on the instance entity). "
             "'VMs with sensor' = instances with a Falcon sensor reporting "
             "vulnerabilities. The gap is the unsensored exposure.",
    )

    # Instance detail -- the work order for the platform team.
    instance_rows = []
    for image_id, data in ranked:
        for iid in sorted(data["instances"]):
            inst = instances.get(iid, {})
            inst_cves = inst.get("cves", {})
            n_exploitable = sum(1 for c in inst_cves.values() if c.get("exploit"))
            n_actionable = sum(
                1 for c in inst_cves.values() if c.get("exprt") in ACTIONABLE_RATINGS
            )
            flags = []
            if any(c.get("kev") for c in inst_cves.values()):
                flags.append("KEV")
            if n_exploitable:
                flags.append("Public exploit")
            meta = resolved_meta.get(iid, {})
            state = meta.get("instance_state") or ("active" if meta.get("active") else "unknown")
            instance_rows.append([
                mask_id(iid),
                inst.get("hostname") or "unknown",
                mask_id(meta.get("account") or "unknown"),
                meta.get("account_name") or "unknown",
                meta.get("region") or "unknown",
                state,
                mask_id(image_id),
                meta.get("provider") or data["provider"] or "unknown",
                len(inst_cves),
                sorted(inst_cves.keys()),
                n_actionable,
                ", ".join(flags) if flags else "No known exploit",
                meta.get("resolution") or "unknown",
            ])
    if instance_rows:
        report.table(
            "Instance detail",
            ["Instance ID", "Instance Name", "Account ID", "Account Name",
             "Region", "Status", "Image", "Cloud", "CVEs", "CVE IDs", "ExPRT crit/high", "Flags",
             "Resolution path"],
            instance_rows,
            mono=[0, 6, 12],
            details=[9],  # CVE IDs: pivot-drill
            badges=[11],
            collapsed=len(instance_rows) > 10,
            note="Every instance traced to a vulnerable image. "
                 "Hand this to the platform team.",
        )

    # Coverage per cloud, always rendered -- including the rows that resolved
    # nothing. A cloud missing from the ranking above must be visible here as a
    # zero rather than as an absence, because an absence reads as "you don't run
    # that cloud" and this script cannot tell the difference from the outside.
    report.table(
        "Sensor coverage by cloud",
        ["Cloud", "VMs in CSPM", "Active", "With sensor", "Sensor coverage",
         f"Critical vuln findings", "Traced to image"],
        [
            [name,
             "—" if tally["inventory"] is None else tally["inventory"],
             "—" if tally["running"] is None else tally["running"],
             "—" if tally["sensored"] is None else tally["sensored"],
             (f"{tally['sensored'] / tally['running'] * 100:.0f}%"
              if tally["running"] and tally["sensored"] is not None
              else "—"),
             tally["findings"],
             tally["resolved"]]
            for name, tally in sorted(coverage.items(),
                                      key=lambda kv: -(kv[1]["inventory"] or 0))
            if name != "unidentified"
        ],
        numeric=[1, 2, 3, 5, 6],
        note=(
            "All three left columns come from CSPM (same system, same scan). "
            "'Active' = active:true in CSPM — works across all three clouds "
            "(AWS instance_state:'running' misses Azure's 'VM running' and GCP's "
            "state strings; active:true is the cross-cloud denominator). "
            "'With sensor' = managed_by:'Sensor' in CSPM — the instances Falcon "
            "can assess for vulnerabilities. "
            "Sensor coverage = sensor / active. The gap is the blind spot. "
            "Stopped instances still carry vulnerabilities but are not exposed "
            "until restarted. "
            + "Every instance carrying a finding was resolved. A cloud showing "
            "findings but few or no instances resolved was queried and came back "
            "denied, errored, or with no CSPM asset -- see the gaps above, not a "
            "sampling artifact."
        ),
    )

    if total_cves:
        report.text(
            "Why this ranking is not just a CVE count",
            f"{len(images)} image(s) carry {total_cves} distinct CVSS-{SEVERITY} "
            f"CVEs. Of those, {total_actionable} are ExPRT critical or high, "
            f"{total_exploitable} have a public exploit, and {total_kev} are on "
            "CISA's Known Exploited list. The Flags column is where the actual "
            "urgency lives — CVSS severity alone overstates the workload.",
        )

    # -- evidence, so the numbers above can be checked rather than trusted --
    if EVIDENCE.get("edge"):
        e = EVIDENCE["edge"]
        c = EVIDENCE.get("config") or {}
        # Determine the cloud from the resource_type
        edge_rt = e.get("resource_type") or ""
        if "AWS" in edge_rt:
            cloud = "AWS"
        elif "Microsoft" in edge_rt or "microsoft" in edge_rt:
            cloud = "Azure"
        else:
            cloud = "GCP"
        report.code(
            f"Evidence — instance-to-image edge ({cloud} sample)",
            "\n".join([
                f"instance   {mask_id(e['instance'])}",
                f"cloud      {cloud}",
                "",
                "relationships[] entry (a first-class graph edge):",
                f"  resource_type       {e.get('resource_type')}",
                f"  resource_id         {mask_id(e.get('resource_id'))}",
                f"  relationship_name   {e.get('relationship_name')}",
                "",
                "configuration (parsed from JSON string):",
                f"  imageId             {mask_id(c.get('imageId'))}",
                f"  instanceType        {c.get('instanceType')}",
                f"  launchTime          {c.get('launchTime')}",
            ]),
            note=f"One sample from the {cloud} resolution path. Two independent fields "
                 "in the same record agree, so the attribution is read rather than "
                 "inferred. Every row in the ranked table was resolved through the "
                 "same record shape. Per-instance evidence is available in the JSON "
                 "output via the queries evidence table.",
        )

    if hard_fail:
        return finish(report, 1)
    return finish(report, 2 if (total_exploitable or total_kev) else 0)


def print_dry_run():
    print("Requests this script would make (none are being made):\n")
    print(f"  GET {SPOTLIGHT}")
    if EXPRT_ONLY:
        print("      2 parallel partitions: ExPRT CRITICAL + ExPRT HIGH")
    print(f"      filter={vuln_filter()}")
    print("      facet=host_info&facet=cve")
    print(f"      limit={PAGE_SIZE}, token-paginated"
          + (f" up to {MAX_PAGES} pages per partition" if MAX_PAGES else " until exhausted")
          + "\n")
    cap_desc = f"up to {MAX_INSTANCES}" if MAX_INSTANCES else "one per instance with a finding"
    print(f"  GET {CSPM_QUERY}          ({len(CLOUDS)} inventory counts, one per cloud)")
    for name, spec in CLOUDS.items():
        print(f"      {name}: filter=resource_type:'{spec['instance']}'")
    print(f"  GET {CSPM_QUERY}          ({cap_desc}, {RESOLVE_WORKERS} workers in parallel)")
    for name, spec in CLOUDS.items():
        print(f"      {name}: filter={asset_filter(spec['instance'], '<id>')}")
        if spec["disk"]:
            print(f"        then: filter={asset_filter(spec['disk'], '<disk-id>')}")
    print(f"  GET {CSPM_QUERY}          (per ranked image — ~30-50 queries, not full inventory)")
    for name, spec in CLOUDS.items():
        if spec["image"]:
            print(f"      {name}: filter={asset_filter(spec['image'], '<image-id>')}")
        else:
            print(f"      {name}: no lookup -- identity comes from the disk config")
    print(f"  GET {CSPM_ENTITIES}       (1 id per call)\n")
    print(f"  Scope: accounts={ACCOUNTS or 'all'} severity={SEVERITY}"
          f"{' exprt=HIGH/CRITICAL' if EXPRT_ONLY else ''}"
          f"{f' max_instances={MAX_INSTANCES}' if MAX_INSTANCES else ''}")
    print("  All requests are GET. This script cannot modify your tenant.")
    print("  Every request made is recorded and rendered as an evidence table.")


def main() -> int:
    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__.strip().split("\n")[0])
        print("\n  --dry-run   list every request without making one")
        print("  --verbose   debug-level logging (page-by-page progress)")
        print("  --unmask    show full account IDs (default: obfuscated for stage)")
        print("  --help      this message\n")
        print_dry_run()
        return 3

    if "--dry-run" in sys.argv:
        print_dry_run()
        return 3

    global MASK_ACCOUNTS
    if "--unmask" in sys.argv:
        MASK_ACCOUNTS = False

    level = logging.DEBUG if "--verbose" in sys.argv else logging.INFO
    fmt = logging.Formatter("%(asctime)s %(levelname)-5s %(message)s", datefmt="%H:%M:%S")
    stderr_h = logging.StreamHandler(sys.stderr)
    stderr_h.setFormatter(fmt)
    # Mirror to a file so `tail -f findings/run.log` works even when
    # stderr is captured through a pipe that buffers at the OS level.
    _findings = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "findings")
    os.makedirs(_findings, exist_ok=True)
    _log_stream = open(os.path.join(_findings, "run.log"), "w", buffering=1)  # noqa: SIM115 — line-buffered
    file_h = logging.StreamHandler(_log_stream)
    file_h.setFormatter(fmt)
    logging.basicConfig(level=level, handlers=[stderr_h, file_h])

    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"))
    try:
        client = FalconClient(timeout=60.0)
    except FalconError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    t0 = time.monotonic()
    try:
        report, code = build_report(client)
    except FalconError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    log.info("report built in %.1fs — writing dashboard + CSVs", time.monotonic() - t0)
    masked_cid = mask_id(client.cid) if client.cid else "unknown-cid"
    unix_ts = int(time.time())
    html_path, json_path = report.save(
        f"falcon-{masked_cid}-critical-vulns-by-image-{unix_ts}",
    )
    log.info("saved: %s", html_path)
    print(f"dashboard: {html_path}")
    print(f"data:      {json_path}")
    if code == 1:
        # The dashboard still exists and is still worth reading -- it names what
        # went wrong in its gaps list. But the run failed, so a scheduler must
        # not record it as a clean pass.
        print("exit 1: the run did not complete -- see the gaps at the top of "
              "the dashboard", file=sys.stderr)
    if code == 2:
        print("exit 2: findings with a public exploit or a KEV listing are present")
    return code


if __name__ == "__main__":
    sys.exit(main())
