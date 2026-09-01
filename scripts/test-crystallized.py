#!/usr/bin/env python3
"""Offline self-test for the crystallized scripts and the dashboard renderer.

Runs with no credentials and touches no tenant. Two things it proves:

  1. The dashboard renderer holds its security properties -- no script tags, no
     external references, everything escaped, and `None` rendered differently
     from `0`.
  2. The ranking logic in `crystallized/critical-vulns-by-image.py` reproduces
     the conclusion the interactive `/trace-vm-image` investigation reached, using
     synthetic findings shaped like real ones.

Point 2 is the one that matters. A crystallized script is only trustworthy if it
agrees with the investigation that justified writing it, and this is how that
agreement gets checked without a live tenant. All data here is synthetic:
`i-AAA` / `ami-AAA` are placeholders, deliberately not real identifiers.

    python3 scripts/test-crystallized.py
"""

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.join(ROOT, "crystallized"))

import importlib.util  # noqa: E402

from falcon_report import Report  # noqa: E402

# The module name has a hyphen, so it needs the explicit loader.
_spec = importlib.util.spec_from_file_location(
    "cvbi", os.path.join(ROOT, "crystallized", "critical-vulns-by-image.py")
)
cvbi = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cvbi)

FAILURES: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  ok    {label}")
    else:
        print(f"  FAIL  {label}" + (f" -- {detail}" if detail else ""))
        FAILURES.append(label)


def synthetic_findings():
    """Two instances, shaped like a real Spotlight response with both facets.

    Modelled on the profile the interactive investigation found: a heavily
    exposed host where most CVSS-critical findings are not actually urgent, and a
    quieter one where none are.
    """
    findings = []

    # Instance A: 76 CVSS-critical CVEs. ExPRT: 10 critical, 25 high, 9 of the
    # criticals have a public exploit, 3 of those 9 are on CISA KEV. This is the
    # shape that motivates ranking on ExPRT rather than CVSS.
    for i in range(76):
        if i < 10:
            rating, exploit = "CRITICAL", (i < 9)
        elif i < 35:
            rating, exploit = "HIGH", False
        elif i < 44:
            rating, exploit = "MEDIUM", False
        else:
            rating, exploit = "LOW", False
        findings.append({
            "host_info": {
                "instance_id": "i-AAA", "hostname": "host-a",
                "service_provider": "AWS_EC2_V2",
                "service_provider_account_id": "000000000001",
            },
            "cve": {
                "id": f"CVE-2000-{1000 + i}",
                "exprt_rating": rating,
                "exploit_status": "90" if exploit else "0",
                "cisa_info": {"is_cisa_kev": i < 3},
            },
        })

    # Instance B: 23 CVSS-critical CVEs, none exploitable, none ExPRT critical.
    for i in range(23):
        findings.append({
            "host_info": {
                "instance_id": "i-BBB", "hostname": "host-b",
                "service_provider": "AWS_EC2_V2",
                "service_provider_account_id": "000000000001",
            },
            "cve": {
                "id": f"CVE-2001-{2000 + i}",
                "exprt_rating": "HIGH" if i < 19 else "MEDIUM",
                "exploit_status": "0",
                "cisa_info": {"is_cisa_kev": False},
            },
        })

    # A finding on a non-cloud host: no instance_id, so it cannot be traced to an
    # image. It must be counted as a gap, not silently dropped.
    findings.append({
        "host_info": {"hostname": "laptop-1"},
        "cve": {"id": "CVE-2002-3000", "exprt_rating": "HIGH", "exploit_status": "0"},
    })
    return findings


def test_grouping() -> dict:
    print("\nGrouping and counting")
    instances, untraceable = cvbi.group_by_instance(synthetic_findings())

    check("two traceable instances", len(instances) == 2, f"got {len(instances)}")
    check("untraceable finding counted, not dropped", untraceable == 1, f"got {untraceable}")
    check("instance A has 76 distinct CVEs", len(instances["i-AAA"]["cves"]) == 76)
    check("instance B has 23 distinct CVEs", len(instances["i-BBB"]["cves"]) == 23)

    a = instances["i-AAA"]["cves"].values()
    exploitable = sum(1 for c in a if c["exploit"])
    actionable = sum(1 for c in a if c["exprt"] in cvbi.ACTIONABLE_RATINGS)
    kev = sum(1 for c in a if c["kev"])
    check("instance A: 9 exploitable", exploitable == 9, f"got {exploitable}")
    check("instance A: 35 ExPRT critical/high", actionable == 35, f"got {actionable}")
    check("instance A: 3 on CISA KEV", kev == 3, f"got {kev}")

    # The headline of the investigation: CVSS-critical overstates the workload.
    check("CVSS overstates urgency (76 critical, 9 exploitable)", 76 > exploitable * 8)

    b = instances["i-BBB"]["cves"].values()
    check("instance B: nothing exploitable", sum(1 for c in b if c["exploit"]) == 0)
    check("instance B: nothing on KEV", sum(1 for c in b if c["kev"]) == 0)
    return instances


def _image(grouped, cve_source, **kwargs):
    """Build an image aggregate with every key rank_images reads.

    Spelled out rather than defaulted, so adding a ranking key to the script
    breaks this test loudly instead of ranking on a silently-absent field.
    """
    image = {
        "instances": set(), "cves": grouped[cve_source]["cves"],
        "accounts": {"000000000001"}, "exploitable": 0, "kev": 0,
        "actionable": 0, "name": None, "created": None,
    }
    image.update(kwargs)
    return image


def test_ranking(instances: dict) -> None:
    print("\nRanking")
    images = {
        # One instance, one KEV CVE. Smallest blast radius, highest urgency:
        # someone has already used this against someone else.
        "ami-KEV": _image(instances, "i-BBB", instances={"i-EEE"},
                          kev=1, actionable=19, name="image-kev",
                          created="2023-05-05"),
        "ami-AAA": _image(instances, "i-AAA", instances={"i-AAA"},
                          exploitable=9, kev=0, actionable=35,
                          name="image-a", created="2021-08-16"),
        # More instances and a larger blast-radius product, but nothing
        # exploitable. It must still rank last.
        "ami-BBB": _image(instances, "i-BBB",
                          instances={"i-BBB", "i-CCC", "i-DDD"},
                          exploitable=0, kev=0, actionable=19,
                          name="image-b", created="2024-01-01"),
    }
    ranked = cvbi.rank_images(images)
    order = [ami for ami, _ in ranked]
    check("KEV outranks a merely public exploit", order[0] == "ami-KEV",
          f"got {order}")
    check("exploitability outranks blast radius", order[1] == "ami-AAA",
          f"got {order}")
    check("all images ranked", len(ranked) == 3)

    # The row tint and the flag chips are read off the same evidence the ranking
    # uses. A row tinted `critical` with a `No known exploit` chip would be a
    # contradiction the reader could see, so both are checked against one input.
    check("KEV image is labelled critical",
          cvbi.risk_label(images["ami-KEV"]) == "critical")
    check("exploitable image is labelled critical",
          cvbi.risk_label(images["ami-AAA"]) == "critical")
    check("actionable-only image is labelled high",
          cvbi.risk_label(images["ami-BBB"]) == "high")
    check("KEV flag rendered", cvbi.flag_tokens(images["ami-KEV"]) == "KEV")
    check("exploit flag rendered",
          cvbi.flag_tokens(images["ami-AAA"]) == "Public exploit")
    check("absence of exploit is stated, not left blank",
          cvbi.flag_tokens(images["ami-BBB"]) == "No known exploit")


def test_renderer() -> None:
    print("\nDashboard renderer")
    report = Report("Self test", subtitle="Synthetic data", scope="offline")
    report.metric("A real zero", 0)
    report.metric("Unavailable", None, note="missing scope")
    report.gap("A gap line.")
    report.table("Escaping", ["Name", "Sev", "N"],
                 [["<script>alert(1)</script>", "Critical", 3],
                  ['tag:"q" & <b>', "Low", 1]], numeric=[2])
    report.table("Empty", ["A"], [])
    body = report.to_html()

    check("no script tag in output", "<script" not in body.lower())
    check("payload is escaped", "&lt;script&gt;" in body)
    check("ampersand escaped", "&amp;" in body)
    check("no external http(s) reference",
          not re.search(r'(?:src|href)\s*=\s*["\']https?:', body))
    check("real zero renders as 0", '<div class="v">0</div>' in body)
    check("None renders as unavailable", "unavailable" in body)
    check("gaps section present", "Not established by this run" in body)
    check("empty table states it is a real answer", "real answer" in body)
    check("severity colouring applied", "sev-critical" in body)

    data = report.to_dict()
    check("json mirrors the html", data["metrics"][1]["value"] is None)


def test_uncapped_parallel_resolution() -> None:
    """40 instances — well past the old default cap of 25 — all get classified."""
    print("\nUncapped parallel resolution")
    N = 40
    # Synthetic findings: N instances, 2 CVEs each, spread across AWS and GCP.
    findings = []
    for i in range(N):
        provider = "AWS_EC2_V2" if i % 2 == 0 else "GCP"
        for j in range(2):
            findings.append({
                "host_info": {
                    "instance_id": f"i-{i:04d}", "hostname": f"host-{i}",
                    "service_provider": provider,
                    "service_provider_account_id": "111111111111",
                },
                "cve": {
                    "id": f"CVE-9999-{i * 10 + j}",
                    "exprt_rating": "HIGH",
                    "exploit_status": "0",
                    "cisa_info": {"is_cisa_kev": False},
                },
            })

    # Monkeypatch: resolve_image returns a fixed image per instance, and
    # resolve_image_name returns a stub name. No real API calls.
    def fake_resolve_image(_client, provider, instance_id):
        return {"image": f"img-{instance_id}", "provider": provider,
                "account": "111111111111", "name": None}

    def fake_resolve_image_name(_client, _provider, _image_id):
        return "ok", {"name": "fake-image", "created": "2024-01-01"}

    orig_fetch = cvbi.fetch_findings
    orig_resolve = cvbi.resolve_image
    orig_resolve_name = cvbi.resolve_image_name
    orig_calls = cvbi.CALLS[:]
    orig_evidence = dict(cvbi.EVIDENCE)
    cvbi.fetch_findings = lambda _client: ("ok", findings, False)
    cvbi.resolve_image = fake_resolve_image
    cvbi.resolve_image_name = fake_resolve_image_name
    try:
        cvbi.CALLS.clear()
        cvbi.EVIDENCE.clear()

        class StubClient:
            token = "fake"
            def get(self, *a, **kw):
                return {"resources": [], "meta": {"pagination": {"total": 0}}}
            @staticmethod
            def denied(p): return False
            @staticmethod
            def errored(p): return False
            @staticmethod
            def total(p):
                try: return int(p["meta"]["pagination"]["total"])
                except Exception: return None

        report, code = cvbi.build_report(StubClient())
        data = report.to_dict()
    finally:
        cvbi.fetch_findings = orig_fetch
        cvbi.resolve_image = orig_resolve
        cvbi.resolve_image_name = orig_resolve_name
        cvbi.CALLS[:] = orig_calls
        cvbi.EVIDENCE.clear()
        cvbi.EVIDENCE.update(orig_evidence)

    # Count resolved instances across all images in the report.
    resolved_instances = set()
    for block in data["blocks"]:
        if block.get("kind") == "table" and block["heading"] == "Coverage by cloud":
            total_resolved = sum(row[3] for row in block["rows"])
            check("all 40 instances resolved (coverage table)",
                  total_resolved == N, f"got {total_resolved}")
            break
    else:
        check("coverage table exists", False, "not found")

    # No gap about a cap should appear when MAX_INSTANCES is None.
    gap_texts = " ".join(data.get("gaps") or [])
    check("no cap gap when MAX_INSTANCES is None",
          "HARNESS_MAX_INSTANCES" not in gap_texts,
          f"found cap gap: {gap_texts[:120]}")

    check("exit code 0 (no exploits in synthetic data)", code == 0, f"got {code}")


def test_dry_run_makes_no_requests() -> None:
    print("\nDry run")
    # A dry run must not construct a client, so it must work with no credentials
    # set. This test process has none, which is the point.
    argv = sys.argv
    sys.argv = ["x", "--dry-run"]
    try:
        code = cvbi.main()
    finally:
        sys.argv = argv
    # 3, not 0: a dry run must be distinguishable from a clean run forever, or a
    # cron entry with a stray --dry-run silently reports success every night.
    check("dry run exits 3 with no credentials", code == 3, f"got {code}")


def main() -> int:
    print("Offline self-test: renderer and crystallized ranking logic")
    print("No credentials required; no tenant is contacted.")
    instances = test_grouping()
    test_ranking(instances)
    test_renderer()
    test_uncapped_parallel_resolution()
    test_dry_run_makes_no_requests()

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) failed:")
        for name in FAILURES:
            print(f"  - {name}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
