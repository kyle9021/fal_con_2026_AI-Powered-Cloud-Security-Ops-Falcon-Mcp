#!/usr/bin/env python3
"""Offline self-test for the evidence and provenance paths.

Runs with no credentials and touches no tenant. `scripts/test-crystallized.py`
checks that the ranking is *right*; this checks that the ranking is *traceable*,
which is a different property and the one that decides whether a finding survives
being questioned three weeks later.

It drives `crystallized/critical-vulns-by-image.py` with a stub client that
returns REST-shaped envelopes, then asserts four things:

  1. Every request the script makes reaches the rendered evidence table. A query
     that happened but was not recorded is an unsourced number.
  2. Filters cannot drift. Each recorded FQL string must be byte-identical to one
     the stub was actually sent -- which is what the shared filter functions in
     that script exist to guarantee.
  3. The **four kinds of nothing** stay distinct: a denial (401/403/404), a real
     empty result (HTTP 200, zero rows), a transient error (429/5xx), and a clean
     tenant. A 403 reported as "0 results" is false assurance; an empty result
     reported as a 403 sends someone to fix a permission that was never broken;
     and a 429 reported as either is the worst of the three, because it produces a
     confident green zero for a query that never ran.
  4. The instance-to-image edge is quoted verbatim into the dashboard, so a reader
     can check the pivot rather than take it on trust.

The stubs classify status codes with `FalconClient.denied` and
`FalconClient.errored` themselves rather than a test-only convention. That is
deliberate: it means widening `denied()` to swallow a 429 breaks this test instead
of quietly passing it.

All identifiers here are synthetic placeholders, deliberately not real.

    python3 scripts/test-provenance.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from falcon_api import FalconClient  # noqa: E402

INSTANCE = "i-0000000000000test0"
AMI = "ami-0000000000000test"

FAILURES: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  ok    {label}")
    else:
        print(f"  FAIL  {label}" + (f" -- {detail}" if detail else ""))
        FAILURES.append(label)


def load():
    """Fresh module per scenario -- CALLS and EVIDENCE are module-level state."""
    spec = importlib.util.spec_from_file_location(
        "cvbi", os.path.join(ROOT, "crystallized", "critical-vulns-by-image.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def one_critical_finding():
    """One CVSS-critical finding with a public exploit, on one instance."""
    return {
        "resources": [{
            "id": "finding-1",
            "host_info": {
                "instance_id": INSTANCE, "hostname": "synthetic-host",
                # Spotlight's host_info facet carries the bare literal, not the
                # suffixed AWS_EC2_V2 that /devices returns. Verified live; the
                # script keys CLOUDS off this exact string.
                "service_provider": "AWS",
                "service_provider_account_id": "000000000000",
            },
            "cve": {
                "id": "CVE-2026-00001", "severity": "CRITICAL",
                "exprt_rating": "CRITICAL", "exploit_status": 90,
            },
        }],
        "meta": {"pagination": {}},
    }


def http_error(status: int) -> dict:
    """An error envelope shaped exactly like `FalconClient.get` returns one.

    `_status` is the field the real client sets, so the stubs and the production
    code classify the same bytes. A test-only convention here (`return None` for
    "denied", say) would let the classification logic itself go untested -- and
    the classification logic is where the bug was.
    """
    return {"_status": status, "errors": [{"code": status, "message": "synthetic"}]}


class StubBase:
    """Shared status classification: the real implementations, not stand-ins."""

    denied = staticmethod(FalconClient.denied)
    errored = staticmethod(FalconClient.errored)
    total = staticmethod(FalconClient.total)
    # The scripts pre-warm auth before fanning out to threads. A stub missing this
    # has drifted from the client it stands in for.
    token = "stub-token"


class StubClient(StubBase):
    """GET-only, returns REST-shaped envelopes. Records what it was asked for.

    `image_asset` controls whether the AMI has an AWS::EC2::Image record of its
    own. Defaulting it to absent is deliberate: on a real tenant that lookup
    frequently returns nothing, so the empty path is the common path and needs to
    be the one under test.
    """

    def __init__(self, module, image_asset: bool = False):
        self.m = module
        self.image_asset = image_asset
        self.sent: list[tuple[str, str]] = []

    def get(self, path, params=None):
        params = params or {}
        self.sent.append((path, params.get("filter", "")))
        m = self.m
        if path == m.SPOTLIGHT:
            return one_critical_finding()
        if path == m.CSPM_QUERY:
            if "resource_id" not in params["filter"]:
                # Tenant-wide inventory count, one per cloud. Azure is inventoried
                # but has no findings -- the unsensored-fleet case, which is the one
                # a report can miss without erroring.
                total = {"AWS::EC2::Instance": 1,
                         "Microsoft.Compute/virtualMachines": 2}.get(
                             params["filter"].split("'")[1], 0)
                return {"resources": [], "meta": {"pagination": {"total": total}}}
            if "AWS::EC2::Instance" in params["filter"]:
                return {"resources": ["synthetic-asset-1"]}
            if "AWS::EC2::Image" in params["filter"]:
                return {"resources": ["synthetic-image-1"] if self.image_asset else []}
        if path == m.CSPM_ENTITIES:
            return {"resources": [{
                "account_id": "000000000000",
                "region": "us-west-2",
                "relationships": [{
                    "resource_type": "AWS::EC2::Image",
                    "resource_id": AMI,
                    "relationship_name": "is attached to",
                    "crn": f"aws|000000000000|us-west-2|AWS::EC2::Image|{AMI}",
                }],
                # configuration is a JSON *string* on the real API, not an object.
                # Sending an object here would let a parsing bug pass this test.
                "configuration": json.dumps({
                    "imageId": AMI, "instanceType": "t2.medium",
                    "launchTime": "2026-08-27T11:22:07Z",
                }),
            }]}
        return {"resources": []}


def test_every_query_reaches_the_report():
    print("\nThe ledger reaches the dashboard")
    m = load()
    client = StubClient(m)
    report, exit_code = m.build_report(client)
    data = report.to_dict()

    check("a request was actually made", len(client.sent) > 0)
    check("every request was recorded", len(m.CALLS) == len(client.sent),
          f"{len(client.sent)} sent, {len(m.CALLS)} recorded")
    check("every record was rendered", len(data["queries"]) == len(m.CALLS),
          f"{len(m.CALLS)} recorded, {len(data['queries'])} rendered")
    check("exploitable findings exit 2", exit_code == 2, f"got {exit_code}")
    # An inventoried cloud with zero findings must be named, not omitted. This is
    # the one failure mode with no error to trip over: the row just isn't there.
    check("an inventoried cloud with no findings is called out",
          any("Azure" in g and "unsensored" in g for g in data["gaps"]),
          f"gaps: {data['gaps']}")
    return data


def test_filters_cannot_drift():
    print("\nFilters cannot drift from what was queried")
    m = load()
    client = StubClient(m)
    report, _ = m.build_report(client)
    data = report.to_dict()

    sent = {f for _, f in client.sent if f}
    # Rows for the entities endpoint carry an `ids=` descriptor, not FQL; only
    # the FQL rows are comparable.
    recorded = {q["filter"] for q in data["queries"]
                if ":" in q["filter"] and "'" in q["filter"]}
    check("every recorded filter was really sent", recorded <= sent,
          f"not sent: {sorted(recorded - sent)}")
    check("every sent filter was recorded", sent <= recorded,
          f"unrecorded: {sorted(sent - recorded)}")


def test_nothing_is_reported_four_ways():
    print("\nThe four kinds of nothing stay distinct")

    class DeniedCSPM(StubClient):
        def get(self, path, params=None):
            if path == self.m.SPOTLIGHT:
                return one_critical_finding()
            return http_error(403)

    class EmptyCSPM(StubClient):
        def get(self, path, params=None):
            if path == self.m.SPOTLIGHT:
                return one_critical_finding()
            return {"resources": []}

    class RateLimitedCSPM(StubClient):
        """Spotlight answers, CSPM is rate-limiting. The ranking is incomplete for
        a reason that has nothing to do with the images."""

        def get(self, path, params=None):
            if path == self.m.SPOTLIGHT:
                return one_critical_finding()
            return http_error(429)

    class SpotlightDown(StubClient):
        """The case that produced a green, confident, wholly fictional zero."""

        def get(self, path, params=None):
            return http_error(503)

    m = load()
    denied_report, _ = m.build_report(DeniedCSPM(m))
    denied = denied_report.to_dict()
    denial_claim = any("denied (401/403)" in g for g in denied["gaps"])
    empty_claim = any("HTTP 200, zero results" in g for g in denied["gaps"])
    check("a denial is reported as a denial", denial_claim)
    check("a denial is not reported as an empty result", not empty_claim)
    check("a denial is not reported as a transient error",
          not any("429" in g for g in denied["gaps"]))
    check("a denial is not recorded as 0 results",
          not any(q["returned"] == 0 and "queries/resources" in q["tool"]
                  for q in denied["queries"]))

    m = load()
    empty_report, _ = m.build_report(EmptyCSPM(m))
    empty = empty_report.to_dict()
    check("an empty result is reported as an empty result",
          any("HTTP 200, zero results" in g for g in empty["gaps"]))
    check("an empty result is not reported as a 403",
          not any("denied (401/403)" in g for g in empty["gaps"]))
    check("an empty result is not reported as a transient error",
          not any("429" in g for g in empty["gaps"]))
    check("the empty query itself is recorded",
          any(q["returned"] == 0 for q in empty["queries"]))

    # -- the regression cases -------------------------------------------------
    # A 429 or 5xx once fell through denied(), extended an empty list, found no
    # `after` token, and was reported as a fully-paginated zero: no gap, exit 0,
    # green in CI. Both halves of that failure are asserted here.
    m = load()
    limited_report, limited_code = m.build_report(RateLimitedCSPM(m))
    limited = limited_report.to_dict()
    check("a 429 is reported as transient, not as a denial",
          any("429/5xx" in g for g in limited["gaps"])
          and not any("denied (401/403)" in g for g in limited["gaps"]))
    check("a 429 is not reported as an empty result",
          not any("HTTP 200, zero results" in g for g in limited["gaps"]))
    check("a 429 fails the run", limited_code == 1, f"got {limited_code}")

    m = load()
    down_report, down_code = m.build_report(SpotlightDown(m))
    down = down_report.to_dict()
    check("a 5xx fails the run", down_code == 1, f"got {down_code}")
    check("a 5xx raises a gap", len(down["gaps"]) > 0)
    check("a 5xx never claims full pagination",
          not any("Fully paginated" in str(q["note"]) for q in down["queries"]))
    check("a 5xx never renders a confident zero",
          not any(q["returned"] == 0 for q in down["queries"]))
    check("a 5xx reports findings as unavailable, not as 0",
          any(mt["value"] is None for mt in down["metrics"]))
    check("a 5xx still shows what it tried to ask", len(down["queries"]) > 0)

    m = load()
    clean_report, clean_code = m.build_report(Clean(m))
    clean = clean_report.to_dict()
    check("a clean tenant exits 0", clean_code == 0, f"got {clean_code}")
    check("a clean tenant still records its query",
          any(q["returned"] == 0 for q in clean["queries"]))
    # The pair that pins the distinction: only the clean run may claim it saw
    # every page. If this ever passes for SpotlightDown too, the bug is back.
    check("a clean tenant does claim full pagination",
          any("Fully paginated" in str(q["note"]) for q in clean["queries"]))
    check("a clean tenant raises no gaps", not clean["gaps"],
          f"got {clean['gaps']}")


class Clean(StubBase):
    """Nothing wrong anywhere -- the answer is genuinely 'no findings'."""

    def __init__(self, module):
        self.m = module

    def get(self, path, params=None):
        return {"resources": [], "meta": {"pagination": {}}}


def test_the_pivot_is_quoted_verbatim():
    print("\nThe pivot is shown, not asserted")
    m = load()
    report, _ = m.build_report(StubClient(m))
    data = report.to_dict()

    check("relationship edge captured", m.EVIDENCE.get("edge", {}).get("resource_id") == AMI)
    check("relationship name captured",
          m.EVIDENCE.get("edge", {}).get("relationship_name") == "is attached to")
    check("configuration string was parsed",
          m.EVIDENCE.get("config", {}).get("imageId") == AMI)

    code_blocks = [b for b in data["blocks"] if b["kind"] == "code"]
    check("a verbatim evidence block was emitted", len(code_blocks) >= 1)
    body = "\n".join(b["body"] for b in code_blocks)
    check("the AMI appears in the evidence block", AMI in body)
    check("the instance appears in the evidence block", INSTANCE in body)


def test_the_rendered_html_carries_it_all():
    print("\nThe rendered dashboard carries the receipts")
    m = load()
    report, _ = m.build_report(StubClient(m))
    data = report.to_dict()
    html_path, json_path = report.save("selftest-provenance")
    try:
        html = open(html_path, encoding="utf-8").read()
        check("evidence values present in html", AMI in html and INSTANCE in html)
        check("the edge is rendered", "is attached to" in html)
        check("one row per recorded query", html.count("<tr") >= len(data["queries"]))
        check("no script tag", "<script" not in html.lower())
        check("no external reference", "http://" not in html and "https://" not in html)
        check("written 0600", oct(os.stat(html_path).st_mode)[-4:] == "0600")
    finally:
        # Synthetic, but findings/ is for real output. Do not leave it behind.
        for path in (html_path, json_path):
            if os.path.exists(path):
                os.remove(path)


def main() -> int:
    print("Offline self-test: evidence and provenance")
    print("No credentials required; no tenant is contacted.")

    test_every_query_reaches_the_report()
    test_filters_cannot_drift()
    test_nothing_is_reported_four_ways()
    test_the_pivot_is_quoted_verbatim()
    test_the_rendered_html_carries_it_all()

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
