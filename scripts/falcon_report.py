"""Render an investigation into a self-contained HTML dashboard and a JSON file.

Why this exists
---------------
An MCP investigation is expensive and exploratory: a model burns tokens deciding
*which* questions to ask. Once you know the questions, the answers no longer need
a model at all. `/crystallize` turns a finished investigation into a plain script
that calls the Falcon API directly -- and this module is what those scripts use to
present their results.

Who the output is for
---------------------
A cloud security engineer triaging on a Monday morning, or the same person putting
the file on a projector. That reader has one question -- *what do I fix first?* --
so the layout answers it before it justifies it: verdict, then what is missing,
then the numbers, then the ranked work, then the receipts. Severity is carried by
colour and row position rather than by a column the reader has to scan for, and
blast radius is drawn as a proportion bar so nobody has to divide two numbers in
their head to see that one image dominates.

Design constraints (deliberate, and each one is a security property):

  * **Stdlib only.** No pip install, works on any Python 3.9+, nothing to audit
    beyond this file.
  * **Zero external resources in the output.** No CDN, no webfont, no analytics,
    no `<script>` tag at all. A dashboard full of your vulnerability data must not
    make a single outbound request when opened. Sorting and aggregation happen
    here, in Python, before rendering -- which is why no JavaScript is needed. The
    one interactive element, the collapsible evidence section, is native
    `<details>`: interaction without script.
  * **Everything is HTML-escaped.** Hostnames, tags and image names are attacker-
    influenceable in principle; a container image tag is a fine place to hide
    `<script>`. All interpolation goes through `html.escape`.
  * **None is not zero.** A metric whose value could not be determined renders as
    "unavailable" in grey, visibly different from a real 0. Reporting "0 critical
    vulnerabilities" when the truth is "no Spotlight scope" is the most dangerous
    output this harness can produce.
  * **Gaps render at the top, not the bottom.** An incomplete answer the reader
    believes is complete is worse than one they know is partial.
  * **Every claim carries its evidence.** `query()` records the exact filter that
    produced each number, and `code()` shows verbatim payload excerpts. The
    evidence table renders expanded by default and can be folded away for a demo,
    but it is never omitted. A dashboard that asserts "246 findings" without
    showing the query is asking to be trusted; one that shows the FQL is asking to
    be checked. In front of a customer, only the second is defensible -- and
    months later it is the only kind still auditable.

`generated_at` is an input, not something rendering computes, so a fixture can be
replayed and compared byte for byte against `tests/golden/report.html`.

Output goes to `findings/`, which is gitignored: a dashboard of where you are
weakest is not something to push to a public repo.
"""

from __future__ import annotations

import csv
import html
import json
import os
import re as _re
import time
from typing import Any, Iterable, Sequence

__all__ = ["Report"]

# Resolve findings/ relative to the repo, not the caller's cwd, so a crystallized
# script behaves the same whether it is run from the repo root or from cron.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUTPUT_DIR = os.path.join(_REPO_ROOT, "findings")

_CSS = """
:root {
  --ink: #f3f5f8; --body: #d4d9e1; --muted: #9aa2b1; --faint: #6b7284;
  --line: #2c3038; --rule: #3a3f49; --bg: #14161a; --card: #1f2229;
  --brand: #e0091a;
  --crit: #ff5468; --crit-bg: #3a1620; --high: #ff9d42; --high-bg: #3a2810;
  --med: #f0c93b; --med-bg: #382f0e; --low: #8fa8d6; --low-bg: #1c2636;
  --ok: #4ade80; --ok-bg: #113322; --info: #6fb0ff; --info-bg: #142a42;
  --surface: #262a33; --stripe: #242830; --hover: #2a2f3a;
  --neutral-bg: #2a2e38; --neutral-ink: #aab0bd;
  --handle-bg: #332b0f; --handle-border: #6b551c; --handle-accent: #bf9518;
  --handle-ink: #e3cf8f;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 1.75rem 1.5rem 4rem; background: var(--bg); color: var(--body);
  font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  -webkit-text-size-adjust: 100%;
}
main { max-width: 1180px; margin: 0 auto; }

/* -- header ------------------------------------------------------------- */
header { border-bottom: 3px solid var(--brand); padding-bottom: .85rem; margin-bottom: 1.1rem; }
h1 { font-size: 1.75rem; line-height: 1.15; margin: 0 0 .35rem; color: var(--ink);
  letter-spacing: -.015em; font-weight: 650; }
h2 { font-size: 1.02rem; margin: 2.1rem 0 .5rem; color: var(--ink); font-weight: 650;
  letter-spacing: -.005em; }
.sub { color: var(--muted); font-size: .88rem; margin: .15rem 0 0; }
.sub b { color: var(--body); font-weight: 600; }
.meta { display: flex; flex-wrap: wrap; gap: .3rem .9rem; margin: .5rem 0 0;
  font-size: .82rem; color: var(--muted); }
.meta span { white-space: nowrap; }

/* -- verdict: the answer, before the justification ---------------------- */
.verdict {
  background: var(--card); border: 1px solid var(--line); border-left: 6px solid var(--rule);
  border-radius: 5px; padding: .85rem 1.1rem; margin: 0 0 1.15rem;
}
.verdict .vk { font-size: .7rem; font-weight: 700; text-transform: uppercase;
  letter-spacing: .1em; color: var(--muted); margin-bottom: .2rem; }
.verdict p { margin: 0; font-size: 1.12rem; line-height: 1.4; color: var(--ink);
  font-weight: 550; }
.verdict.t-critical { border-left-color: var(--crit); background: var(--crit-bg); }
.verdict.t-critical .vk { color: var(--crit); }
.verdict.t-high { border-left-color: var(--high); background: var(--high-bg); }
.verdict.t-high .vk { color: var(--high); }
.verdict.t-medium { border-left-color: var(--med); background: var(--med-bg); }
.verdict.t-medium .vk { color: var(--med); }
.verdict.t-ok { border-left-color: var(--ok); background: var(--ok-bg); }
.verdict.t-ok .vk { color: var(--ok); }
.verdict.t-info { border-left-color: var(--info); background: var(--info-bg); }
.verdict.t-info .vk { color: var(--info); }

/* -- gaps: what this run did not establish ------------------------------ */
.gaps { background: var(--card); border: 1px solid var(--line);
  border-left: 6px solid var(--med); border-radius: 5px;
  padding: .8rem 1.1rem; margin-bottom: 1.15rem; }
.gaps h2 { margin: 0; font-size: .78rem; text-transform: uppercase;
  letter-spacing: .08em; color: var(--med); font-weight: 700; }
.gaps ul { margin: .45rem 0 0; padding-left: 1.15rem; }
.gaps li { margin: .3rem 0; font-size: .9rem; }

/* -- metrics ------------------------------------------------------------ */
.metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
  gap: .7rem; margin: 1.15rem 0 0; }
.metric { background: var(--card); border: 1px solid var(--line);
  border-top: 3px solid var(--rule); border-radius: 5px; padding: .75rem .9rem; }
.metric .l { font-size: .72rem; color: var(--muted); text-transform: uppercase;
  letter-spacing: .07em; font-weight: 650; }
.metric .v { font-size: 2.05rem; font-weight: 660; line-height: 1.05;
  letter-spacing: -.03em; color: var(--ink); font-variant-numeric: tabular-nums;
  margin-top: .15rem; }
.metric .n { font-size: .78rem; color: var(--muted); margin-top: .3rem; line-height: 1.35; }
.metric .unavailable { font-size: 1.05rem; font-weight: 600; font-style: italic;
  color: var(--muted); letter-spacing: 0; padding: .45rem 0 .35rem; }
.metric.t-critical { border-top-color: var(--crit); }
.metric.t-critical .v { color: var(--crit); }
.metric.t-high { border-top-color: var(--high); }
.metric.t-high .v { color: var(--high); }
.metric.t-medium { border-top-color: var(--med); }
.metric.t-medium .v { color: var(--med); }
.metric.t-ok { border-top-color: var(--ok); }
.metric.t-ok .v { color: var(--ok); }
.metric.t-info { border-top-color: var(--info); }
.metric.t-info .v { color: var(--info); }

/* -- tables: built to be triaged top-down ------------------------------- */
.tbl { background: var(--card); border: 1px solid var(--line); border-radius: 5px;
  margin: .55rem 0 0; overflow: auto; max-height: 78vh; }
table { border-collapse: separate; border-spacing: 0; width: 100%; font-size: .92rem; }
th, td { text-align: left; padding: .52rem .7rem; vertical-align: top;
  border-bottom: 1px solid var(--line); }
thead th { position: sticky; top: 0; z-index: 1; background: var(--surface);
  font-weight: 700; font-size: .715rem; text-transform: uppercase;
  letter-spacing: .06em; color: var(--muted); border-bottom: 2px solid var(--rule);
  white-space: nowrap; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:nth-child(even) { background: var(--stripe); }
tbody tr:hover { background: var(--hover); }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }

/* Rank gutter, and a left accent that carries severity without a column. */
td.rank, th.rank { width: 2.6rem; text-align: right; padding-right: .55rem;
  color: var(--faint); font-variant-numeric: tabular-nums; font-weight: 650;
  font-size: .82rem; }
tbody tr.top td.rank { color: var(--ink); }
tbody tr.top td { font-weight: 550; }
td:first-child { border-left: 4px solid transparent; }
tr.a-critical td:first-child { border-left-color: var(--crit); }
tr.a-high td:first-child { border-left-color: var(--high); }
tr.a-medium td:first-child { border-left-color: var(--med); }
tr.a-low td:first-child { border-left-color: var(--low); }
tr.a-ok td:first-child { border-left-color: var(--ok); }

/* Proportion bar: the number stays authoritative, the bar is the glance. */
td.bar { position: relative; text-align: right; font-variant-numeric: tabular-nums;
  min-width: 6.5rem; }
td.bar .track { display: block; height: .34rem; margin-top: .28rem;
  background: var(--line); border-radius: 2px; overflow: hidden; }
td.bar .fill { display: block; height: 100%; background: var(--low); border-radius: 2px; }
tr.a-critical td.bar .fill { background: var(--crit); }
tr.a-high td.bar .fill { background: var(--high); }
tr.a-medium td.bar .fill { background: var(--med); }

/* Badges: exploit status and KEV read as flags, not as prose. */
.badge { display: inline-block; padding: .1rem .38rem; margin: 0 .2rem .18rem 0;
  border-radius: 3px; font-size: .68rem; font-weight: 750; letter-spacing: .05em;
  text-transform: uppercase; white-space: nowrap; border: 1px solid transparent; }
.b-critical { background: var(--crit-bg); color: var(--crit); border-color: transparent; }
.b-high { background: var(--high-bg); color: var(--high); border-color: transparent; }
.b-medium { background: var(--med-bg); color: var(--med); border-color: transparent; }
.b-low { background: var(--low-bg); color: var(--low); border-color: transparent; }
.b-ok { background: var(--ok-bg); color: var(--ok); border-color: transparent; }
.b-neutral { background: var(--neutral-bg); color: var(--neutral-ink); border-color: var(--line); }
.bnone { color: var(--faint); }

/* -- text, code, notes -------------------------------------------------- */
.lede { background: var(--card); border: 1px solid var(--line); border-radius: 5px;
  padding: .8rem 1.05rem; margin: .55rem 0 0; font-size: 1rem; line-height: 1.5; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .85em; }
pre {
  background: var(--surface); border: 1px solid var(--line); border-left: 4px solid var(--rule);
  border-radius: 4px; padding: .75rem .9rem; margin: .55rem 0 0; overflow-x: auto;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .82rem; line-height: 1.5; white-space: pre-wrap; word-break: break-word;
  color: var(--body);
}
td.mono, td.fql { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .805rem; word-break: break-word; line-height: 1.45; }
td.fql { max-width: 34rem; color: var(--body); }
td.id { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .805rem; color: var(--body); word-break: break-all; }
.note { color: var(--muted); font-size: .84rem; margin: .4rem 0 0; line-height: 1.45; }
.sev-critical { color: var(--crit); font-weight: 700; }
.sev-high { color: var(--high); font-weight: 700; }
.sev-medium { color: var(--med); font-weight: 600; }
.sev-low { color: var(--low); }
.sev-none, .sev-informational { color: var(--faint); }
.empty { color: var(--muted); font-style: italic; padding: .85rem .7rem; }

/* -- evidence: foldable for a demo, never absent ------------------------ */
.evidence { margin-top: 2.4rem; border-top: 3px solid var(--ink); padding-top: .1rem; }
.evidence summary { cursor: pointer; list-style: none; padding: .75rem 0 .1rem;
  font-size: 1.02rem; font-weight: 650; color: var(--ink); }
.evidence summary::-webkit-details-marker { display: none; }
.evidence summary::before { content: "\\25bc  "; font-size: .7em; color: var(--muted); }
.evidence:not([open]) summary::before { content: "\\25b6  "; }
.evidence summary .count { font-weight: 600; color: var(--muted); font-size: .84rem;
  letter-spacing: .02em; }
.evidence .tbl { max-height: none; }
.evidence tr.note-row td.note { padding: .1rem 1rem .6rem; color: var(--muted);
  font-size: .84rem; font-style: italic; border-top: none; }

/* -- fold: a real bucket that isn't the headline ------------------------ */
.fold { margin: 1.6rem 0; }
.fold summary { cursor: pointer; list-style: none; padding: .5rem 0;
  font-size: .92rem; font-weight: 600; color: var(--muted); }
.fold summary::-webkit-details-marker { display: none; }
.fold summary::before { content: "\\25b6  "; font-size: .7em; color: var(--faint); }
.fold[open] summary::before { content: "\\25bc  "; }
.fold summary .count { font-weight: 600; color: var(--faint); font-size: .84rem; }
.fold h2 { margin-top: .35rem; }

/* -- drill-down: pivot-like expand in a table cell ------------------------ */
td .drill { margin: 0; }
td .drill summary { cursor: pointer; list-style: none; font-weight: 600;
  color: var(--info); font-size: .88rem; }
td .drill summary::-webkit-details-marker { display: none; }
td .drill summary::before { content: "\\25b6  "; font-size: .65em; color: var(--faint); }
td .drill[open] summary::before { content: "\\25bc  "; }
.drill-list { padding: .25rem 0 0; line-height: 1.55;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .78rem; color: var(--body); white-space: nowrap; }

/* -- data-handling notice: real, but not the headline ------------------- */
.handling { margin-top: 1.6rem; background: var(--handle-bg); border: 1px solid var(--handle-border);
  border-left: 4px solid var(--handle-accent); border-radius: 4px; padding: .6rem .85rem;
  font-size: .83rem; line-height: 1.5; color: var(--handle-ink); }
footer { margin-top: 1.1rem; padding-top: .85rem; border-top: 1px solid var(--line);
  color: var(--muted); font-size: .8rem; line-height: 1.5; }

@media (max-width: 640px) {
  body { padding: 1rem .75rem 3rem; }
  h1 { font-size: 1.4rem; }
  .metric .v { font-size: 1.7rem; }
  .tbl { max-height: none; }
}
@media print {
  :root {
    --ink:#14161a; --body:#2a2f39; --muted:#646b78; --faint:#8b929e;
    --line:#dfe3e9; --rule:#c8ced8; --bg:#fff; --card:#fff;
    --brand:#a80f1c;
    --crit:#a80f1c; --crit-bg:#fdeaec; --high:#b4530a; --high-bg:#fdf0e4;
    --med:#7d6300; --med-bg:#fbf5e0; --low:#45526a; --low-bg:#eef1f6;
    --ok:#14603a; --ok-bg:#e6f4ec; --info:#1f4f8f; --info-bg:#e8f0fa;
    --surface:#e9edf3; --stripe:#fafbfc; --hover:#f2f6fc;
    --neutral-bg:#eef0f4; --neutral-ink:#4a5262;
    --handle-bg:#fdf8e8; --handle-border:#e6d191; --handle-accent:#bf9518;
    --handle-ink:#4a4433;
  }
  body { background: #fff; padding: 0; font-size: 10.5pt; color: #000; }
  main { max-width: none; }
  .tbl { max-height: none; overflow: visible; border-radius: 0; }
  thead th { position: static; }
  tbody tr:hover { background: transparent; }
  .handling { border-color: #999; }
  table, .metric, .gaps, .verdict, pre, .lede { break-inside: avoid; }
  h2 { break-after: avoid; }
  .evidence summary::before { content: ""; }
  .fold summary::before { content: ""; }
  .fold > *:not(summary) { display: block !important; }
}
"""

# Cell values matching these (after ASCII folding) get severity colouring.
_SEVERITIES = {"critical", "high", "medium", "low", "none", "informational"}

# Tones a caller may request. Anything else is ignored rather than emitted, so a
# typo cannot inject a class name into the document.
_TONES = {"critical", "high", "medium", "low", "ok", "info"}

# Badge text -> tone. The only producer in the repo emits "KEV", "Public exploit"
# and "No known exploit"; the rest are the tone words a skill may pass directly.
# Unmapped text renders b-neutral, which is why "No known exploit" is absent.
_BADGE_TONES = {
    "kev": "critical", "public exploit": "critical", "critical": "critical",
    "high": "high", "poc": "high", "medium": "medium", "low": "low", "none": "low",
    "ok": "ok", "fixed": "ok", "patched": "ok",
    "yes": "ok", "no": "critical",
}


def _key(value: Any) -> str:
    """Normalise a cell value for classification. Never used for display."""
    if value is None:
        return ""
    return str(value).strip().lower()


def _esc(value: Any) -> str:
    """HTML-escape any value. None becomes an em dash, never the string 'None'."""
    if value is None:
        return "&mdash;"
    return html.escape(str(value), quote=True)


def _tone_class(tone: Any, prefix: str) -> str:
    """`' t-high'` for a recognised tone, `''` otherwise. Unknown tones are dropped."""
    if not tone:
        return ""
    folded = _key(tone)
    return f" {prefix}-{folded}" if folded in _TONES else ""


def _as_count(value: Any) -> int | None:
    """A non-negative integer, or None. Only used to scale proportion bars."""
    if value is None or isinstance(value, bool):
        return None
    try:
        n = int(str(value).strip())
    except ValueError:
        return None
    return n if 0 <= n <= 2**53 else None


def _bar_pct(value: int, maximum: int) -> int:
    """Integer floor percentage."""
    if maximum <= 0:
        return 0
    return min(100, value * 100 // maximum)


class Report:
    """Collects an investigation's findings, then renders them.

    Sections render in a fixed order that answers before it justifies: verdict,
    gaps, metrics, your blocks in the order you added them, evidence. So build the
    report in the order a reader should encounter it -- headline metrics, then the
    ranked table, then supporting detail.

        report = Report("Critical vulnerabilities by base image", scope="prod, us-east-1")
        report.verdict("Rebuilding 3 of 47 images retires 128 of 195 findings.",
                       tone="critical")
        report.metric("Public exploit available", 9, tone="critical",
                      note="fix these first")
        report.metric("Stale hosts", None, note="Hosts scope unavailable")
        report.table("Ranked images", ["Image", "Instances", "CVEs", "Flags"], rows,
                     numeric=[1, 2], bar=1, accent=2, badges=[3], rank=True)
        report.gap("Azure VMs resolve to publisher/offer/sku/version, not an "
                   "image asset -- there is no image record to rank.")
        report.query("falcon_search_vulnerabilities",
                     "status:'open'+cve.severity:'CRITICAL'", returned="1000 (capped)")
        html_path, json_path = report.save("critical-by-image")
    """

    def __init__(self, title: str, subtitle: str = "", scope: str = "") -> None:
        self.title = title
        self.subtitle = subtitle
        self.scope = scope
        # An input to rendering, never recomputed during it -- that is what lets a
        # fixture be replayed and compared byte for byte against the golden.
        self.generated_at = time.strftime("%Y-%m-%d %H:%M:%S %Z")
        self._verdict: dict[str, str] | None = None
        self._blocks: list[dict[str, Any]] = []
        self._gaps: list[str] = []
        self._metrics: list[dict[str, Any]] = []
        self._queries: list[dict[str, Any]] = []

    # -- collection ---------------------------------------------------------

    def verdict(self, statement: str, tone: str = "") -> "Report":
        """The single sentence the reader should leave with, rendered first.

        This is the "what do I fix" line -- the one an executive would repeat.
        Everything below it is the justification. Setting it twice replaces it:
        a report with two verdicts has none.

        `tone` is one of critical / high / medium / low / ok / info and colours the
        band. Choose it from the finding, not from the mood: `ok` on a report whose
        gaps list is three items long is a lie told in CSS.
        """
        self._verdict = {"text": statement, "tone": tone}
        return self

    def metric(self, label: str, value: Any, note: str = "", tone: str = "") -> "Report":
        """A headline number. Pass None when the value could not be determined --
        it renders as 'unavailable', which is deliberately not the same as 0.

        `tone` tints the tile. Reserve `critical` for the one or two numbers that
        should drive the next hour's work; if every tile is critical, none is.
        """
        self._metrics.append({"label": label, "value": value, "note": note,
                              "tone": tone})
        return self

    def table(
        self,
        heading: str,
        columns: Sequence[str],
        rows: Iterable[Sequence[Any]],
        note: str = "",
        numeric: Sequence[int] = (),
        bar: int | None = None,
        accent: int | None = None,
        badges: Sequence[int] = (),
        mono: Sequence[int] = (),
        details: Sequence[int] = (),
        rank: bool = False,
        collapsed: bool = False,
    ) -> "Report":
        """A table, built to be read top-down and stopped early.

        Sort `rows` before passing them in -- the output has no JavaScript, so
        whatever order you supply is the order a reader sees. That is a feature:
        the ranking is a decision the investigation made, not something the
        reader has to rediscover by clicking.

        All of these are column **indices into `columns`**, and all are optional:

        | Argument  | Effect |
        |---|---|
        | `numeric` | right-align, tabular figures |
        | `bar`     | one column: draw a proportion bar scaled to that column's max |
        | `accent`  | one column: its severity value tints the whole row's left edge |
        | `badges`  | render cells as flag chips; a comma splits one cell into several |
        | `mono`    | monospace, break-anywhere -- for AMI IDs, digests, ARNs |
        | `details` | pivot-drill: cell is a list, rendered as collapsible `<details>` |
        | `rank`    | prepend a `#` gutter and emphasise row 1 |

        `details` columns expect each cell to be a Python list. The HTML shows a
        clickable count that expands to one item per line -- a pivot-table drill-
        down with no JavaScript. The CSV denormalises: one row per list item, with
        every other column duplicated, so the file is directly importable into a
        pivot table.

        `collapsed=True` wraps the whole table in a native `<details>`, closed by
        default. Use it for a real but non-headline bucket -- findings that could
        not be traced to an image, say -- so it has an honest, inspectable home
        without competing with the table a reader should see first.

        `bar` is the one worth using on every ranked table. "47 instances" and
        "3 instances" in adjacent rows are two numbers to compare; a full bar next
        to a stub is a glance. Point it at the column that *is* the blast radius.
        """
        self._blocks.append({
            "kind": "table",
            "heading": heading,
            "columns": list(columns),
            "rows": [list(row) for row in rows],
            "note": note,
            "numeric": list(numeric),
            "bar": bar,
            "accent": accent,
            "badges": list(badges),
            "mono": list(mono),
            "details": list(details),
            "rank": bool(rank),
            "collapsed": bool(collapsed),
        })
        return self

    def text(self, heading: str, body: str) -> "Report":
        """A narrative block -- the supporting paragraph.

        For the one-sentence conclusion use `verdict()` instead, which renders at
        the top where a reader will actually see it.
        """
        self._blocks.append({"kind": "text", "heading": heading, "body": body})
        return self

    def gap(self, description: str) -> "Report":
        """Something this run did NOT establish. Renders near the top."""
        self._gaps.append(description)
        return self

    def code(self, heading: str, body: str, note: str = "") -> "Report":
        """A verbatim excerpt -- a relationship edge, a parsed `configuration`
        fragment, a raw record. This is the difference between a report that
        asserts an instance boots from an AMI and one that shows the edge it read.

        Keep excerpts short and pointed. The goal is a reader able to verify the
        claim, not a paste of the 139 KB record it came from.
        """
        self._blocks.append({"kind": "code", "heading": heading, "body": body,
                             "note": note})
        return self

    def query(
        self,
        tool: str,
        filter: str = "",
        returned: Any = None,
        facet: str = "",
        limit: Any = None,
        note: str = "",
    ) -> "Report":
        """Record a query this report's numbers came from.

        All recorded queries render as one table at the end, under a rule. Every
        number above it should be traceable to a row here -- including the queries
        that returned *nothing*, which are evidence too: an empty result is what
        distinguishes "no findings" from "never asked".
        """
        self._queries.append({
            "tool": tool, "filter": filter, "facet": facet,
            "limit": limit, "returned": returned, "note": note,
        })
        return self

    # -- rendering ----------------------------------------------------------

    def _render_verdict(self) -> str:
        if not self._verdict:
            return ""
        tone = _tone_class(self._verdict.get("tone"), "t")
        return (
            f'<div class="verdict{tone}"><div class="vk">Verdict</div>'
            f'<p>{_esc(self._verdict.get("text"))}</p></div>'
        )

    def _render_metrics(self) -> str:
        if not self._metrics:
            return ""
        tiles = []
        for m in self._metrics:
            # `is None`, not falsiness: a real 0 must render as 0. This is the
            # single most important line in the file.
            if m["value"] is None:
                value = '<div class="v unavailable">unavailable</div>'
            else:
                value = f'<div class="v">{_esc(m["value"])}</div>'
            note = f'<div class="n">{_esc(m["note"])}</div>' if m["note"] else ""
            tone = _tone_class(m.get("tone"), "t")
            tiles.append(
                f'<div class="metric{tone}"><div class="l">{_esc(m["label"])}</div>'
                f"{value}{note}</div>"
            )
        return '<div class="metrics">' + "".join(tiles) + "</div>"

    def _render_gaps(self) -> str:
        if not self._gaps:
            return ""
        items = "".join(f"<li>{_esc(g)}</li>" for g in self._gaps)
        return (
            '<div class="gaps"><h2>Not established by this run</h2>'
            f"<ul>{items}</ul></div>"
        )

    @staticmethod
    def _render_badge_cell(cell: Any) -> str:
        if cell is None or not str(cell).strip():
            return '<span class="bnone">&mdash;</span>'
        chips = []
        for token in str(cell).split(","):
            token = token.strip()
            if not token:
                continue
            tone = _BADGE_TONES.get(token.lower(), "neutral")
            chips.append(f'<span class="badge b-{tone}">{_esc(token)}</span>')
        return "".join(chips) or '<span class="bnone">&mdash;</span>'

    def _render_table(self, block: dict[str, Any]) -> str:
        columns = block["columns"]
        rows = block["rows"]
        numeric = set(block["numeric"])
        badges = set(block.get("badges") or ())
        mono = set(block.get("mono") or ())
        details = set(block.get("details") or ())
        bar = block.get("bar")
        accent = block.get("accent")
        rank = bool(block.get("rank"))

        # Scale bars to the largest value actually present in that column, so the
        # longest bar is always full width and the comparison is within-table.
        bar_max = 0
        if bar is not None:
            for row in rows:
                if bar < len(row):
                    count = _as_count(row[bar])
                    if count is not None and count > bar_max:
                        bar_max = count

        head = ['<th class="rank">#</th>'] if rank else []
        for i, column in enumerate(columns):
            cls = "num" if i in numeric and i != bar else ""
            attr = f' class="{cls}"' if cls else ""
            head.append(f"<th{attr}>{_esc(column)}</th>")

        if not rows:
            span = len(columns) + (1 if rank else 0)
            body = (
                f'<tr><td colspan="{span}" class="empty">'
                "No rows. For this query that is a real answer, not a failure."
                "</td></tr>"
            )
        else:
            body_rows = []
            for index, row in enumerate(rows):
                row_classes = []
                if rank and index == 0:
                    row_classes.append("top")
                if accent is not None and accent < len(row):
                    key = _key(row[accent])
                    if key in _SEVERITIES:
                        row_classes.append(f"a-{key}")
                    elif key in _BADGE_TONES:
                        row_classes.append(f"a-{_BADGE_TONES[key]}")
                row_attr = f' class="{" ".join(row_classes)}"' if row_classes else ""

                cells = []
                if rank:
                    cells.append(f'<td class="rank">{index + 1}</td>')
                for i, cell in enumerate(row):
                    if i in badges:
                        cells.append(f"<td>{self._render_badge_cell(cell)}</td>")
                        continue
                    if i in details:
                        items = cell if isinstance(cell, list) else [
                            s.strip() for s in str(cell).split(",") if s.strip()
                        ] if cell else []
                        if not items:
                            cells.append('<td><span class="bnone">&mdash;</span></td>')
                        else:
                            body = "<br>".join(_esc(item) for item in items)
                            cells.append(
                                f'<td><details class="drill">'
                                f"<summary>{len(items)}</summary>"
                                f'<div class="drill-list">{body}</div>'
                                f"</details></td>"
                            )
                        continue
                    if i == bar:
                        count = _as_count(cell)
                        if count is None:
                            cells.append(f'<td class="num">{_esc(cell)}</td>')
                        else:
                            pct = _bar_pct(count, bar_max)
                            cells.append(
                                f'<td class="bar">{_esc(cell)}'
                                f'<span class="track"><span class="fill" '
                                f'style="width:{pct}%"></span></span></td>'
                            )
                        continue
                    classes = []
                    if i in numeric:
                        classes.append("num")
                    if i in mono:
                        classes.append("id")
                    key = _key(cell)
                    if key in _SEVERITIES:
                        classes.append(f"sev-{key}")
                    attr = f' class="{" ".join(classes)}"' if classes else ""
                    cells.append(f"<td{attr}>{_esc(cell)}</td>")
                body_rows.append(f"<tr{row_attr}>" + "".join(cells) + "</tr>")
            body = "".join(body_rows)

        note = f'<p class="note">{_esc(block["note"])}</p>' if block["note"] else ""
        fragment = (
            f'<h2>{_esc(block["heading"])}</h2>'
            f'<div class="tbl"><table><thead><tr>{"".join(head)}</tr></thead>'
            f"<tbody>{body}</tbody></table></div>{note}"
        )
        if not block.get("collapsed"):
            return fragment
        # <details>, closed by default: a real bucket, not the headline. Native
        # interaction, same as the evidence section -- no script needed.
        count = len(rows)
        plural = "row" if count == 1 else "rows"
        return (
            '<details class="fold">'
            f'<summary>{_esc(block["heading"])} '
            f'<span class="count">({count} {plural})</span></summary>'
            f'{fragment}</details>'
        )

    def _render_queries(self) -> str:
        if not self._queries:
            return ""
        rows = []
        for q in self._queries:
            returned = q["returned"]
            # `is None` again: "not recorded" and 0 are different findings.
            returned_cell = (
                '<td class="num empty">not recorded</td>' if returned is None
                else f'<td class="num">{_esc(returned)}</td>'
            )
            note = (
                f'<tr class="note-row"><td class="note" colspan="5">'
                f'{_esc(q["note"])}</td></tr>' if q["note"] else ""
            )
            rows.append(
                f'<tr><td class="mono">{_esc(q["tool"])}</td>'
                f'<td class="fql">{_esc(q["filter"]) or "&mdash;"}</td>'
                f'<td class="mono">{_esc(q["facet"]) or "&mdash;"}</td>'
                f'<td class="num">{_esc(q["limit"])}</td>'
                f"{returned_cell}</tr>{note}"
            )
        count = len(self._queries)
        plural = "query" if count == 1 else "queries"
        # <details open>: foldable for a demo, expanded by default, and native --
        # so the one interactive element in the document still needs no script.
        return (
            '<details class="evidence" open>'
            f"<summary>Evidence <span class=\"count\">&mdash; {count} {plural} "
            "behind this report</span></summary>"
            '<p class="note">Each number above traces to a row here. Re-running '
            "these filters reproduces the report; a row returning nothing is "
            "evidence too, since it separates &ldquo;no findings&rdquo; from "
            "&ldquo;never asked&rdquo;.</p>"
            '<div class="tbl"><table><thead><tr><th>Tool</th><th>FQL filter</th>'
            '<th>Facet</th><th class="num">Limit</th><th class="num">Returned</th>'
            f"</tr></thead><tbody>{''.join(rows)}</tbody></table></div></details>"
        )

    def to_html(self) -> str:
        parts = []
        for block in self._blocks:
            if block["kind"] == "table":
                parts.append(self._render_table(block))
            elif block["kind"] == "code":
                note = (
                    f'<p class="note">{_esc(block["note"])}</p>'
                    if block["note"] else ""
                )
                parts.append(
                    f'<h2>{_esc(block["heading"])}</h2>'
                    f'<pre>{_esc(block["body"])}</pre>{note}'
                )
            else:
                parts.append(
                    f'<h2>{_esc(block["heading"])}</h2>'
                    f'<div class="lede">{_esc(block["body"])}</div>'
                )

        meta = [f"<span>Scope: <b>{_esc(self.scope)}</b></span>" if self.scope else "",
                f"<span><b>Generated {_esc(self.generated_at)}</b></span>",
                "<span>No model tokens consumed</span>"]
        meta = [m for m in meta if m]
        subtitle = f'<p class="sub">{_esc(self.subtitle)}</p>' if self.subtitle else ""

        disclaimer = (
            '<div class="handling" style="margin-bottom:1.15rem">'
            f'<strong>Point-in-time snapshot: {_esc(self.generated_at)}.</strong> '
            'Cloud VMs are ephemeral &mdash; instances launch, terminate, and scale '
            'between runs. This report reflects the state of the tenant at the moment '
            'it was generated. Re-run the script for current data.'
            '</div>'
        )

        # The CSP meta tag is belt-and-braces: this document contains no script
        # and no external reference, and the policy makes that unenforceable to
        # violate by later hand-editing.
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer">
<title>{_esc(self.title)}</title>
<style>{_CSS}</style>
</head>
<body>
<main>
<header>
<h1>{_esc(self.title)}</h1>
{subtitle}
<div class="meta">{"".join(meta)}</div>
</header>
{disclaimer}
{self._render_verdict()}
{self._render_gaps()}
{self._render_metrics()}
{"".join(parts)}
{self._render_queries()}
<div class="handling">
<strong>Live tenant data.</strong> This file names real hosts, accounts and
weaknesses. It was written to <code>findings/</code>, which is gitignored &mdash;
keep it there. Share the script that produced it, not this output.
</div>
<footer>
Produced by a crystallized Falcon API script. Opens offline; makes no network
requests and contains no JavaScript. Re-run the script to refresh.
</footer>
</main>
</body>
</html>
"""

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "subtitle": self.subtitle,
            "scope": self.scope,
            "generated_at": self.generated_at,
            "verdict": self._verdict,
            "gaps": self._gaps,
            "metrics": self._metrics,
            "blocks": self._blocks,
            "queries": self._queries,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Report":
        """Rebuild a Report from `to_dict()` output, `generated_at` included.

        Carrying the timestamp is what lets a committed fixture be rendered and
        compared byte for byte against a committed golden.
        """
        report = cls(
            data.get("title") or "",
            subtitle=data.get("subtitle") or "",
            scope=data.get("scope") or "",
        )
        if data.get("generated_at") is not None:
            report.generated_at = data["generated_at"]
        report._verdict = data.get("verdict")
        report._gaps = list(data.get("gaps") or [])
        report._metrics = [dict(m) for m in (data.get("metrics") or [])]
        report._blocks = [dict(b) for b in (data.get("blocks") or [])]
        report._queries = [dict(q) for q in (data.get("queries") or [])]
        # Blocks written by an older renderer, or by hand, lack the newer and the
        # optional keys. Normalise every kind, not just tables: `to_html` reads
        # `block["note"]` directly, so a hand-written code block with no note used
        # to raise KeyError here -- which is a crash on the most likely kind of
        # third-party input this method exists to accept.
        for block in report._blocks:
            kind = block.get("kind")
            block.setdefault("heading", "")
            if kind == "table":
                block.setdefault("columns", [])
                block.setdefault("rows", [])
                block.setdefault("numeric", [])
                block.setdefault("note", "")
                block.setdefault("bar", None)
                block.setdefault("accent", None)
                block.setdefault("badges", [])
                block.setdefault("mono", [])
                block.setdefault("details", [])
                block.setdefault("rank", False)
                block.setdefault("collapsed", False)
            elif kind == "code":
                block.setdefault("body", "")
                block.setdefault("note", "")
            else:
                block.setdefault("body", "")
        return report

    def save(self, basename: str, output_dir: str | None = None, dated: bool = True) -> tuple[str, str]:
        """Write `<basename>-<date>.html` and `.json`. Returns both paths.

        Pass `dated=False` when the basename already carries its own timestamp
        (e.g. a unix epoch) and the automatic date suffix would be redundant.
        """
        # A basename is a filename, not a path. Without this, a configurable
        # output name escapes findings/ via `../` and lands somewhere with
        # different permissions than the 0600 below assumes.
        if not basename or any(c in basename for c in "/\\\0") or ".." in basename:
            raise ValueError(
                f"basename must be a plain filename, not a path: {basename!r}"
            )
        directory = output_dir or DEFAULT_OUTPUT_DIR
        os.makedirs(directory, exist_ok=True)
        stem = f"{basename}-{time.strftime('%Y-%m-%d')}" if dated else basename
        html_path = os.path.join(directory, f"{stem}.html")
        json_path = os.path.join(directory, f"{stem}.json")

        with open(html_path, "w", encoding="utf-8") as handle:
            handle.write(self.to_html())
        with open(json_path, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2, default=str)

        # CSV: one file per table block, so each can be opened in Excel / imported
        csv_paths = []
        for block in self._blocks:
            if block.get("kind") != "table" or not block.get("rows"):
                continue
            slug = _re.sub(r"[^a-z0-9]+", "-", block["heading"].lower()).strip("-")[:40]
            csv_name = f"{stem}-{slug}.csv"
            csv_path = os.path.join(directory, csv_name)
            with open(csv_path, "w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow(block["columns"])
                details_cols = set(block.get("details") or ())
                if details_cols:
                    for row in block["rows"]:
                        lists = {}
                        for ci in details_cols:
                            if ci < len(row):
                                val = row[ci]
                                lists[ci] = (
                                    val if isinstance(val, list)
                                    else [s.strip() for s in str(val).split(",") if s.strip()]
                                ) if val else []
                            else:
                                lists[ci] = []
                        max_items = max((len(v) for v in lists.values()), default=1) or 1
                        for j in range(max_items):
                            expanded = list(row)
                            for ci, items in lists.items():
                                expanded[ci] = items[j] if j < len(items) else ""
                            writer.writerow(expanded)
                else:
                    writer.writerows(block["rows"])
            csv_paths.append(csv_path)

        # 0600: this is tenant weakness data on a possibly shared machine.
        for path in [html_path, json_path] + csv_paths:
            os.chmod(path, 0o600)
        return html_path, json_path


def _main(argv: list[str]) -> int:
    """`python3 scripts/falcon_report.py --render report.json [out.html]`

    Renders a report JSON to HTML on stdout, or to a named file. This is the entry
    point `scripts/test-render-parity.sh` drives; it is not part of the normal
    workflow, where a crystallized script builds a Report and calls `save()`.
    """
    if len(argv) < 2 or argv[0] != "--render":
        print(__doc__.strip().splitlines()[0])
        print("usage: falcon_report.py --render <report.json> [output.html]")
        return 2
    with open(argv[1], "r", encoding="utf-8") as handle:
        data = json.load(handle)
    rendered = Report.from_dict(data).to_html()
    if len(argv) > 2:
        with open(argv[2], "w", encoding="utf-8") as handle:
            handle.write(rendered)
        os.chmod(argv[2], 0o600)
    else:
        # Bypass print() so the output is byte-exact: no added newline, and no
        # platform newline translation on the way out.
        import sys
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(_main(sys.argv[1:]))
