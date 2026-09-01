#!/usr/bin/env python3
"""Offline self-test for the subagent definitions and the skills that dispatch them.

Runs with no credentials and touches no tenant. It exists because of a bug that
shipped and was found by hand: a skill named a Falcon tool this server build does
not expose. A skill that names a nonexistent tool does not fail at load time -- it
fails halfway through a live demo, and the failure looks like a Falcon problem
rather than a typo.

Three classes of that same bug are checked here:

  1. A skill dispatches a subagent whose definition does not exist, or whose name
     does not match its filename.
  2. A skill or agent names a Falcon tool that this build does not expose.
  3. An agent is granted a tool that would let it write tenant data somewhere.

Class 3 is a security property rather than a correctness one, and it is the reason
`falcon-asset-resolver` is safe to hand the largest payloads in the harness: it
cannot write a file or reach the network. A future edit that adds `Bash` to it for
convenience should fail a test, not pass review.

Class 2 used to be a hand-written list of names believed absent. Every entry in
it was wrong: `falcon_aggregate_detections` and `falcon_list_enabled_tools` both
exist in 0.17.0, so the suite passed by successfully forbidding two working
tools -- and `posture-brief` grew a paragraph explaining that an aggregation tool
it could have been calling did not exist. A list of 168 tool names cannot be
maintained by hand, so this file no longer tries: it reads the tool surface out
of the installed wheel. See `tool_surface()`.

    python3 scripts/test-agents.py
"""

from __future__ import annotations

import ast
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT_DIR = os.path.join(ROOT, ".claude", "agents")
SKILL_DIR = os.path.join(ROOT, ".claude", "skills")

# Registered outside modules/, in the server itself, so the AST walk below does
# not see them. Short enough to keep honest by hand.
CORE_TOOLS = frozenset({
    "falcon_check_connectivity",
    "falcon_list_enabled_modules",
    "falcon_list_enabled_tools",
})

# A `falcon_*` name a skill may mention without it being a call. Prose that
# explains why a tool is unavailable is the fix, not the bug -- posture-brief
# says so about CrowdScore on purpose. Exemptions live here rather than in
# frontmatter so a skill cannot excuse itself by editing its own file.
NAME_EXEMPT = {
    "falcon_search_incidents": "removed upstream in 0.17.0; named only to warn",
    "falcon_show_crowd_score": "removed upstream in 0.17.0; named only to warn",
    "falcon_get_incident_details": "removed upstream in 0.17.0; named only to warn",
}

# The Agent Skills spec ceiling. The description goes into the system prompt on
# every turn, so it is the one field where length is a live cost.
MAX_DESCRIPTION = 1024

# A description has to say when to reach for the skill, or the model has nothing
# to route on. Negated forms ("do not use when") are exclusions, not triggers.
TRIGGER = re.compile(r"\buse (?:this |it )?(?:when|before|after|during|for)\b", re.I)

# Tools that would let an agent put tenant data on disk or on the network. The
# Falcon read tools are fine -- reading is the job. Persisting is not.
EXFIL_TOOLS = {
    "Bash", "Write", "Edit", "NotebookEdit", "WebFetch", "WebSearch", "Agent",
}

FAILURES: list[str] = []

# Filled in by main() from the installed wheel. Empty means "could not read the
# tool surface", which skips the name checks rather than failing them.
SURFACE: set[str] = set()


def check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  ok    {label}")
    else:
        print(f"  FAIL  {label}" + (f" -- {detail}" if detail else ""))
        FAILURES.append(label)


def frontmatter(text: str) -> tuple[dict, str]:
    """Split a leading `---` block into a flat dict, plus the body.

    Deliberately not a YAML parser: the frontmatter here is flat `key: value`
    lines, and requiring PyYAML would give this test a dependency that the rest
    of the harness does not have.
    """
    match = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    if not match:
        return {}, text
    fields = {}
    for line in match.group(1).split("\n"):
        if ":" in line and not line.startswith((" ", "\t", "#")):
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
    return fields, match.group(2)


def load(directory: str, nested: bool) -> dict[str, tuple[dict, str]]:
    found = {}
    if not os.path.isdir(directory):
        return found
    for entry in sorted(os.listdir(directory)):
        path = (os.path.join(directory, entry, "SKILL.md") if nested
                else os.path.join(directory, entry))
        if not os.path.isfile(path) or not path.endswith(".md"):
            continue
        stem = entry[:-3] if not nested else entry
        fields, body = frontmatter(open(path, encoding="utf-8").read())
        if nested:
            # Sibling reference-*.md files are part of the skill and name tools
            # too. Splitting a long playbook must not move tool names out of
            # the test's view -- that would make the split itself a way to
            # smuggle a nonexistent tool name past this suite.
            for sibling in sorted(os.listdir(os.path.dirname(path))):
                if sibling != "SKILL.md" and sibling.endswith(".md"):
                    body += open(os.path.join(os.path.dirname(path), sibling),
                                 encoding="utf-8").read()
        found[stem] = (fields, body)
    return found


def wheel_modules_dir() -> str | None:
    """Locate `falcon_mcp/modules` in whichever environment installed it.

    `uvx` installs into a content-addressed cache directory, so the path carries
    a hash that differs per machine and per version -- it cannot be written down.
    Try an ordinary import path first, then the uv cache.
    """
    try:
        import importlib.util
        spec = importlib.util.find_spec("falcon_mcp")
        if spec and spec.submodule_search_locations:
            return os.path.join(list(spec.submodule_search_locations)[0], "modules")
    except (ImportError, ValueError):
        pass

    import glob
    pattern = os.path.expanduser(
        "~/.cache/uv/archive-v0/*/lib/python*/site-packages/falcon_mcp/modules")
    # Newest first, so a stale earlier install does not shadow the current one.
    hits = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    return hits[0] if hits else None


def tool_surface(modules_dir: str) -> tuple[set[str], dict[str, set[str]]]:
    """Every tool name the installed server can register, read from its source.

    Parses rather than imports: importing falcon_mcp would pull in its
    dependencies and, worse, could contact the network. Every module registers
    its tools with a literal `self._add_tool(..., name="search_detections")`, so
    an AST walk over the call sites is exact and costs nothing.

    Returns (all tool names, name -> {modules that register it}).
    """
    everything: set[str] = set(CORE_TOOLS)
    by_module: dict[str, set[str]] = {}
    for entry in sorted(os.listdir(modules_dir)):
        if not entry.endswith(".py") or entry in ("__init__.py", "base.py"):
            continue
        source = open(os.path.join(modules_dir, entry), encoding="utf-8").read()
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.Call):
                continue
            if getattr(node.func, "attr", "") != "_add_tool":
                continue
            for keyword in node.keywords:
                if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                    name = "falcon_" + keyword.value.value
                    everything.add(name)
                    by_module.setdefault(name, set()).add(entry[:-3])
    return everything, by_module


def enabled_modules() -> set[str]:
    """The module allowlist the server will actually be started with.

    An unknown module name is a hard argparse abort at startup, and a module that
    is not loaded takes its tools with it -- so a skill naming a real tool from an
    unloaded module fails exactly as loudly as a typo.
    """
    for filename in (".env", "env.example"):
        path = os.path.join(ROOT, filename)
        if not os.path.isfile(path):
            continue
        for line in open(path, encoding="utf-8"):
            key, _, value = line.strip().partition("=")
            if key == "FALCON_MCP_MODULES" and value:
                return {m.strip() for m in value.split(",") if m.strip()}
    return set()


def test_agents(agents: dict) -> None:
    print("\nAgent definitions")
    check("at least one agent is defined", bool(agents), "none found in .claude/agents")

    for stem, (fields, body) in agents.items():
        for key in ("name", "description"):
            check(f"{stem}: has {key}", key in fields)
        # The dispatch name is the `name` field, but humans edit by filename. When
        # the two drift, every skill that dispatches by filename breaks silently.
        check(f"{stem}: name matches filename", fields.get("name") == stem,
              f"name={fields.get('name')!r}")

        tools = [t.strip() for t in fields.get("tools", "").split(",") if t.strip()]
        check(f"{stem}: declares an explicit tool allowlist", bool(tools),
              "no `tools:` field means it inherits everything, including Bash")

        granted_exfil = sorted(set(tools) & EXFIL_TOOLS)
        check(f"{stem}: granted no tool that can persist or transmit data",
              not granted_exfil, f"granted {granted_exfil}")

        absent = sorted(t for t in tools
                        if t.startswith("mcp__falcon-mcp__")
                        and t.split("__")[-1] not in SURFACE)
        check(f"{stem}: every granted tool exists on this build", not absent,
              f"{absent} -- not registered by the installed falcon-mcp")

        # The body carries the discipline (the five states, tags-keys-only). An
        # agent reduced to its frontmatter has lost the part that makes it safe.
        check(f"{stem}: has a substantive body", len(body.split()) > 100,
              f"{len(body.split())} words")


def test_skill_dispatches(agents: dict, skills: dict) -> None:
    print("\nSkill -> agent references")
    # Resolve against the `name:` field, not the filename, because that is what
    # the runtime dispatches on. Keying this by filename would let a drifted
    # `name:` pass here and fail live -- the check would model the wrong lookup.
    by_name = {fields.get("name", stem): stem for stem, (fields, _) in agents.items()}
    pattern = re.compile(r"subagent_type=[\"']([\w-]+)[\"']|`(falcon-[\w-]+)`")
    dispatched = False

    for stem, (_, body) in skills.items():
        named = set()
        for quoted, backticked in pattern.findall(body):
            candidate = quoted or backticked
            # `falcon-mcp` is the server, not an agent; it appears in prose.
            if candidate and candidate != "falcon-mcp":
                named.add(candidate)
        for agent in sorted(named):
            dispatched = True
            check(f"{stem} dispatches an agent that exists: {agent}",
                  agent in by_name,
                  f"no agent declares `name: {agent}` "
                  f"(defined: {sorted(by_name) or 'none'})")

    check("at least one skill dispatches a subagent", dispatched,
          "the fan-out is documented nowhere a skill can act on")


def test_tool_names(agents: dict, skills: dict, by_module: dict) -> None:
    """Every Falcon tool a skill instructs a call to must exist AND be loaded.

    Inverted from the list of names once believed absent, all of which were
    wrong. The question is no longer "is this on my denylist" but "did the
    installed server register it", which no human has to keep current.
    """
    print("\nFalcon tool names named as calls")
    loaded = enabled_modules()
    check("FALCON_MCP_MODULES is set", bool(loaded),
          "no module allowlist found in .env or env.example")

    everything = {**{f"agents/{k}": v for k, v in agents.items()},
                  **{f"skills/{k}": v for k, v in skills.items()}}
    for name, (fields, body) in everything.items():
        text = body + "\n" + "\n".join(fields.values())
        # A prose mention is allowed and is often the point -- posture-brief
        # explains that CrowdScore is gone, which is the fix, not the bug. So
        # match only the two shapes that read as an instruction to call.
        called = set(re.findall(
            r"\(`?(falcon_[a-z_0-9]+)`?\)|"                 # (falcon_x) heading
            r"^\s*(?:use|call)\s+`?(falcon_[a-z_0-9]+)|"     # "use falcon_x"
            r"^(falcon_[a-z_0-9]+)\s*$",                     # fenced call block
            text, re.I | re.M))
        for tool in sorted({a or b or c for a, b, c in called}):
            if tool in NAME_EXEMPT:
                continue
            if tool not in SURFACE:
                check(f"{name}: {tool} exists on this build", False,
                      "not registered by the installed falcon-mcp -- typo, or "
                      "removed upstream since the skill was written")
                continue
            # CORE_TOOLS live in the server, not a module, so they are always on.
            owners = by_module.get(tool, set())
            check(f"{name}: {tool} comes from a loaded module",
                  not owners or bool(owners & loaded),
                  f"{tool} lives in {sorted(owners)}, but FALCON_MCP_MODULES "
                  f"loads {sorted(loaded)} -- add the module or drop the call")


def test_descriptions(skills: dict) -> None:
    """The description is the only field the model routes on, so lint it.

    Two checks, both cheap. A deliberate non-check: nothing here measures whether
    two descriptions are too similar. With six skills a reader can see that; the
    stemmed-TF-IDF routing evals the large skill collections run are worth their
    weight at 200 skills, not at six.
    """
    print("\nSkill descriptions")
    for stem, (fields, _) in skills.items():
        description = fields.get("description", "")
        check(f"{stem}: description is under {MAX_DESCRIPTION} chars",
              0 < len(description) <= MAX_DESCRIPTION,
              f"{len(description)} chars -- it is injected into the system prompt")
        check(f"{stem}: description says when to use the skill",
              bool(TRIGGER.search(description)),
              "no 'Use when ...' clause, so the model has nothing to route on")


def main() -> int:
    print("Offline self-test: subagent definitions and skill dispatches")
    print("No credentials required; no tenant is contacted.")

    global SURFACE
    modules_dir = wheel_modules_dir()
    by_module: dict[str, set[str]] = {}
    if modules_dir:
        SURFACE, by_module = tool_surface(modules_dir)
        print(f"\nTool surface: {len(SURFACE)} tools across "
              f"{len(set().union(*by_module.values()))} modules, read from "
              f"{os.path.relpath(modules_dir, os.path.expanduser('~'))}")
    else:
        # A fresh clone has not run uvx yet. Skipping is right: the alternative
        # is a test that fails for everyone who has not started the server.
        print("\n  warn  falcon-mcp is not installed; tool-name checks skipped.")
        print("        Run ./scripts/doctor.sh once, then re-run this test.")

    agents = load(AGENT_DIR, nested=False)
    skills = load(SKILL_DIR, nested=True)
    print(f"\nFound {len(agents)} agent(s), {len(skills)} skill(s).")

    test_agents(agents)
    test_skill_dispatches(agents, skills)
    test_descriptions(skills)
    if modules_dir:
        test_tool_names(agents, skills, by_module)

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
