---
name: falcon-setup
description: Guided first-run setup and diagnosis for the Falcon MCP harness. Creates the credentials file, checks API scopes, explains authentication failures, and verifies the security guardrails are live. Use when setting up for the first time, when Falcon tools fail or return no data, or when asked to check whether the harness is configured correctly.
---

# Get connected, safely

Your job in this skill is to get one working, least-privileged connection to
Falcon and prove it works. Nothing else. Resist the urge to start investigating
before the connection is verified — a half-configured harness produces empty
results that look like good news.

## Step 1 — Run the doctor first

```bash
./scripts/doctor.sh
```

This checks tooling, credential file permissions, the read-only posture, the
write guardrail, and then authenticates and probes each capability the harness
uses. Read its output before doing anything else. It names the specific next
action for every failure, so in most cases your job is simply to help the
operator carry that action out.

If the doctor reports everything green, stop. Setup is done. Suggest a first
question instead of tinkering further.

## Step 2 — Create credentials, if needed

If `.env` does not exist:

```bash
cp env.example .env
chmod 600 .env
```

The `chmod` is not optional. Without it the file is world-readable and every
other account on the machine can read your API keys. The doctor will fail the
run if the bits are wrong.

Then the operator fills in three values by hand. **You do not do this for them**
— never ask for a client secret in chat, never write one into a file yourself,
and never echo one back. Chat transcripts get logged, summarised and pasted.

In the Falcon console: **Support and resources → API clients and keys → Create
API client.**

- Grant only the READ scopes in `docs/api-scopes.md`.
- Copy the secret immediately; the console shows it exactly once.
- `FALCON_BASE_URL` must match the tenant's region. See the region table in
  `env.example`.

## Step 3 — When authentication fails

A failed auth is almost always one of four things. Check in this order, because
the symptoms are identical:

| Symptom | Most likely cause |
|---|---|
| 403 at the token endpoint | **Wrong region** in `FALCON_BASE_URL` |
| 403 with correct region | Client revoked, or secret truncated on copy |
| 401 | Malformed credentials — check for stray whitespace or quotes |
| Auth works, tools return nothing | Missing per-capability scopes |

The wrong-region case is the one that wastes the most time, because a valid key
pointed at the wrong cloud looks exactly like a bad key. Check it first, every
time.

## Step 4 — When a specific tool returns nothing

Distinguish three outcomes that look the same from the model's side. The doctor
already separates them, which is why running it first saves time:

- **403 → missing scope.** Add it to the API client and retry. The doctor prints
  the exact scope name.
- **404 → not licensed or not enabled** on this tenant. Some features
  404 where they are not provisioned. Nothing to fix; the capability is not there.
- **200 with an empty result set → a real, correct answer.** The tenant genuinely
  has no data matching that filter.

Never present the third case as a failure, and never present the first two as
"no findings." Reporting "no critical vulnerabilities" when the truth is "no
Spotlight scope" is the single most dangerous failure mode in this harness.

## Step 5 — Verify the guardrails are actually live

Security controls that are not verified are decoration.

```bash
./scripts/test-guardrail.sh
```

All checks must pass. Then confirm both layers are in place:

1. **`FALCON_MCP_READ_ONLY=true` in `.env`** — the server never registers write
   tools, so the model cannot see them at all.
2. **The PreToolUse hook** — default-deny on anything that is not a recognised
   read verb, independent of what the server exposes.

These are deliberately redundant. Layer 1 can be switched off with an env var;
layer 2 cannot be switched off by the model. Destructive tools stay blocked even
when writes are unlocked.

To see the reasoning and the trust boundaries, read `docs/security.md`.

## Step 6 — Trim the tool surface

Check `FALCON_MCP_MODULES` in `.env`. The default in `env.example` loads five
modules; the server ships 27 modules and 139 tools. An unknown module name is a
hard startup failure, so `./scripts/doctor.sh` validates the list against the
installed server.

This is a performance control as much as a security one. Every loaded tool's
schema occupies context, and a model choosing between 139 tools picks worse than
one choosing between 30. If workflows only need detections and hosts, load only
those.

## Step 7 — Prove it end to end

Have the operator ask one question they already know the answer to. Something
like:

> How many hosts have not been seen in the last 14 days?

You want an answer that matches their expectations. If the number is surprising,
resolve that now — either the harness is misconfigured or they have just learned
something true about their estate. Both are worth knowing before they trust it
with a real investigation.

Then point them at `WORKSHOP.md` for the two demo playbooks and a set of
starter questions.
