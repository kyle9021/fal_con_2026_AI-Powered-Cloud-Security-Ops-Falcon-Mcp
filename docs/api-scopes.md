# API scopes: least privilege in practice

The harness asks for **read scopes only**. This page tells you which ones you
actually need, so you can grant those and nothing more.

## Create the API client

Falcon console → **Support and resources → API clients and keys → Create API
client**.

Give it a name that says what it is (`claude-mcp-readonly`, not `test`) so the
next person auditing your API clients knows whether they can revoke it. The
secret is shown exactly once — copy it before closing the dialog.

## Start here: the minimum viable set

These four cover the automatic posture brief and most of the starter questions.
Grant these first, confirm the harness works, then add more only when a workflow
needs them.

| Scope | Access | Gives you |
|---|---|---|
| **Alerts** | Read | Detections and alerts |
| **Hosts** | Read | Host/device inventory, sensor health |
| **Vulnerabilities** | Read | Spotlight vulnerability findings |
| **Incidents** | Read | Incidents |

### The two demos need more than this

Both workshop demos reach into cloud data, which none of the four scopes above
covers. If you want `/trace-vm-image` or `/image-sprawl` to work, add:

| Demo | Additional scope, Read | Without it |
|---|---|---|
| `/trace-vm-image` | **CSPM registration** | You get the vulnerability list but cannot resolve any instance to its image — the demo stops at step 3 |
| `/image-sprawl` | **Kubernetes Protection** | No container inventory, so no sprawl answer at all |
| `/image-sprawl` step 4 | **Falcon Container Image** | Sprawl works, but you cannot assess the image's own CVEs |

These are the `cloud` module's scopes, listed again in the table below. They are
separated out here because the four-scope set is a genuinely good starting point
for daily use, and it is worth knowing exactly where it stops.

## Adding capabilities

Grant these as you need the corresponding module. Each row costs you real
surface area, so add deliberately.

| falcon-mcp module | Scope(s), all Read | Needed for |
|---|---|---|
| `detections` | Alerts | Detection search and triage |
| `hosts` | Hosts | Inventory, stale-sensor sweeps |
| `spotlight` | Vulnerabilities | `/trace-vm-image`, vulnerability backlog |
| `incidents` | Incidents | Incident search |
| `cloud` | Falcon Container Image; Kubernetes Protection; CSPM registration | `/image-sprawl`, `/trace-vm-image`'s image lookup, cloud asset inventory |
| `intel` | Actors, Indicators, Reports (Falcon Intelligence) | Threat actor and IOC research |
| `idp` | Identity Protection Entities | Identity investigation |
| `discover` | Falcon Discover | Unmanaged assets, application inventory |
| `serverless` | Falcon Container Image | Serverless function vulnerabilities |
| `sensor_usage` | Sensor usage | Licence and sensor usage reporting |
| `ngsiem` | NGSIEM search | Raw CQL event search |

Scope labels in the console vary a little between tenant versions and regions.
If a name below does not match what you see, look for the closest match on the
same product — and treat `./scripts/doctor.sh` as the authority, since it probes
each capability against your live tenant and prints the specific scope that is
missing.

## Write scopes: not now

Several modules offer write access — IOC management, custom IOA rules, firewall
rule groups, host containment.

**Do not grant them yet.** Not because writes are never appropriate, but because
of the order of operations: you cannot judge whether an AI-driven workflow should
be allowed to change your environment until you have watched it read your
environment for a few weeks.

If you do grant write scopes later, note that the harness still has two
independent layers in front of them (`FALCON_MCP_READ_ONLY` and the PreToolUse
hook), and that destructive tools stay blocked regardless. See
[security.md](security.md) for how to unlock writes deliberately.

## Verify what you granted

```bash
./scripts/doctor.sh
```

The Falcon API section probes each capability and separates three outcomes:

- **ok** — reachable, with a record count.
- **no access (needs `<Scope>`)** — a 401/403. The scope is missing; add it.
- **not available on this tenant** — a 404. The feature is not licensed or
  enabled here. Nothing to fix.

That third category matters. Some features 404 on tenants where they are not
provisioned. A 404 is not a permissions problem and no amount of scope granting
will change it.

## MSSP and Flight Control

Authenticating with parent-CID credentials and targeting a child tenant: set
`FALCON_MEMBER_CID` in `.env` to the child CID. The parent API client needs the
same read scopes, plus the parent-child relationship configured in Flight
Control.

Only one member CID is active per session. To work across several, run separate
sessions rather than trying to switch mid-conversation — mixing tenants inside
one context is how findings get attributed to the wrong customer.
