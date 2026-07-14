# The delivery-node pattern: memory-read → render → send

**Status: canonical.** This is the blessed shape for any workflow that
delivers actor-memory content to an external destination (email, webhook,
chat). It is a deliberate design decision, not a workaround — see the
rationale below before proposing a combined capability world.

## The shape

Two nodes, two capability worlds, one edge:

```
compose (agent-node)          send (http-node)
  agent_memory reads     ──▶    HTTP to the destination
  deterministic render          vault:// auth header
  NO network access             NO memory access
```

- **compose** reads the memory keys (e.g. `daily_brief/latest`), renders
  the deliverable deterministically (never re-run content through an LLM
  at delivery time — the verbatim-copy rule), and outputs
  `{subject, html, skip}`.
- **send** takes only the rendered payload, applies the `vault://` auth
  header, and POSTs to the destination host. Honor a `DRY_RUN` config
  (default **true**) and a `skip` input (compose emits `skip: true` when
  every source key is absent — mirror of the organize-no-op rule).

Reference implementation: the `pa-morning-dispatch` workflow
(compose-v1 / send-v1 modules, 2026-07-14).

## Why not one node with memory + HTTP?

No capability world below `automation-node` grants both `agent-memory`
and plain `http`, and that is intentional:

- A node holding **memory + network** can exfiltrate the actor's entire
  memory to any host on its allowlist. Splitting means the compose node
  *physically cannot* reach the network, and the send node can leak only
  the rendered artifact it was handed.
- The blast radius of a compromised or buggy render (prompt injection in
  remembered content, template bugs) is bounded to what crosses the edge.
- Each node's grant is auditable at a glance: `allowed_hosts` and
  `allowed_secrets` live only on the send node.

If you find yourself wanting `automation-node` just to deliver content,
use this pattern instead — the actor's capability ceiling usually
forbids `automation-node` anyway (`agent-node` is the recommended
ceiling for assistant actors).

## Freshness

`agent_memory::get` returns the value only. When the deliverable must be
today's (a stale `daily_brief/latest` from yesterday should be flagged,
not silently delivered), use `get-entry` (returns `created-at-unix`) and
render a staleness note when the entry predates the current period.
Until your module adopts `get-entry`, schedule the delivery after the
producer (e.g. producer at 7:12/7:37, delivery at 7:45) and accept the
race.

## Where DLP applies (so you don't re-verify with a live send)

`redact_json()` runs at the **execution-output storage boundary** — the
stored trace of a node whose output contains emails/tokens shows
`[REDACTED:EMAIL]` etc. The **delivered side-effect is untouched**: what
the send node POSTs is exactly what compose rendered. Verified
empirically 2026-07-14 (trace redacted, received email intact). Corollary:
never copy content out of a stored trace into a deliverable and expect
the original values.
