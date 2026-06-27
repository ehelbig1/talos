# RFCs

Design documents for changes with enough surface area that the
"propose → align → code" sequence is cheaper than the
"code → realize it was wrong → rewrite" sequence.

An RFC lives here when it's:

- A cross-cutting architectural change (new service boundary, new
  auth model, schema reshape touching > 10 tables).
- An irreversible or very-expensive-to-reverse decision (key
  management, data format choice, API contract).
- A multi-phase migration where each phase needs explicit sign-off.

An RFC does **not** live here when:

- The change is a single-PR refactor. Just do it.
- The design is already written in `docs/architecture/` or
  `docs/security/`. Extend those docs instead.
- The scope is "survey + recommendation" without implementation
  intent. That's a brain-dump, keep it in your session notes.

## Lifecycle

```
Draft  →  In progress  →  Shipped  (or)  Superseded  (or)  Rejected
```

- **Draft**: author's proposal. Open for comment. No code yet.
- **In progress**: phase 1 has started. Subsequent phases may still
  change based on what phase 1 revealed.
- **Shipped**: all phases landed in production. RFC becomes
  historical documentation — don't edit retrospectively.
- **Superseded**: later RFC replaces this one. Link the new RFC from
  the header.
- **Rejected**: decision was made not to proceed. Keep the document
  as a record of the discussion.

## Numbering

Four-digit, zero-padded, allocated in order. Never reused.

## Index

| # | Title | Status | Header |
|---|-------|--------|--------|
| [0001](0001-multi-tenancy.md) | Multi-tenancy implementation | Draft | Three-phase plan for T1 logical + T2 cryptographic + T3 physical tenant isolation |
| [0002](0002-extract-compilation-service.md) | Extract the compilation service | Draft | First extraction from the controller monolith; compilation as HTTP service behind a feature flag |
| [0003](0003-durable-execution.md) | Durable workflow execution | In progress | Controller-restart resume of checkpointed executions; Phase 1 + Phase 2 (crash-recovery sweep + epoch fence) landed, flag-gated default-off; remaining = staging validation + fresh-run fencing decision |
| [0004](0004-tenant-equals-organization.md) | Tenant = Organization | In progress | The tenant is the organization; membership-union policy, GUC primitives, permissive rollout (M1 landing) |
| [0005](0005-tenant-isolation-target-architecture.md) | Tenant-isolation target architecture | Draft | End-state RLS: dual-role via `SET LOCAL ROLE`, request-scoped unit-of-work, fail-closed `WITH CHECK`; executed in stages |
| [0006](0006-org-scoped-write-isolation-pins-org-not-user.md) | Org-scoped write isolation pins `org_id`, not `user_id` | In progress | Decided (enterprise): `secrets` gets a per-user owner pin (Option B, implemented); `workflows`/`actors` stay org-pinned only. Latent until RLS enforcement is on + secret writes wired to `begin_org_scoped` |
| [0007](0007-native-github-integration.md) | Native GitHub integration | Phase A complete | Server-side event-type filtering shipped: `event_filter` on `webhook_triggers` (create+validate+read-back across GraphQL & MCP) + `__webhook__` event metadata to the trigger input. Phase B (separate future RFC): GitHub App OAuth vs PATs |

## Template for new RFCs

```markdown
# RFC NNNN — Short title

**Status:** Draft
**Author:** You
**Date:** YYYY-MM-DD

## TL;DR

One paragraph. What changes. What it buys us. What it costs.

## Context

Why now. What the current shape is. What doesn't work about it.

## Decisions

Numbered. Each one: the decision, the alternative(s) considered,
why this one wins.

## Migration plan

Phased. Each phase independently shippable. Rollback procedure per
phase.

## Non-goals

Explicit list of what this RFC does NOT solve. Important for
preventing scope creep during implementation.

## Open questions

Anything that needs a decision before the first phase ships.

## Success criteria

How we know we're done. Concrete metrics, not vibes.
```
