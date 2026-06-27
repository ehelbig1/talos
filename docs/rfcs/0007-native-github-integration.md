# RFC 0007 — Native GitHub integration (Phase A: event-typed triggers)

**Status:** Phase A complete (A.1 engine-side filter + matcher ✓; A.2 GraphQL create CRUD + write-time validation ✓; A.3 MCP `create_webhook` wiring ✓; A.4 read-back of `event_filter` on GraphQL + MCP list queries ✓; A.5 `__webhook__` event metadata to the trigger input — RFC D5 ✓). Phase B (GitHub App OAuth) is a separate future RFC.
**Author:** Claude (paired with Evan)
**Date:** 2026-06-27

## TL;DR

Most of a "native GitHub integration" inbound path **already exists** and is
correct: `talos-webhooks` verifies GitHub's `X-Hub-Signature-256` (HMAC-SHA256
over the raw body, constant-time compare), enforces GitHub-specific replay
protection (MCP-1100 — GitHub signs the body alone, so it requires the dedup
store), and dedups on `X-GitHub-Delivery`. The PAT-based outbound modules
(`github-pr-reviewer`, `github-analyzer`) already call the GitHub API.

The real gap is **server-side event-type filtering**: every verified delivery
fires the workflow, so a trigger can't say *"only `pull_request` opened/
synchronize — ignore `push`, `star`, `check_run`, …"*. Today the workflow must
inspect the payload and self-skip, burning an execution (budget + audit row +
worker dispatch) per ignored event.

**Phase A** (this RFC, small + additive): add an optional, provider-agnostic
`event_filter` to `webhook_triggers`; in `handle_webhook`, *after* signature
verification, evaluate it against `X-GitHub-Event` + a payload field (`action`)
and skip non-matching deliveries with `200 OK` and no dispatch. Surface the
GitHub event metadata to the workflow as structured trigger input. **Phase B**
(separate RFC): GitHub App OAuth — scoped, auto-rotating installation tokens
instead of long-lived PATs, plus click-to-connect that auto-registers the repo
webhook.

## Context

**What already works** (cite, so we don't rebuild it):

- `talos-webhooks::WebhookService::verify_hmac_signature` handles three signature
  formats by header: `x-slack-signature`, `x-hub-signature-256` (GitHub), and a
  generic `x-signature` + `x-webhook-timestamp`. The GitHub arm strips `sha256=`,
  computes `HMAC-SHA256(signing_secret, body)`, and `ct_eq`-compares — exactly
  GitHub's scheme.
- Replay defense: GitHub deliveries carry no timestamp, so the handler refuses
  the `x-hub-signature-256` format unless the dedup store is wired, and dedups on
  `X-GitHub-Delivery` (MCP-1100). Slack/generic bind a timestamp + freshness
  window.
- Fail-closed HMAC (`webhook_must_fail_closed_on_hmac`), per-trigger
  `allowed_ips`, a circuit breaker, rate limiting, and (per the per-org DEK arc)
  the trigger's `signing_secret_enc` is encrypted at rest under the owner's org
  DEK.
- Outbound: `github-pr-reviewer` / `github-analyzer` WASM modules call the GitHub
  API with a PAT stored as a secret.

**What's missing:**

1. **No event-type filter.** `webhook_triggers` has no `event_*` column; a GitHub
   repo webhook fires the workflow for *every* event the repo emits.
2. **Event metadata isn't surfaced.** `X-GitHub-Event` / `X-GitHub-Delivery` /
   `action` aren't passed to the workflow as structured input — only the raw body
   is.
3. **(Phase B) No GitHub App / OAuth.** Outbound auth is long-lived PATs, not
   scoped auto-rotating installation tokens; no connect-UX.

**Why now.** GitHub is the natural #1 connector for a dev-automation platform —
the [AI PR-review example](../examples/ai-pr-review.md) is the flagship use case,
and it currently can't filter events server-side.

## Decisions

**D1. Reuse the existing receiver; do NOT build a `talos-github` inbound crate.**
A dedicated crate would duplicate the hardened HMAC / replay / dedup / circuit-
breaker / rate-limit / encryption logic. The signature side is done and correct;
Phase A is purely additive on top of it.

**D2. Add a provider-agnostic `event_filter` (JSONB), not a GitHub-only column.**
The receiver is already multi-provider (Slack/GitHub/generic); a generic
header+payload match filter serves all of them, with GitHub as the motivating
case. Shape:
```jsonc
{
  "header": "X-GitHub-Event",                 // which request header carries the event type
  "values": ["pull_request", "push"],          // fire only if the header is one of these
  "payload_match": { "action": ["opened", "synchronize", "reopened"] }
  // optional: fire only if body.<key> ∈ values (top-level keys only, bounded)
}
```
`NULL` = no filter = today's behavior (fire on every verified delivery), so the
change is backward-compatible. *Alternative — a narrow `github_events TEXT[]`:*
rejected; doesn't cover the `action` sub-filter or other providers.

**D3. Filter AFTER signature verification, never before.** Unverified input must
never reach filter logic. Order in `handle_webhook`: content-type → size →
`allowed_ips` → **signature/replay/dedup** → **event_filter** → dispatch.

**D4. A filtered-out delivery returns `200 OK` with no dispatch.** GitHub retries
non-2xx deliveries, so a deliberately-ignored event must not 4xx. No workflow
execution is created (no budget/audit/worker cost), but `log_request` still
records it and rate-limiting still applies — so "ignored" is observable, not
invisible.

**D5. Surface event metadata to the workflow.** Pass a structured
`__webhook__ = { event, delivery, action }` alongside the existing body in the
trigger input, so both the filter and the workflow read the event type from one
authoritative place (rather than re-parsing the body).

*Implemented (A.5):* `__webhook__` is injected as a reserved top-level key inside
the trigger-input body (the workflow reads `{{__trigger_input__.__webhook__.event}}`;
modules also see it under `input`). It's a **curated allowlist, not a header
dump** — only `event` / `delivery` / `action` are surfaced, so signature/auth
headers (`X-Hub-Signature-256`, `Authorization`, `X-Verification-Token`, …) can
never leak into trigger input. `event` reads the header named by the trigger's
`event_filter.header` when a filter is set (the same header the server matched
on — one source of truth), else GitHub's `X-GitHub-Event`; `delivery` reads
`X-GitHub-Delivery`; each field is `null` when absent (stable interpolation
shape). Injection applies only when the body is a JSON object (a bare
string/array body has no field surface). **Caveat:** DLQ replay
(`dispatch_replay`) does NOT reconstruct `__webhook__` — the original request
headers aren't stored with the dead-lettered body, so a replayed delivery has no
header-derived metadata. (Live deliveries are the overwhelmingly common path;
storing headers for replay is deferred.)

**D6. Validate the filter at write time; fail-OPEN at fire time.** The trigger
create/update surface (GraphQL/MCP) validates `event_filter` shape + caps its
size, so a malformed filter never persists. If a stored filter is somehow
unparseable at fire time, treat it as "no filter" (fire) + `WARN` — silently
*dropping* a delivery is worse than an occasional over-fire, and the workflow can
still self-skip. (Tradeoff noted; revisit if over-fire proves worse for a given
user.)

## Migration plan

**Phase A — event-typed triggers (this RFC).** Independently shippable.
1. Migration: `ALTER TABLE webhook_triggers ADD COLUMN event_filter JSONB` (nullable).
2. `talos-webhooks::handle_webhook`: after the signature/replay block, if
   `event_filter` is set, evaluate it against the request headers + parsed body;
   on no-match, `log_request` + return `200` without dispatch.
3. Trigger CRUD (`talos-api` webhook mutations + the MCP webhook handlers):
   accept + validate `event_filter` on create/update.
4. Trigger input: inject `__webhook__` metadata.
   - *Rollback:* the column is nullable and ignored when absent; revert the
     handler block and `event_filter` becomes inert data. No data migration.

**Phase B — GitHub App auth (separate RFC).** OAuth/App flow: App JWT (signed
with the App private key) → installation access token (hourly) → refresh; a
`connect GitHub` UX that registers the repo webhook via the API and stores the
installation. Follows `oauth_provider_guide.md` + `integration-pattern.md`, but
the App-token mint differs from a standard OAuth refresh — it deserves its own
RFC. The PAT path keeps working in the meantime.

**Out of scope.** Any change to signature/replay/dedup (already correct);
GitHub-specific receiver code; retiring the PAT modules.

## Tests

- Matching event (`X-GitHub-Event: pull_request`, `action: opened`) → workflow
  fires.
- Non-matching event (`push` when filter is `pull_request`) → `200`, **no**
  execution row created.
- Matching event header, non-matching `action` → no fire.
- `event_filter = NULL` → fires (backward-compat).
- Body missing the `payload_match` key → handled (no panic; treated as non-match
  for that clause).
- Signature still required: an unsigned/bad-signature request with a matching
  event is rejected at the HMAC stage, before the filter ever runs.
- Malformed stored filter → fires + WARN (D6).

## Effort

Small: one migration, one handler block in `talos-webhooks`, trigger-CRUD
plumbing + validation, and the test set above. The expensive, security-critical
parts (signature, replay, dedup, encryption, rate-limit, circuit-breaker) are
reused unchanged.

## See also

- [`docs/examples/ai-pr-review.md`](../examples/ai-pr-review.md) — the use case this sharpens.
- `talos-webhooks/src/lib.rs` — `handle_webhook`, `verify_hmac_signature` (MCP-1100).
- [`integration-pattern.md`](../integration-pattern.md), `oauth_provider_guide` — Phase B groundwork.
