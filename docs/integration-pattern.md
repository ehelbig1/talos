# Integration pattern

How to add a new push-notification integration to Talos.

The two reference implementations are `google_calendar` (commits
`d1d098b` → `fab8902`) and `gmail` (`aaa3e51` → `b9ad7ab`). This
doc extracts the pattern so the third, fourth, and fifth
integrations converge instead of diverging.

## Quick start

Ask yourself these five questions BEFORE reading further or
touching any code:

1. **Does the upstream actually push?** If it's poll-only
   (OAuth + API client, no webhook / watch / push), stop reading
   — you don't need any of this. Add the OAuth integration and
   let workflows poll on schedule.
2. **What's the webhook-auth shape?** One of:
   - (a) Upstream lets ME supply an opaque token → **HMAC-signed**
     (gcal's `webhook_token.rs`).
   - (b) Upstream signs with THEIR keys → **JWT verification**
     (gmail's `pubsub_jwt.rs`).
   Decide now; different crypto surface.
3. **What's the renewal cadence?** Most push integrations expire
   (Google: 7d, Slack: 90d, GitHub: never). Drives the scheduler
   threshold and TTL grace.
4. **How does the webhook payload identify the mailbox / channel
   / target?** This becomes `idx_str_1` and the webhook hot-path
   lookup key. Must be indexed for O(1) lookup.
5. **How many watches per user?** One per mailbox (gmail)? One
   per calendar (gcal)? Drives the concurrency lock scope:
   `(user, integ)` vs `(user, integ, target)`.

If you can't answer all five from upstream docs, STOP and
research before coding. Answering mid-implementation produces
re-architecture.

## Table of contents

- [Architecture — three layers](#architecture--three-layers)
- [Required pieces — the checklist](#required-pieces--the-checklist)
  - [1. Upstream API client](#1-upstream-api-client-small-isolated)
  - [2. Webhook / push authentication](#2-webhook--push-authentication)
  - [3. Watch lifecycle](#3-watch-lifecycle--integrationwatchrs)
  - [4. Renewal scheduler](#4-renewal-scheduler--integrationschedulerrs)
  - [5. WASM dispatch](#5-wasm-dispatch--integrationdispatchrs)
  - [6. User REST endpoints](#6-user-rest-endpoints)
  - [7. Admin endpoints](#7-admin-endpoints--integrationadminrs)
  - [8. Watch-channel summary service](#8-watch-channel-summary-service)
  - [9. Frontend panel](#9-frontend-panel)
  - [10. Operator docs](#10-operator-docs--docsintegration-push-setupmd)
- [Common pitfalls](#common-pitfalls--dont-re-learn-these)
- [Testing strategy](#testing-strategy)
- [Cross-references](#cross-references)

## Fast-start: scaffold the 10 files

```bash
scripts/scaffold-integration.sh <snake_name> <CamelName>
# e.g.
scripts/scaffold-integration.sh slack_events SlackEvents
```

Creates the directory + 10 stub files with docstrings pointing
back at this pattern and the nearest reference implementation.
Does NOT fill in logic — that's the part that varies per upstream.
Refuses to overwrite existing files, so it's safe to re-run.

After scaffolding, follow the checklist below in order. The
scaffold is mkdir+touch+pointers, not code generation.

## Claude Code workflow for this pattern

If you're Claude Code (or working with it), the efficient flow is:

1. **Explore subagent first** — survey `controller/src/google_calendar/`
   and `controller/src/gmail/` in parallel to see the two reference
   implementations. Don't re-derive from scratch.
2. **Plan subagent** for the 10-file sequence — which files to
   create, in what order, what goes in each. The checklist below
   maps 1-to-1 but the Plan agent is faster at laying out
   dependencies.
3. **Implement** in the checklist's order. Compile + test green
   between pieces. One file at a time. Expect to consult this doc
   repeatedly mid-implementation — that's the point.
4. **Review subagent** when done, focused specifically on the
   `webhook_token` / JWT-verify layer (highest blast radius) and
   the renewal path (most common bug site).
5. **Live test**: run the operator setup in
   `docs/<integration>-push-setup.md`, then exercise the live
   pipeline with a real upstream push.

Do NOT:
- Start coding before reading this doc end-to-end.
- Assume the pattern generalizes cleanly without checking the
  common-pitfalls section — most of the pitfalls were learned
  AFTER the pattern was "done."
- Skip the operator runbook. Without it, no one (including you
  next month) can reproduce the setup.

**Use this for integrations that:**
- Receive push notifications from an upstream (Google Calendar,
  Gmail, Slack events, GitHub webhooks, Jira webhooks, ...)
- Have per-user state that expires / needs renewal (watch channels,
  subscriptions, OAuth tokens)
- Dispatch WASM modules on incoming events

**Skip this for:**
- Integrations where Talos only polls on demand (OAuth + API client
  with no push path). Gmail was like this before `aaa3e51`. If the
  user says "add Slack push," you use this pattern. If they say
  "add Slack API access for workflows," you don't.

## Architecture — three layers

```
┌──────────────────────────────────────────────────────────────────┐
│                        Upstream provider                         │
│                 (Google, Slack, GitHub, ...)                     │
└──────────────────────────────────────────────────────────────────┘
                              │  push (HTTPS)
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  <integration>::handlers::webhook / pubsub_push_handler          │
│     • Verify signature / token                                   │
│     • Resolve user_id from the request                           │
│     • Spawn background dispatch                                  │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  <integration>::dispatch::dispatch_<events>                      │
│     • Load module once (registry scoped to user)                 │
│     • Optional Redis dedup                                       │
│     • Per-event: build JobRequest, sign, publish to NATS         │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                      worker NATS subscriber
                              │
                              ▼
                   WASM module runs the event
```

Persistent state is stored in `integration_state` scoped to
`(integration_name, user_id, key)` — see
`docs/platform-primitive-checklist.md` for the RPC contract and
slot layout rules.

## Required pieces — the checklist

Build these in this order. Each one should compile + test green
before the next. Resist the urge to open all ten files at once.

### 1. Upstream API client (small, isolated)

`<integration>/api.rs`. Just the endpoints the watch path needs,
plus typed response decoders.

- Use `reqwest::Client` with timeouts (30 s request, 5 s connect).
- Accept the access token as an argument — OAuth lives in
  `integration.rs` / `OAuthCredentialService`, not here.
- Decode Google-style polymorphic fields: many Google APIs return
  `historyId` / `expiration` as string OR number depending on which
  client library the sender used. Always accept both.
- Truncate any response body we log; external APIs can return
  megabytes. See `gmail/api.rs::truncate`.
- Unit test the decoders with realistic payload shapes.

### 2. Webhook / push authentication

Two shapes we've built:

**(a) HMAC-signed opaque token** — we issue the token, we verify it.
See `google_calendar/webhook_token.rs`. Use when the upstream lets
us supply a `token` field (Google Calendar's `X-Goog-Channel-Token`,
Slack's `X-Slack-Signature` bootstrap, etc.).

- Embed `user_id` in the token + cryptographically bind to whatever
  request-level identifier the upstream passes (channel id,
  resource id). This lets the webhook resolve user without a DB
  lookup by an upstream-supplied value.
- HMAC-SHA256, truncated to 16 bytes (128-bit strength, header-size
  friendly). Constant-time compare via `subtle::ConstantTimeEq`.
- **Domain-separate** — prefix a constant string in the HMAC input
  so a token signed in another context can't cross over.
- Reject tokens > a reasonable length cap before any crypto work
  (DoS lever).

**(b) Upstream-signed JWT verification** — the upstream signs with
their own keys. See `gmail/pubsub_jwt.rs`. Use for Google Cloud
Pub/Sub pushes, GitHub's new Smee JWT push, etc.

- Fetch upstream's JWKs lazily; cache in `ArcSwap<HashMap>` for
  atomic hot-swap.
- Single-flight `tokio::sync::Mutex` around the refresh so N
  concurrent unknown-kid requests don't all fetch.
- **Separate `backoff_until` atomic** from the refresh-TTL marker.
  Without this, a sustained upstream outage turns every push into a
  fresh timeout. See `gmail/pubsub_jwt.rs` commit `13ea09c` for the
  regression we paid to learn this.
- Validate: signature (RS256 only — reject `alg: none` and HS256),
  `iss`, `aud`, any identity claim the upstream uses, expiration
  with ±60 s leeway.

Whichever shape — **unit-test each rejection path**. Not just
happy path. See `gmail/pubsub_jwt.rs::tests` for the 15-case
template: expired, wrong audience, wrong issuer, missing kid,
unknown kid with network unavailable, tampered signature, `alg:
none`, HS256, backoff guard.

### 3. Watch lifecycle — `<integration>/watch.rs`

A service struct + five methods:

| Method | Purpose |
|---|---|
| `create_watch(user, integration_id, ...)` | Fast path: if existing row, update module_id + return. Slow path: acquire lock → call upstream create API → upsert row with indexed slots → audit-log. |
| `create_fresh_watch_locked(...)` | Unconditionally-create helper. **Separate from `create_watch`** — never reuse the fast-path helper in renewal. See gcal commit `e43430b` for the zero-channel bug we paid to learn this. |
| `renew_watch(user, channel_uuid)` | Read old row → acquire lock → **delete old row** → `create_fresh_watch_locked` → preserve sync cursor → audit-log. The delete-before-create order is critical — reversing it creates the zero-channel bug. |
| `stop_watch(user, channel_uuid)` | Best-effort upstream stop → delete row → audit. Idempotent. |
| `find_by_<upstream-identifier>(identifier)` | Hot-path webhook lookup. Resolves to `(user_id, row)`. Must be O(1) with the right indexed slot. |

**Storage layout** — use the four indexed slots deliberately:
- `idx_str_1` = the identifier the webhook payload carries (for
  O(1) lookup in step 2's `find_by_...`)
- `idx_str_2` = a logical secondary identifier (calendar_id,
  channel_name, room_id) — for dedup / observability queries
- `idx_ts_1` = the upstream expiration (for the renewal scheduler's
  filter)
- `idx_int_1` = a fourth slot, usually unused

**TTL grace**: always 14 days past the upstream expiration. Gives
the renewal scheduler ≥14 full-day retry windows past expiry before
the row is swept. The 5-minute grace we started with in gcal caused
silent disappearance during OAuth-dead streaks — see commit
`e43430b`.

**Concurrency lock**: `tokio::sync::Mutex` in a `DashMap` keyed by
the uniqueness granularity (for gcal: `(user, integ, calendar)`;
for gmail: `(user, integ)`). Serialize across create AND renew.
Sweep idle locks hourly — see `cleanup_create_locks` + the hourly
spawn in `main.rs`.

**Audit rows**: write `<integration>_channel_created`,
`<integration>_channel_renewed`,
`<integration>_channel_renewal_failed`,
`<integration>_channel_stopped` to `google_calendar_audit_log`
(yes, the name is inherited from gcal — it functions as a
shared integration-events log). Include `resource_id` /
`channel_id` / any other upstream-generated identifier in
metadata; without it, orphan cleanup is impossible because the
upstream API needs both our internal uuid AND the upstream id
to cancel the push. gcal lost this and had to document
"orphan channels expire naturally in 7 days."

### 4. Renewal scheduler — `<integration>/scheduler.rs`

Hourly tokio task. Lists rows with `idx_ts_1 < now + 24h`, renews
each in sequence.

- Audit-log every attempt (`<integration>_channel_renewed` on
  success, `<integration>_channel_renewal_failed` with the error
  text on failure).
- On failure, **keep the row** — the 14-day TTL grace means the
  scheduler sees it again next hour. Don't delete on single failures.
- Spawn once, forever. No shutdown awareness; tokio task drops
  cleanly when the runtime shuts down.

### 5. WASM dispatch — `<integration>/dispatch.rs`

Only once the pipeline from steps 1-4 is proven in logs with no
dispatch. Shape:

```rust
pub(crate) async fn dispatch_<events>(
    ctx: &<Integration>DispatchContext,
    user_id: Uuid,
    row: &<IntegrationWatch>Row,
    events: &[UpstreamEvent],
) -> Result<()>
```

Critical properties:

- **Module loaded once** per push (registry call hoisted outside
  the per-event loop). Not once per event. N+1 hell otherwise.
- **Redis dedup optional but recommended**: SETNX on
  `<integration>:processed:{scope}:{event_id}` with 24 h TTL.
  Long enough to outlast the upstream's retry window; bounded so
  idle keys age out.
- **Vault paths, not plaintext tokens**: inject
  `vault://oauth/<provider>/{user}/{key}/access_token` into the
  payload. Worker resolves at execution time. Plaintext never
  crosses controller → NATS.
- **Sign every JobRequest** with `worker_shared_key`. Unsigned
  jobs are rejected by the worker anyway — publishing one is
  burning NATS.
- **Per-event errors log + mark execution row failed, but don't
  abort the batch**. A permanent failure shouldn't loop every
  push. The cursor should advance past the event regardless.
- **Honor `ENABLE_EDGE_ROUTING`** for per-user NATS topics.

See `gmail/dispatch.rs` as the reference implementation.

### 6. User REST endpoints

Five in total, all session-authenticated:

- `GET  /api/<integ>/watch-channels` — list summaries with
  `recent_failure` enrichment (see step 8)
- `POST /api/<integ>/watch-channels` — create
- `POST /api/<integ>/watch-channels/:uuid/renew` — force renewal
- `POST /api/<integ>/watch-channels/:uuid/test` — **read-only
  probe** against the upstream. Critically, do NOT advance any
  sync cursor from the test. See gcal commit `fab8902` for the
  event-loss bug we paid to learn this.
- `DELETE /api/<integ>/watch-channels/:uuid` — stop

All handlers should be 5-20 line wrappers around a service method.
The list endpoint's enrichment + shape projection belongs in
`<integration>/watch_channel_service.rs`, not inline.

### 7. Admin endpoints — `<integration>/admin.rs`

Two-gate defense:

1. `ENABLE_ADMIN_OPS=1` env var — "big red button," unset in prod
2. `X-Admin-Secret` header vs `ADMIN_SECRET_KEY`, constant-time compare

Endpoints:

- `POST /api/admin/<integ>/watch` — create for arbitrary user
- `POST /api/admin/<integ>/stop-all` — stop everything for a user
- `POST /api/admin/<integ>/stop-orphan` — only if the upstream
  needs both an internal and an upstream identifier to cancel,
  AND we can reconstruct the upstream id from audit metadata
  (gcal yes; gmail no, because `users.stop` is per-mailbox and
  self-replacing)

Every successful action writes an `admin_<integ>_*` audit row. See
`google_calendar/admin.rs` and `gmail/admin.rs` — near-identical
skeletons.

### 8. Watch-channel summary service

`<integration>/watch_channel_service.rs`. Single source of truth for
the list-view projection:

- `list_for_user(user_id)` returns `Vec<<Integration>WatchSummary>`
- Enriches every summary with `recent_failure` via a single
  batched `DISTINCT ON (channel_uuid)` audit query. Looks back 25
  hours so old failures don't flag self-healed channels.
- **Reuse `RenewalFailure` and `looks_like_oauth_failure`** from
  `google_calendar::watch_channel_service`. Single canonical OAuth-
  dead heuristic. Do NOT re-implement.
- Batched module-name resolution via one UNION query filtered by
  `user_id IS NULL OR user_id = $caller` (defense-in-depth).

### 9. Frontend panel

`<Integration>WatchChannels.tsx`. Mirror `GmailWatchChannels` or
`GoogleCalendarWatchChannels` structurally. Uses React Query.

- Rendering gates:
  - No integration connected → render nothing
  - Integration connected + no watches → empty-state CTA
  - Integration connected + ≥ 1 watches → table + actions
- Per-row actions: **Test** / **Renew** / **Stop**
- Optimistic updates: `Stop` removes the row instantly with
  rollback on server rejection; `Renew` bumps expiration to
  ~7 days.
- `useIsFetching` disables Submit during post-create refetch —
  closes the double-submit window (see gcal commit `7018372`).
- OAuth-dead banner when any `recent_failure.likely_oauth_failure`
  is set, with a "scroll to provider card" CTA using
  `data-provider-id`.
- 30 s auto-refresh while tab is visible (RQ pauses when hidden).

Slot it into `IntegrationsManager.tsx` below the other integration
panels.

### 10. Operator docs — `docs/<integration>-push-setup.md`

One page covering:

- Prerequisites (the upstream's admin concepts: topic, subscription,
  service account, OAuth scopes)
- Step-by-step `gcloud` / `gh` / equivalent CLI commands
- Env vars Talos expects
- End-to-end verification steps
- Teardown
- Cost expectations at personal scale

See `docs/gmail-push-setup.md` for the shape.

## Predictive checks — new classes we haven't hit yet

The "common pitfalls" section below is retrospective — mistakes
real commits fixed. Use this section BEFORE coding to catch bug
classes we haven't yet paid for. Each question ends with the
answer pattern if you find yourself in the "yes" case.

### Event ordering

- **Does the upstream guarantee ordered delivery?** Gmail does
  (`historyId` is monotonic per mailbox). Google Calendar does
  (`sync_token` advances opaquely). Slack does within a workspace
  (`event_ts`). GitHub webhooks do **not** — events can arrive
  out of order, even for the same resource.
  - If NO: don't use a single monotonic cursor. Use per-event
    idempotency keys + timestamp comparison. Drop `advance_cursor`.
  - If YES: the `advance_history_id` / sync-token pattern works;
    never regress monotonically.

### Payload size

- **What's the upstream's max webhook body size?** GitHub: 25 MB.
  Slack: ~1 MB. Gmail Pub/Sub: ~10 KB (just the envelope; body
  fetched separately).
  - If > 100 KB is plausible: wrap the handler body extractor
    with `DefaultBodyLimit::max(N)`. Axum's default is 2 MB, which
    is wrong in both directions — too small for GitHub, too large
    for Slack.

### Rate limits + quota scope

- **Is OAuth quota per-user or per-app?** Gmail + gcal: per-user
  (each user has their own quota bucket). Slack: per-workspace.
  GitHub: per-installation OR per-user depending on app type.
  - Per-user quota: `users.history.list` usage scales with push
    volume per mailbox. Bounded per-user. No global concern.
  - Per-app quota: one noisy user can exhaust quota for ALL
    users. Need a token bucket per upstream + backoff-with-jitter.
    Document in operator runbook.

### Idempotency keys

- **Does every push carry a globally-unique event id?** Gmail:
  yes (message_id). Google Calendar: yes (event_id + updated).
  Slack: yes (event_id). GitHub webhook: yes (`X-GitHub-Delivery`).
  - If NO: dedup becomes content-hash + time-window, which is
    fragile. Push back on the integration and see if you missed
    an id field. If the upstream truly has none, Redis dedup is
    unreliable — switch to DB-level "seen" tracking with FK +
    unique constraint on synthetic content hash.

### Partial OAuth scopes

- **Can a user connect with REDUCED scopes?** Almost always yes
  via the OAuth consent screen. The user might grant read-only
  when your watch-create needs write.
  - Watch-create may succeed but dispatch-path calls fail 403.
    Validate scopes at OAuth callback OR at watch-create time
    (preferred: fail fast on create, before the user binds a
    module and expects it to work).

### Time zones + timestamps

- **Does the upstream send times in UTC, user's local, or zone-
  tagged?** Google Calendar: zone-tagged (`dateTime` + `timeZone`).
  Gmail: UTC epoch ms. Slack: UTC epoch seconds. Jira: UTC in API
  responses but user-local in UI.
  - Always store UTC + original zone. Convert for display, never
    for storage. If you only store the epoch, timezone info is
    lost and rebuilding the user's view requires heuristics.

### Multi-account same user

- **Can one Talos user have multiple accounts on the same
  provider?** Gmail: yes (multiple email addresses). Gcal: yes.
  Slack: yes (multiple workspaces). GitHub: yes.
  - If YES: the `gmail_integrations` / `google_calendar_
    integrations` table must be `UNIQUE(user_id, provider_key)`,
    NOT `UNIQUE(user_id)`. Check the migration.

### Webhook secret rotation

- **Does the upstream support rotating the webhook secret
  without dropping pushes?** Slack: yes (overlap window). Stripe:
  yes. Gmail Pub/Sub: effectively yes (JWK rotation handled by
  the verifier). Custom-HMAC integrations (gcal-style): NO by
  default — rotating `WORKER_SHARED_KEY` invalidates every
  active token simultaneously.
  - If rotating HMAC secret: either accept a dispatch outage
    (worst case 7 days until all channels naturally expire +
    re-create) OR implement dual-verify with N/N+1 key windows.
    Document either choice in the operator runbook.

### Backfill on first-watch

- **What happens between OAuth consent and watch-create?** Events
  during that window are missed. Does the upstream provide a
  backfill API? Gmail: yes (`users.history.list` with pre-watch
  `historyId`). Slack: yes (`conversations.history`). GitHub: no.
  - If backfill is possible: decide whether "first 24h worth of
    events" should fire workflows. Default: NO (surprising to the
    user, can flood). Make it opt-in via module config.

### Webhook delivery at-most-once vs at-least-once

- **Does the upstream retry on non-2xx?** Pub/Sub: yes, up to 7
  days. Slack: yes, 3 attempts over 1 hour. GitHub: yes, same-day.
  - At-least-once: MUST have Redis dedup on event_id. Without it,
    a transient 500 from our side produces duplicate WASM jobs.
  - At-most-once (rare — basically only Slack's "interactive"
    responses): don't 500 unless you can recover by reprocessing.

## Common pitfalls — "don't re-learn these"

Drawn from real commits we paid for.

### Renewal zero-channel bug (`e43430b`)

Reusing the public `create_watch_channel` from within `renew_watch`
short-circuits the fast path (which finds the OLD row and returns
it unchanged). Delete-then-create then wipes both, leaving zero
channels. **Renewal MUST call `create_fresh_watch_channel_locked`,
NOT `create_watch_channel`.** Guard with `debug_assert_ne!` on the
new vs. old upstream id.

### Destructive "Test" button (`fab8902`)

`Test` must NOT call `sync_channel_events` / anything that advances
a sync cursor. Any events consumed in the test window are silently
dropped because there's no downstream dispatch in the test path.
Use a read-only upstream probe (e.g. Gmail's `users.me/profile`,
Google Calendar's `list_calendars`).

### Overeager SQL redaction on the frontend (`728fe55`)

The frontend's sanitizer chopped any error message containing
lowercase "create" / "update" / "delete" / "select" / "insert"
because the regex was case-insensitive. **English verbs collide
with SQL keywords.** The regex is now ALL-CAPS only + requires a
grammatical follow-on (`INSERT INTO`, `UPDATE x SET`, etc.). New
integration error messages should NOT re-break this.

### JWK refresh backoff (`13ea09c`)

In JWT-verify integrations, a sustained upstream JWKs outage will
turn every push into a 5 s HTTP timeout unless a dedicated
`backoff_until` atomic is checked BEFORE the refresh mutex AND
after re-acquiring it. Staleness-TTL alone is not enough; the
mutex path always falls through to refresh on unknown kid.

### Double-submit on Create (`7018372`)

Disable the Create button until the post-create list refetch
completes, not just until the POST returns. Otherwise a
fast second click hits a stale `existingChannels` and the user
gets two upstream subscriptions for the same target.

### Localhost webhook URL (`728fe55`)

The upstream rejects `http://` and `localhost` push endpoints.
Pre-check the webhook URL in `create_watch_channel` and fail
with an actionable error ("run `make ngrok`") BEFORE spending
an API call.

### Empty HMAC key (`3b2ae4f`)

`jsonwebtoken` / `hmac` accept keys of ANY length including zero.
An empty-string shared key produces a deterministic MAC over public
data — trivially forgeable. Reject keys < 16 bytes at startup
wiring.

### Resource-id capture in audit (`7018372`)

If the upstream requires BOTH an internal uuid AND an
upstream-assigned id to cancel a resource, **capture the upstream
id in the `channel_created` audit row's metadata**. Without it,
orphan cleanup is impossible — the upstream id can't be
re-fetched from anywhere.

### Missing hot-path index (`bf4d98e`)

The `find_by_<upstream-identifier>` hot path needs an index on
that identifier column. `UNIQUE (a, b)` composites can't serve
`WHERE b = $1` lookups (the leading column must be first). Check
with `EXPLAIN` before shipping.

## Testing strategy

Minimum coverage per new integration:

- **Authentication unit tests** (JWT verifier or token signer):
  every rejection path — expired, wrong aud/iss/email, missing
  kid, `alg: none`, HS256, tampered signature, unknown kid during
  outage, backoff guard. See `gmail/pubsub_jwt::tests` for the
  15-case template.
- **API client decoder tests**: happy path for each response
  shape, plus the quirky polymorphic fields (string-or-number
  ids, missing optional fields).
- **Projection tests** on the watch-channel service: basic
  row shape, sync-token-absent/null/empty, invalid-uuid rejection.
- **Regression guard**: for renew-fresh-id (see the
  `debug_assert_ne!` in gcal/gmail).

Live-test harness:

- `docs/<integration>-push-setup.md` walks the operator through
  the external setup.
- If the upstream supports push, use ngrok for the real end-to-end
  test. Admin endpoints bypass UI auth for scripted runs.

## Cross-references

- `docs/platform-primitive-checklist.md` — how to add a NEW signed-
  NATS-RPC primitive (layer below this).
- `docs/gcal-live-test.md` — gcal-specific live test walkthrough.
- `docs/gmail-push-setup.md` — gmail-specific operator runbook.
- `google_calendar/*` — reference implementation (first).
- `gmail/*` — reference implementation (second, where the pattern
  was re-used rather than re-invented).

## When adding the third integration

Start from this doc, not from gcal or gmail. If you find yourself
diverging from the pattern, the right move is to:

1. Ask whether the divergence is genuinely required by the
   upstream, or whether you're just moving fast.
2. If genuinely required, update this doc before diverging, so the
   fourth integration sees the new variant.
3. If not required, converge.

The whole point of capturing this is that integration 3 should be
significantly faster than integration 2 was, and integration 4
faster still.
