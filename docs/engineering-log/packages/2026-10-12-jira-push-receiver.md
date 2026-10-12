# 2026-10-12 — a Jira webhook delivery can start a workflow

**Why.** The owner wants a workflow to start within seconds of a Jira ticket
assigned to them changing, the way a calendar change already does. Talos's
Atlassian integration did OAuth and token handling and received nothing. The
workflow that will be bound is level-triggered (it re-reads Jira and is safe
to run twice), so the push is a wake-up and carries identifiers only.

Operator steps and behaviour: `docs/jira-push-setup.md`.

**What Atlassian fixes, and what follows.** One webhook URL per app, on the
app's base URL: the address is the same for every user and cannot carry a
per-user token. Each delivery is signed with the app's client secret, the same
key for everyone. So neither auth shape the integration guide knew (a token we
mint per channel; a provider-signed token that names the account) can say
whose a delivery is. The owner is whoever REGISTERED the webhook id the
delivery names. That is the reason for every storage and tenancy decision
below, and it is now a section of `docs/integration-pattern.md`.

**Decided.**
- **A table of its own**, `atlassian_webhook_registrations`, not
  `integration_state`: the receiver must find a row by Atlassian's webhook id
  before it knows the user, which a per-user store cannot do. Unique on
  `(webhook_id, cloud_id)` — webhook id first, so the same index serves the
  receiver's lookup (a separate index on `webhook_id` would be a leading
  prefix, which `index_hygiene_tests` refuses) — and on `(user_id, cloud_id)`:
  one registration per connection. `workflow_id` is a foreign key that a
  deleted workflow sets to null. No RLS policy, like `plaid_items` and
  `google_health_integrations`: the receiver's read is the one that FINDS the
  user, and every other reader names the user on the service pool. Both new
  tables are granted to `talos_admin_read` (no token, no ticket content).
- **The receiver verifies before it reads anything.** Order: bearer token
  present → JWT verifies under the client secret → body read (≤ 1 MiB) and
  parsed → registrations looked up → execution pause → delivery recorded →
  starts planned → 200 → starts run in a task. The body is not read and the
  database is not touched before the token verifies.
- **The token check is the narrowest that can be justified today**
  (`talos_atlassian::push_jwt`). HS256 / HS384 / HS512 only, decided from the
  header's own text before a key is built; `none` and every asymmetric name
  refused by name; `crit` refused; a client secret shorter than 16 bytes
  verifies nothing (503). `exp` and `nbf` are honoured when present (60 s
  leeway) and NOT required, and `aud` / `iss` are not checked: Atlassian
  documents neither the algorithm nor the claims, and requiring a guessed
  claim would refuse every real delivery. The first delivery a process
  authenticates logs the algorithm and the sorted claim NAMES once
  (`event_kind="jira_webhook_jwt_shape"`), so the check can be tightened from
  evidence.
- **Three fields are read from the body** (`matchedWebhookIds`,
  `webhookEvent`, `issue.key`) by hand-written visitors that skip everything
  else without holding it, bound the id list at 64 and treat a field of an
  unexpected shape as absent rather than as an error.
- **Owner mapping is one query on the registration table**, by webhook id.
  Nothing else in the request is consulted. A lookup that fails is 503
  (Atlassian retries a 5xx); no row is 200.
- **A webhook id held on more than one site starts nothing** for any of its
  registrations (`split_ambiguous`). The delivery does not say which site
  sent it, and acting on a guess would start one user's workflow for another
  site's ticket and hand it that ticket's key. Recorded: a WARN under
  `talos_audit` and, where a workflow was bound, an audit row with reason
  `ambiguous_webhook_id`.
- **A delivery that matches more registrations than are read starts
  nothing** (`TooManyRegistrations`, 200). The lookup asks for one row more
  than it will use. With a plain `LIMIT`, a webhook id's second site could
  fall outside the limit and the id would look unambiguous: 51 ids on five
  sites each, then one id on two, is enough. Not reachable by Atlassian's own
  limits; closed because the mapping is the tenancy decision.
- **The pause is consulted BEFORE the delivery is recorded as handled.** The
  brief listed dedupe before the pause. That order drops a delivery: a 503
  after the record is retried by Atlassian and then skipped as a duplicate.
  This is the calendar handler's own reasoning (package BG), applied.
  `PauseGatePath::JiraPush`.
- **Deduplication is a table**, `atlassian_webhook_deliveries
  (registration_id, delivery_id)`, written with one `INSERT … ON CONFLICT DO
  NOTHING RETURNING`: atomic, shared by every replica, and it does not need
  Redis (which the push routes only optionally have). Rows older than seven
  days are deleted by the hourly task. A delivery with no usable
  `X-Atlassian-Webhook-Identifier` is handled as new.
- **The start is made as the registration's own user**, through
  `ExecutionOrchestrationService::trigger`, so ownership is checked a second
  time there. A row made to name someone else's workflow starts nothing
  (`workflow_not_found`).
- **The trigger is `{jira_push: {cloud_id, webhook_id, event, issue_key}}`.**
  `event` and `issue_key` only when plain (`^[a-z_:]{1,64}$`;
  `^[A-Z][A-Z0-9_]{0,19}-[0-9]{1,10}$`), otherwise left out.
- **A refused start is recorded, not retried**: a WARN under `talos_audit`
  and a row in the shared events log (`jira_workflow_not_started`).
  **The reason words moved** to `OrchestrationError::push_refusal_reason`
  (+ `PUSH_REFUSAL_TRIGGER_FAILED`, `PUSH_REFUSAL_TRIGGER_SERVICE_NOT_WIRED`)
  in `talos-execution-orchestration`; the calendar handler now calls it and
  its private `trigger_refusal_reason` is gone.
- **Registration** (`register_push_channel`) refuses, before Atlassian is
  called: an address that is not `https://` or is this machine's own; a
  connection that is not the caller's (`user_id = $caller`, and "not yours"
  is "no such"); a connection without `manage:jira-webhook`; a missing or
  non-plain Jira account id (it is written into a JQL string, so it is
  refused rather than escaped). The Atlassian call and the row write run
  under a fleet lock with a re-check, because a second POST is a second
  webhook. A webhook created but not recorded is deleted again.
- **Creating and deleting go through a new `PushChannelProvisioner`**, carried
  by `PushChannelInventorySet` beside the inventories. The inventory stays
  pool-only (it cannot register anything and is built whether or not
  Atlassian is configured); the provisioner holds the service. The MCP
  handlers stay thin and `McpState` gained no field.
- **Refresh** is the shared renewal loop (`run_renewal_scheduler`), supervised
  as `BackgroundTask::JiraWebhookRefresh`, started only when Atlassian is
  configured. Within 10 days of expiry, hourly. No lease: a refresh replaces
  the expiry, so two replicas doing it is one call too many and nothing
  else. **Atlassian's refresh ignores ids it does not know**, so after a
  refresh the listing is read and a webhook Atlassian no longer lists is a
  failure (`WebhookGone`); a listing that cannot be read is not evidence and
  leaves the refresh's answer standing. A failure is written on the row
  (`refresh_failed_at`, `refresh_error`, cleared by the next success), to the
  audit log, and logged at ERROR; `list_push_channels` shows it as
  `recent_failure`. A registration expired more than seven days is no longer
  retried and is shown as expired.
- **An upstream failure keeps its kind** (`UpstreamFailure`: unreachable,
  unauthorized, rate limited, server, refused, rejected, malformed). The
  operation is called "renewal" in an error, not "refresh":
  `looks_like_oauth_failure` reads the word "refresh" as a dead credential,
  and a 503 during one is not. A 401 is answered once by forcing a token
  refresh through the credential service's own refresh path.
- **Disconnect** deletes the connection's webhooks before its token is
  removed, on both paths: `AtlassianIntegrationService::disconnect_integration`
  and the generic GraphQL `disconnectServiceIntegration` (which gained an
  Atlassian arm like Plaid's, and `talos-api` a dependency on
  `talos-atlassian`).
- **`ATLASSIAN_WEBHOOK_BASE_URL`**: documented, in the compose `environment:`
  map, and derived by the chart from the controller's ingress host (the same
  host as `ATLASSIAN_REDIRECT_URI`). Unset, the public-URL helper answers,
  with `BASE_URL` as its last fallback.
- **`manage:jira-webhook`** is appended to `REQUESTED_SCOPES`.

**Deviations from the brief, each stated above.** Pause before dedupe (the
brief's order drops a deferred delivery). The unique index is
`(webhook_id, cloud_id)` rather than `(cloud_id, webhook_id)` plus a second
index. A second unique `(user_id, cloud_id)`, two columns for the last refresh
failure, a foreign key on `workflow_id`, and the dedupe table were added. The
token is verified BEFORE the body is read (the brief had the body cap first).
The refresh confirms against the listing. Registrations long expired stop
being retried.

**Deliberately NOT done.**
- **No required claim, no audience check.** See above; needs a real delivery.
- **No binding of the token to the body.** Nothing known ties one to the
  other. See "Not verified".
- **No REST endpoints and no frontend control.** The four MCP tools are the
  surface.
- **No metric.** As for the calendar binding: the audit row and the WARN are
  the record; a counter needs a seeded closed label set and an alert to be
  worth registering (check 58). The refusal of an unauthenticated request is
  one WARN per request, behind the route's rate limiter.
- **No module binding.** A Jira registration starts a workflow or nothing.
- **Gmail and Google Cloud channels** still cannot start a workflow.
- **No re-registration on reconnect.** After a disconnect the channel and its
  binding are gone and are created again by hand.
- **`TALOS_PUBLIC_BASE_URL` is not transported** by the compose file or the
  chart (it is documented and in `.env.example`). Found here, not changed
  here: on compose, set `ATLASSIAN_WEBHOOK_BASE_URL`.

**Tests.**
- `talos-atlassian` unit tests (40, 33 new). The token: accepted under each
  HMAC algorithm; refused for another secret, swapped claims, `none` and each
  asymmetric name, `crit`, expired, not yet valid, and junk. The receiver,
  against a pool that cannot connect, so a receipt that is not a database
  failure proves the database was not asked: no bearer, bad signature, `none`
  / RS256 / ES256 / PS256 / EdDSA, expired, no usable client secret, an
  oversized or malformed body — with a control showing a verified delivery
  does reach the database. The body parser, the issue-key and event shapes,
  the trigger input, the ambiguity split, the address check, the account-id
  and cloud-id shapes, the registration request, both expiry formats, the
  failure kinds, the scope list.
- `controller/tests/jira_push_receiver_tests` (13, in-process stand-in for
  Atlassian): registration only for the caller's own connection; everything
  refusable refused before Atlassian is asked; a delivery starts the bound
  workflow once as the registration's owner and a retry, an odd issue key, a
  switched-off workflow and a missing trigger service each start nothing and
  say why; the route itself answers 401 / 200 and the start follows the
  answer; unknown and ambiguous webhook ids; more matching registrations
  than are read; one user's delivery never
  starts another's workflow, including a row pointed at it behind the bind's
  back; binding ownership, directly and by integration name through the set;
  refresh success, failure, a webhook Atlassian no longer lists, the give-up
  cut-off; the hourly task; delete and disconnect; the two tools through the
  MCP dispatcher; the pause.
- What a start carries is pinned through the workflow's own input schema
  (an `enum` of the one accepted object): the trigger service refuses any
  other input before it creates an execution. The trigger input is not
  stored until a run is dispatched, and this harness has no bus.
- Also run: the whole of `talos-push-channel-inventory`,
  `talos-execution-orchestration`, `talos-google-calendar`, `talos-metrics`,
  `talos-task-supervision`, `talos-execution-pause`, `talos-mcp-handlers`,
  `talos-api`, `talos-integration-helpers`, `talos-oauth`,
  `talos-integrations`; the controller's unit tests (which caught the
  supervised-loop count pin, now 42); `admin_read_role_grants`; `make lint`
  with the PREPARE leg of check 88 on; clippy `-D warnings`, all targets, on
  the ten touched crates.
- **All 145 controller DB-harness binaries** (CI's `ctrl` set), once, on a
  scratch Postgres of this change's own: 142 passed (791 tests). Three failed
  for reasons of the machine, not the change: `ml_reembed_tests` picks up the
  developer `.env`'s embedding endpoint through the harness's dotenv walk
  (it passes with that masked), and `rpc_instrument_tests` /
  `rpc_write_ceiling_tests` need the NATS server CI provisions and were
  refused by the stack's. That run preceded the row-limit change, which
  touched only the receiver; its own binary and the unit suite were re-run
  after it. The Jira and calendar binaries were also run with
  `TALOS_RLS_SET_ROLE` off, as CI runs them (the developer `.env` turns it
  on).

**Mutations.** Each applied by a script that writes the mutation, runs the
suites, and restores the file byte for byte; a mutation that does not compile
is reported as that and not as caught (the first two attempts at M1 did not
compile, and were reported so). All thirteen were run against the final code.

| | Mutation | Caught by |
|---|---|---|
| M1 | signature not verified (a token that fails verification is decoded with `dangerous::insecure_decode`) | unit: bad signature / tampered / expired tests, both modules (4); DB: the route test |
| M2 | algorithm restriction removed (any name the library knows) | unit: both "refused by name" tests |
| M3 | owner mapping removed (`OR true` on the lookup) | DB: another user's workflow, unknown id, delete |
| M4 | ambiguity refusal removed | unit: the split; DB: the ambiguous id |
| M5a | bind: workflow ownership check removed | DB: bind ownership |
| M5b | bind: `user_id` predicate removed | DB: bind ownership |
| M6a | registration: `user_id` predicate on the connection removed | DB: registration ownership, the tools |
| M6b | refresh / delete: `user_id` predicate removed | DB: refresh, delete, the tools |
| M7 | a non-plain issue key passed on | unit: trigger input; DB: the delivery test (input schema) |
| M8 | a repeated delivery not recognised | DB: the delivery test |
| M9 | the pause not consulted | DB: the pause test |
| M10 | `exp` not honoured | unit: both expired tests |
| M11 | the lookup's row limit truncates silently | DB: more registrations than are read |

M2, stated plainly: with the restriction removed, an RS256 or `none` token is
still not ACCEPTED — the library will not verify an asymmetric algorithm with
an HMAC key. What the tests catch is this module's own gate no longer being
the one that refuses (the reason changes). The gate is kept because the
refusal should not depend on a property of the library.

**Not verified, stated.**
- **No real delivery has been received.** Not verified against Atlassian:
  that the token is HS256 over the client secret's bytes; which claims it
  carries; that `jqlFilter: assignee = "<account id>"` is accepted with a
  quoted id; the shape of `expirationDate`; that the listing reports
  `isLast`; that refresh ignores unknown ids (documented); whether a connect
  asking for a scope the app has not enabled is refused.
- **The token is not known to be bound to the body.** If it is not, a holder
  of one valid token, while it is valid, can POST a body naming any webhook
  ids and wake those registrations' workflows with a plain issue key of its
  choosing. It gains no content (the trigger has none; the workflow reads
  Jira with its owner's grants) and each start passes the trigger's gates.
  Getting a token needs the TLS session or the client secret. If `exp` is
  absent the token never expires. Tightening this needs the claim names the
  shape log records.
- **The 401-then-refresh path** is not driven: the credential service's
  Atlassian refresh posts to the real token endpoint and has no test hook.
- A start is driven as far as the execution row; the harness has no bus.
- The refresh's listing check was built from the documented response shape;
  if the real one differs it answers "unknown", not "gone".
- A user who reconnects the same site as a DIFFERENT Jira account keeps a
  webhook filtered on the old account id until the channel is re-created.
- Not run: the 14 testcontainers binaries and the one serial binary of the
  controller, and the two NATS binaries above. `quality.yml` runs them on the
  pull request.

**One home.** `push_jwt::verify_delivery_jwt` and `accepted_algorithm` for
what a delivery must prove; `push_receiver::receive_push` for the order;
`split_ambiguous` for ambiguity; `jira_push_trigger_input` for what a start
carries; `push::bind_registration_workflow` for the binding;
`push::webhook_url_from_base` for the address rule;
`OrchestrationError::push_refusal_reason` for the recorded words.

**CLAUDE.md.** One paragraph, beside the calendar one: the receiver's order,
owner mapping only through the registration row, ambiguity starts nothing,
identifiers only, the one home for the reason words, and a provisioner
beside (not inside) a pool-only inventory.
