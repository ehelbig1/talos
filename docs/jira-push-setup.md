# Jira push (a Jira webhook that starts a workflow)

Lets Jira tell Talos, within seconds, that an issue assigned to the connected
user was created or changed, so a workflow starts then instead of at its next
scheduled run.

The push is a wake-up and nothing more. The workflow it starts is given
identifiers only and reads Jira itself, so it must be one that is safe to run
twice and it should keep a schedule as a catch-up.

## What it is made of

| Piece | Where | What it does |
|---|---|---|
| The connection | `talos-atlassian`, the **Jira (Atlassian)** card on the integrations page | Obtains and refreshes the OAuth token. Unchanged, except that it now asks for one more permission. |
| The channel | `create_jira_push_channel` (MCP) → `talos_atlassian::push` | Registers a Jira *dynamic webhook* for one connection: issues where `assignee` is the connected Jira user, events `jira:issue_created` and `jira:issue_updated`, for changes to status, assignee, priority or due date. One per connection. |
| The receiver | `POST /api/atlassian/webhook` (public) → `talos_atlassian::push_receiver` | Verifies the delivery, finds whose webhook it is, and starts that user's bound workflow once. |
| The binding | `set_push_channel_workflow` (integration `atlassian`) | Names the workflow a delivery starts. |
| The refresh | a background task in the controller, hourly | Refreshes each webhook before Atlassian's 30-day expiry. |

Tools: `create_jira_push_channel`, `list_push_channels`,
`set_push_channel_workflow`, `delete_jira_push_channel`. There is no screen for
this yet.

## Operator setup

Four things about Atlassian decide how this is set up. They are Atlassian's
rules, not Talos's.

1. **The app needs one more scope.** In the
   [Atlassian developer console](https://developer.atlassian.com/console/myapps/),
   open the OAuth 2.0 (3LO) app this deployment uses, and under
   **Permissions → Jira API** add the classic scope **`manage:jira-webhook`**
   ("Manage Jira webhooks"). `read:jira-work` must stay enabled. **Do this
   before deploying the version of Talos that asks for it**: Talos requests
   the scope on every new Jira connect, and whether Atlassian refuses a
   connect that asks for a scope the app has not enabled was not tested.
   Existing connections keep working either way (a token refresh asks for no
   scopes).
2. **One webhook URL per app, on the app's own base address.** Atlassian
   accepts a single webhook URL for the whole app and requires it to share the
   app's base URL. Talos therefore uses one fixed address,
   `https://<host>/api/atlassian/webhook`, for every user, where `<host>` is
   the host of the app's callback URL (`ATLASSIAN_REDIRECT_URI`). The address
   must be reachable from the internet over `https://`.
3. **A private app delivers only for its owner.** If the app is not
   distributed publicly, Atlassian delivers a webhook only when the user who
   registered it is the app's owner. On a single-owner deployment, connect
   Jira as the account that owns the app.
4. **Five webhooks per app, per user, per site.** Talos keeps one per
   connection.

Then:

1. **Set the address.** `ATLASSIAN_WEBHOOK_BASE_URL` is the scheme and host
   Jira delivers to, with no path, for example `https://talos.example.com`.
   - Helm: nothing to do. The chart sets it to the controller's ingress host,
     the same host as `ATLASSIAN_REDIRECT_URI`.
   - Compose: set `ATLASSIAN_WEBHOOK_BASE_URL` in `.env` and restart the
     controller. If it is unset, the ngrok tunnel is used when the `public`
     profile is running; an ngrok address only suits a trial, and only if the
     Atlassian app's callback URL uses the same address.
   - A value that is not `https://`, or is this machine's own address, is
     refused when a channel is created, with a message naming this variable.
     It is never silently replaced.
2. **Reconnect Jira.** A connection made before this change does not hold
   `manage:jira-webhook`. In Settings → Integrations, disconnect Jira and
   connect it again, approving the new permission.
3. **Create the channel.** `create_jira_push_channel` (add `cloud_id` if you
   have more than one Jira site connected). It answers with a `channel_id`.
4. **Bind a workflow.**
   `set_push_channel_workflow(integration: "atlassian", channel_id, workflow_id)`.
   The workflow must be your own. Until one is bound, deliveries are accepted
   and start nothing.
5. **Check it.** Change a ticket assigned to you. `list_push_channels` shows
   the channel's `last_event_at` moving, and the workflow has a new execution.

## What a delivery starts the workflow with

```json
{ "jira_push": {
    "cloud_id":   "11111111-2222-3333-4444-555555555555",
    "webhook_id": 1000,
    "event":      "jira:issue_updated",
    "issue_key":  "PROJ-123"
} }
```

`event` and `issue_key` are present only when they are a plain event name and
a plain issue key; anything else is left out. No summary, description, status,
comment or user name is ever passed, logged or stored: the receiver's parser
reads only the matched webhook ids, the event name and the issue key from the
body, and skips the rest.

Write the workflow so that it also runs correctly with no `jira_push` at all,
because that is what its scheduled catch-up run looks like.

## How a delivery is checked

The address is public and the same for everyone, so nothing in a request is
believed until it is verified, in this order:

1. `Authorization: Bearer <token>` must be present.
2. The token must be a JWT signed with the app's **client secret**
   (`ATLASSIAN_CLIENT_SECRET`) using HS256, the algorithm a real delivery
   uses. `none`, the other HMACs and every asymmetric algorithm are refused. `exp` is required and may be at most an
   hour away; `nbf` is honoured when present. A request that fails here is
   answered 401 before the body is read and before the database is touched.
3. **A token is used once.** Its hash is remembered until it can no longer
   verify (on every replica, when the controller runs a shared replay guard);
   a second use is answered 200 and does nothing, before the body or the
   database is read. A delivery answered 503 forgets its token, so
   Atlassian's retry is read again.
4. The delivery is mapped to its owner by the webhook id Talos registered,
   and only on the delivery's own site: a Jira webhook id is unique only
   within one site, so the receiver reads the site from the delivery's
   `issue.self` (its host, or the cloud id on `api.atlassian.com/ex/jira/…`)
   and a registration acts only when that is its own connection's site. A
   delivery with no `issue.self`, or from another site, starts nothing,
   is answered 202, and is recorded (`site_mismatch`). The request cannot name
   a user. A webhook id that Talos holds on more than one site, with both on
   the delivery's site, is ambiguous and starts nothing.
5. Each channel acts on at most 60 deliveries a minute (per controller), and
   remembers at most 10,000 deliveries; above that a delivery starts nothing
   and is recorded (`dedup_cap`) until the seven-day sweep makes room.
6. Atlassian's `X-Atlassian-Webhook-Identifier` is remembered for seven days:
   a retried delivery starts nothing a second time.
7. The workflow is started as the channel's owner through the same service as
   `trigger_workflow`, so the execution pause, whether the workflow is live,
   its actor's budget and ceilings, its input schema and its concurrency limit
   all apply, and ownership is checked again.

Atlassian does not document the token's algorithm or its claims. The first
delivery a controller process authenticates writes one INFO line,
`event_kind="jira_webhook_jwt_shape"`, with the algorithm, the *names* of the
claims (never a value) and the token's lifetime in seconds. A real delivery
(2026-10-14) carried `HS256` and `context, exp, iat, iss, jti, sub` — which is
why `exp` is now required. The values of `iss` and `sub` for an OAuth 2.0
app are still undocumented, so they are not checked; the token carries no
`qsh`, so it is not bound to the body, which is what the single-use rule
covers.

## What it answers Atlassian

| Status | When | Atlassian |
|---|---|---|
| 200 | Verified. Includes "matched no channel", "already handled", "token already used" and "no workflow bound". | does not retry |
| 202 | Verified, but about another Jira site than every channel it named (or names no site). Recorded. | does not retry |
| 401 | No bearer token, or it does not verify. | does not retry |
| 400 / 413 | The body is not a delivery, or is over 1 MiB. | does not retry |
| 503 | The execution pause is set, the database did not answer, the replay memory could not answer, or the client secret is not configured. | retries (up to five times) |

## Behaviour worth knowing

- **A refused start is recorded and not retried.** If the bound workflow
  cannot be started (switched off, archived, over its concurrency limit, its
  input schema refuses the input, the actor's budget is spent), the delivery
  is still answered 200. One row is written to the integration events log
  (`google_calendar_audit_log`, `event_type = 'jira_workflow_not_started'`)
  with a reason, and a WARN under `talos_audit`. The schedule catches it up.
- **A ticket that leaves you is not delivered.** The filter is "assigned to
  me", evaluated after the change, so reassigning a ticket away does not
  match. The scheduled run is what notices.
- **Expiry.** A webhook lives 30 days. The controller refreshes each one once
  it is within 10 days of expiring, hourly until it succeeds. A failed refresh
  is written on the channel and shown by `list_push_channels` as
  `recent_failure`; `likely_oauth_failure: true` means reconnect Jira. If
  Atlassian no longer lists the webhook, the failure says so: delete the
  channel and create it again. A webhook that expired more than seven days
  ago is no longer retried; the channel stays listed, marked as expired,
  until you delete it.
- **Disconnecting Jira** deletes the connection's webhook at Atlassian (best
  effort) and the channel here, with its binding. After reconnecting, create
  the channel and bind the workflow again.
- **Rotating the client secret** at Atlassian without updating
  `ATLASSIAN_CLIENT_SECRET` makes every delivery fail with 401, and Atlassian
  does not retry those. Update the variable and restart the controller.
- **Changing the deployment's address** leaves existing webhooks pointing at
  the old one. Delete each channel and create it again.
- **Several controller replicas** are fine: registration takes a lock they
  share, a refresh made twice changes nothing, and a delivery is recorded as
  handled in the database, so a retry that lands on another replica is still
  a duplicate.

## What is stored

- `atlassian_webhook_registrations`: one row per channel — the user, the Jira
  site, Atlassian's webhook id, the address it delivers to, the expiry, the
  bound workflow, the last delivery and the last refresh failure. No token.
- `atlassian_webhook_deliveries`: the delivery identifiers handled in the last
  seven days.
- The OAuth token stays where it was, in the vault.

## Teardown

`delete_jira_push_channel(channel_id)`, or disconnect Jira. To stop asking for
the scope, remove `manage:jira-webhook` from the app in the Atlassian console;
existing connections then fail to create channels and say to reconnect.

## Not yet verified against Atlassian

This was built from Atlassian's published API description and webhook guide
and tested against a stand-in. A real delivery had not been received when it
was written. See
`docs/engineering-log/packages/2026-10-12-jira-push-receiver.md` for the list
of what that leaves open.
