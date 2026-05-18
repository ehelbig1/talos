# Google Calendar live integration test

End-to-end verification that the `integration_state`-backed Google
Calendar integration works against real Google servers.

The unit/security tests (`controller::google_calendar::webhook_token::tests`,
the four curl-based boundary tests) prove every boundary in the controller.
This test proves **Google can actually reach us + we dispatch correctly**.

## Prerequisites

- Docker compose up (`make up-dev` or `make up`).
- `WORKER_SHARED_KEY` is set to ≥16 bytes in `.env` (controller refuses to
  boot otherwise — see `main.rs`).
- Google OAuth client credentials in `.env`:
  - `GOOGLE_CLIENT_ID`
  - `GOOGLE_CLIENT_SECRET`
  - `GOOGLE_REDIRECT_URI` (must match whatever ngrok issues below)
- `NGROK_AUTHTOKEN` in `.env` (free-tier ngrok v3 requires auth).
- **To use the admin harness endpoints** (used for steps 3 + 7 below):
  - `ENABLE_ADMIN_OPS=1` in `.env`
  - `ADMIN_SECRET_KEY=<strong-random>` in `.env`

  Both MUST remain unset in production. The admin endpoints are a
  "big red button" feature gated by both — leaving either unset
  reverts the endpoints to 404 / 401 for every caller.

## Steps

### 1. Establish the tunnel

```bash
make ngrok
```

This:
- Starts an ngrok tunnel to port 8000.
- Exports `BASE_URL=https://<sub>.ngrok.io`.
- Restarts the controller so the webhook-create path uses that URL.

Verify:

```bash
curl -s https://<sub>.ngrok.io/health
# {"status":"ok","ts":...}
```

### 2. Connect a Google account (OAuth)

Open the frontend (`http://localhost:3002`) and sign in. Navigate to
settings → integrations → Google Calendar. Complete the OAuth consent
flow. The callback lands at `$BASE_URL/auth/oauth/google/callback`.

Verify via GraphQL:

```graphql
query { googleCalendarIntegrations { id email isActive } }
```

Should return one row with `isActive: true`.

### 3. Create a watch channel (admin harness path)

With `ENABLE_ADMIN_OPS=1` + `ADMIN_SECRET_KEY` set:

```bash
INTEG_ID=<id from step 2>
ADMIN=$(docker exec talos-controller sh -c 'echo -n "$ADMIN_SECRET_KEY"')
curl -sS -X POST https://<sub>.ngrok.io/api/admin/google-calendar/watch \
  -H 'Content-Type: application/json' \
  -H "X-Admin-Secret: $ADMIN" \
  -d "{\"integration_id\":\"$INTEG_ID\",\"calendar_id\":\"primary\"}"
```

Expected response:

```json
{
  "channel_uuid": "...",
  "google_channel_id": "...",
  "calendar_id": "primary",
  "expiration": "...",
  "webhook_url": "https://<sub>.ngrok.io/api/google-calendar/webhook"
}
```

End users have their own path (session-cookie authenticated):
`POST /api/google-calendar/watch` — used by the frontend's "connect
calendar" flow. The admin endpoint is purely for scripted test
harnessing.

Verify the row landed in `integration_state`:

```bash
docker exec talos-postgres psql -U talos -d talos -c \
  "SELECT key, idx_str_1 AS google_channel_id, idx_str_2 AS calendar \
   FROM integration_state WHERE integration_name = 'gcal';"
```

### 4. Trigger a real Google push

Add or edit an event on the calendar you subscribed to. Google fires a
push to `$BASE_URL/api/google-calendar/webhook` within seconds.

### 5. Observe dispatch

Stream controller logs:

```bash
docker compose logs -f controller | grep -E 'gcal|webhook|Channel'
```

You should see, in order:
1. `📬 Google Calendar webhook - Channel: Some(...), State: Some("sync"), ...`
2. For the initial `sync` state: `🔄 Initial sync handshake — establishing sync token`
3. For subsequent `exists` states: `✅ Synced N events for channel ...`
4. If a module is bound: `✅ Job published to worker: ...`

### 6. Force a renewal

Manually trigger renewal by expiring the `idx_ts_1` on the row:

```bash
docker exec talos-postgres psql -U talos -d talos -c \
  "UPDATE integration_state SET idx_ts_1 = now() + interval '1 hour' \
   WHERE integration_name = 'gcal';"
```

Wait ≤1 hour for the scheduler tick (or restart controller), then check
the audit log:

```bash
docker exec talos-postgres psql -U talos -d talos -c \
  "SELECT event_type, success, calendar_id, created_at \
   FROM google_calendar_audit_log ORDER BY created_at DESC LIMIT 5;"
```

Expected rows (newest first):

```
 channel_created     | t | primary | 2026-04-15 ...
 channel_stopped     | t | primary | 2026-04-15 ...
 (original row)
 channel_created     | t | primary | 2026-04-15 ...
```

The `channel_stopped` + fresh `channel_created` pair confirms renewal
executed the delete-before-create sequence correctly (see the zero-
channel-bug fix in commit `e43430b`).

### 7. Cleanup

```bash
USER_ID=<owning user uuid, from step 2>
ADMIN=$(docker exec talos-controller sh -c 'echo -n "$ADMIN_SECRET_KEY"')
curl -sS -X POST https://<sub>.ngrok.io/api/admin/google-calendar/stop-all \
  -H 'Content-Type: application/json' \
  -H "X-Admin-Secret: $ADMIN" \
  -d "{\"user_id\":\"$USER_ID\"}"
```

End users do the equivalent via `POST /api/google-calendar/integrations/:id/disconnect`,
which cascades to stopping every channel owned by that integration.

After cleanup, remember to remove `ENABLE_ADMIN_OPS=1` from `.env`
if this was a one-off live test. Production instances must never
have it set.

Verify no rows remain:

```bash
docker exec talos-postgres psql -U talos -d talos -c \
  "SELECT count(*) FROM integration_state WHERE integration_name = 'gcal';"
-- count: 0
```

## Success criteria

| Observation | Interpretation |
|---|---|
| Webhook returns 200 on valid push | Signed-token verification works end-to-end |
| `channel_created` audit row after step 3 | Watch creation persisted correctly |
| `Synced N events` log after step 4 | Google can reach us + sync token handshake works |
| `channel_stopped` + `channel_created` pair after step 6 | Renewal takes the delete-before-create path |
| Zero rows after step 7 | Disconnect cascade works |

## Automated pre-flight

`scripts/gcal-live-test-preflight.sh` runs the parts we can automate:
tunnel health, webhook-token boundary (invalid/missing/valid-stale/
wrong-channel), `integration_state` reachability, audit log readability.
It does NOT create real Google-side channels — that requires an
OAuth'd account. Run it before kicking off the manual steps above.
