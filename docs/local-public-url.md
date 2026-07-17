# Public URLs for a local stack (ngrok auto-tunnel)

Push-based integrations need to reach your controller from the
internet: Google Pub/Sub push (`/api/gcp/pubsub/<token>`), Google
Calendar watch webhooks (`/api/google-calendar/webhook`), and any
inbound webhook you hand to an external system (`/webhooks/<id>`).
A localhost dev stack can't receive those. This feature makes a local
stack publicly reachable with zero per-run ceremony.

## One-time setup

1. Get an ngrok authtoken: <https://dashboard.ngrok.com/get-started/your-authtoken>
2. (Strongly recommended) claim your free reserved domain:
   <https://dashboard.ngrok.com/domains> — one is included in the free
   tier. Without it every stack restart mints a NEW public URL and
   everything registered provider-side goes stale.
3. Add both to `.env`:

   ```bash
   NGROK_AUTHTOKEN=<your token>
   NGROK_STATIC_DOMAIN=<yours>.ngrok-free.app
   ```

That's it. `make up` now automatically:

* starts the `ngrok` compose sidecar (profile `public`) tunneling to
  the controller,
* prints the public URL once the stack is healthy,
* and the controller discovers the tunnel origin from the ngrok agent
  API (`TALOS_NGROK_API_URL`, wired in compose) and uses it for every
  externally-reachable URL it formats from then on — refreshed every
  60 s (`TALOS_PUBLIC_URL_REFRESH_SECS`), so even a mid-run tunnel
  restart is picked up.

Without `NGROK_AUTHTOKEN` nothing changes: the profile stays off, the
discovery loop stays silent, and every URL falls back to the previous
`FRONTEND_URL` / `BASE_URL` behavior.

## What updates automatically vs. what needs a step

Run the **`get_public_url_status`** MCP tool any time — it reports the
resolved URL, its source (`explicit` / `ngrok` / `fallback`), and
per-integration guidance with the live URL substituted in. Summary:

| Surface | Automatic? | Notes |
|---|---|---|
| Inbound webhooks (`/webhooks/<id>`) | ✅ | URL formatted at display time; nothing registered provider-side |
| Approval / callback links | ✅ | Links minted after the tunnel is up use the public origin |
| GCP Pub/Sub push subscriptions | ⚠️ manual (P1) | Google stores the push endpoint on the subscription — update it (`gcloud pubsub subscriptions update … --push-endpoint=…`) after a URL change; `get_public_url_status` prints the exact command |
| Google Calendar watch channels | ⚠️ manual (P1) | Google stores the channel address at watch-creation — stop + re-create the watch after a URL change; Google also requires https + non-localhost, so GCal watches only work with a tunnel or public deploy |
| OAuth redirect URIs | ✅ (by design) | Consent flows stay on `FRONTEND_URL` — browser-mediated, so localhost works locally and the provider console allowlist never needs to change |

With a reserved domain, the two ⚠️ rows become one-time setup instead
of per-restart maintenance. (Automatic re-registration on URL change is
the planned follow-up phase.)

## Resolution order

`talos-public-url` resolves the public base with this chain, validated
by the same origin predicate as `FRONTEND_URL` (scheme + host, no
path — the open-redirect-misconfig defense):

1. `TALOS_PUBLIC_BASE_URL` — explicit override (production, or a
   hand-managed tunnel).
2. ngrok discovery — the sidecar's agent API, cached, background-refreshed.
3. The call site's legacy fallback (`FRONTEND_URL` for nginx-proxied
   paths, `BASE_URL` for controller-direct paths).

A tunnel-URL **change** logs a WARN naming what went stale; the first
discovery logs the URL at INFO.

## Security notes

* The tunnel exposes ONLY the controller (`controller:8000`). All its
  public-path handlers carry their own auth (push-token + OIDC JWT for
  Pub/Sub, verification tokens/HMAC for webhooks, hashed tokens for
  approval links) — same posture as a production deploy behind nginx.
* The ngrok inspector UI binds host-only (`127.0.0.1:4040`).
* Plaintext secret-handling rules are unchanged — the tunnel carries
  TLS end-to-end (https terminates at ngrok's edge, agent → local hop
  stays on the compose network).
