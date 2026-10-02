# Google Health connection (Pixel Watch / Fitbit readings)

Lets a workflow read the owner's sleep, step count and resting heart rate from
the [Google Health API](https://developers.google.com/health/about). Read-only.

## What it is made of

| Piece | Where | What it does |
|---|---|---|
| The connection | `talos-google-health`, `/api/google-health/connect` and `/callback`, the **Google Health** card on the integrations page | Obtains, refreshes and revokes the OAuth token. Holds no API client. |
| The reader | catalog template `google-health-daily` | A sandboxed module that makes three GET requests with a `vault://` token reference. |

The module never holds the token: the worker resolves the `vault://` reference
at the outbound call.

## Operator setup

In the Google Cloud console, for the project that owns the OAuth client in
`GOOGLE_CLIENT_ID` (the same client Google Calendar uses):

1. Enable the **Google Health API** (`health.googleapis.com`).
2. On the OAuth consent screen, add the scopes
   `…/auth/googlehealth.sleep.readonly`,
   `…/auth/googlehealth.activity_and_fitness.readonly` and
   `…/auth/googlehealth.health_metrics_and_measurements.readonly`.
3. On the OAuth client, add the redirect URI
   (`GOOGLE_HEALTH_REDIRECT_URI`; the development default is
   `http://localhost:8000/api/google-health/callback`, and the chart derives
   `https://<ingress host>/api/google-health/callback`).

Then connect from the integrations page, install `google-health-daily` from the
catalog, and set its `AUTH_HEADER` to
`Bearer vault://oauth/google_health/{user_id}/{provider_key}/access_token` and
its `TIME_ZONE` to an IANA zone.

Google classes these scopes as restricted. An OAuth app in **Testing** status
issues refresh tokens that expire after seven days; one in production status
does not, but shows an unverified-app warning until Google has reviewed it.

## What is stored

- `google_health_integrations`: one row per connected account — the account
  address (a label), the granted scopes, the expiry. No token.
- The access and refresh tokens, encrypted, at
  `oauth/google_health/{user_id}/{provider_key}/…`. A module granted
  `oauth/google_calendar/*` or `oauth/gmail/*` cannot name them.
- Nothing from the Health API is stored by the connection. What a workflow does
  with the reader's output is the workflow's own design; a module's output is
  kept, encrypted, with its execution.

## Behaviour worth knowing

- A consent completed with every health scope unticked is refused at the
  callback (`google_health_error=no_health_scope`) and stores nothing.
- A consent that returns no refresh token is refused and stores nothing.
- Disconnecting deletes this connection's tokens from the vault. **It revokes
  at Google only when it is the last connection on that Google account.** A
  Google revoke ends the account's whole grant to the OAuth client — tested
  live on 2026-10-02: disconnecting Health on an account returned 401 on that
  account's Calendar token two minutes later, and the next refresh was refused
  with `invalid_grant`. So while Gmail, Calendar or Cloud is still connected on
  the same Google account, the Health permissions stay granted at Google (with
  no token stored here) until the last of them is disconnected. To remove them
  sooner, use the Google account's third-party access page — that ends every
  connection on the account.
- The reader reports `nothing_recorded: true` when the API answered every
  reading with no data (the device was not worn, or has not synced), and lists
  under `unavailable` any reading the API refused. Those are different
  statements and are kept apart.

## Privacy posture

Bind the workflow that reads health data to an actor with
`max_llm_tier = tier1` and `egress_scope = public`: the reader reaches
`health.googleapis.com`, and no external model provider can be reached from
that actor. The reader itself calls no model.
