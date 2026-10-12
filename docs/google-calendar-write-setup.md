# Google Calendar (add events) connection

Lets a workflow add an event to a calendar the owner owns: a block of time
held from a button on a notification, for example.

It is a second connection to Google Calendar, beside the read-only one, and
the two are kept apart on purpose. The read connection is granted to every
module that reads a calendar; this one carries the only write scope and its
tokens live in their own vault namespace. Adding a write did not turn every
calendar reader into a calendar writer.

## What it is made of

| Piece | Where | What it does |
|---|---|---|
| The connection | `talos-google-calendar-write`, `/api/google-calendar-write/connect` and `/callback`, the **Google Calendar (add events)** card on the integrations page | Obtains, refreshes and revokes the OAuth token. Holds no API client. |
| The writer | a sandboxed module of your own | Makes one `POST …/calendars/primary/events` with a `vault://` token reference. |

The module never holds the token: the worker resolves the `vault://` reference
at the outbound call.

## What the connection can do

One scope: `https://www.googleapis.com/auth/calendar.events.owned` — events on
calendars the account **owns**. Not `calendar.events` (every calendar the
account can see, shared ones included), and not `calendar` (sharing and
deleting calendars).

That scope still permits changing and deleting an owned event. Narrow it
further in the module that uses it:

- `allowed_methods: ["POST"]` — the worker refuses `PATCH`, `PUT` and
  `DELETE`, so the module can add an event and cannot change or remove one;
- `allowed_hosts: ["www.googleapis.com"]`;
- `allowed_secrets`: the EXACT token path, not a prefix.

Grant the token path to that one module and to no reader.

## Operator setup

In the Google Cloud console, for the project that owns the OAuth client in
`GOOGLE_CLIENT_ID` (the same client the read-only Google Calendar connection
uses):

1. The **Google Calendar API** is already enabled if the read connection works.
2. On the OAuth consent screen, add the scope `…/auth/calendar.events.owned`.
3. On the OAuth client, add the redirect URI
   (`GOOGLE_CALENDAR_WRITE_REDIRECT_URI`; the development default is
   `http://localhost:8000/api/google-calendar-write/callback`, and the chart
   derives `https://<ingress host>/api/google-calendar-write/callback`).

Then connect from the integrations page. `list_connections` shows the
connection and the token path to grant:
`oauth/google_calendar_write/{user_id}/{provider_key}/access_token`.

Google classes this scope as sensitive. An OAuth app in **Testing** status
issues refresh tokens that expire after seven days; one in production status
does not, but shows an unverified-app warning until Google has reviewed it.

## What is stored

- `google_calendar_write_integrations`: one row per connected account — the
  account address (a label), the granted scopes, the expiry. No token.
- The access and refresh tokens, encrypted, at
  `oauth/google_calendar_write/{user_id}/{provider_key}/…`. A module granted
  `oauth/google_calendar/*` (the read connection) cannot name them.

## Behaviour worth knowing

- A consent completed with the calendar scope unticked, or one that names a
  different calendar scope, is refused at the callback
  (`google_calendar_write_error=no_calendar_scope`) and stores nothing.
- A consent that returns no refresh token is refused and stores nothing.
- Disconnecting deletes this connection's tokens from the vault. **It revokes
  at Google only when it is the last connection on that Google account**
  (`docs/google-health-setup.md` has the reason: a Google revoke ends the
  account's whole grant to the OAuth client). While the read connection or
  Gmail is still connected on the same account, the write permission stays
  granted at Google, with no token for it stored here, until the last of them
  is disconnected. To remove it sooner, use the Google account's third-party
  access page — that ends every connection on the account.
- Connecting or reconnecting the READ connection does not pick up this scope:
  no connect here asks Google to include previously granted scopes, so each
  token carries only what its own consent asked for.
