# Microsoft 365 connection (2026-10-08)

The OAuth connection that lets a sandboxed module read a person's Outlook mail
and calendar through Microsoft Graph: crate `talos-microsoft-365`, provider
string `microsoft_365`, routes `/api/microsoft-365/{connect,callback}`, table
`microsoft_365_integrations`. Built from `scripts/new-integration.py`, with
`talos-google-health` as the reference (OAuth only, no API client, no push
channel). Setup: `docs/microsoft-365-setup.md`.

## Decided

- **The token refresh body is chosen per provider** — `TokenBody::{Json, Form}`
  in `talos_oauth::credentials::refresh_route`. Microsoft refuses a JSON token
  body (AADSTS900144) with a 400 that is not `invalid_grant`, so with the
  previous JSON-for-everyone refresh a connection would have worked for its
  first access token's hour, then failed every dispatch while the proactive
  sweep logged a 400 and never marked it for reconnect. Microsoft is `Form`;
  every other provider stays `Json`.
- **The refresh match is a pure function** (`refresh_route`), so which endpoint,
  client and encoding each provider gets is unit-tested rather than only
  reachable through a database and a token endpoint.
- **One tenant resolution** — `talos_oauth::microsoft_365_tenant()` and the two
  URL builders. The connect's authorize and code exchange and every refresh use
  the same tenant's endpoints. `MICROSOFT_365_TENANT` empty = `common`; a value
  that is not a tenant id or domain is an error and turns the connect off (503),
  never widened to `common` — an operator who set it meant to restrict.
- **The account key is Graph's `/me.id`** (an object id for a work or school
  account; sixteen hex digits for a personal one). The card's label is
  `userPrincipalName`, then `mail`. A sign-in name can be renamed; the id
  cannot.
- **Refused at the callback, nothing stored**: no refresh token (checked by
  presence, not by `offline_access` in the granted scopes — Microsoft does not
  always list it), and a consent granting neither `Mail.Read` nor
  `Calendars.Read`. Each has its own closed code on the settings page. The
  granted-scope match accepts Microsoft's full resource URIs and its
  lower-casing.
- **No revoke at Microsoft on disconnect** (`revoke_at_provider` names
  `microsoft_365` → `Ok(false)`). There is no per-token revoke endpoint; Graph's
  `revokeSignInSessions` ends every app's sessions for the user. Local cleanup
  proceeds as for Atlassian.
- **`prompt=select_account`** so a second account can be connected from a
  browser signed in to the first.

## Deliberately NOT done

- **Sending mail.** `Mail.Send` would ride on every connection; a separate
  consent tier means a second provider string. Deferred until a customer asks.
- **Flipping Google or Atlassian to a form-encoded refresh.** RFC 6749 says
  form, and both would likely accept it, but neither has a loopback test here
  and both work today.
- **A `scope` parameter on the refresh request.** Microsoft's v2 endpoint
  treats it as optional and issues the originally granted scopes without it.
  To be confirmed live.
- **Mapping `consent_required` / `access_denied` to an `admin_consent_required`
  code.** The callback reflects the sanitized provider code as it does for every
  provider; the setup page documents the admin-consent path.
- **Exchange that is not Exchange Online** (`MailboxNotEnabledForRESTAPI`): out
  of scope, documented.

## Measured / tested

- Unit: endpoints and scopes, the refusals and their codes, the tenant
  validation (path-segment escapes refused, not widened), `refresh_route`
  pinning `Form` for Microsoft and `Json` for every Google, Google Cloud and
  Atlassian provider.
- `controller/tests/microsoft_365_connect_tests.rs` against a template clone
  and a loopback token endpoint and `/me`: tokens under the state's user only,
  cross-browser completion refused, every unusable consent stores nothing,
  reconnect updates the row, disconnect is the owner's, and a predictive refresh
  is form-encoded, stores the ROTATED refresh token, and on `invalid_grant`
  stamps `needs_reauth_at` and stops calling.
- Switching Microsoft's refresh back to `Json` fails both the unit pin and the
  loopback refresh test (checked once; the encoding is a correctness property,
  not a security gate).

## Latent vs live

Nothing is connected anywhere yet; no live tenant has been used. Two things to
check on the first live connect: that the token response's `scope` names the
Graph permissions in a form `reading_scopes_granted` recognises, and that
`/me.userPrincipalName` is populated for the accounts in question.

## Stated limits

- An expired client secret fails every refresh with `invalid_client`, which is
  not marked as needing reconnect; every connection fails until the secret is
  replaced.
- The readers are `outlook-list-messages` (one GET, at most 25 messages) and
  `outlook-calendar-list-events` (calendarView, paged up to 250 events). Their
  recorded runs use 25.9% and 44.1% of the declared fuel; the calendar's
  limit is sized for about 100 events, so a node asking for more sets
  `max_fuel` above the default (its `MAX_RESULTS` description says so). A
  next-page link off `https://graph.microsoft.com/v1.0/` fails the run rather
  than receiving the token.
