# Microsoft 365 connection (Outlook mail and calendar)

Lets a workflow read the owner's Outlook mailbox and calendar through
[Microsoft Graph](https://learn.microsoft.com/graph/overview). Read-only:
sending mail is not asked for.

## What it is made of

| Piece | Where | What it does |
|---|---|---|
| The connection | `talos-microsoft-365`, `/api/microsoft-365/connect` and `/callback`, the **Microsoft 365** card on the integrations page | Obtains and refreshes the OAuth token. Holds no API client. |
| The reader | a sandboxed module with `allowed_hosts: ["graph.microsoft.com"]` and `allowed_methods: ["GET"]` | Calls Graph with a `vault://` token reference. There is no catalog template for it yet. |

The module never holds the token: the worker resolves the `vault://` reference
at the outbound call.

## Operator setup

In the [Microsoft Entra admin center](https://entra.microsoft.com), under
**Applications → App registrations → New registration**:

1. **Supported account types**: match `MICROSOFT_365_TENANT`. For `common`
   (the default), choose "Accounts in any organizational directory and
   personal Microsoft accounts". For one firm, choose "this organizational
   directory only" and set `MICROSOFT_365_TENANT` to its tenant id or a
   verified domain (`contoso.onmicrosoft.com`).
2. **Redirect URI**: platform **Web**, the value of
   `MICROSOFT_365_REDIRECT_URI`. The development default is
   `http://localhost:8000/api/microsoft-365/callback`; the chart derives
   `https://<ingress host>/api/microsoft-365/callback`.
3. **Certificates & secrets → New client secret**. Copy the value (not the
   secret id) into `MICROSOFT_365_CLIENT_SECRET`, and the registration's
   **Application (client) ID** into `MICROSOFT_365_CLIENT_ID`. A client secret
   expires (at most 24 months); see *Behaviour worth knowing*.
4. **API permissions → Add a permission → Microsoft Graph → Delegated**:
   `User.Read`, `Mail.Read`, `Calendars.Read` and `offline_access`. Nothing
   else is asked for.

With the client id and secret unset the card is shown as not configured and
`/api/microsoft-365/connect` answers 503. So does a `MICROSOFT_365_TENANT` that
names no tenant: it is refused, not widened to `common`.

Then connect from the integrations page. A module reads with
`AUTH_HEADER` = `Bearer vault://oauth/microsoft_365/{user_id}/{provider_key}/access_token`,
where `provider_key` is the account's Graph object id (`list_connections`
gives the whole reference).

### Admin consent

Many organisations stop users consenting to `Mail.Read` for a new app. The
consent screen then asks for an administrator, or the redirect comes back with
`microsoft_365_error=consent_required` or `access_denied`. An administrator of
that tenant grants it once for everyone: **Enterprise applications** → the app
→ **Permissions → Grant admin consent for \<tenant\>**. The URL form, for an
administrator who has not seen the app yet, is
`https://login.microsoftonline.com/<tenant>/adminconsent?client_id=<MICROSOFT_365_CLIENT_ID>`.

## What is stored

- `microsoft_365_integrations`: one row per connected account — the account's
  sign-in name (a label; its mail address when it has no sign-in name), the
  granted scopes, the expiry. No token.
- The access and refresh tokens, encrypted, at
  `oauth/microsoft_365/{user_id}/{provider_key}/…`. A module granted another
  provider's `oauth/<provider>/*` cannot name them.
- Nothing from Graph is stored by the connection. What a workflow does with the
  reader's output is the workflow's own design; a module's output is kept,
  encrypted, with its execution.

## Behaviour worth knowing

- A consent that returns no refresh token is refused at the callback
  (`microsoft_365_error=no_refresh_token`) and stores nothing. So is one that
  granted neither `Mail.Read` nor `Calendars.Read`
  (`microsoft_365_error=no_mail_or_calendar_scope`), which happens when an
  administrator consented to fewer permissions than the app asks for. One of
  the two is enough to connect.
- Reconnecting the same account updates its card rather than adding one. The
  account picker is always shown, so a second account can be connected.
- Tokens are refreshed before they expire, against the same tenant's token
  endpoint the connect used. Microsoft issues a new refresh token on every
  refresh and the old one stops working; the new one is what is stored.
- When Microsoft refuses a refresh with `invalid_grant` (the user revoked the
  app, an administrator removed it, a password reset, or 90 days unused), the
  connection is marked as needing to be reconnected and is not retried until
  it is.
- **An expired client secret** fails every refresh with `invalid_client`, which
  is not a revoked grant: the connections are not marked, and every workflow
  using them fails until `MICROSOFT_365_CLIENT_SECRET` is replaced. Put the
  secret's expiry in the calendar when you create it.
- **Disconnecting does not revoke at Microsoft.** Microsoft has no endpoint
  that revokes one app's refresh token (the one that exists ends every app's
  sign-in sessions for the user). Disconnecting deletes this connection's
  tokens here; to remove the app's access at Microsoft, the user removes it at
  [myapplications.microsoft.com](https://myapplications.microsoft.com) (work or
  school) or [account.live.com/consent/Manage](https://account.live.com/consent/Manage)
  (personal). An unused refresh token lapses after 90 days anyway.
- **A mailbox that is not in Exchange Online** (on-premises Exchange, or a
  hosted Exchange outside Microsoft 365) connects — `User.Read` works — but
  every mail and calendar read is refused by Graph with
  `MailboxNotEnabledForRESTAPI`. That is out of scope; a reader sees Graph's
  error, not an empty mailbox.

## Privacy posture

Bind the workflow that reads mail to an actor with `max_llm_tier = tier1` and
`egress_scope = public`: the reader reaches `graph.microsoft.com`, and no
external model provider can be reached from that actor.
