# 2026-10-11 — Google Calendar (add events): a write connection of its own

**Why.** The owner's weekly plan proposes blocks of time worth protecting and
his phone notification carries a button for each. The button could only open
the calendar with the event filled in, because the Google Calendar connection
is read-only. Holding the time in one tap needs a token that can add an event.

**Decided.**
- **A second connection, not a wider first one.** New crate
  `talos-google-calendar-write`, provider string `google_calendar_write`, its
  own table and vault namespace. Widening `talos-google-calendar`'s scopes was
  one line, and would have put a write-capable token behind every grant on
  `oauth/google_calendar/…` — every calendar reader installed today.
- **`calendar.events.owned`, alone.** The narrowest scope that can add an
  event to the owner's own calendar. Not `calendar.events` (shared calendars
  too), not `calendar`. A consent that returns any other calendar scope in its
  place — a read scope, or a broader write scope — is refused
  (`ConnectRefusal::NoWriteScope`, shown as `no_calendar_scope`): the check is
  equality with the one scope asked for, not "some calendar scope".
- **The crate is `talos-google-health`'s shape**, started from
  `scripts/new-integration.py` and then filled from the health crate (shared
  Google client, the shared account-key derivation, `account_email`, row
  before tokens with the compensating hide).
- **Refresh, revoke and the shared grant.** The provider is in
  `GOOGLE_SHARED_CLIENT_PROVIDERS` and `GOOGLE_REVOKE_PROVIDERS`, and
  `active_google_connections` reads its account address from its own table.
  Without that arm the connection's address is unknown, and an unplaceable
  connection withholds the revoke of every Gmail disconnect.
- **Listing and disconnecting are the generic paths** (a `PROVIDERS` entry,
  soft delete). No REST list or delete handler.
- **The table is granted to `talos_admin_read`** in its own migration: it
  holds which account is connected and no token, like its read sibling.

**Deliberately NOT done.**
- **No calendar-write module in the catalog and no API client in the
  controller.** The event is added by the owner's own sandboxed module with a
  `vault://` reference, POST-only. A catalog template waits for a second user
  of it.
- **`calendar.app.created` was considered and declined.** It is narrower still
  (only calendars the app itself created), but a held block would then sit on
  a separate secondary calendar that the weekly plan's reader does not read,
  so the plan would keep proposing a time already held.
- **A tier column on `google_calendar_integrations`** (the Google Cloud
  shape, one callback route for both). That crate is 7,000 lines of watch
  channels and webhooks that a write token has no part in; a separate small
  crate keeps the write connection readable in one sitting. The cost is one
  more redirect URI to register on the OAuth client.
- **The worker does not narrow the scope.** `calendar.events.owned` permits
  changing and deleting an owned event. A module using the token is held to
  adding by `allowed_methods: ["POST"]`, which is the module owner's
  declaration, not something this crate enforces. Stated in the setup page.

**Checked that it holds.** No connect in the workspace sends
`include_granted_scopes` (grep, 0 hits), so reconnecting the read connection
does not return a token carrying this scope.

**Tests.**
- `controller/tests/google_calendar_write_connect_tests` (4): tokens under the
  state-bound user at the `google_calendar_write` path; a URL minted in one
  browser cannot be completed in another; seven unusable consents store no row
  and no credential (no refresh token, scope unticked, a read scope, a broader
  scope, a refused exchange, no account id, a blank one); reconnect updates
  the row; the generic disconnect is the owner's only.
- `google_disconnect_shared_grant_tests::the_calendar_write_connection_shares_its_accounts_grant`:
  beside the read connection it revokes nothing and deletes only its own
  tokens; on Gmail's address it withholds; on a different account from Gmail
  neither withholds the other.
- Mutations, each applied and reverted: the scope check accepting any grant
  (caught by the connect test); the address arm removed from
  `active_google_connections` (caught — first draft of the test did NOT catch
  it: with no address the connection falls to "cannot be placed", which also
  withholds, so the Gmail-on-the-same-address case passed either way; the
  different-account case was added for it); the provider removed from
  `GOOGLE_REVOKE_PROVIDERS` (caught).

**Not verified, stated.** Nothing has been driven against Google: the scope
and the redirect URI must be added to the OAuth client by the operator first.
A real refresh or revoke of a `google_calendar_write` token is not driven by a
test (the lists are pinned by unit tests). The compensating hide after a failed
token store is not driven by a test, as in the health crate it was copied from.

**One home.** `talos_google_calendar_write::WRITE_SCOPE` for the scope;
`docs/google-calendar-write-setup.md` for the operator steps. `CLAUDE.md`
carries the rule (a calendar write uses this connection; the read
connection's scopes are not widened).
