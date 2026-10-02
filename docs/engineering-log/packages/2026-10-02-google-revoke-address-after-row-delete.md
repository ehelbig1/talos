# The Settings disconnect dropped the address the revoke decision needs (2026-10-02)

Follow-up to `2026-10-02-google-disconnect-shared-grant.md`, from its first
live use.

**Seen live.** After #1041 deployed, the operator disconnected a throwaway
account's Calendar connection — the LAST connection on that Google account.
The vault entries were deleted and their audit rows written (which is #1040
working under enforced row security). The revoke was withheld:
`sharing=Shared { same_account: 0, unidentified: 2 }`.

**Cause.** The Settings disconnect is two steps: the registry-driven row
disconnect, then `revoke_and_cleanup`. Calendar's row disconnect is a HARD
delete, so when the revoke decision looked up the connection's address in
`google_calendar_integrations` the row was gone. A connection with no address
cannot be told apart from a Gmail connection, so the user's two Gmail
connections (on other accounts) each counted as possibly the same account.
The #1041 tests stored credentials and called `revoke_and_cleanup` directly;
none took the resolver's two steps, so none removed the row first.

**Harm.** In the withholding direction only: no working connection was
affected. The cost is the stated one made permanent — an account whose last
connection is Calendar never has its grant revoked while the user has any
Gmail connection. (In the live case the grant had already been revoked by the
earlier Health disconnect.)

**Fix.**
* The registry entry names the address column (`account_email_column`):
  Calendar, Cloud and Health `account_email`, Gmail `email_address`, none for
  Slack and Atlassian.
* `disconnect_user_integration` returns it in the SAME statement that removes
  the row (`DisconnectOutcome::account_email`).
* `revoke_and_cleanup_for_account(.., account_email)` uses it only when the
  integration's own row cannot supply one; `revoke_and_cleanup` is that call
  with `None`. The Settings resolver passes the returned address.

**Reach.** Calendar through the Settings page is the only path that
hard-deletes a non-Gmail Google row. Cloud and Health soft-delete (the row is
still readable); Gmail's key is its address; the per-integration disconnect
handlers soft-delete before calling in.

**Tests.** Four added to `google_disconnect_shared_grant_tests`: a removed
row placed by the caller's address (and withheld when that address is a Gmail
connection's); a row that is still there outranking the caller's address; the
Settings disconnect in its two real steps — the live case; a TEXTUAL pin that
the resolver passes `outcome.account_email` (no GraphQL harness drives the
resolver). One registry test.

**Mutations (6 applied, 6 caught).** The row delete not returning the
address; the decision ignoring it; the resolver passing none; the address not
trimmed; the caller's address overriding a present row; Calendar naming no
column.

**Stated limit.** The resolver call is pinned by text, not driven.
