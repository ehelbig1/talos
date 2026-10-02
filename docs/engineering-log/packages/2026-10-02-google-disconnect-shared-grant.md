# A Google disconnect revokes only for the account's last connection (2026-10-02)

**The question.** Every Google integration (Gmail, Calendar, Cloud's three
tiers, Health) uses one OAuth client and revoked its own refresh token on
disconnect. Whether that revoke ends only the one connection was not
documented in any passage that could be fetched, so it was tested.

**The test, on a throwaway Google account.** Calendar and Health were
connected, each verified with a read-only call on its own token. Health was
disconnected at 20:02:34 UTC (`OAuth token revoked at provider`).
* 20:02:5x — a Calendar call on that account's still-unexpired access token:
  **401**.
* 20:51:03 — the background refresh of that Calendar token: refused,
  **`invalid_grant`** (`oauth_grant_revoked`, `needs_reauth_at` set).
* Control: the operator's real connections on other accounts answered
  read-only calls throughout and refreshed in that same 20:51 pass.

So a revoke ends the account's WHOLE grant to the client — access and refresh
tokens of every connection on that Google account. On the reference
deployment one account carries six connections, including the Gmail connection
behind about half of all executions.

**The rule.** `OAuthCredentialService::revoke_and_cleanup` revokes at Google
only when no other active connection of the user is, or may be, on the same
Google account. Otherwise the revoke is WITHHELD: the tokens are deleted from
the vault, the credential row is retired, and the grant stays at Google until
the account's last connection is disconnected, which revokes it all.

**"Same account" (`talos_oauth::google_grant`, pure).**
* Equal connection keys are one account. Calendar, Cloud and Health key a
  connection by the same UUID derived from the Google account id (three copies
  of one derivation; Health and Cloud are pinned equal by a test, Calendar's is
  inline).
* Equal addresses are one account. Gmail's key is its address; the others
  record `account_email` in their own table. This also guards a derivation
  that drifts.
* Two non-Gmail connections with different keys are different accounts.
* A Gmail connection against one with no recorded address cannot be placed and
  counts as POSSIBLY shared: the revoke is withheld.
* A sibling lookup that fails withholds.

**Why withholding is the safe direction.** A withheld revoke leaves a grant
that nothing here holds a token for (the vault entries are deleted — which is
why the vault-delete fix of the same day had to come first). A wrong revoke
takes working connections down, and is noticed only at the next refresh.

**Stated costs and limits.**
* A disconnected connection's scopes stay granted at Google while a sibling
  remains. The owner can remove the grant in the Google account's third-party
  access page; that ends every connection on the account.
* If the last connection on an account is one that was withheld-against for
  being unplaceable, a grant can be left at Google with no connection here and
  no token to revoke it with.
* The Settings page does not yet say that a revoke was withheld. The record is
  a `talos_oauth_revoke` log line, `event_kind = "google_revoke_withheld"`,
  with `reason` `grant_shared` or `siblings_unreadable`.
* `active_google_connections` names three integration tables in one statement
  inside `talos-oauth`. A new Google integration with its own table is not in
  it until added; its connections are still related to non-Gmail ones by key.
* A refused Health connect still leaves its new grant at Google unrevoked.

**Not changed.** Slack and Atlassian disconnects; the refresh path; which
token is revoked (the refresh token, falling back to the access token).

**Tests.** `controller/tests/google_disconnect_shared_grant_tests` (6) drives
the real `revoke_and_cleanup` against a loopback stand-in for Google's revoke
endpoint, with row security enforced: the live case (Health withheld, then
Calendar revokes as the last); Gmail related by address; different accounts
each revoked (the control); an unplaceable connection withholds; another
user's and retired connections do not count; the key derivations agree. Seven
unit tests cover the classifier.

**Mutations (9 applied, 9 caught).** Never withhold; always withhold; siblings
read across users; retired connections counted; an unplaceable connection
assumed elsewhere; equal addresses not one account; equal keys not one
account; a withheld revoke skipping the vault cleanup; the access token sent
instead of the refresh token.
