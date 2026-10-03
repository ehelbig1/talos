# Connecting a bank through Plaid Link (2026-10-03)

**What existed.** A Plaid client (`talos-plaid`) and a CLI that links a
SANDBOX item from a terminal. Production needs a person to sign in to the bank
in Plaid Link, and Talos had no way to run it.

**What this adds.**
* `talos-plaid` gains `create_link_token` (products: transactions, two years of
  history, `client_user_id` = the Talos user id) and `remove_item`, plus a
  test-only base URL (deliberately not configurable from the environment).
* `talos-plaid-connect`: `PlaidConnectService` and two handlers, mounted at
  `POST /api/plaid/link-token` and `POST /api/plaid/connect` behind session
  auth and the cookie-session CSRF gate.
* Migration `20261003120000`: `plaid_items` (user, item id, institution label,
  environment, active), metadata only.
* Settings: provider registry entry `plaid` ("Bank accounts"), GraphQL
  `IntegrationService::PLAID`, and a disconnect branch that ends a bank
  connection through the Plaid service instead of the OAuth revoke path.
* Web app: `lib/plaidLink.ts` loads Link from Plaid's CDN on first use (Plaid
  forbids bundling it) and the bank card's connect button runs it.
* Production CSP: Link's exact script URL, its iframe, Plaid's API hosts.

**Decisions.**
* The access token is stored for the user at `plaid/access_token/{item_id}`
  and never returned to the browser; the connect reply carries only the bank's
  name and an account count.
* The browser's `public_token` is checked for Plaid's shape before it is sent
  anywhere; institution name and id are display labels, sanitised and bounded.
* Once Plaid has made a connection, every later failure UNDOES it at Plaid
  (`/item/remove`): an unusable connection would still count against the
  plan's 10-Item Trial limit.
* A disconnect reads the token as the user (not the system) and deletes it as
  the user, so naming another user's item id neither reaches Plaid with their
  token nor deletes it.
* `'unsafe-inline'` is NOT added to the production CSP although Plaid's
  guidance lists it.
* Not an OAuth credential: no `integration_credentials` row, so the refresh
  task never sees it.

**Tests.** `controller/tests/plaid_connect_tests` (6) against a loopback
stand-in for Plaid and a real database: the token stored for its owner and
not returned; a malformed token never sent; a refused exchange stores nothing;
an unstorable connection undone at Plaid; a disconnect ends it at Plaid and in
the vault; another user cannot end it. Unit tests for token shape and labels.
Web: four tests for the Link wrapper.

**Mutations (5, all caught).** The undo skipping Plaid; the disconnect reading
the token as the system; any browser token accepted; the disconnect deleting
as an admin; the token not stored.

**Stated limits.**
* No test drives Plaid Link itself or the real Plaid API; the first real
  sign-in is the test.
* Link is untested under the production CSP (the deployment runs the
  development web server, which sets none).
* The reader module (`plaid-read`) still allows only `sandbox.plaid.com`, and
  nothing reads more than one connection yet; the daily sync is the next
  package.
* Mobile browsers: no redirect URI is registered, so OAuth banks rely on the
  pop-up.
