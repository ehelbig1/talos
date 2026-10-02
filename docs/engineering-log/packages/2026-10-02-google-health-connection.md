# 2026-10-02 — Google Health connection and a daily-readings reader

**Why.** The owner's Pixel Watch records sleep, steps and heart rate; nothing in
Talos could read them. The Fitbit Web API was turned down in September 2026, so
the Google Health API is the only cloud route.

**Shape, decided by what already exists.** OAuth only. The connection is a new
crate, `talos-google-health`, that obtains, refreshes and revokes a token; the
reading is done by a sandboxed catalog module (`google-health-daily`) holding a
`vault://oauth/google_health/…` reference. No API client runs in the
controller, and the token is never in a guest's address space.

**Decisions.**
- **Its own provider string, `google_health`**, on the SHARED Google client.
  Distinct vault namespace: a module granted `oauth/google_calendar/*` or
  `oauth/gmail/*` cannot name a health token. Same model as the Google Cloud
  consent tiers.
- **Read scopes only, and three of them**: sleep, activity-and-fitness,
  health-metrics. Not `profile`, `location`, `nutrition` or any write scope.
- **`talos_oauth::shared_google_client()` is the one resolution** of
  `GOOGLE_CLIENT_ID`/`_SECRET` (each falling back to its `GMAIL_*` spelling),
  used by the token REFRESH and by this crate's AUTHORIZE step. A token issued
  by one client cannot be refreshed by another, and the two had no shared home.
- **The refresh match is keyed on a list** (`GOOGLE_SHARED_CLIENT_PROVIDERS`),
  not on literals, and a test holds every member to `GOOGLE_REVOKE_PROVIDERS`.
  A provider left out of refresh expires an hour after a connect that looked
  fine; left out of revoke, a disconnect leaves a live grant on health data.
- **A consent that cannot be used stores nothing**: no refresh token, every
  health scope unticked (`ConnectRefusal::NoHealthScope`, shown to the page as
  `no_health_scope`), a refused exchange, an account answer with no id.
- **The row is written before the tokens, and hidden again if the tokens
  cannot be stored.** The first draft stored the tokens first; review pointed
  out that a failure then leaves a token that is refreshed every hour with no
  card to disconnect it from. A row with no token behind it needs both the
  store and the compensating hide to fail, and shows itself at the first read.
- **Listing and disconnecting are the generic paths** (`PROVIDERS` entry,
  soft delete, `provider_key` returned for the revoke). No REST list/delete
  handlers were added.
- **The reader is GET-only** (`allowed_methods: ["GET"]`). The API's
  `dailyRollUp` would total a day's steps in one small answer but is a POST;
  the reader sums the day's intervals from `list` instead, bounded at three
  pages, so it needs no verb-ceiling override and the least grant.
- **Three independent readings.** One the API refused is named under
  `unavailable` and the others are returned; one with no data is `null`. A 401
  is an error for the whole run.
- **`nothing_recorded` is true only when all three readings were answered and
  every answer was empty.** The first draft derived it from "no reading has
  data", so two refused readings plus one empty one reported a watch that was
  not worn. With any reading unavailable, what was recorded is not known.
- **A step page that cannot be read makes the reading unavailable.** The first
  draft summed the pages that did arrive and presented the sum as the day's
  total.
- **No RLS policy on `google_health_integrations`**, as
  `google_cloud_integrations`: every reader names the user on the service pool
  and no tenant-scoped connection touches it. No `idx_…_user_id` (the unique
  key already serves it; the index-hygiene test refuses the duplicate).
- **`GOOGLE_HEALTH_REDIRECT_URI`** defaults to the development URL and is
  derived from the ingress host in the chart, like its siblings.

**Tests.**
- `controller/tests/google_health_connect_tests` (CTRL): the real service
  against a real database and a loopback stand-in for Google's token and
  userinfo endpoints. Tokens land under the state-bound user at the
  `google_health` vault path and nobody else's list shows them; a URL minted in
  one browser cannot be completed in another (the code is not even exchanged);
  five unusable consents store no row and no credential; a reconnect updates
  the row; the generic disconnect is the owner's only.
- Mutation run on that binary, 8 applied: tokens under another user, row under
  another user, missing refresh token accepted, no-health-scope accepted, a
  reconnect that does not restore the row, a disconnected row still listed,
  another provider's vault path — caught. **One survived first**: accepting an
  account answer with a blank id passed, because the only such case in the test
  had NO id field and failed at deserialization before the check. A blank-id
  case was added and the mutation is caught.
- `talos-google-health` unit tests (6), the registry entry test, the
  refresh/revoke list test, the reader's own tests (5, run natively), and the
  catalog's manifest checks.

**Found in review, NOT fixed here: Google's revoke is not per token.**
`oauth2.googleapis.com/revoke` removes every scope the account has granted to
the OAuth PROJECT and invalidates the tokens of every client in it (Google's
own documentation). Every Google integration here revokes on disconnect, and
they share one project, so disconnecting any one of them ends all of that
account's Google connections — Calendar's disconnect ends Gmail's today. This
package adds a third connection that can do it, and for that reason does NOT
revoke the grant when a consent is refused after the exchange (the tokens are
dropped unstored). The fix — revoke at Google only when it is the account's
last Google connection, and say so otherwise — changes what "disconnect" means
for the existing integrations and ships as its own change.

**Review.** An independent read of the staged diff confirmed the flow
(state-bound user, binding cookie set and presented, consume before exchange,
closed set of redirect codes, nothing sensitive logged), the refresh and
revoke reachability, the route stacks and the migration, and produced the
three corrections above plus: an offset from the API is bounded before it is
added to a timestamp (an absurd one panicked chrono); the reader's step-page
fake now keys pages by the token the request carries (it handed out pages in
call order, so a reader that dropped the token still passed); the "stores
nothing" tests now look at the vault as well as the two tables.

**Not verified, stated.** The reader's tests are run natively by hand: no CI
job compiles a catalog template's own `#[cfg(test)]` module (the catalog check
is a component build). The compensating hide after a failed token store, and a
real refresh or revoke of a `google_health` token, are not driven by a test. Nothing has been driven against the real Google
Health API: the API must be enabled and the scopes added to the consent screen
by the operator first. The reader's request filters and field names come from
the published reference; its parsing is tolerant (every field optional, int64
accepted as string or number) for that reason. Whether an OAuth app that is not
in Testing status is granted these restricted scopes without Google's review is
unconfirmed until a consent is attempted. The connect and callback HANDLERS are
not driven by a test (the service they call is); their layer stacks are copies
of Slack's.

**Operator steps.** `docs/google-health-setup.md`.
