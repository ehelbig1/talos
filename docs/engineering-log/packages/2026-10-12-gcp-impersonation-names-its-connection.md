# A GCP impersonated token is minted from one named connection

2026-10-12.

## The defect

`gcp/impersonated/<sa>/access_token` is resolved at dispatch by minting a
ten-minute service-account token from the requesting user's broad Google
Cloud consent (`google_cloud_full`). The consent was found with

    ORDER BY updated_at DESC LIMIT 1

and a comment said a user holds at most one such row. The table's key is
`(user_id, provider_key, tier)`: one per Google ACCOUNT. A user who connects a
second account for impersonation has two, and the mint then used whichever
was updated last. A token refresh updates the row, so the answer moved
between dispatches. A workflow written for one account could run on the
other's consent: a token minted from the wrong account acts as the wrong
person, in another organisation's project.

## Latent or live

Latent on the reference fleet: one user, one full-tier connection (measured
with `list_connections`, 2026-10-12). It becomes live the moment a second
account is connected, which is what prompted the change.

## Decided

- **The path may name the connection:**
  `gcp/impersonated/<sa>/as/<connection key>/access_token`. The key is the
  connection's `provider_key`, a UUID written the canonical way; any other
  spelling is not a mint path, because a path is granted and compared as
  text and two spellings of one key would be two paths for one credential.
- **The mint never chooses.** `choose_consent(active, named)`: a named key
  is used only if it is in the user's own active full-tier list; unnamed is
  used only when the list has exactly one; several and none named mints
  nothing; a name outside the list mints nothing and never falls back to
  "the only one".
- **One consent, no name: unchanged.** The single-account user's existing
  paths resolve exactly as before.
- **The list is ordered by key, not by time**, so nothing "latest" exists to
  be picked by a later edit.
- **The cache key includes the connection**, so a token minted from one
  account is not served to a request naming another.
- **`list_connections` shows the reference** (`mint_reference`) on each
  impersonation connection, with the key filled in.

## One home

- The path's two forms: `talos_workflow_job_protocol::parse_gcp_impersonated_path`
  and `gcp_impersonated_path`. The resolver's private parser is gone.
- The choice: `talos_google_cloud::impersonation::choose_consent`, fed by
  `active_full_tier_connections` (filtered on the requesting user's id).

## Deliberately NOT done

- **A binding table from service account to connection.** It would let the
  short path keep working with two accounts, at the cost of a second place
  where "which account" is recorded and a migration. The path is already
  per-node configuration; the choice belongs beside the service account it
  is made for.
- **Trying each consent until one works.** It would send a personal
  account's token to Google against another organisation's service account
  on every miss.
- **Evicting cached tokens on disconnect.** Unchanged from before: a token
  minted before a disconnect lives out its ten minutes.
- **Rejecting a second full-tier connection.** Two accounts are a legitimate
  setup (a personal sandbox and an employer's projects).

## Proved

- Unit: `choose_consent_tests`, `gcp_impersonated_path_tests`.
- Rows: `controller/tests/gcp_impersonation_consent_tests.rs` — the list is
  the user's own, active, full tier only, and does not move when a row is
  touched.
- Ten mutations (the choice, the cache key, each predicate of the query, the
  ordering, the parser's canonical-key and `as` checks), each failed by a
  test.

## Stated limits

- The mint call itself (a request to Google) is not driven by a test here.
- A workflow that used the short path stops receiving a token when its owner
  connects a second account, until the path names one. It fails closed, with
  a log line that says what to write; nothing tells the owner at connect
  time.
