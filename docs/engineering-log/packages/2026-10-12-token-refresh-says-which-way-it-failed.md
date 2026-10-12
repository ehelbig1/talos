# A token refresh says which way it failed (2026-10-12)

A token refresh that failed to connect was reported as refused. The engine's
sentence was made truthful on 2026-10-11 (`2026-10-11-scheduler-resume-settle.md`)
by naming both causes; the result underneath stayed two-valued.

## Found

A connection was ALREADY marked for reconnect only on `invalid_grant`:
`refresh_oauth_token_inner` stamps `needs_reauth_at` in that one branch, and
a transport failure stamps nothing. So "only a real refusal marks a
connection" held. What did not:

* `force_refresh_vault_paths` returned `bool`, so the engine could not say
  which way a refresh produced no new token.
* The reactive refresh's log line called every failure "REFUSED by the
  provider — the grant is most likely revoked or expired".
* The MCP `refresh_oauth_token` tool had one failure sentence listing three
  "common causes", a revoked token among them, whatever had happened.
* `looks_like_oauth_failure` matches the bare word "refresh", so a renewal
  that failed on "Token refresh request failed" set `likely_oauth_failure`
  on a watch channel, and the settings page showed the reconnect banner over
  a working connection.

## Decided

* **`RefreshFailureKind` in `talos-oauth`:** `RefusedByProvider`
  (`invalid_grant`, or a credential already marked), `ProviderUnreachable`
  (no answer, a 5xx, or a 429), `Failed` (everything else). The refresh path
  attaches it to its error at the three places it fails;
  `refresh_failure_kind(&error)` reads it back.
* **An error nothing classified is `Failed`, never a refusal.** A refusal
  tells a person to reconnect.
* **`ForcedRefresh` in `talos-workflow-engine-core`** replaces the trait's
  `bool`: `Refreshed`, `RefusedByProvider`, `ProviderUnreachable`, `Failed`,
  `NothingToRefresh`. Only `Refreshed` authorises the retry, exactly as
  `true` did. Over several credentials, one new one is enough; otherwise the
  outcome that asks most of a person wins.
* **The engine's sentence is the outcome's own** (`operator_note`): a
  refusal says re-authorise; an unreachable provider says the integration
  does NOT need re-authorising and the next run will try again.
* **The MCP tool has three sentences**, one per kind.
* **`looks_like_oauth_failure` excludes the unreachable sentence.** The
  phrase is `talos_oauth::TOKEN_ENDPOINT_UNREACHABLE`; the helpers crate
  keeps a lowercased copy (it does not depend on `talos-oauth`) and a test
  holds the two equal.
* **The transport failure's text changed** from "Token refresh request
  failed" to that sentence.

## Not changed

* What marks a connection: `invalid_grant`, as before.
* Whether the node is retried: only on a new credential, as before.
* The metric's label set (`repaired`, `not_refreshed`, `refresh_failed`).

## Stated limits

* A renewal-failure row stored BEFORE this change holds the old text ("Token
  refresh request failed"), which still matches "refresh", so an old row can
  still show the reconnect banner until its next renewal.
* A 4xx other than `invalid_grant` (a misconfigured client, for example) is
  `Failed`. It is not a refusal of the grant and not an unreachable provider.
* An unreachable provider does not make the node's failure transient: the
  node failed on a rejected credential, and nothing retries it.

## Tests

* `talos-oauth`: a failure is read back as the kind it was raised with,
  through further context; an unclassified error is `Failed`; each kind maps
  to its engine outcome.
* `talos-workflow-engine-core`: only `Refreshed` retries; the aggregation;
  the two sentences an operator acts on do not say each other's thing.
* `talos-workflow-engine` (the real dispatch path with a scripted resolver):
  an unreachable token endpoint fails the node once, names the cause, says
  NOT to re-authorise and does not say "refused"; every outcome without a
  new credential fails once with its own sentence; a refusal still says
  re-authorise.
* `talos-mcp-handlers`: only a refusal tells the caller to re-authorise; the
  reply is fixed text.
* `talos-integration-helpers`: a refresh that could not reach the provider
  is not an OAuth failure; a refusal still is; the copied phrase equals
  `talos-oauth`'s.

* `controller/tests/microsoft_365_connect_tests.rs`, against the fake token
  endpoint on a migrated clone: `invalid_grant` is `RefusedByProvider` and
  marks the connection; the later refusal made without a round trip is one
  too; a 503 and a 429 are `ProviderUnreachable`, a 400 `invalid_client` is
  `Failed`, and none of the three marks the connection; the batch the engine
  calls reports the same outcome.

**Mutation:** a 5xx classified as a refusal is caught by
`a_token_endpoint_that_does_not_answer_is_not_a_refusal_and_marks_nothing`.

**Not tested:** a token endpoint that refuses the CONNECTION (no HTTP answer
at all). That branch maps a transport error to `ProviderUnreachable` and is
covered only by the unit test that builds the same error shape.
