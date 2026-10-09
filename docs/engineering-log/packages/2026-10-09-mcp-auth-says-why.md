# `/mcp` says why it refused a credential (2026-10-09)

The operator's MCP client (Claude, through `npx mcp-remote`) could not connect.
Its log showed only "Dynamic Client Registration rejected (HTTP 404)". The
cause was a Talos API key (`talos_sk_…`) sent where an MCP agent token
(`talos_mcp_…`) belongs. Talos answered `initialize` with a bare 401, and
`mcp-remote` treats any 401 as "start an OAuth sign-in", which Talos does not
offer. Neither side said what was wrong:
* the client log showed an OAuth registration 404;
* the reply had no body;
* the controller logged the refusal as `unknown_token`, which is the right
  reason, but nothing in it said "API key".

A second stale proxy process with the old credential produced the same error
after the fix on the client side; this change makes that diagnosable too.

## Decided

* **The caller is told what was wrong with its own request.**
  * Every 401 carries a JSON-RPC error body (`error.code` -32001,
    `error.data.reason`) and an RFC 6750 `WWW-Authenticate: Bearer
    realm="talos-mcp"` challenge.
  * The reasons are `missing_credentials`, `malformed_authorization` (a header
    that is not `Bearer <token>`, or `Bearer` with nothing after it) and
    `api_key_not_agent_token`.
  * These depend only on the request's own contents, so they are no oracle.
* **The token outcomes stay one reply**, as decision AX (2026-09-13) requires.
  An unknown token, an invalid one, and a token that matched a row with a
  malformed stored hash (previously a separate bare 401) all get the same
  `invalid_token` reply, byte for byte: same status, headers and body. Tested
  in the unit tests and end to end.
* **An API key is refused by its prefix, before any lookup.**
  `talos_api_keys::API_KEY_PREFIX` (`talos_sk_`) is now the one constant;
  `talos-api-keys` uses it to mint and validate keys too. Agent tokens are
  minted in one place as `talos_mcp_<64 hex>`
  (`talos-api/src/schema/actors/mutations.rs:101`), so no agent token can carry
  the prefix.
* **The `Bearer` scheme is matched case-insensitively** (RFC 9110 §11.1), and
  the token is trimmed. A malformed header still falls back to `?token=`, as
  before.
* **Logging.** A request with no credential at all moves from DEBUG to INFO.
  AX chose DEBUG because a probe carries nothing to guess with; it also hid a
  client that sent nothing, and INFO keeps probes below WARN. A malformed
  header or an API key is WARN under `talos_audit` (`event_kind =
  "mcp_auth_refused"`, `reason = "missing_token"`, `detail = <reason>`):
  somebody is trying to authenticate and getting the credential wrong.
* **The metric label set is unchanged.** All three cases count as
  `missing_token`, so no new series needs pre-seeding.
* **`docs/security/operational-runbook.md` §3.4** says how to read a client's
  "registration rejected" error, and where the reason is.

## Tests

* **Unit tests (`talos-mcp-handlers` `mcp_auth_refusal_tests`):**
  * no credential is refused before any database read and named, with its
    challenge;
  * four malformed headers are named, and a malformed header beside
    `?token=` still reaches the lookup;
  * header parsing: case, whitespace, tab, `Basic`, no scheme, `Bearertoken`,
    a bare `Bearer`, non-text;
  * an API key in the header or the query is refused before any lookup and
    not echoed;
  * the three token outcomes are byte-identical to the caller;
  * the outcome and reply table.
* **`controller/tests/mcp_auth_metrics_tests.rs`**, through the production
  middleware against real `mcp_agents` rows: each reason; a guessed token and
  a corrupted row's token getting the same reply, byte for byte; `bearer`
  (lower case) admitting a valid token. The existing outcome-delta test
  passes. The two tests share process-global counters, so they now take
  turns (a mutex); found when they first ran in parallel. Green three runs
  in a row.

**Mutations.** All seven caught; every file's SHA-256 was equal after
restore.

| mutation | caught by |
|---|---|
| an invalid token gets its own reply (an existence oracle) | the indistinguishable-replies test |
| a malformed stored hash keeps its bare 401 | the same test and the table test |
| the API-key check removed | the API-key test |
| the scheme matched case-sensitively | the header-parsing test |
| a malformed header no longer falls back to `?token=` | the malformed-header test |
| an empty `Bearer` looked up as a token | the header-parsing and malformed-header tests |
| absent credentials reported as malformed | the missing-token test |

## Run

In a cloud session (Linux), not on the operator's deployment.

* `cargo clippy --workspace --all-targets -- -D warnings`: clean.
* `make lint`: passes (helm legs included; not run: 7, 36, 72).
* `make test-unit`: 7544 run, 7544 passed, 2 skipped.
* `controller --test mcp_auth_metrics_tests` (migrated template, via
  `scripts/dev-test-db.sh`): 2 passed, three runs in a row.

## Stated limits

* **`mcp-remote` never shows a 401's body.** It goes straight to OAuth
  discovery. The reason is in the reply for curl and other clients, and in
  the controller log.
* **The log lines are not asserted by a test**, as before (AX's stated limit).

## Deliberately not done

* **OAuth for `/mcp`** (protected-resource metadata, dynamic client
  registration). That would make `mcp-remote`'s fallback succeed, but it is
  a new authentication surface. Agent tokens are the design.
* **A separate metric outcome per reason.** A new label would need
  pre-seeding and an alerting story, and nobody has asked for an alert.
