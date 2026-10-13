# A path minted at dispatch is never called a missing secret (2026-10-13)

For `gcp/impersonated/<service account>/as/<connection key>/access_token`,
`test_secret_access` answered `vault_presence: false`, `would_succeed: false`
and "Add it in the dashboard"; `create_workflow` listed the grant under
`missing_secrets`. Nothing is ever stored at such a path: the token is minted
when a job is dispatched. Following the advice stores a secret that is never
read.

## What the brief had right, and what it did not

Read in the code before anything was changed:

* **`update_node_config`'s "SECRET ACCESS WILL FAIL" is by design.**
  `describe_blocked_vault_refs` asks one thing, `vault_path_permitted` against
  the module's `allowed_secrets`. It never looks in the vault, and its advice
  is to grant the path, not to store a secret. A grant that names
  `…/<sa>/access_token` does not cover `…/<sa>/as/<key>/access_token`, and the
  worker refuses that reference with the same matcher. So where the warning
  was seen, the grant did not cover the path at that moment. Not changed; a
  test now pins it (covered: silent; not covered: warns, and never mentions
  storage).
* **`missing_secrets` is computed over grant ENTRIES**, not over paths in node
  config: `gcp/impersonated/*` or `github_app:<owner>` is "missing" because no
  stored key path satisfies it.
* **The GitHub scheme is `github_app:<owner>`**, and it had the same gap.
* **More surfaces than three gave the advice**: `get_workflow_quickstart` (a
  `missing_secret` blocker), `get_config_suggestions` ("not yet in vault"),
  and `test_module` / `run_sandbox` ("Ensure the secret exists").
* **`talos-mcp-handlers` may not depend on `talos-google-cloud`** (its
  `Cargo.toml` says so), so the consent question could not be asked there
  directly.
* **The resolver that mints did not use the path parsers to recognise a mint
  path.** It tested a prefix and a suffix inline.

## Decided

* **One recogniser: `talos_workflow_job_protocol::dispatch_mint`.** It
  answers `GcpImpersonated(target)`, `GithubApp { owner }`, `Malformed(scheme)`
  or `None` (an ordinary stored path). `ControllerSecretsResolver` now
  partitions with it, so a tool cannot call a path "stored" that the resolver
  will not look up. Membership is exactly what the resolver tested before:
  `github_app:` by prefix; `gcp/impersonated/` by prefix AND `/access_token`
  by suffix. `gcp/impersonated/x/refresh_token` is therefore still an ordinary
  path, as it was.
* **For a grant entry: `grant_reaches_minted_paths`.** An entry is a path, a
  prefix or a glob, so this is asked of its text.
* **"Could a mint be made" is asked of the provider that would mint**, through
  the seam that already exists: a `mint_readiness` method on
  `GcpImpersonationTokenProvider` and `GithubInstallationTokenProvider`
  (engine-core), reached by `talos_oauth::resolver::check_mint`. The handlers
  already depend on `talos-oauth`. No new dependency edge.
  * Google Cloud: `mint_readiness_for` puts the list
    `active_full_tier_connections` reads under the user's id to
    `choose_consent`, the function the mint uses. `readiness_of` maps its
    four outcomes.
  * GitHub: is the App configured, and does the user own an active
    installation for the owner.
  * Nothing is minted, refreshed or read, and no outbound call is made. The
    mint cache is not consulted.
* **`test_secret_access` gate 4** is `mint_readiness` for a mint path and
  `vault_presence` otherwise. `would_succeed` uses whichever applied. Still
  five gates.
* **`create_workflow`**: a mint grant is never in `missing_secrets`, does not
  hold `ready_to_run` false, and is listed under `minted_at_dispatch` (the
  field is absent when there is none). No readiness check there: a grant may
  be a glob with no connection named.
* **One sentence for "this is not stored"**:
  `talos_workflow_creation_helpers::unstored_secret_advice`. For a stored
  path it is the text `get_config_suggestions` already used, byte for byte.
* **`test_module` / `run_sandbox`**: an absent mint path is
  `VaultResolverError::MintedAtDispatch`. These tools read stored secrets and
  do not mint, so a module that uses a minted token cannot be rehearsed there;
  the message says to use `test_workflow`. They were not made to mint.

## Who may learn what

`NamedConnectionNotUsable` is one answer for a key that is another user's, a
disconnected connection and a key that never existed. `choose_consent` cannot
tell them apart (its list is the asking user's own), and the gate's text does
not try. `NoConnection` and `SeveralAndNoneNamed` describe only the asker's
own connections, which `list_connections` already shows them.

## Mutations (the readiness check is a tenancy boundary)

| Mutation | Caught by |
|---|---|
| `mint_readiness_for` ignores the named key | DB test, `SeveralAndNoneNamed` where `Ready` was expected |
| the consent list is not filtered by `user_id` | DB test (and the existing list test) |
| `readiness_of` maps `NamedIsNotTheirs` to `Ready` | unit test |

Each restored and touched; all pass.

## Tests

* `talos-workflow-job-protocol` `dispatch_mint_tests` (4): stored paths, both
  Google forms and the GitHub form, malformed mint paths, grant entries.
* `talos-google-cloud`: `readiness_of` over every state, including a foreign
  key against zero, one and two consents.
* `controller/tests/gcp_impersonation_consent_tests.rs` (+1), real rows:
  usable, no consent, two and none named, and another user's key answered
  as a key nobody holds, for two different askers.
* `talos-oauth` `check_mint_tests`: a stored path is not checked; a malformed
  one is `Malformed`; with no provider injected, `NotConfigured`.
* `talos-mcp-handlers` `mint_readiness_gate_tests` (5): no outcome advises
  storing a secret; each state says what to do; the foreign-key text names
  no owner; an unreadable check is not passed and not evidence.
* `talos-workflow-creation-helpers` (+2): a mint grant is never missing
  (failed before the fix: all three were listed); the quickstart entry.
* `talos-workflow-engine` `vault_resolver`: an absent mint path is not called
  a missing secret; a stored one still is.
* `talos-mcp-handlers` `blocked_vault_report_tests` (+1): the
  `update_node_config` warning, as described above.

Not driven end to end: `handle_test_secret_access` needs an `McpState`. The
gate function, the check and the provider are each tested; the join is four
lines.

## Stated limits

* `Ready` means there is ONE connection to mint from. Whether Google will
  issue the token (the connected account must be allowed to impersonate the
  service account) is only known by minting, which a diagnostic must not do.
  The gate's text says so.
* The GitHub owner is whatever follows `github_app:`, as the resolver has
  always read it. `talos-github-connect` exports a stricter parser that no
  production code calls. Not unified: applying it in the resolver could
  refuse an owner that resolves today. Not measured: whether any installation
  has a login outside that parser's alphabet.
* `import_platform_state`'s "is not provisioned" warning was left: its
  `secret_refs` are stored secrets from an export, so a mint path does not
  appear there.
* `get_workflow_quickstart` checks a grant entry by exact equality against
  stored key paths (`create_workflow` uses the grant matcher), so a prefix
  grant can read as unprovisioned there. Seen while here; not changed.

## Found, not fixed: a module replay never mints

`ReplayService::prefetch_secrets` (`talos-replay-service`) calls
`SecretsManager::get_secrets_by_paths` directly, like `test_module`. A replay
of a module that reads a minted token gets none. Not changed: making replay
mint is a behaviour change with its own tenancy questions.

## Rule added to CLAUDE.md

In the RPC-layer section, beside the impersonation rule: a path minted at
dispatch is never called a missing secret; the recogniser, the advice
function and the no-mint check are named there.
