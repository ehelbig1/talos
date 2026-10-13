# A module run outside a workflow mints what a dispatch would (2026-10-13)

Found while fixing the secret diagnostics and recorded there as not fixed:
`test_module`, `run_sandbox` and a module replay asked the vault directly for
a module's secrets (`SecretsManager::get_secrets_by_paths`). Nothing is
stored at a path whose value is MINTED (an impersonated Google Cloud service
account, a GitHub App installation), so a module that authenticates with one
failed on a missing secret and could not be rehearsed or replayed alone.

This supersedes one line of that record: "they were not made to mint".

## Decided

* **One function, the dispatch's own resolver**:
  `talos_oauth::resolver::resolve_for_standalone_run(sm, granted, wanted,
  user_id)`, which is `ControllerSecretsResolver::resolve_by_paths` over
  `standalone_run_paths(granted, wanted)`. The three surfaces call it.
* **A stored path is fetched exactly as before.** The resolver hands
  non-mint paths to the same `get_secrets_by_paths` call.
* **A mint needs a grant.** `standalone_run_paths` keeps a mint path only
  when `granted` covers it (`vault_path_permitted`). A mint is an outbound
  call that creates a credential, so it needs what a real dispatch of the
  module would need:
  * `test_module`: the MODULE's own `allowed_secrets`, which is also the
    list its security context enforces. Not the tool's `allowed_secrets`
    argument, and not a `vault://` reference in `config` (both only widen
    what is fetched);
  * `run_sandbox` (inline code): what the caller declared in
    `allowed_secrets`, taken BEFORE references found in the input are merged
    in;
  * module replay: the module's own list (it is also the only thing wanted).
* **A rehearsal mints nothing.** With `http_fixtures` no request is sent, so
  a token minted for it would be a real credential created for no call:
  `test_module_mint_grant` is empty for a rehearsal.
* **Tenancy is the dispatch's.** The resolver mints only for the `user_id`
  it is given, from that user's own connection, and with no user identity
  mints nothing. `run_sandbox` passes the agent's `user_id`, which may be
  absent.
* **The error for an unresolved mint path says what a mint needs**
  (`VaultResolverError::MintedAtDispatch`): the grant must cover the path
  and there must be a connection; `test_secret_access` checks both. It still
  never advises storing a secret.

## What a caller can now do that they could not

Mint a token, for their own connection, by running their own module (or
inline code) with a grant on the mint path. They could already do exactly
that through a workflow: a module's grants are its owner's to set. No path to
another user's connection is added: the provider is asked about the caller's
user id only (pinned below), and a refused mint is an absent path.

## Mutations (who may cause a credential to be minted)

| Mutation | Caught by |
|---|---|
| `standalone_run_paths` keeps a mint path without a grant | unit test, and the database test ("a mint was made with no grant") |
| a rehearsal is given the module's grant | handler unit test |
| `test_module` judges against its own `allowed_secrets` argument | pin test |
| `run_sandbox` judges against the merged list | pin test |

Each restored and touched; all pass.

## Tests

* `talos-oauth` `standalone_run_paths_tests` (2): stored paths unchanged
  (order kept, duplicates dropped, nothing withheld); a mint path only under
  a grant, where a grant on one service account does not reach another's and
  a Google grant does not reach a GitHub one.
* `controller/tests/standalone_run_mints_tests.rs` (1), a real
  `SecretsManager` and providers that record what they were asked: granted,
  both schemes are minted, for the caller, from the connection the path
  names; wanted but not granted, no provider is asked; a partial grant
  reaches that one only; another user with the same grant is asked about as
  THAT user, refused, and gets nothing; with no user identity no provider is
  asked.
* `talos-mcp-handlers` (+2): the rehearsal rule; a pin on which list each
  tool judges a mint against, on the declared list being taken before the
  merge, and on neither tool asking the vault directly.
* `talos-workflow-engine` `vault_resolver`: the reworded error.

Not driven end to end: `test_module` running a real module that sends a
minted token. The resolver, the path rule and the handler's choice of grant
are each tested.

## Stated limits

* A mint that fails (the connected account may not impersonate the service
  account) leaves the path absent, and the run fails on the reference with
  the error above. The reason is in the controller log, as on a dispatch.
* A replay passes the module's grant list verbatim, as the engine's first
  resolution step does: an EXACT mint path in the grants is minted, a glob
  (`gcp/impersonated/*`) is not, because a glob names no path. A workflow
  dispatch covers that case from the node's config reference, which a replay
  of stored rows does not re-read here.
* These surfaces still swallow a vault read error into an empty map
  (`unwrap_or_default`), as they did. Not changed.
* GraphQL `testModule` passes no secrets at all and is not changed.
* `get_workflow_quickstart` still checks a grant entry by exact equality
  against stored key paths, under a different ownership column from
  `create_workflow`. Seen again; which predicate is right is a decision, not
  made here.

## Rule added to CLAUDE.md

Beside the minted-path rule: a module run outside a workflow resolves its
secrets through `resolve_for_standalone_run`, and what counts as a grant.
