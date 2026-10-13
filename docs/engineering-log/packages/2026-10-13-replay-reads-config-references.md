# A replay resolves the secret references in the node config it replays with (2026-10-13)

Left open by `2026-10-13-standalone-runs-mint.md`: "a replay passes the
module's grant list verbatim … an EXACT mint path in the grants is minted, a
glob (`gcp/impersonated/*`) is not, because a glob names no path. A workflow
dispatch covers that case from the node's config reference, which a replay
of stored rows does not re-read here."

## What was wrong, and it was wider than the mint

A module's grant is often a prefix or a glob (`oauth/gmail`,
`gcp/impersonated/*`), and the exact path is named only by the node's
config, as `Bearer vault://…`. A dispatch resolves the grant list AND the
config's references. A replay resolved the grant list alone, and a grant
entry is looked up as a literal path.

So this was not only the minted case. A module with a prefix grant on a
STORED token was replayed with no credential too, and every row failed on a
missing secret. The replay service already reads each row's node config (it
is what the module is run with); it did not read the references in it.

## Decided

* `replay_wanted_paths(grants, node_configs)`: the grant list, then every
  `vault://` reference in the node configs the rows are replayed with THAT
  THE GRANT PERMITS (`vault_path_permitted`), read where the engine reads
  them (`extract_vault_refs`, the top level of the config). Order kept,
  duplicates dropped, at most 64 distinct references (the rest are logged
  as a count and not asked for).
* The GRANT a mint is judged against is unchanged: the module's own
  `allowed_secrets`. What changed is what is wanted. A mint is therefore
  gated twice against the same grant, here and in
  `talos_oauth::resolver::standalone_run_paths`.
* A reference the grant does not permit is not asked for, stored or minted.
  A real dispatch could not use it either: the worker refuses a path
  outside the grant.
* Both modes: module mode passes each row's node config, workflow mode the
  target node's.

## What a caller can now do that they could not

Replay a module whose grant is a prefix or a glob and have it run with the
credential its node config names. Nothing outside the module's own grant is
fetched or minted, and everything is resolved for the caller's own user id.

**A replay runs the module for real.** That was already true: a module
with an exact grant was replayed with its token and made its requests. It is
now also true for a module with a prefix or glob grant, whose replay used to
stop at the missing secret. A replay of a module that writes, writes again.
That is what `replay_module_regression` does and was not changed here;
whether a replay should refuse to send a state-changing request is a
separate question, not decided.

## Mutations (who may cause a credential to be fetched or minted)

| Mutation | Caught by |
|---|---|
| a reference outside the grant is asked for | unit test. The database test still passes, because the mint's second gate holds: no provider is asked |
| the configs are not read (the behaviour before) | three unit tests and the database test |
| the grant a mint is judged against is the wanted list | the wiring pin |
| workflow mode passes no config | the wiring pin |
| no bound on the references taken | unit test |

## Tests

* `talos-replay-service` (+5): the path rule (a glob mint grant and a
  prefix stored grant, each with its config reference); references outside
  the grant; duplicates, row order and top-level-only; the bound; a pin on
  both modes' wiring and on which list is the grant.
* `controller/tests/standalone_run_mints_tests.rs`, with providers that
  record what they were asked: a replay under a glob grant alone asks no
  provider; with the node config, one mint, for the caller, from the
  connection the path names, and none for the reference outside the grant;
  the same replay by another user is asked about as that user and refused.

Not driven end to end: a replay running a real module that sends the token.

## Stated limits

* The module's own stored `config` is not scanned, only the node config the
  replay runs the module with. The engine merges the two at dispatch.
* Module mode finds a row's node config by the module's id in the row's
  workflow graph. A row with no workflow (a `test_module` run) has no
  config and so no references, as before.
