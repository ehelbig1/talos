# A secret granted to a module reaches only its owner's jobs (2026-10-14)

Security review 2026-10-14, finding **C-1** (High). Package 1 of the review's
remediation.

## The defect, as verified

`secrets.allowed_modules` grants a secret to a MODULE id. Step 1 of the
engine's secret pipeline (`talos-workflow-engine/src/secrets_pipeline.rs`,
`resolve_secrets_map_for`) asked `SecretsResolver::resolve_module_secrets(node_id)`
— no user — and the controller's resolver answered with
`SecretsManager::get_module_secrets(module_id)`, whose SQL was
`WHERE $1 = ANY(allowed_modules)` with no owner predicate. Every engine
dispatch path (single node, its credential-repair re-resolve, pipeline step,
loop body) goes through that pipeline. A module id is not a tenant: a catalog
module, or one shared with an organization, is run by many users. So a secret
user A granted to such a module was decrypted and sealed into user B's job of
it, where B's module code could read it through a `"*"` grant. The reverse
(B grants B's secret to A's module id, and it rides A's jobs) held too,
because `create_secret` did not check the ids.

The scoped read (`get_module_secrets_for_user`, MCP-589) already existed and
the webhook router and integration helpers used it; the engine trait was the
one caller left, and its doc comment said the blocker was a sibling-repo trait
signature that no longer exists (the engine was folded into this workspace in
May 2026).

## Decided

- `SecretsResolver::resolve_module_secrets(module_id, user_id: Option<Uuid>)`.
  `Option` to match `resolve_by_paths`; the engine's single-node path already
  refuses to run without a user, so `None` is reached only by user-less
  harnesses.
- `SecretsManager::get_module_secrets` (unscoped) is **deleted**. The read is
  `get_module_secrets_for(module_id, Option<Uuid>)`: `Some` is the existing
  scoped predicate, `None` returns system secrets only (`owner_user_id IS
  NULL`), the rule `get_secrets_by_paths` already applies to a user-less read.
  There is no unscoped arm left in the SQL.
- `allowed_modules` may name only a module the writer can run: their own, a
  catalog module (no owner, no org), or a module of an organization they
  belong to. The check is in `SecretsManager` (`refuse_unreachable_allowed_modules`),
  called by both writers of the column (`create_secret`, `upsert_secret`), so
  GraphQL `createSecret`, OAuth credential storage and the CLI all pass it.
  One message for an unknown id and a foreign one (`Validation:` prefix, which
  the GraphQL error scrub lets through).

## One home

- Read: `SecretsManager::get_module_secrets_for` / `get_module_secrets_inner`.
- Write: `SecretsManager::refuse_unreachable_allowed_modules`.
- Lint check 98 refuses a reintroduced unscoped `get_module_secrets(` anywhere
  in the tree (opt-out `// allow-unscoped-module-secrets: <reason>`; there is
  no known legitimate use).

## Measured

- Check 98: 2 hits on `main` @ 8192b6e0 (the definition and the resolver's
  call — both the defect), 0 after, 0 false positives (comment lines that tell
  the story are skipped).
- Live vs latent: not measured against the reference fleet's `secrets` table.
  The exposure needs a non-empty `allowed_modules` on a module that a second
  user dispatches; whether any such row exists was not queried from this
  session.

## Mutation proof (tenancy gate)

| Test | Mutation | Verdict |
|---|---|---|
| `controller/tests/module_grant_secrets_user_scope_tests.rs::a_secret_granted_to_a_shared_module_reaches_only_its_owners_jobs` | the scoped SQL arm's owner predicate replaced with `$2 IS NOT NULL` (every grant, any owner) | FAIL / PASS on restore |
| `talos-workflow-engine/tests/loop_body_secrets.rs::a_loop_body_is_given_the_secrets_its_config_and_grant_name` | the pipeline passes `None` instead of the run's user | FAIL / PASS on restore |
| `module_grant_secrets_user_scope_tests.rs::allowed_modules_may_name_only_a_module_the_writer_can_run` | the reachability comparison made always-true | FAIL / PASS on restore |
| lint check 98 | the pre-fix call `self.sm.get_module_secrets(node_id)` re-added to the resolver | FAIL / PASS on restore |

## Deliberately NOT done

- The scoped predicate keeps `owner_user_id IS NULL OR … OR created_by = $2`.
  Narrowing the legacy `created_by` arm and the org-member read arm is finding
  C-2 / operator decision D-4, Package 10.
- No backfill or cleanup of existing `allowed_modules` values that name a
  module the writer cannot reach: the read fix makes such a grant inert (it is
  delivered only to its owner's jobs), and rewriting user data was not needed
  to close the defect.

## Stated limits

- The pipeline-step path (`engine_dispatch_pipeline.rs`) passes the STEP's
  node id where the module id belongs, so module grants are never found for a
  chain step. That is a correctness gap, not a leak (it finds less, never
  another user's), and the chain path is disabled (G-15). Not changed here.
