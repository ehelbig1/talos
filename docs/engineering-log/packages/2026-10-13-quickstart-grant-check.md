# The quickstart and `create_workflow` give one answer about a workflow's secret grants (2026-10-13)

Two earlier records listed this as found and not fixed:
`get_workflow_quickstart` checks a grant entry by exact equality, under a
different ownership column from `create_workflow`.

## What was wrong

A module's `allowed_secrets` entry is an exact path, a prefix (`oauth/gmail`)
or a glob (`oauth/gmail/*`). Two tools report which entries have nothing
stored behind them:

| | how a grant was judged | whose secrets counted |
|---|---|---|
| `create_workflow` | the grant matcher, over the caller's key paths | `created_by = caller` |
| `get_workflow_quickstart` | a secret stored at a path EQUAL to the entry | `owner_user_id = caller` |
| a dispatch (the truth) | n/a | `owner_user_id IS NULL OR owner_user_id = caller OR created_by = caller` |

So for a workflow whose module is granted `oauth/gmail`, with the token
stored, `create_workflow` said nothing was missing and the quickstart said
`provisioned: false`, raised a `missing_secret` blocker and reported
`ready_to_run: false`. No secret is ever stored at a path named
`oauth/gmail/*`, so a workflow with a glob grant could never be ready there.

## Decided

* **One listing**: `SecretsManager::list_dispatch_readable_key_paths(user)`.
  Key paths only, never a value, under the ownership rule a dispatch reads
  with. Both tools call it. One query per call, served by the existing
  indexes on `owner_user_id` and `created_by`; no query per grant.
* **One judgement per grant**:
  `talos_workflow_creation_helpers::grant_has_a_stored_secret`, which asks
  the one grant matcher (`vault_path_permitted`). `missing_secret_grants`
  (`create_workflow`) and the new `quickstart_secrets` both use it.
* **The listing refuses instead of truncating.** It asks for one row more
  than its cap (10,000). Past the cap it is an error, which both tools
  already render as "could not check" (`null`), instead of a listing that
  silently lacks a path and calls a stored secret missing. `create_workflow`
  read a listing that was cut at 10,000 without saying so.
* **Removed**: `WorkflowRepository::get_provisioned_secrets`. The quickstart
  was its only caller, and it was a second ownership rule for the same
  question.
* The quickstart handler lost its per-path loop and its sort; the helper
  returns the entries sorted. A `*` grant is still not listed.

## Tenancy

The listing decides whose secrets can satisfy a grant, so another user's
must not be in it. The database test puts a second user's secrets in the
table, one under a glob the first user's module declares and one at the
exact path the first user lacks, and asserts both stay missing and that
neither reply names the second user's path.

An ownerless secret (`owner_user_id IS NULL`) counts, for every user,
because a dispatch delivers it to every user. This discloses nothing a
dispatch does not: the module would receive the value.

## Mutations (whose secrets count)

| Mutation | Caught by |
|---|---|
| the quickstart asks for a path equal to the grant (the behaviour before) | the helper's unit test and both database tests |
| the listing has no ownership rule | the database test (the listing, and `chat/*` satisfied by another user's secret) |
| the listing leaves out the ownerless secrets | the database test (`shared` reported missing) |
| a listing past the cap is returned cut short | the cap's unit test |
| `create_workflow` reads the old listing | the database test (the two tools disagree on `shared`) |

## Measured, and not measured

* Both writers of `secrets` rows bind the creating user to `created_by` AND
  `owner_user_id` (the create and the upsert in `SecretsManager`). Through
  the platform, the two ownership columns do not differ for a user-owned
  row; the old rules differed only for an ownerless row.
* How many ownerless rows, and how many prefix or glob grants, the live
  stack holds was NOT measured: the platform-admin query tool refuses the
  `secrets` table by design, and that was not worked around.
* Every `create_workflow` database test takes 60 seconds locally, including
  the one that existed before this change (measured: 60.5 s). Something in
  that handler waits out a timeout in the test harness. Not investigated
  here.

## Deliberately not done

* `test_secret_access` checks ONE exact path with `secret_exists_by_path`
  (`created_by = caller`). It still does. For rows the platform writes it
  agrees with a dispatch; for an ownerless row it reports "not stored" where
  a dispatch would deliver. Changing it is a change to a diagnostic's answer
  and was left for its own change.
* `normalize_secret_paths` keeps `list_user_secret_key_paths`: it rewrites
  the caller's own secrets, and an ownerless secret is not theirs to rename.
* No SQL version of the grant matcher. Filtering in the query would need a
  second implementation of `vault_path_permitted`; the listing is names
  only and bounded, and the matcher runs over it in memory.
* The pinned swallowed-read inventory (`docs/swallowed-reads-inventory.md`)
  still names `get_provisioned_secrets` at the commit it is pinned to.
