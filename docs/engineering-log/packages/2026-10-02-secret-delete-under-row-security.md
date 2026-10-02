# A user's secret delete was refused by the audit table's row security (2026-10-02)

**Found live.** A Google Health disconnect on a throwaway account logged
"OAuth disconnect complete (revoke + vault cleanup)" and left both token
entries in the vault.

**Cause.** Migration `20260912140000` re-keyed `secret_audit_log`'s policy on
its parent: a row is admitted only while `secrets` holds its `secret_id`. Both
delete paths (`SecretsManager::delete_secret`, `delete_secret_by_id`) ran
`DELETE … RETURNING` and wrote the audit row AFTER it. Under `talos_app`
(`TALOS_RLS_SET_ROLE` on) the insert fails the policy's `WITH CHECK`, the
transaction rolls back and the secret stays. `revoke_and_cleanup` logged that
error at DEBUG as "not present or already removed" and reported success.

**Reach.** Every user-scoped secret delete on a deployment with
`TALOS_RLS_SET_ROLE` on: the GraphQL `deleteSecret` mutation and the vault
cleanup of every OAuth disconnect. For a provider with no revoke endpoint
(Atlassian) that leaves a LIVE token in the vault after a disconnect. On the
reference deployment: `secret_audit_log` holds 18 `delete` rows, the last from
2026-07-21; no disconnect had ever been made before this one. With the switch
off (the code default, and CI) the delete worked, which is why no test saw it.

**Fix.**
* Both paths lock the row (`SELECT … FOR UPDATE` under the same ownership
  predicate), write the audit row, then delete by id. A delete that removes a
  different number of rows than it locked commits nothing.
* `delete_secret_if_present` is the three-valued form — removed / nothing the
  caller may delete / could not delete. `delete_secret` keeps its contract
  (absence is an error) on top of it.
* `revoke_and_cleanup` no longer reads every delete error as "not present". A
  token entry it could not delete is a WARN (`oauth_disconnect_vault_entry_left`)
  and the call returns `Err` after the rest of the cleanup has run. Its five
  callers already log an `Err` and continue with their own metadata flip.

**Behaviour changes, stated.** `delete_secret` records one audit row per
deleted row (a path can exist in more than one namespace; it recorded only the
first). `revoke_and_cleanup` can now return `Err` where it returned `Ok`.

**Not changed.** The policy. Giving `secret_audit_log` an actor arm would let
the old ordering work, but it changes who may write and read audit rows; the
ordering fix needs no policy change. A deleted secret's audit rows remain
invisible to a scoped reader, as before.

**Tests.** `controller/tests/secret_delete_under_rls_tests` (6) drives both
paths and a disconnect as `talos_app`, and proves the role is in force first.
`controller/tests/secret_delete_predicate_tests` (2) pins the ownership
predicate with row security bypassed — under `talos_app` the `secrets` policy
hides a stranger's row before the predicate is consulted, so dropping the
predicate passes every test in the first binary. Two binaries because the
switch is read once per process.

**Mutations (5 applied, 5 caught).** The original ordering by path and by id;
the ownership predicate dropped by path and by id (caught only by the
predicate binary); a failed vault delete not counted.

**Stated limits.**
* The org-membership arm of the predicate (a member deleting an org-shared
  secret) is not driven under `talos_app` by these tests.
* The two token entries left by the disconnect that found this are still in
  the reference deployment's vault. They belong to a throwaway account and were
  revoked at Google; removing them is an operator action.
* A local `.env` with `TALOS_RLS_SET_ROLE=true` is loaded by the controller
  test harness, so local runs enforce row security and CI does not. A test
  whose meaning depends on the switch sets it explicitly.
