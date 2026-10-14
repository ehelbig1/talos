# Production requires per-worker identity; a durable write names a live run; guest SQL carries its tenant (2026-10-14)

Security review 2026-10-14, findings **B-2** (High), **B-3**, **B-4** and
**D-2** (Medium). Package 5a of the review's remediation.

## The defects, as verified

- **B-2.** `result_accept_legacy_hmac`, `rpc_accept_legacy_hmac` and the
  worker's dispatch `accept_legacy_hmac` default to accepting the fleet-shared
  `WORKER_SHARED_KEY`; nothing required the three `TALOS_*_REQUIRE_ED25519`
  switches in production. The subscribers take `actor_id`/`user_id`/
  `execution_id` from a signed envelope, which is correct against an outsider
  and inert against a key holder. The fleet key as a shared trust boundary is
  a recorded decision; the boot gate is what this package adds.
- **B-3.** `talos.state.write` upserted `execution_state` for any
  `execution_id` with no existence check and no per-execution bound.
  **Corrected:** the review's "crash recovery then resumes that run on
  attacker-chosen state" does NOT hold — nothing reads `execution_state` back
  at runtime (the worker's `state::get` reads its in-memory store; the table's
  only readers are the archival move, the orphan sweep and a test). The
  growth half holds.
- **B-4 / D-2.** The guest SQL transaction set `SET LOCAL ROLE` and no tenant
  GUC, so every RLS policy's permit-when-unset arm admitted every tenant's
  rows on any table granted to the guest role. `GuestRoleSetting::Unset` ran
  guest SQL as the pool user, in production too with
  `TALOS_ALLOW_UNSCOPED_DB_SANDBOX`. Postgres error text reached guest code.

## Measured

- `execution_state` on the reference stack: 0 rows, 0 executions (nothing to
  migrate; the quotas are chosen, not fitted).
- The reference stack runs with `RUST_ENV` unset and `TALOS_RPC_GUEST_ROLE`
  set, so neither production-only refusal changes it.
- A real Jira-free path for the switches: `deploy/k3s/lib/worker-trust.sh`
  phase D already set RESULT and DISPATCH required; no phase set RPC.

## Decided

- **Boot gate (B-2), one home:** `talos_config::fleet_identity`. The
  controller gates the surfaces it verifies (result, rpc); the worker gates
  dispatch. `TALOS_ALLOW_LEGACY_FLEET_HMAC` is GRANULAR (`dispatch`,
  `result`, `rpc`, or `all`), parsed strictly (an unknown word refuses), and an
  acknowledged surface is logged at ERROR every boot. `security_audit` gains
  `fleet_identity` (weight 0, by the same argument as
  `audit_chain_verification`; production `Fail`/`Warn` carry the finding).
- **Rollout:** the installer renders the acknowledgement for exactly the
  surfaces each worker-trust phase does not yet require (off–C: controller
  `result,rpc`, worker `dispatch`; D: controller `rpc`). `rpc` stays
  acknowledged at D because the controller's in-process rehearsal runtime
  signs RPCs with the fleet key (it holds no worker identity) — requiring it
  would refuse every rehearsal's memory call. Operator decision D-8.
  Migration path: `docs/worker-identity.md`.
- **Durable state (B-3):** one statement, `execution_state_write`, writes only
  for an execution in `running`/`resuming`/`waiting`, within
  `MAX_STATE_KEYS_PER_EXECUTION` (1 000) and `MAX_STATE_BYTES_PER_EXECUTION`
  (16 MiB) — an overwrite of a held key is not a new key. The delete has the
  same live-execution rule. Refusals are counted as `not_found` (not live) and
  `storage_full` (quota) on `talos_rpc_calls_total{subject="talos.state.write"}`
  — the existing outcome taxonomy, added to the subject's closed set, rather
  than a new `refused` label. Still outside the write ceiling (recorded
  decision).
- **Guest tenancy (B-4/D-2):** the guest transaction reads the signed actor's
  owner (before the role switch; no actor ⇒ `Unauthorized`) and sets the GUCs
  with the one statement that sets them (`TenantReadScope::set_local_sql`, no
  org list — the owner's personal rows) in the same round trip as
  `SET LOCAL ROLE`. `guest_fence`: in production an unset guest role is
  refused per query, and the boot gate no longer accepts
  `TALOS_ALLOW_UNSCOPED_DB_SANDBOX` (outside production nothing changes). A
  database failure reaches the guest as `"query failed"`; only the SQLSTATE is
  logged — never Postgres' text, which can quote a guest literal.

## Deliberately NOT done

- No per-job RPC capability (binding an RPC's actor/user/execution to the
  dispatch record) — the review's stronger option (2); the boot gate is the
  actionable part today.
- No deletion of `execution_state` at terminal status: there is no single
  terminal chokepoint (five finalizers across two repositories), nothing reads
  the rows, the archival move deletes them atomically, the orphan sweep takes
  rows with no execution, and the per-execution quota now bounds what one run
  can hold. The instruction was "do not add a new sweep if one exists".
- The guest GUC carries no org list. Org-shared rows on a granted table are
  not visible to guest SQL; widen only with the membership read and a reason.

## Mutation proof (tenancy / authentication)

| Gate | Mutation | Test | Verdict |
|---|---|---|---|
| guest tenant GUC | GUC dropped from the role round trip | `data_plane_tenancy_db_tests::guest_sql_sees_only_its_actors_owners_rows` | FAIL / PASS restored |
| unknown actor refused | owner defaulted to nil | same test | FAIL / PASS restored |
| state write needs a live run | status predicate made always-true | `a_state_write_for_an_execution_that_is_not_live_writes_nothing` | FAIL / PASS restored |
| per-execution key quota | quota +10⁶ | `a_state_write_past_the_executions_quota_is_refused` | FAIL / PASS restored |
| production guest fence | refusal disabled | `guest_fence_tests::production_refuses_guest_sql_with_no_fence` | FAIL / PASS restored |
| fleet identity posture | refusal disabled | `fleet_identity::tests` (2) | FAIL / PASS restored |

## Stated limits

- An acknowledged legacy surface is exactly as open as before; the gate makes
  the choice explicit and visible, it does not close the surface.
- The state quota is read then written in one statement; two concurrent writes
  may both pass it, bounded by the subscriber's in-flight cap (32).
- Guest-SQL tests run against the migrated database (`lib-migrated`) with a
  fixture table in the platform's policy shape, not against a granted platform
  table (a grant on a shared test database would leak into other suites).
