# 2026-09-30 — a recorded `delete_actor`

**Why.** No path deleted an actor. `archive_actor`'s description deferred name
reuse to "an admin-level tool" that did not exist, so the only way to remove a
leftover (here `probe-750-readonly`, a terminated probe whose description says
"Delete after use") was a hand-written `DELETE`. That records nothing, and the
foreign keys silently cascade away the actor's own audit trail
(`actor_action_log`), along with its memory and policies.

**Decided.** One method, `ActorRepository::delete_actor_recorded`, in ONE
transaction under a row lock on the actor:

- **Refuses, writing nothing,** when the actor:
  - is not the caller's: one `NotFound` for absent and foreign, which the MCP
    reply renders as the collapsed "not found or access denied", so it is not
    an existence oracle;
  - is the user's **Default** actor, which every execution without an actor
    falls back to;
  - is not in a **final** state (`terminated`, `archived`): end it first;
  - is referenced by any **workflow** or any **execution history** (live,
    archived, or sub-workflow runs), since deleting it would falsify that
    history;
  - gets a `confirm_name` that does not match its name. That check runs
    inside the transaction, against the name the delete would remove, so a
    rename between preview and delete cannot slip through.
- **Records before it deletes:** one `admin_event_log` row (`actor_deleted`)
  holds the counts the cascade removes and the actor's action log (first
  `DELETION_ACTION_LOG_SNAPSHOT_MAX` = 100 entries plus the true count), so
  the audit trail outlives the actor. A deletion that cannot be recorded does
  not happen.
- **`dry_run`** runs every check and the snapshot, then rolls back.
- **What keeps the id:** ledgers with an `actor_id` but no foreign key
  (`execution_cost_rollup`, `llm_usage`, `execution_memory_context`,
  `secret_audit_log`) keep it. They are history, not the actor.
- **The MCP tool** `delete_actor(actor_id, dry_run, confirm_name)` requires
  `confirm_name` for a real delete. `archive_actor`'s description now names it
  as the way to free a name.

**Proof.** Database tests on a real clone, driving the production method:
- every refusal (foreign, Default, active, bound to a workflow, with execution
  history, wrong name) leaves the actor and writes no audit record;
- a dry run writes nothing;
- a delete removes the actor and its cascades, writes exactly one audit record
  holding the action log, and frees the name.

Unit tests map every outcome to its reply and error kind.
`talos-mcp-handlers`: 671 passed.

**Mutations: 7 applied, 7 caught:**
- tenancy dropped from the locking read;
- the Default actor made deletable;
- a non-final actor made deletable;
- a referenced actor made deletable;
- the confirm name ignored;
- the delete not recorded;
- a dry run that commits.

**Stated limits.**
- MCP only; GraphQL has no actor-delete mutation.
- An actor with any execution history is refused, and it stays refused until
  retention removes that history. Each table ages out differently, and one
  does not age out at all on the reference fleet (corrected 2026-09-30, below):
  - `workflow_executions`: the 30-day live window, then 30 days in
    `workflow_executions_archive`, then gone;
  - `sub_workflow_runs`: the child-run ledger purge;
  - `module_executions`: ONLY while `MODULE_EXECUTION_RETENTION_ENABLED` is
    on, and then only terminal rows whose parent workflow execution no longer
    exists. It is off by deliberate decision (package AT: the off-host backup
    chain must be proven first), so an actor that ever ran a module is kept
    PERMANENTLY there.

**Correction (2026-09-30, first live use).** The record above said an actor
with history "is kept until retention removes it". On the reference fleet
that is false for module history. The first real `delete_actor` (a dry run on
the terminated `probe-750-readonly`) was refused for 2 `module_executions`
rows: the two Actor Memory Writer runs that were the live verification of the
#750 write-ceiling gate. Both rows are orphans (their parent workflow
executions were purged), so an enabled module-retention sweep would remove
them. With it off they stay, and so does the actor. The refusal is correct:
those rows are audit evidence, and `module_executions.actor_id` is
`ON DELETE RESTRICT` to stop exactly that history being deleted or
re-attributed. The pre-check made by hand before the dry run had looked at
`workflow_executions` only and missed them; the tool did not.
