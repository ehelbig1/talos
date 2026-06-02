# Split-brain fencing design (crash-recovery durability, F4)

Status: **design** — the cheap, unambiguous guards are landed; the epoch fence
below is the remaining work. This doc is the implementation plan so the next
pass doesn't have to re-derive the threat model.

## Threat

Crash-recovery (`talos-execution-orchestration/src/crash_recovery.rs`) resumes
an execution that has sat in `running` past the stale window. The claim
(`ExecutionRepository::claim_stuck_execution_for_resume`) is `FOR UPDATE SKIP
LOCKED` + status CAS, so two *sweeps* can never double-claim the same row.

That does **not** stop a **live-but-slow** original controller. If controller A
is GC-paused / partitioned / just running a workflow longer than the stale
window, its execution is still `running`. Controller B restarts (rolling
deploy), its startup sweep sees the stale `running` row, claims it
(`running -> resuming`), and resumes it. Now **A and B both drive the same
execution**: both dispatch its nodes (duplicate side effects) and both try to
write its checkpoint and terminal status.

## What is already fenced (no epoch needed)

- **Terminal completion / failure** — `mark_execution_completed` and
  `mark_execution_failed` guard `WHERE id = $1 AND status = 'running'`. Once B's
  claim flips the row to `resuming`, A's terminal write no-ops. ✓
- **Suspend (`waiting`)** — `ExecutionRepository::mark_execution_waiting` now
  guards `status = 'running'` too (this PR), closing the lone bare writer; a
  superseded controller can't resurrect a terminal/claimed row into `waiting`. ✓
- **Checkpoint writes** — monotonic `checkpoint_seq` guard (PR #148): a
  reordered/stale snapshot can't clobber newer resume material. ✓

## The residual gap the guards can't close

Status alone is **ambiguous** for the engine's own NATS-completion terminal
write (the path the *resume* uses) and for any write that must legitimately run
from `resuming`:

- A superseded fresh-run controller (row now `resuming` after B's claim) and the
  legitimate resumer B **both observe `resuming`**. A `status IN ('running',
  'resuming')` guard would admit both. Only a per-owner token distinguishes them.
- A resumer B that itself goes slow gets failed by the next restart's
  `reclaim_orphaned_resuming` (`resuming -> failed`); if B then completes via an
  unguarded write it resurrects the row. Status can't tell "B" from "the reclaim".

Both require an **epoch** (a monotonic ownership token bumped on each claim).

## The fence: an `epoch` ownership token

1. **Schema.** `ALTER TABLE workflow_executions ADD COLUMN epoch BIGINT NOT NULL
   DEFAULT 0;` Fresh executions are created at epoch 0.
2. **Bump on claim.** `claim_stuck_execution_for_resume` sets `epoch = epoch + 1`
   and `RETURNING epoch`. `reclaim_orphaned_resuming` also bumps (so a resumer
   that the reclaim superseded loses its epoch). The claimed epoch travels in
   `StuckExecutionForResume` into the resume path.
3. **Engine carries its epoch.** A fresh run carries epoch 0; a resume carries
   the bumped epoch. Thread it through `EngineOpts` / the run entry points the
   same way `actor_id` / `max_llm_tier` already travel.
4. **Heartbeat-abort (stops continued dispatch).** The controller spawns a
   per-run task: every `FENCE_HEARTBEAT_SECS`, `UPDATE workflow_executions SET
   updated_at = NOW() WHERE id = $1 AND epoch = $2`. On `rows_affected = 0` the
   controller has been superseded — fire the engine's existing cancellation
   token (same mechanism as `set_execution_timeout_secs`) so the loser stops
   dispatching new nodes promptly instead of running to completion.
5. **Epoch-guard the engine's terminal write.** Whatever the NATS-completion
   path writes for terminal status must add `AND epoch = $myepoch`, so a write
   that slips past the last heartbeat (final node dispatched in the gap before B
   claims) still no-ops. Locate it first: trace from `run_with_seed_via_nats`'s
   returned `WorkflowContext` and the `ControllerNodeHook` / event-sink wiring in
   `talos-engine/src/builder.rs` — the crash-recovery module comments it as "the
   engine's bare `UPDATE ... WHERE id = $1`", and that bare write is the one to
   guard.

## Why it can't be CI-validated, and how to test anyway

True split-brain needs two controllers racing one row — not expressible in the
single-process test harness. Cover it by:

- Unit-testing the epoch arithmetic: claim bumps `0 -> 1`, a second claim
  `1 -> 2`, `StuckExecutionForResume.epoch` carries the post-bump value.
- Unit-testing the guarded writes via `InMemoryCheckpointStore`-style fakes:
  a write at epoch 0 against a row now at epoch 1 reports `rows_affected = 0`.
- Integration-testing the heartbeat-abort with two `ExecutionRepository`
  handles on one pool (simulating two controllers): handle A starts, handle B
  claims (bumps epoch), A's next heartbeat returns 0 rows and trips the abort.
- Flag the live validation explicitly: exercise a real rolling deploy with a
  deliberately slow workflow and confirm the superseded pod logs the fence and
  stops, while the resumer finishes — same "validate under real conditions"
  caveat carried for the RLS `WITH CHECK` and otel-bridge changes.

## Ordering / invariants to preserve

- `reclaim_orphaned_resuming` MUST keep running **before** the claim loop
  (existing invariant) and MUST bump epoch so a reclaimed-then-revived resumer is
  fenced.
- The heartbeat write MUST NOT itself reset the stale clock for *other*
  controllers — it only touches its own epoch-matched row, so a superseded
  controller's heartbeat no-ops and never extends the row's `updated_at`.
- Keep the fence additive on the wire/schema (DEFAULT 0) so a mixed-version
  fleet during the deploy that introduces it degrades to today's behavior rather
  than fencing everything.
