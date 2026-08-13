-- Relabel the `module_executions` rows the engine never finalized.
--
-- WHY
-- ---
-- Until 2026-08-12 `run_single_node_dispatch` opened a `module_executions`
-- row with `record_started` and never closed it. (Its two siblings — the loop
-- path and the pipeline-step path — did.) Every single-node workflow dispatch
-- therefore sat in `'running'` until the 30-minute stuck-execution sweep
-- rewrote it to `status='timeout'`, `error_type='stuck'`, with the message
-- "Execution timed out — worker did not report completion within the allowed
-- window".
--
-- That message is false for these rows. The worker DID report; nothing on the
-- controller side wrote the report down. Census on the dev fleet, all figures
-- from one read on 2026-08-13: 22,103 rows total, of which 21,592 `timeout`
-- and **0 `completed` in the table's entire history**; 20,747 of the swept
-- rows have a parent `workflow_executions` row whose status is `completed`;
-- and NOT ONE row in the table carries an output payload.
--
-- Their `duration_ms` is equally false — the BEFORE UPDATE trigger
-- `calculate_module_execution_duration` derives it from
-- `completed_at - started_at`, and `completed_at` was stamped by the sweep, so
-- the number records TIME UNTIL THE SWEEP NOTICED, not work time. The minimum
-- WITHIN THE SWEPT POPULATION is 1,800,022 ms: the 30-minute threshold plus
-- 22 ms. The maximum is 216,917,679 ms (~60 h).
--
-- SCOPE THAT MINIMUM CORRECTLY — an earlier draft of this comment called it
-- "the minimum across the whole table", and it is not. Whole-table
-- `min(duration_ms)` is 11 ms, on a `'cancelled'` row; the `'failed'`
-- population's minimum is 17 ms. Both predate this change.
--
-- AND THOSE SUB-SECOND ROWS ARE EVIDENCE, NOT A FOOTNOTE. "Nothing in this
-- table ever gets finalized" OVERSTATES the defect. Two non-sweep terminal
-- writers demonstrably work, and the sub-second durations are the proof —
-- 327 of the 491 non-`timeout` terminal rows are under a second, which no
-- sweep-stamped row can be.
--
--   * 486 `'cancelled'` rows carry the verbatim message "Workflow failed —
--     parallel sibling cancelled", from the node hook's sibling-cancel UPDATE
--     in `talos-engine/src/node_hook.rs`.
--   * 4 `'failed'` rows carry `Execution failed: {"error": ...}` — the exact
--     shape of `talos-webhooks/src/router.rs:1383`
--     (`format!("Execution failed: {}", result.output_payload.value())`, hence
--     a JSON object after the prefix), written through
--     `ModuleExecutionService::fail_execution_from_worker`. What is evidenced
--     is the FINALIZE writer, not which INSERT opened them: they date from
--     2026-07-17, before `insert_webhook_module_execution` existed (#619,
--     2026-07-31), and they carry a non-NULL parent, so the opener is not
--     established and this comment does not guess. (`talos-worker-runtime`
--     formats the same prefix over a bare error string rather than a JSON
--     object, and never writes this column.)
--
-- The defect being fixed is therefore specific — the ENGINE's single-node
-- dispatch path never closed the row it opened — and not a claim that the
-- table has no working writers. Stating it the broad way would have made the
-- guard added to `record_completed` look like belt-and-braces; the
-- sibling-cancel writer above is exactly what that guard protects against.
--
-- WHAT THIS MIGRATION DELIBERATELY DOES NOT DO
-- --------------------------------------------
-- It does NOT resurrect these rows as `'completed'`, for two independent
-- reasons, each sufficient on its own:
--
--  1. NOT ONE row in the table carries an output payload — `output_data` and
--     `output_data_enc` are both NULL for all 22,103, because the sweep never
--     had an output to write. `'completed'` is precisely the status
--     `WorkflowRepository::list_completed_module_executions` selects on to
--     build `replay_module_regression`'s corpus, and
--     `find_latest_completed_execution_io` likewise. Backfilling would swap
--     an EMPTY corpus for a corpus of 20,747 empty baselines — replay would
--     then diff live output against NULL. A silent no-op is a better failure
--     than a loud wrong answer.
--
--  2. "The parent workflow completed" does not entail "this node succeeded".
--     A node can fail under `continue_on_error` (or be skipped, or return an
--     `__error` envelope) while its workflow still reaches `completed`. The
--     predicate is a good filter for "the ledger was broken here"; it is not
--     evidence about the node's outcome. We do not know these nodes'
--     outcomes and this migration does not pretend to.
--
-- It also leaves `status` alone. The CHECK constraint admits only
-- pending/running/completed/failed/timeout/cancelled, and every reader in the
-- workspace routes on those six; inventing a seventh would need each of them
-- audited. `'timeout'` remains defensible as a literal statement about the
-- LEDGER — no completion was ever recorded — while `error_type` is the field
-- that carries the CAUSE, and `'stuck'` (a worker that died) is the part that
-- was never true.
--
-- WHAT IT DOES
-- ------------
-- For rows the sweep converted whose parent workflow COMPLETED:
--   * `error_type`    'stuck' -> 'ledger_unfinalized'
--   * `error_message` replaced with an honest description
--   * `duration_ms`   -> NULL (it measured the sweep, not the module)
--
-- `duration_ms` can be set here: the duration trigger only fires when
-- `completed_at` transitions from NULL, and it is already non-NULL on these
-- rows, so this UPDATE will not recompute it.
--
-- Idempotent: re-running matches nothing (the predicate requires
-- `error_type = 'stuck'`, which the first run clears).
--
-- THE PREDICATE IS CONSERVATIVE, NOT CORRECT — SAY SO
-- ---------------------------------------------------
-- The inner JOIN to `workflow_executions` excludes two populations, and an
-- earlier draft of the change described them as "correctly left as genuine
-- `'stuck'`". That is not established, and the difference matters because
-- everything left behind keeps a message this same migration calls false.
--
--   * ORPHANS — 833 rows on the dev fleet (3.9%) whose `workflow_execution_id`
--     is NON-NULL but resolves to no `workflow_executions` row, so the JOIN
--     drops them. WHY it dangles is not established and this comment does not
--     guess: there is NO foreign key on `module_executions
--     .workflow_execution_id` (checked — the table's FKs are user_id,
--     module_id, payload_enc_key_id, org_id, actor_id), so the id could name a
--     parent that was later deleted (execution archival and cleanup are real
--     mechanisms) or one that never existed. What IS clear is that neither
--     reading says anything about whether a WORKER died — and these rows are,
--     if anything, more likely instances of the same engine gap, having been
--     produced by the same dispatch path over the same period. Their parents'
--     outcome cannot be re-derived, so they are left alone. That is a decision
--     to not assert, not a finding.
--   * FAILED PARENTS — 6 rows. Here the ambiguity is real in both directions:
--     the workflow failed, so a genuinely dead worker is plausible, and so is
--     the ledger gap. Same treatment, same reason.
--
-- Net: the relabel is deliberately UNDER-inclusive. A row that keeps
-- `'stuck'` is not thereby certified as a real worker death; it is a row this
-- migration declined to make a claim about. Widening the predicate would need
-- evidence we do not have.
--
-- On validation: the batching, idempotency and exclusion behaviour were
-- exercised on a throwaway database seeded with SYNTHETIC rows (the live
-- database was never written). The 833 real orphans were never seen by it —
-- and the synthetic stand-ins were not even the same shape: they carried
-- `workflow_execution_id IS NULL`, whereas every real orphan has a NON-NULL id
-- that resolves to no row (the live table has never held a NULL-parent row at
-- all). Both are dropped by the same inner JOIN, so the exclusion BEHAVIOUR is
-- what was proven; the real excluded population was not characterised.
--
-- WHO READS `error_type = 'ledger_unfinalized'`
-- --------------------------------------------
-- Named explicitly, because in a change whose thesis is "a state nobody
-- checks is the defect", writing a new value nothing consumes would be the
-- same mistake one level up.
--
-- `module_executions.error_type` is a DISPLAY column, not a routing one. It
-- has exactly one code writer (the stuck-execution sweep,
-- `talos-module-executions/src/lib.rs`) and NO code path in the workspace
-- branches on its value — not on the pre-existing `'stuck'` either. What it
-- has is a read path to a human:
--
--   `ModuleExecutionService::get_execution` / `list_executions` select it into
--   `ModuleExecution.error_type` → `talos-api`'s GraphQL `ModuleExecution`
--   (`talos-api/src/schema/types.rs`) → the `moduleExecutionHistory` query.
--
-- So the value IS consumed, by the reader it is for: the operator (or the
-- assistant triaging on their behalf) looking at why a node's row says what it
-- says. That is the whole job here — the row previously asserted "worker did
-- not report completion", which is a specific, actionable, and FALSE claim
-- that sends an operator to look at worker health. `'ledger_unfinalized'`
-- retracts the claim rather than making a new one.
--
-- The alternative — a routing predicate, or a seventh `status` value — was
-- rejected deliberately: `status` is what every reader in the workspace
-- switches on, and adding a value means auditing all of them, for rows whose
-- module outcomes are genuinely unknown. A label with no branch behind it is
-- the right size for information that is only ever "do not trust the other
-- columns on this row".
--
-- The migration's own `error_type = 'stuck'` predicate is the second consumer,
-- and the one that makes re-running a no-op.
--
-- Batched with per-batch exception handling per CLAUDE.md's migration rules.
-- The nested BEGIN/EXCEPTION creates an implicit SAVEPOINT so a single bad
-- batch cannot abort the whole migration. Batching (rather than one statement
-- per row) is the right granularity here: the work is a column rewrite with
-- no per-row logic that can fail differently, and 21k single-row UPDATEs
-- inside one transaction is needless lock churn.
--
-- allow-actor-memory-sql: not actor_memory — this is module_executions.

DO $$
DECLARE
    batch_size CONSTANT int := 2000;
    touched    int;
    total      int := 0;
BEGIN
    LOOP
        BEGIN
            WITH candidates AS (
                SELECT m.id
                FROM module_executions m
                JOIN workflow_executions w ON w.id = m.workflow_execution_id
                WHERE m.status = 'timeout'
                  AND m.error_type = 'stuck'
                  AND w.status = 'completed'
                LIMIT batch_size
            )
            UPDATE module_executions m
            SET error_type = 'ledger_unfinalized',
                error_message = 'Never finalized by the engine (pre-2026-08-12 '
                                || 'single-node dispatch gap); converted by the '
                                || 'stuck-execution sweep. The recorded outcome and '
                                || 'duration are not evidence about this module run.',
                duration_ms = NULL
            FROM candidates c
            WHERE m.id = c.id;

            GET DIAGNOSTICS touched = ROW_COUNT;
            total := total + touched;
            EXIT WHEN touched = 0;
        EXCEPTION WHEN others THEN
            RAISE WARNING 'relabel_unfinalized_module_executions: batch failed, stopping: %', SQLERRM;
            EXIT;
        END;
    END LOOP;

    RAISE NOTICE 'relabel_unfinalized_module_executions: relabelled % rows', total;
END $$;
