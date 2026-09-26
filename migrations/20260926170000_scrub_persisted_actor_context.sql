-- Scrub decrypted actor memory that earlier releases persisted in PLAINTEXT.
--
-- `__actor_context__` is the engine-authored key carrying an actor's DECRYPTED
-- memory into a node's input. Actor memory is stored only as ciphertext
-- (`actor_memory.value_enc`, per-context AEAD subkeys under the org DEK), but
-- before #960 two writers copied the decrypted form into plaintext columns:
--
--   * `workflow_executions.input_data` — the continuation path persisted the
--     merged trigger input, key included. Archival carries the column into
--     `workflow_executions_archive`.
--   * `execution_events.log_message` for `event_type = 'node_input'` — the
--     node-I/O inspector's ≤4 KiB input preview.
--
-- #960 fixed both writers (`lift_actor_context_for_storage`,
-- `WithoutEngineAuthoredKeys`). The fix was forward-only; this removes the rows
-- already written. Measured on the reference fleet 2026-09-26: 3 245 live and
-- 1 804 archived `input_data` rows (key always TOP-LEVEL in an object), and
-- 22 264 `node_input` previews (all truncated at 4 KiB, the object on average
-- ~94% of the text). Zero rows written after the fix deployed.
--
-- Deliberately NOT touched:
--   * `workflow_executions.output_data_enc` — a pre-fix `test_workflow_draft`
--     could copy the key into `__trigger_input__` there, but that column is
--     ciphertext under the same org DEK as the memory itself, and SQL cannot
--     rewrite it.
--   * Mentions of the key NAME in `workflows`, `workflow_versions`, `modules`
--     and `schema_audit_log` (prompts, source code, DDL text) — measured, none
--     holds memory data.
--   * Backups taken before this runs. They age out on their own schedule.
--
-- Every statement is idempotent: its WHERE clause matches only rows that still
-- carry the decrypted OBJECT, so a re-run rewrites nothing. No statement can
-- raise on a row it selects (`-` is applied to objects only; the text rewrite
-- is total), so a set-based UPDATE is safe without a per-row savepoint loop.
-- The `updated_at` trigger bumps `workflow_executions.updated_at` on scrubbed
-- rows; its only readers select `running`/`resuming` rows (stale and crash-
-- recovery sweeps), and archival/purge key on `completed_at`/`archived_at`.

UPDATE workflow_executions
SET input_data = input_data - '__actor_context__'
WHERE jsonb_typeof(input_data) = 'object'
  AND input_data ? '__actor_context__';

UPDATE workflow_executions_archive
SET input_data = input_data - '__actor_context__'
WHERE jsonb_typeof(input_data) = 'object'
  AND input_data ? '__actor_context__';

-- The preview is TRUNCATED text, not JSON (`...(truncated)` suffix), so the
-- object cannot be removed structurally and its end cannot be found reliably.
-- Keys serialise in sorted order and the object runs to the cut on most rows,
-- so the preview is cut where the object starts and ends in a marker that
-- says why, instead of a silent cut that would read as "this node had no
-- actor context". `strpos`/`left` count characters, so the cut is UTF-8 safe.
UPDATE execution_events
SET log_message =
        left(log_message, strpos(log_message, '"__actor_context__":{') - 1)
        || '"__actor_context__":"[scrubbed: decrypted actor memory is not kept in input previews]"'
        || '...(truncated)'
WHERE event_type = 'node_input'
  AND strpos(log_message, '"__actor_context__":{') > 0;
