# 2026-09-26 — scrub the decrypted actor memory that earlier releases persisted

**Why.** #960 stopped two writers from copying the decrypted
`__actor_context__` (an actor's memory, otherwise stored only as ciphertext)
into plaintext columns. That fix was forward-only. The live verification of
#960 (`docs/engineering-log/verification/2026-09-26-pr-960-live-verification.md`)
measured what had already been written.

**Measured (reference fleet, 2026-09-26).** A scan of every `text`/`json`/`jsonb`
column in `public` for the key:

| Column | Rows | Shape |
|---|---|---|
| `workflow_executions.input_data` | 3 245 (2026-08-27 → 16:10Z on deploy day) | top-level key of an object, every row; 13 MB of `input_data` |
| `workflow_executions_archive.input_data` | 1 804 | same |
| `execution_events.log_message`, `event_type = 'node_input'` | 22 264 | ≤4 KiB preview, all ending `...(truncated)`, never valid JSON; the object starts ~225 chars in and runs ~3 833 chars on average |
| `workflows`, `workflow_versions`, `modules`, `schema_audit_log` | 2–8 each | the key's NAME in prompts, source and DDL — no data (`"__actor_context__":{` matches 0) |

Rows written after #960 deployed: 0 in every column. So the defect is LIVE
residue, not a live writer.

**Decided.**
- **A migration**, `20260926170000_scrub_persisted_actor_context.sql`, so every
  deployment with the same residue is cleaned on its next upgrade, not only this
  fleet.
- **`input_data`**: `input_data - '__actor_context__'` — exact, every other key
  kept. Guarded by `jsonb_typeof = 'object'`, because `?` also matches a string
  element of an ARRAY and `-` would then delete it.
- **Previews**: they are truncated text, so the object cannot be removed
  structurally and its end cannot be found reliably. The preview is cut where
  `"__actor_context__":{` begins and ends in a marker saying why. A silent cut
  would read as "this node had no actor context" — the misleading-report class.
  Scoped to `node_input`, the only renderer of this preview.
- **Idempotent and write-free on re-run**: each WHERE matches only rows still
  carrying the decrypted OBJECT (`":{`), so a re-run rewrites 0 rows (package X's
  rule: never rewrite a row to the value it holds).
- **Set-based, no per-row savepoint loop**: no statement can raise on a row it
  selects (`-` only on objects; the text rewrite is total).

**Deliberately NOT done.**
- `workflow_executions.output_data_enc`: a pre-#960 `test_workflow_draft` could
  copy the key into `__trigger_input__` there. It is ciphertext under the same
  org DEK as the memory itself, and SQL cannot rewrite it.
- Preserving `workflow_executions.updated_at`: the trigger sets `NOW()`
  unconditionally, and avoiding it needs `ALTER TABLE … DISABLE TRIGGER` (an
  ACCESS EXCLUSIVE lock on a live table under the migrator's 5 s
  `lock_timeout`) or superuser. Measured harmless: the only `updated_at`
  readers select `running`/`resuming` rows (stale sweep, crash recovery), and
  archival/purge key on `completed_at`/`archived_at`.
- Batching: sqlx wraps a migration in one transaction, so batching inside it
  buys nothing.

**Performance.** On a synthetic set at about 3× the fleet's population (9 735
keyed executions among 20 000, 80 000 keyed previews among 100 000) in one
transaction under `lock_timeout = 5s`: 188 ms + 892 ms. A re-run takes 45 ms
and updates 0 rows. The fleet's real previews compress worse than the
synthetic ones, so expect a small multiple of that.

**Proof.** `controller/tests/actor_context_scrub_tests.rs` (migrated harness)
replays the migration's own SQL against fixtures of each stored shape. Its
controls are an unkeyed row, an ARRAY `input_data` containing the key string, a
preview naming the key as a string, an unkeyed preview and a `node_completed`
event. It asserts the controls are byte-identical AND unwritten (`xmin`), that
nothing decrypted remains, and that a re-run changes no `xmin`. Mutation
proof (a data-at-rest control), each caught at its intended assertion:

| Mutation | Caught by |
|---|---|
| drop the `jsonb_typeof` guard | array control rewritten |
| preview UPDATE matches nothing | preview assertion |
| drop the `event_type` scope | `node_completed` control rewritten |
| match `"__actor_context__":` instead of `":{` | re-run rewrites the scrubbed row |
| archive UPDATE matches nothing | archive assertion |
| live UPDATE matches nothing | live assertion |

**Stated limits.**
- Backups taken before the upgrade keep the plaintext until they rotate out.
  That covers the daily `pg_dump` PVC/volume (7 days) and any off-host copy.
- A preview's text after the object is lost with it: the keys that sort after
  `__actor_context__` and fit before the 4 KiB cut. These are historical
  debugging previews of completed runs (≤30 days old); readers already handled
  them as non-JSON truncated text.
- Outside Postgres: the retained controller and worker container logs hold 0
  lines mentioning the key. Traces and Redis were not checked.
