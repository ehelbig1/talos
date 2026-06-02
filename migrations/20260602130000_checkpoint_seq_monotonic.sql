-- Monotonic checkpoint sequencing.
--
-- Per-node checkpoint saves are fire-and-forget (`tokio::spawn`), so two
-- writes for the same execution race: a save capturing N completed nodes
-- can land in Postgres AFTER a save capturing N+k nodes. Without a guard
-- the older (smaller) snapshot overwrites the newer one and a crash-resume
-- then re-runs the trailing nodes that were already durably checkpointed —
-- bounded progress loss, but real.
--
-- `checkpoint_seq` records the cardinality of the snapshot last written
-- (the count of completed nodes — monotonically increasing over an
-- execution's lifetime, and it continues to grow across a resume boundary
-- because the resumed engine re-seeds its result map from the loaded
-- checkpoint). `ControllerCheckpointStore::save` now writes only when the
-- incoming seq is >= the stored seq, so a reordered stale write is a clean
-- no-op. DEFAULT 0 makes every existing row accept its first new save.
ALTER TABLE workflow_executions
    ADD COLUMN IF NOT EXISTS checkpoint_seq BIGINT NOT NULL DEFAULT 0;
