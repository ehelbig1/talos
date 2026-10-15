-- The per-user ceiling on stored ML examples (security review 2026-10-14,
-- I-1) counts a user's rows before every append:
-- `SELECT COUNT(*) FROM ml_examples WHERE user_id = $1`. No index led with
-- user_id (the table's are keyed on dataset_id), so the count was a scan.
CREATE INDEX IF NOT EXISTS idx_ml_examples_user ON ml_examples (user_id);
