-- Add UNIQUE constraint on (workflow_id, input_hash) so ON CONFLICT DO UPDATE works.
-- Drops the plain B-tree index added in 20260406000002 (replaced by the unique index).
-- Any duplicate rows are de-duped by keeping the row with the highest hit_count
-- (i.e. the most-used entry), then the newer row for ties.

-- Remove duplicates before adding the constraint.
DELETE FROM semantic_execution_cache
WHERE id IN (
    SELECT id FROM (
        SELECT id,
               ROW_NUMBER() OVER (
                   PARTITION BY workflow_id, input_hash
                   ORDER BY hit_count DESC, created_at DESC
               ) AS rn
        FROM semantic_execution_cache
    ) ranked
    WHERE rn > 1
);

-- Drop the plain index (the unique index below supersedes it).
DROP INDEX IF EXISTS idx_exec_cache_workflow_hash;

-- Unique constraint / index used by ON CONFLICT (workflow_id, input_hash).
CREATE UNIQUE INDEX IF NOT EXISTS idx_exec_cache_workflow_hash_unique
    ON semantic_execution_cache (workflow_id, input_hash);
