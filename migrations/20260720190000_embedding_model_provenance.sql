-- Embedding-model provenance (AI-arch review 2026-07-20, R1).
--
-- Stored vectors were only guarded by a DIMENSION check — two models
-- with the same dimensionality (768 is ubiquitous) would silently mix
-- incomparable vector spaces across knn/semantic reads after a model
-- swap. Every row that carries an embedding now records WHICH model
-- produced it; semantic reads filter to the active model (fail-closed:
-- rows from other models are invisible until re-embedded, degrading
-- recall, never correctness).
--
-- NULL = legacy row. The controller's startup grandfather-backfill
-- stamps legacy rows with the currently-configured model on first boot
-- after this migration (a true statement as long as the operator does
-- not change EMBEDDING_MODEL in the same deploy — release notes call
-- this out). After that backfill, reads are strict-equality.

ALTER TABLE actor_memory ADD COLUMN IF NOT EXISTS embedding_model text;
ALTER TABLE ml_examples ADD COLUMN IF NOT EXISTS embedding_model text;

-- The semantic-read hot paths already use the vector indexes; the
-- model filter is a cheap residual predicate. One partial index serves
-- the re-embed sweeps' "wrong-model rows" scans:
CREATE INDEX IF NOT EXISTS idx_actor_memory_embed_model
    ON actor_memory (embedding_model) WHERE embedding IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ml_examples_embed_model
    ON ml_examples (embedding_model) WHERE embedding IS NOT NULL;
