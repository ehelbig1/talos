-- RFC 0011 P1 follow-up: ml_examples.embedding must match the
-- platform's embedding dimensionality, which has been 1024
-- (mxbai-embed-large / Voyage-class) since 20260429120000 resized every
-- embedding column — the P1a migration hardcoded vector(768) (the old
-- nomic default) and shipped before any deployment applied it. Ship the
-- correction as a follow-up migration per the Migration Rules (never
-- edit a merged migration), not an in-place edit.
--
-- Safe unconditionally: the P1a table is brand-new, so either it is
-- empty (nothing to re-embed) or it only holds rows whose embeddings
-- were degraded to NULL by the dimensionality guard — the ALTER loses
-- nothing either way.
DROP INDEX IF EXISTS idx_ml_examples_embedding;
ALTER TABLE ml_examples
    ALTER COLUMN embedding TYPE vector(1024) USING NULL;
CREATE INDEX IF NOT EXISTS idx_ml_examples_embedding
    ON ml_examples USING ivfflat (embedding vector_cosine_ops) WITH (lists = 20);
