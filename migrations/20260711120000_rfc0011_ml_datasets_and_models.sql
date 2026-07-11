-- RFC 0011 P1 — datasets + model registry as first-class platform objects.
--
-- Four tables backing the ML lifecycle (bootstrap → review → train/eval
-- → promote → serve): datasets of labeled examples, and a versioned
-- model registry whose promoted version is what workflows reference by
-- name. See docs/rfcs/0011-ml-models-as-platform-primitives.md.
--
-- Tenancy: org-scoped with the membership-union RLS policy shape
-- (fail-closed, mirroring scratch_sessions / RFC 0004 M4). All four
-- tables are request-plane only in P1 (controller services; workers
-- reach them via controller RPC in P2), so every query path runs on a
-- tenant-scoped transaction from day one — no permissive rollout phase
-- needed.
--
-- Sensitivity: example features are user content (email subjects,
-- snippets, arbitrary workflow data) — encrypted at rest with the
-- per-org AEAD envelope (formats v3 global / v4 per-org, same
-- discipline as actor_memory.value_enc). Labels, embeddings, and
-- metrics are derived/less-sensitive and stored plain (embedding
-- posture matches actor_memory.embedding).

-- ── Datasets ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ml_datasets (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id      UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    task_type   TEXT NOT NULL CHECK (task_type IN
                    ('classification', 'regression', 'forecasting', 'ranking')),
    -- JSON Schema-ish description of the feature shape; documentation +
    -- append-time validation input, not DB-enforced.
    schema_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One name per owner (personal) / per org (shared) — partial pair, same
-- shape as other nameable resources.
CREATE UNIQUE INDEX IF NOT EXISTS idx_ml_datasets_user_name
    ON ml_datasets (user_id, name) WHERE org_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_ml_datasets_org_name
    ON ml_datasets (org_id, name) WHERE org_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS ml_examples (
    id              UUID PRIMARY KEY,
    dataset_id      UUID NOT NULL REFERENCES ml_datasets(id) ON DELETE CASCADE,
    -- Denormalized tenancy columns so RLS applies without a join.
    user_id         UUID NOT NULL,
    org_id          UUID,
    -- Encrypted feature payload (AEAD envelope; v3 = global DEK,
    -- v4 = per-org root DEK). AAD binds (dataset_id, example id).
    -- features_key_id names the DEK row (decrypt_versioned resolves
    -- global-or-org by id), same triple as actor_memory.
    features_enc    BYTEA NOT NULL,
    features_key_id UUID NOT NULL,
    features_format SMALLINT NOT NULL CHECK (features_format IN (3, 4)),
    -- Target: {"label": "..."} for classification, {"value": n} for
    -- regression, etc. Plain JSONB — labels are category names, not
    -- user content.
    label_json      JSONB NOT NULL,
    -- Local-nomic embedding of the feature TEXT (label deliberately
    -- excluded from the embedded text so inference-time queries share
    -- the training geometry). NULL for non-text datasets.
    embedding       vector(768),
    source          TEXT NOT NULL CHECK (source IN
                        ('llm_bootstrap', 'correction', 'llm_fallback',
                         'import', 'synthetic')),
    -- Assigned lazily by the eval harness (stratified); NULL = unsplit.
    split           TEXT CHECK (split IN ('train', 'holdout')),
    -- Upsert/dedupe key (e.g. gmail message id). A correction row
    -- REPLACES the bootstrap row for the same key (upsert), so
    -- authoritative labels win without tombstone logic.
    example_key     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ml_examples_dedupe
    ON ml_examples (dataset_id, example_key) WHERE example_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ml_examples_dataset
    ON ml_examples (dataset_id, created_at);
CREATE INDEX IF NOT EXISTS idx_ml_examples_dataset_split
    ON ml_examples (dataset_id, split);
-- ivfflat over cosine, matching the workflows-embedding index posture.
-- lists=20 is fine for the 1k-100k rows P1 targets; revisit at scale.
CREATE INDEX IF NOT EXISTS idx_ml_examples_embedding
    ON ml_examples USING ivfflat (embedding vector_cosine_ops) WITH (lists = 20);

-- ── Model registry ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ml_models (
    id                    UUID PRIMARY KEY,
    user_id               UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id                UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,
    task_type             TEXT NOT NULL CHECK (task_type IN
                              ('classification', 'regression',
                               'forecasting', 'ranking')),
    dataset_id            UUID REFERENCES ml_datasets(id) ON DELETE SET NULL,
    -- FK added below (circular with ml_model_versions).
    production_version_id UUID,
    -- Backend-specific knobs: {"k": 7, "confidence_threshold": 0.6,
    -- "fallback": {"provider": "ollama", "model": "...", ...}}.
    config_json           JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ml_models_user_name
    ON ml_models (user_id, name) WHERE org_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_ml_models_org_name
    ON ml_models (org_id, name) WHERE org_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS ml_model_versions (
    id              UUID PRIMARY KEY,
    model_id        UUID NOT NULL REFERENCES ml_models(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL,
    org_id          UUID,
    version         INT NOT NULL,
    backend         TEXT NOT NULL CHECK (backend IN
                        ('llm', 'knn-pgvector', 'classical',
                         'statistical', 'onnx')),
    -- Serialized model parameters / ONNX bytes. NULL for lazy backends
    -- (llm, knn-pgvector) whose "artifact" is config + the dataset.
    artifact        BYTEA,
    artifact_sha256 TEXT,
    -- Eval results: per-class precision/recall/F1, latency percentiles,
    -- holdout fingerprint, baseline comparison. Written by eval_model.
    metrics_json    JSONB NOT NULL DEFAULT '{}'::jsonb,
    trained_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status          TEXT NOT NULL DEFAULT 'trained' CHECK (status IN
                        ('trained', 'promoted', 'retired')),
    CONSTRAINT ml_model_versions_artifact_integrity CHECK (
        (artifact IS NULL) = (artifact_sha256 IS NULL)
    ),
    UNIQUE (model_id, version)
);

ALTER TABLE ml_models
    ADD CONSTRAINT fk_ml_models_production_version
    FOREIGN KEY (production_version_id)
    REFERENCES ml_model_versions(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_ml_model_versions_model
    ON ml_model_versions (model_id, version DESC);

-- ── RLS (fail-closed, membership-union shape) ────────────────────────

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['ml_datasets', 'ml_examples',
                             'ml_models', 'ml_model_versions']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS %I_tenant_isolation ON %I', t, t);
        EXECUTE format(
            'CREATE POLICY %I_tenant_isolation ON %I USING (
                user_id = NULLIF(current_setting(''app.current_user_id'', true), '''')::uuid
                OR org_id = ANY(
                     string_to_array(NULLIF(current_setting(''app.current_org_ids'', true), ''''), '','')::uuid[]
                   )
            )', t, t);
    END LOOP;
END $$;
