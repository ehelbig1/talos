-- RFC 0011 P2d — shadow-mode accounting + disagreement log.
--
-- ml_shadow_stats: per-(model, confidence-band) agreement counters,
-- UPSERT-incremented by the engine's DISTILL hook when a model in
-- shadow/hybrid/fast_primary predicts alongside the LLM. Narrow
-- counters instead of a JSONB read-modify-write so concurrent hook
-- fires never race.
--
-- ml_disagreements: the reviewable divergences (fast-vs-LLM label
-- splits and low-confidence samples) the disagreement digest reads.
-- Feature text is ENCRYPTED (per-org AEAD v4, same posture as
-- ml_examples — email-derived content). Capped per model by the hook
-- (oldest-first delete past the cap), so the table stays bounded
-- without a sweeper.

-- Evaluator bookkeeping: skip-if-unchanged (dataset updated_at vs this).
ALTER TABLE ml_models
    ADD COLUMN IF NOT EXISTS last_policy_eval_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS ml_shadow_stats (
    model_id    UUID NOT NULL REFERENCES ml_models(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL,
    org_id      UUID,
    -- Confidence-band lower bound in tenths (0..10) — matches the eval
    -- coverage_curve thresholds so shadow agreement reads against the
    -- same bands the promotion policy uses. Abstentions land in band 0
    -- with total_count only.
    band        SMALLINT NOT NULL CHECK (band BETWEEN 0 AND 10),
    agree_count BIGINT NOT NULL DEFAULT 0,
    total_count BIGINT NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (model_id, band)
);

CREATE TABLE IF NOT EXISTS ml_disagreements (
    id               UUID PRIMARY KEY,
    model_id         UUID NOT NULL REFERENCES ml_models(id) ON DELETE CASCADE,
    user_id          UUID NOT NULL,
    org_id           UUID,
    example_key      TEXT,
    features_enc     BYTEA NOT NULL,
    features_key_id  UUID,
    features_format  SMALLINT NOT NULL DEFAULT 4 CHECK (features_format IN (3, 4)),
    fast_label       TEXT,
    fast_confidence  REAL,
    llm_label        TEXT NOT NULL,
    -- 'divergence' (labels differ) or 'low_confidence' (fast path
    -- abstained / under threshold) — both feed the digest.
    kind             TEXT NOT NULL CHECK (kind IN ('divergence', 'low_confidence')),
    -- One-tap verdict state for the digest loop: pending → resolved
    -- (a correction was appended) / dismissed.
    status           TEXT NOT NULL DEFAULT 'pending'
                         CHECK (status IN ('pending', 'resolved', 'dismissed')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ml_disagreements_model_created
    ON ml_disagreements (model_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ml_disagreements_model_pending
    ON ml_disagreements (model_id, created_at DESC) WHERE status = 'pending';

-- ── RLS (fail-closed, membership-union read + write-pinned) ─────────
-- Same discipline as the sibling ml_* tables (20260711120000): READ is
-- the membership union; WRITE pins user/org per the 2026-06-02
-- write-isolation audit. Backstop behind the app-layer user_id
-- predicates in talos-ml.

ALTER TABLE ml_shadow_stats ENABLE ROW LEVEL SECURITY;
ALTER TABLE ml_shadow_stats FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ml_shadow_stats_tenant_isolation ON ml_shadow_stats;
CREATE POLICY ml_shadow_stats_tenant_isolation ON ml_shadow_stats
USING (
    user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR org_id = ANY(
         string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[]
       )
)
WITH CHECK (
    (
        NULLIF(current_setting('app.current_user_id', true), '') IS NULL
        OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    )
    AND (
        NULLIF(current_setting('app.current_org_id', true), '') IS NULL
        OR org_id IS NULL
        OR org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
    )
);

ALTER TABLE ml_disagreements ENABLE ROW LEVEL SECURITY;
ALTER TABLE ml_disagreements FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ml_disagreements_tenant_isolation ON ml_disagreements;
CREATE POLICY ml_disagreements_tenant_isolation ON ml_disagreements
USING (
    user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR org_id = ANY(
         string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[]
       )
)
WITH CHECK (
    (
        NULLIF(current_setting('app.current_user_id', true), '') IS NULL
        OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    )
    AND (
        NULLIF(current_setting('app.current_org_id', true), '') IS NULL
        OR org_id IS NULL
        OR org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
    )
);
