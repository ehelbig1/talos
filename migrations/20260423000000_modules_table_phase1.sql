-- Phase 1.1 of module entity unification (docs/module-entity-consolidation.md).
--
-- Creates the new unified `modules` table that will eventually replace the
-- `node_templates` + `wasm_modules` dual-row model. Today's writers continue
-- to write to the OLD tables; this migration only creates the new schema +
-- backfills existing rows so dual-write code paths can be added incrementally
-- without losing the legacy corpus.
--
-- Phase progression:
--   1.1 (THIS) — schema + backfill from existing tables
--   1.2  — write paths add dual-write to `modules` (compile_custom_sandbox first)
--   1.3  — reconciliation job sweeps anything missed by 1.2
--   2    — read path adds modules-first lookup with old-table fallback
--   3    — read path becomes modules-only
--   4    — drop old tables + rewrite graph_json refs
--
-- Reads continue exclusively against `node_templates`/`wasm_modules` until
-- Phase 2 — this migration is purely additive and safe to run on a live
-- system at any time.

CREATE TABLE IF NOT EXISTS modules (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- NULL for catalog entries (system-owned, shared across users); set for
    -- user-compiled sandbox + extracted modules. ON DELETE CASCADE so user
    -- cleanup also removes their modules — same semantics as wasm_modules.
    user_id               UUID REFERENCES users(id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,
    -- Replaces the implicit (category + has-wasm-bytes) typing on the old
    -- pair. The CHECK matches the Rust validator (workflow_creation_helpers
    -- pattern) — operators can't bypass via direct INSERT.
    kind                  TEXT NOT NULL
                          CHECK (kind IN ('catalog', 'sandbox', 'extracted')),
    display_name          TEXT,
    description           TEXT,
    capability_world      TEXT NOT NULL DEFAULT 'minimal-node',
    config_schema         JSONB NOT NULL DEFAULT '{}'::jsonb,
    input_schema          JSONB,
    output_schema         JSONB,
    allowed_hosts         TEXT[] NOT NULL DEFAULT '{}',
    allowed_methods       TEXT[] NOT NULL DEFAULT '{}',
    allowed_secrets       TEXT[] NOT NULL DEFAULT '{}',
    requires_approval_for TEXT[] NOT NULL DEFAULT '{}',
    max_retries           INTEGER NOT NULL DEFAULT 0,
    retry_backoff_ms      BIGINT NOT NULL DEFAULT 500,
    rate_limit_per_minute INTEGER,
    -- Compile artifact columns. Nullable for catalog entries served via OCI
    -- pull-on-dispatch; populated for sandbox/extracted at creation.
    source_code           TEXT,
    wasm_bytes            BYTEA,
    content_hash          TEXT,
    size_bytes            INTEGER,
    max_fuel              BIGINT DEFAULT 2000000,
    oci_url               TEXT,
    integration_name      TEXT
                          CHECK (
                              integration_name IS NULL
                              OR (length(integration_name) BETWEEN 1 AND 64
                                  AND integration_name ~ '^[a-z0-9_-]+$')
                          ),
    language              TEXT NOT NULL DEFAULT 'rust',
    usage_count           BIGINT NOT NULL DEFAULT 0,
    last_used_at          TIMESTAMPTZ,
    -- Forwarding alias to the legacy table id. Lets graph_json blobs that
    -- carry an old node_templates.id keep resolving during Phases 1–3 via
    -- a fallback lookup `WHERE id = $1 OR legacy_template_id = $1`. Dropped
    -- in Phase 4 after the one-shot graph_json rewrite.
    legacy_template_id    UUID,
    legacy_wasm_module_id UUID,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    compiled_at           TIMESTAMPTZ,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Two name-uniqueness scopes: per-user for sandbox/extracted, global for catalog.
-- Partial indexes so each scope is enforced independently.
CREATE UNIQUE INDEX IF NOT EXISTS modules_user_name_uniq
    ON modules (user_id, name)
    WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS modules_catalog_name_uniq
    ON modules (name)
    WHERE user_id IS NULL;

-- Hot-path indexes for read patterns the dual-row tables already serve:
--   - list user's modules ordered by recency
--   - look up by legacy template id (fallback during Phase 2)
--   - look up by legacy wasm_module id (fallback during Phase 2)
--   - filter by kind (e.g. "show only catalog modules")
CREATE INDEX IF NOT EXISTS modules_user_kind_updated
    ON modules (user_id, kind, updated_at DESC);
CREATE INDEX IF NOT EXISTS modules_legacy_template_id
    ON modules (legacy_template_id)
    WHERE legacy_template_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS modules_legacy_wasm_module_id
    ON modules (legacy_wasm_module_id)
    WHERE legacy_wasm_module_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS modules_kind
    ON modules (kind);

-- Trigger: keep updated_at fresh on every UPDATE.
CREATE OR REPLACE FUNCTION modules_touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS modules_set_updated_at ON modules;
CREATE TRIGGER modules_set_updated_at
    BEFORE UPDATE ON modules
    FOR EACH ROW EXECUTE FUNCTION modules_touch_updated_at();

-- ────────────────────────────────────────────────────────────────────────
-- Backfill from the existing dual-row tables.
--
-- Safe to re-run: ON CONFLICT DO NOTHING means subsequent runs no-op for
-- rows already present. Two passes:
--   Pass A: every wasm_modules row → modules row (kind='sandbox' if
--           there's no node_templates sibling, else picks up template metadata).
--   Pass B: every node_templates row WITHOUT a wasm_modules sibling
--           → modules row with no compile artifact (kind='catalog').
--
-- The backfill commits inside the migration transaction. For deployments
-- with massive (>100K) module corpora the per-row UPSERT is acceptable —
-- it's a one-time cost. If a future deployment hits scale issues, switch
-- to a separate background reconciliation job (Phase 1.3).
-- ────────────────────────────────────────────────────────────────────────

-- Pass A: wasm_modules → modules (typically the user-compiled sandbox set)
INSERT INTO modules (
    id, user_id, name, kind, capability_world, config_schema,
    allowed_hosts, allowed_methods, allowed_secrets,
    max_retries, rate_limit_per_minute,
    source_code, wasm_bytes, content_hash, size_bytes, max_fuel,
    integration_name, language,
    usage_count, last_used_at,
    legacy_template_id, legacy_wasm_module_id,
    created_at, compiled_at, updated_at
)
SELECT
    -- Use the wasm_modules.id as the primary key — most graph_json refs
    -- already point at this id, so reads can resolve without consulting
    -- legacy_wasm_module_id during Phase 2.
    w.id,
    w.user_id,
    -- Disambiguate against catalog templates that share a name with a
    -- user's wasm_modules row. The partial unique index splits scopes by
    -- user_id IS NULL vs NOT NULL — collisions can only happen WITHIN a
    -- scope, and wasm_modules rows always have a user_id.
    w.name,
    -- kind: 'catalog' if joined to a system-owned template, 'sandbox' if
    -- user-owned (the common case), 'extracted' inferred when the
    -- node_templates row has no source_template_id (the inline-rust path).
    -- Conservative default: 'sandbox' covers user-compiled modules.
    CASE
        WHEN t.user_id IS NULL AND t.id IS NOT NULL THEN 'catalog'
        WHEN t.id IS NOT NULL AND t.code_template IS NULL THEN 'sandbox'
        WHEN t.id IS NULL THEN 'sandbox'
        ELSE 'sandbox'
    END,
    COALESCE(t.capability_world, 'minimal-node'),
    COALESCE(t.config_schema, '{}'::jsonb),
    COALESCE(t.allowed_hosts, w.allowed_hosts, ARRAY[]::TEXT[]),
    COALESCE(t.allowed_methods, ARRAY[]::TEXT[]),
    COALESCE(t.allowed_secrets, w.allowed_secrets, ARRAY[]::TEXT[]),
    COALESCE(t.max_retries, 0),
    w.rate_limit_per_minute,
    w.source_code,
    w.wasm_bytes,
    w.content_hash,
    w.size_bytes,
    COALESCE(w.max_fuel, 2000000),
    w.integration_name,
    'rust',
    COALESCE(w.usage_count, 0),
    -- wasm_modules tracks last_used (no `_at` suffix); preserve as-is.
    w.last_used,
    t.id,
    w.id,
    w.compiled_at,
    w.compiled_at,
    -- wasm_modules has no updated_at column; compiled_at is the closest
    -- proxy (set on every successful compile / hot_update).
    COALESCE(w.compiled_at, NOW())
FROM wasm_modules w
LEFT JOIN node_templates t ON t.id = w.template_id
ON CONFLICT (id) DO NOTHING;

-- Pass B: node_templates rows WITHOUT a wasm_modules sibling — typically
-- catalog templates served via OCI pull or precompiled_wasm. These don't
-- have a wasm_modules.id; we fabricate a fresh modules.id but record the
-- legacy_template_id so old graph_json refs still resolve.
INSERT INTO modules (
    id, user_id, name, kind, capability_world, config_schema,
    allowed_hosts, allowed_methods, allowed_secrets,
    max_retries, rate_limit_per_minute,
    source_code, wasm_bytes, content_hash, size_bytes, max_fuel,
    integration_name, language,
    legacy_template_id,
    created_at, updated_at
)
SELECT
    gen_random_uuid(),
    t.user_id,
    t.name,
    CASE
        WHEN t.user_id IS NULL THEN 'catalog'
        WHEN t.code_template IS NULL THEN 'sandbox'
        ELSE 'sandbox'
    END,
    COALESCE(t.capability_world, 'minimal-node'),
    COALESCE(t.config_schema, '{}'::jsonb),
    COALESCE(t.allowed_hosts, ARRAY[]::TEXT[]),
    COALESCE(t.allowed_methods, ARRAY[]::TEXT[]),
    COALESCE(t.allowed_secrets, ARRAY[]::TEXT[]),
    COALESCE(t.max_retries, 0),
    NULL,
    t.code_template,
    t.precompiled_wasm,
    NULL,
    -- size_bytes from precompiled_wasm length when available
    CASE
        WHEN t.precompiled_wasm IS NOT NULL
        THEN length(t.precompiled_wasm)::INTEGER
        ELSE NULL
    END,
    2000000,
    NULL,
    'rust',
    t.id,
    -- node_templates doesn't track updated_at; use created_at for both.
    -- The trigger keeps updated_at fresh on subsequent UPDATEs.
    COALESCE(t.created_at, NOW()),
    COALESCE(t.created_at, NOW())
FROM node_templates t
WHERE NOT EXISTS (
    SELECT 1 FROM wasm_modules w WHERE w.template_id = t.id
)
ON CONFLICT DO NOTHING;

COMMENT ON TABLE modules IS
    'Unified module entity (Phase 1 of module-entity-consolidation). Replaces node_templates + wasm_modules. Reads still go to the legacy tables; new writes dual-write here. See docs/module-entity-consolidation.md.';
COMMENT ON COLUMN modules.legacy_template_id IS
    'Forwarding alias to node_templates.id during the migration window. Dropped in Phase 4.';
COMMENT ON COLUMN modules.legacy_wasm_module_id IS
    'Forwarding alias to wasm_modules.id during the migration window. Dropped in Phase 4.';
COMMENT ON COLUMN modules.kind IS
    'Module classification: catalog (system-owned, shared), sandbox (user-compiled), extracted (hoisted from inline rust_code in a workflow node).';
