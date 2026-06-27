-- Per-tenant root DEKs, Phase 1 (foundation, NON-BREAKING).
--
-- Today there is ONE global active DEK for the whole system; per-row isolation
-- is only the HKDF-derived per-context subkey (format v3). This phase scopes the
-- root DEK to the ORGANIZATION (the platform's tenant, per RFC 0004/0005) so a
-- compromised root key caps blast radius to a single org rather than everything.
--
-- This migration adds ONLY the schema substrate. No table starts writing the
-- new per-org format (v4) yet — that happens table-by-table in later phases,
-- lazily, while old global-DEK rows (v0/v1/v3) keep decrypting unchanged.
--
--   org_id IS NULL      → the legacy/global DEK (every existing row references it)
--   org_id IS NOT NULL  → a per-organization root DEK (v4 writers, later phases)
--
-- ON DELETE RESTRICT mirrors the value_key_id discipline: a tenant's root key is
-- key material protecting that tenant's data and must not vanish casually. (The
-- data rows themselves already RESTRICT-pin their DEK via *_key_id, so a DEK is
-- undeletable while data references it regardless.) Tenant-deletion ordering
-- (purge data → drop DEK → drop org) is a later-phase concern; no org has a DEK
-- yet, so RESTRICT is inert today.

ALTER TABLE encryption_keys
    ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE RESTRICT;

COMMENT ON COLUMN encryption_keys.org_id IS
    'Tenant scope of this root DEK. NULL = the legacy GLOBAL DEK (one system-wide '
    'key; every v0/v1/v3 row references it). NOT NULL = a per-organization root '
    'DEK used by v4 writers, so a compromised root key is bounded to one org. '
    'Selection: global paths query (active AND org_id IS NULL); per-org paths '
    'query (active AND org_id = $1).';

-- Exactly one active root DEK per organization. Also closes the rotate-DEK
-- TOCTOU at the schema level for the per-org path (the global path historically
-- relied only on an advisory lock — see rotate_dek's MCP-700 note).
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_dek_per_org
    ON encryption_keys (org_id)
    WHERE active AND org_id IS NOT NULL;

-- At most one active GLOBAL (legacy) DEK. Strengthens the previously
-- advisory-lock-only "exactly one active" invariant for the global key now that
-- per-org actives coexist in the same table. (Indexing the constant-true `active`
-- column under the partial predicate => all qualifying rows share one value =>
-- at most one row.)
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_global_dek
    ON encryption_keys (active)
    WHERE active AND org_id IS NULL;
