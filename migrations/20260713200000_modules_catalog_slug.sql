-- DX #14: stable catalog identity on module rows.
--
-- A module's identity is currently juggled across surfaces: the catalog
-- directory slug for install, the mutable display_name in `modules.name`,
-- and a per-install UUID in workflow graphs. Nothing persisted maps an
-- installed row back to its `module-templates/<slug>` (or OCI template)
-- origin — the root cause of the #480 editor-gate bug class and the
-- catalog-opacity friction (an installed module can't be traced to its
-- template).
--
-- `catalog_slug` records the template slug at seed/install/sync time.
-- NULL for sandbox/extracted modules (they have no catalog origin).
-- Existing catalog rows backfill lazily on the next boot seed / OCI sync
-- / re-install (all three write paths are idempotent upserts that now set
-- the column).

ALTER TABLE modules ADD COLUMN IF NOT EXISTS catalog_slug TEXT;

COMMENT ON COLUMN modules.catalog_slug IS
    'Origin template slug (module-templates/<slug> or OCI template name); NULL for non-catalog modules. Stable under display-name renames.';
