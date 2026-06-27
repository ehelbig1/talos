-- Drop the vestigial `workspace_oci_settings` table.
--
-- Created by migration 032 for a per-workspace OCI-registry-credentials feature
-- that was never wired up: NO live code ever writes it (no INSERT/UPDATE anywhere
-- in the workspace), and OCI credentials are sourced from the env vars
-- `OCI_REGISTRY_USERNAME` / `OCI_REGISTRY_PASSWORD` (see talos-registry::sync +
-- CLAUDE.md). Its `password_encrypted` / `password_nonce` columns have NO crypto
-- code behind them — they only ever misled audits into thinking a bespoke
-- encryption path existed here.
--
-- The dependent trigger (`update_workspace_oci_settings_updated_at`) drops with
-- the table. The platform-state export deny-list entry for this table name is
-- intentionally RETAINED in code as forward-protection (defense in depth) in case
-- the per-workspace-creds feature is ever actually built.

DROP TABLE IF EXISTS workspace_oci_settings;
