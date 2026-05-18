-- Re-scope the secrets unique-key from (namespace, key_path) to
-- (namespace, key_path, created_by) so each tenant has its own
-- key_path namespace. The previous global-per-namespace constraint
-- prevented two users from independently storing their own
-- 'anthropic/api_key', forcing operator workarounds with bespoke
-- key paths.
--
-- The new constraint is strictly LESS restrictive than the old one:
-- every existing row trivially satisfies (namespace, key_path,
-- created_by) UNIQUE because (namespace, key_path) was already
-- UNIQUE. No row migration / dedup needed.
--
-- This pairs with r306's atomic-upsert refactor in `set_secret`:
-- INSERT ... ON CONFLICT (key_path, namespace, created_by) DO
-- UPDATE replaces the destroy-then-recreate workaround that today
-- parses Postgres error strings to detect collisions.
--
-- Also adds an index on (name, namespace, created_by) to speed the
-- operator-name-lookup path used by delete_secret /
-- set_secret_namespace / set_secret_expiry / rotate_secret. The
-- existing (namespace, key_path) index still covers the runtime-
-- resolution path.
--
-- Runtime safety: cross-user secret resolution at runtime is
-- already user-scoped via `secrets.created_by = $user_id` in every
-- read path (see SecretsManager::get_secret_by_path,
-- get_secrets_by_paths, etc.). Loosening the DB constraint does
-- NOT widen the runtime resolution surface — it only allows
-- per-tenant key_path collisions that the runtime layer already
-- resolves correctly via user scoping.

ALTER TABLE secrets
    DROP CONSTRAINT IF EXISTS secrets_namespace_key_path_unique;

ALTER TABLE secrets
    ADD CONSTRAINT secrets_namespace_key_path_user_unique
    UNIQUE (namespace, key_path, created_by);

-- Speed up the operator-side lookup paths (delete_secret_by_name,
-- set_secret_namespace, etc. that key off `name`).
CREATE INDEX IF NOT EXISTS idx_secrets_name_namespace_user
    ON secrets (name, namespace, created_by);
