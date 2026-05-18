-- Fix content_hash clobbering in wasm_modules.
--
-- Problem: wasm_modules has a global UNIQUE constraint on content_hash.  Any two
-- installs that compile to the same binary (same content_hash) share a single row.
-- Installing "hmac-signer" with allowed_secrets=["key-a"] and then reinstalling
-- with allowed_secrets=["key-b"] clobbers the first installation — and clobbers
-- any OTHER user's installation of the same module, because the constraint is
-- across ALL users.
--
-- Root cause: binary identity (content_hash) was conflated with logical module
-- identity (UUID).  Security boundaries (allowed_secrets, allowed_hosts,
-- allowed_methods) are per-installation, NOT per-binary.
--
-- Fix: use (user_id, template_id) as the logical identity for catalog and custom
-- sandbox modules.  Each user gets their own row per template.  Reinstalling the
-- same template for the same user updates the single canonical row (preserving
-- the UUID so existing workflow nodes keep working).  Binary bytes are updated
-- on reinstall in case the catalog template source changed.
--
-- content_hash reverts to a non-unique lookup hint (the two non-unique indexes
-- idx_modules_hash and idx_wasm_modules_content_hash_user already exist).

-- 1. Drop the global unique constraint.
ALTER TABLE wasm_modules DROP CONSTRAINT IF EXISTS wasm_modules_content_hash_key;

-- 2. Add per-user per-template unique index (covers catalog + custom sandbox modules).
--    Partial predicate skips rows where either column is NULL to avoid cross-NULL
--    equality weirdness and to allow NULL template_id rows from other insert paths
--    (registry, marketplace) to remain without conflicting.
CREATE UNIQUE INDEX IF NOT EXISTS idx_wasm_modules_user_template
    ON wasm_modules (user_id, template_id)
    WHERE template_id IS NOT NULL AND user_id IS NOT NULL;
