-- GCP Phase C: consent tiers on google_cloud_integrations.
--
-- A user can now hold TWO independently-consented connections per Google
-- account:
--   tier='read'  — provider "google_cloud", scope cloud-platform.read-only
--                  (Phase A; all existing rows).
--   tier='write' — provider "google_cloud_write", scopes pubsub + monitoring
--                  (Phase C provisioning; deliberately NOT cloud-platform so
--                  a leaked write token is bounded server-side by Google to
--                  Pub/Sub + Monitoring).
--
-- Tokens stay in the unified integration_credentials table; the tier's
-- provider string keys the vault path (oauth/google_cloud_write/{user}/
-- {provider_key}/access_token), which is what gives read modules
-- (`requires_secrets: oauth/google_cloud/*`) structural non-access to the
-- write token.
--
-- The (user_id, provider_key) uniqueness widens to include tier so the SAME
-- Google account (provider_key is derived from the immutable account id)
-- can carry one row per tier, and reconnecting a tier UPDATEs its own row.

ALTER TABLE google_cloud_integrations
    ADD COLUMN IF NOT EXISTS tier TEXT NOT NULL DEFAULT 'read';

DO $$
BEGIN
    ALTER TABLE google_cloud_integrations
        ADD CONSTRAINT google_cloud_integrations_tier_check
        CHECK (tier IN ('read', 'write'));
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- Replace the two-column uniqueness with the tier-aware one. The unique
-- INDEX (not constraint) is sufficient for ON CONFLICT inference.
ALTER TABLE google_cloud_integrations
    DROP CONSTRAINT IF EXISTS google_cloud_integrations_user_id_provider_key_key;

CREATE UNIQUE INDEX IF NOT EXISTS idx_google_cloud_integrations_user_pk_tier
    ON google_cloud_integrations (user_id, provider_key, tier);
