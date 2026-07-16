-- GCP Phase D: add the 'full' consent tier to google_cloud_integrations.
--
-- The full tier holds a broad cloud-platform consent used ONLY
-- controller-side to mint short-lived impersonated service-account tokens
-- (iamcredentials.generateAccessToken). Its tokens are host-reserved
-- (is_controller_internal_vault_path reserves the whole
-- oauth/google_cloud_full/* subtree) and never reach a guest — a module
-- receives the scoped-down minted token instead.
--
-- Widen the tier CHECK from ('read','write') to include 'full'. Follows the
-- follow-up-migration rule (never edit 20260715130000, which introduced the
-- two-value CHECK): drop and re-add the named constraint.

ALTER TABLE google_cloud_integrations
    DROP CONSTRAINT IF EXISTS google_cloud_integrations_tier_check;

DO $$
BEGIN
    ALTER TABLE google_cloud_integrations
        ADD CONSTRAINT google_cloud_integrations_tier_check
        CHECK (tier IN ('read', 'write', 'full'));
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;
