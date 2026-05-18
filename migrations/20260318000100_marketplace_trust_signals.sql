-- Add trust signals to the module marketplace.
-- verified: manually set by platform admins to indicate a well-tested module.
-- star_count: user-driven quality signal; incremented via star_module MCP tool.
ALTER TABLE module_marketplace
    ADD COLUMN IF NOT EXISTS verified boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS star_count integer NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_marketplace_stars ON module_marketplace(star_count DESC);
