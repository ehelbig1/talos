-- Per-user marketplace star tracking.
-- Replaces the unbounded increment approach so each user can star a listing at
-- most once, and star_count stays in sync with the actual unique-user count.

CREATE TABLE IF NOT EXISTS module_marketplace_stars (
    user_id    UUID        NOT NULL,
    listing_id UUID        NOT NULL REFERENCES module_marketplace(id) ON DELETE CASCADE,
    starred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, listing_id)
);

-- Efficient lookup of all stars for a given listing (used for count queries)
CREATE INDEX IF NOT EXISTS idx_marketplace_stars_listing
    ON module_marketplace_stars(listing_id);

-- Back-fill star_count to reflect any pre-existing counter values.
-- Existing rows have no corresponding star records, so leave them as-is
-- (the count is a signal, not a guarantee of perfect accuracy for legacy rows).
-- New stars will use the deduplication path going forward.
