CREATE TABLE IF NOT EXISTS module_marketplace (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    module_id UUID NOT NULL,
    publisher_id UUID NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    capability_world TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '1.0.0',
    downloads INTEGER NOT NULL DEFAULT 0,
    is_public BOOLEAN NOT NULL DEFAULT true,
    tags TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(name, version)
);
CREATE INDEX IF NOT EXISTS idx_marketplace_tags ON module_marketplace USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_marketplace_world ON module_marketplace(capability_world);
CREATE INDEX IF NOT EXISTS idx_marketplace_downloads ON module_marketplace(downloads DESC);
