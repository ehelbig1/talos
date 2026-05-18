CREATE TABLE IF NOT EXISTS scratch_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    name TEXT NOT NULL,
    code TEXT NOT NULL,
    world TEXT NOT NULL DEFAULT 'minimal-node',
    last_output JSONB,
    last_error TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, name)
);

CREATE INDEX IF NOT EXISTS idx_scratch_sessions_user_id ON scratch_sessions(user_id);
