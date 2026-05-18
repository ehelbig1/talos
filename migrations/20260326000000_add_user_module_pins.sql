CREATE TABLE IF NOT EXISTS user_module_pins (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    module_name TEXT NOT NULL,
    pinned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, module_name)
);

CREATE INDEX IF NOT EXISTS idx_user_module_pins_user_id ON user_module_pins(user_id);
