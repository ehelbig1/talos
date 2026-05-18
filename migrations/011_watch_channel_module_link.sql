-- Migration: Link watch channels to WASM modules for execution
-- Date: 2026-02-17
-- Purpose: Enable webhook-to-WASM execution by linking watch channels to their modules

-- Add module_id to watch channels so we know which WASM module to execute
ALTER TABLE google_calendar_watch_channels
ADD COLUMN IF NOT EXISTS module_id UUID REFERENCES wasm_modules(id) ON DELETE CASCADE;

-- Add index for fast lookups when webhook arrives
CREATE INDEX IF NOT EXISTS idx_watch_channels_module_id
ON google_calendar_watch_channels(module_id)
WHERE is_active = true;

-- Backfill module_id for existing watch channels
-- This finds the module that contains each watch channel in its WATCH_CHANNELS config
UPDATE google_calendar_watch_channels wc
SET module_id = (
    SELECT wm.id
    FROM wasm_modules wm
    WHERE wm.config::jsonb->'WATCH_CHANNELS' @> jsonb_build_array(
        jsonb_build_object('id', wc.id::text)
    )
    LIMIT 1
)
WHERE module_id IS NULL;

-- Make module_id required for new watch channels
-- (We keep it nullable for now to allow backfill to complete)

-- Add comment for documentation
COMMENT ON COLUMN google_calendar_watch_channels.module_id IS
'WASM module to execute when webhook notifications arrive for this watch channel';
