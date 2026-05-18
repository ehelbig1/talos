-- Cutover: Google Calendar watch channels move from the dedicated
-- `google_calendar_watch_channels` table to the generic
-- `integration_state` table (scoped by `integration_name = 'gcal'`).
--
-- Why: one integration = one bespoke table was a smell. The
-- `integration_state` primitive (introduced earlier in 2026-04-15)
-- gives every integration a namespaced slot-indexed kv store with
-- HMAC-verified RPC, TTL auto-sweep, and per-(integration, user)
-- quotas. Re-hosting gcal on it is the dog-food the primitive was
-- designed to support.
--
-- This migration does NOT move existing channel rows into
-- integration_state. Existing rows reference random per-channel
-- verification tokens that the new webhook verifier (a signed
-- (user_id, channel_id) HMAC) cannot accept. Migrating the data
-- without also re-registering every active watch on Google's side
-- would leave undispatchable channels on-wire until natural 7-day
-- expiry. Instead we deactivate the old rows here; the controller
-- will create fresh integration_state rows on next watch setup, and
-- the dead Google-side channels expire harmlessly.
--
-- Wrapped in a DO block so the migration is idempotent under
-- partial apply (the gcal table might already be gone in some
-- environments — dev resets, fresh installs, etc.).

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = current_schema() AND table_name = 'google_calendar_watch_channels'
    ) THEN
        UPDATE google_calendar_watch_channels
           SET is_active = false, updated_at = NOW()
         WHERE is_active = true;
    END IF;
END $$;

-- The `google_calendar_watch_channels` table itself is retained for
-- one release as historical record. A follow-up migration drops it
-- after operators have confirmed the cutover (see platform-primitive-
-- checklist for the observation-window pattern).
