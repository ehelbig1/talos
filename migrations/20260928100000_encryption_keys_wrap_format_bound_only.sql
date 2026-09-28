-- RFC 0013, phase 3: every wrapped DEK must be bound to its row.
--
-- Phase 1+2 (20260927100000) bound every NEW wrap to its `encryption_keys` row
-- and added `rebindDekWraps` to bind the rows written before it. While an
-- unbound (`wrap_format = 1`) row could still be read, a writer able to change
-- `encryption_keys` could mark a row 1 and plant an unbound blob copied from
-- another row, which is the swap RFC 0013 exists to stop. This migration
-- refuses that format in the schema, and the same release deletes the code
-- that read it.
--
-- A deployment that has not run `rebindDekWraps` on a phase-2 release still
-- holds unbound rows. It stops here with an instruction, rather than failing
-- on a bare CHECK violation or, worse, booting a controller that can no
-- longer read its own keys.
DO $$
DECLARE
    unbound bigint;
BEGIN
    SELECT count(*) INTO unbound FROM encryption_keys WHERE wrap_format <> 2;
    IF unbound > 0 THEN
        RAISE EXCEPTION
            'RFC 0013 phase 3: % encryption_keys row(s) are not bound to their row. '
            'Deploy the previous release (phase 2), run the rebindDekWraps mutation '
            'until remainingUnbound is 0, then deploy this release.', unbound;
    END IF;
END $$;

ALTER TABLE encryption_keys DROP CONSTRAINT IF EXISTS encryption_keys_wrap_format_check;
ALTER TABLE encryption_keys
    ADD CONSTRAINT encryption_keys_wrap_format_check CHECK (wrap_format = 2);
ALTER TABLE encryption_keys ALTER COLUMN wrap_format SET DEFAULT 2;
