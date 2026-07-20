-- Review remediation (2026-07-20) for the correction-links + self-monitor
-- pair:
--
-- 1. `purpose` on the token table. Severity correction is one of three
--    triage writes (correct / ack / resolve); when ack links inevitably
--    follow, a purpose-less table invites silently widening every
--    already-minted severity token into an ack capability. Encoding the
--    minted-for purpose now costs one column; retrofitting it later
--    means deciding what existing rows meant.
--
-- 2. An index actually serving the auto-resolve predicate. The green-run
--    resolve filters (user_id, source='talos', status new/acked,
--    dedup_key LIKE 'talos/{wf}/%'); the UNIQUE (user_id, dedup_key)
--    btree cannot serve a LIKE prefix under a non-C collation, so every
--    resolve was heap-filtering the user's whole active set.
--    text_pattern_ops + the partial predicate keep it a tight range scan
--    over only the platform's own active alerts.

ALTER TABLE ops_alert_correction_tokens
    ADD COLUMN IF NOT EXISTS purpose text NOT NULL DEFAULT 'correct_severity';

CREATE INDEX IF NOT EXISTS idx_ops_alerts_talos_active_dedup
    ON ops_alerts (user_id, dedup_key text_pattern_ops)
    WHERE source = 'talos' AND status IN ('new', 'acked');
