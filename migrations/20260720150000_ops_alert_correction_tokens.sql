-- One-click correction links (email capability URLs): token store for
-- /corrections/{token}/{severity}.
--
-- Deliberately HASH-ONLY (tighter than the approval-gate table, which
-- keeps the raw token for later re-display): correction links are
-- minted fresh at digest/report render time and never shown again, so
-- the raw 256-bit token exists only inside the email. A DB compromise
-- leaks no clickable links.
--
-- Multi-use within TTL by design: a correction is a severity label with
-- single-alert blast radius, and the user may legitimately change their
-- mind ("high" → "critical") from the same email. Expiry bounds replay;
-- ON DELETE CASCADE ties token lifetime to the alert row (ops_alerts is
-- not an append-only/immutability-trigger table, so CASCADE is safe —
-- cf. lint 47's scope).

CREATE TABLE IF NOT EXISTS ops_alert_correction_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id uuid NOT NULL REFERENCES ops_alerts(id) ON DELETE CASCADE,
    user_id uuid NOT NULL,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);

-- Opportunistic expiry cleanup runs DELETE ... WHERE expires_at < NOW()
-- on each mint batch; keep that a range scan.
CREATE INDEX IF NOT EXISTS idx_ops_alert_correction_tokens_expiry
    ON ops_alert_correction_tokens (expires_at);
