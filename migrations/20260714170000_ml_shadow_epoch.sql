-- RFC 0011 — epoch-windowed shadow agreement (wrongful-demote fix).
--
-- ml_shadow_stats counters were cumulative over the model's whole life:
-- every version, every lifecycle era, and every teacher configuration
-- summed into one number, and the drift guard's demote decision read
-- that aggregate. Found live 2026-07-14 on inbox-classifier-personal:
-- agreement 77% over 322 observations dominated by a since-fixed
-- mislabeling teacher (pre corrections-as-few-shot, #484) and retired
-- model versions. With demote_below_agreement=0.85 / min_shadow_total=50,
-- the moment the model auto-advances to hybrid the guard reads the stale
-- aggregate (already past min_total) and demotes it straight back —
-- an advance→demote ping-pong with no fresh evidence ever consulted.
--
-- Fix: counters gain an `epoch` key and ml_models.shadow_epoch points at
-- the CURRENT era. Every lifecycle transition and version promotion bumps
-- the epoch (plus an operator reset tool for teacher-only changes), so
-- the drift guard measures the current model, in its current era, against
-- the current teacher — and must accumulate min_shadow_total FRESH
-- observations before it may demote.
--
-- Existing rows stay in epoch 0, which is also every existing model's
-- current era: the migration discards nothing. The first transition,
-- promotion, or manual reset rotates the stale history out of the
-- current window (older eras are retained for context and pruned past
-- the retention depth by the bump helper).

ALTER TABLE ml_models
    ADD COLUMN IF NOT EXISTS shadow_epoch INT NOT NULL DEFAULT 0
        CHECK (shadow_epoch >= 0);

ALTER TABLE ml_shadow_stats
    ADD COLUMN IF NOT EXISTS epoch INT NOT NULL DEFAULT 0
        CHECK (epoch >= 0);

-- PK gains the epoch dimension. Reads filter (model_id, epoch = current)
-- and range on band, so epoch sits second.
ALTER TABLE ml_shadow_stats DROP CONSTRAINT IF EXISTS ml_shadow_stats_pkey;
ALTER TABLE ml_shadow_stats ADD PRIMARY KEY (model_id, epoch, band);
