-- One row per periodic background loop that must act once per period for the
-- whole FLEET, not once per controller replica (2026-09-20).
--
-- Every controller replica runs every background loop, and their tickers are
-- at different phases. An advisory lock only excludes CONCURRENT work: replica
-- A fires and releases, replica B ticks two minutes later, takes the free lock
-- and fires again. A loop whose tick has an outward effect (the SLA monitors
-- POST a customer's webhook) needs "this period is already handled", which is
-- a lease on the DATABASE clock:
--
--   INSERT … ON CONFLICT (task) DO UPDATE … WHERE leased_until <= now()
--
-- One atomic statement, one primary-key probe, no connection held while the
-- loop does its work. `talos-background-lease` is the only reader and writer.
--
-- No tenant data: the key is a closed compile-time task name. No RLS.
CREATE TABLE IF NOT EXISTS background_task_leases (
    task         text        PRIMARY KEY,
    leased_until timestamptz NOT NULL,
    claimed_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT background_task_leases_task_len
        CHECK (char_length(task) BETWEEN 1 AND 128)
);
