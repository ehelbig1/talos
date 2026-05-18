-- Add the `Input` status value to the execution_events.status CHECK constraint.
--
-- Pairs with migration 20260420140234 (which added the `node_input` event_type
-- value). The engine emits `node_input` events with `status: "Input"` from
-- talos-workflow-engine/src/engine_dispatch_single.rs:187. Without this value
-- the insert trips `execution_events_status_check` and the event_sink drops
-- the record with a WARN log — same silent-data-loss pattern as the
-- event_type drift.
--
-- Discovered post-r208 retest: the first event_type_check fix surfaced the
-- next constraint downstream.

ALTER TABLE execution_events DROP CONSTRAINT IF EXISTS execution_events_status_check;
ALTER TABLE execution_events ADD CONSTRAINT execution_events_status_check
    CHECK (status = ANY (ARRAY[
        'Running', 'Completed', 'Failed', 'Skipped', 'Input'
    ]));
