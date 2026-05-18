-- Add capability_world to node_templates so inline-compiled sandbox modules
-- correctly declare their WIT world to the runtime and to list_modules.
-- Previously every node_templates entry was reported as capability_world="sandbox"
-- (a hardcoded placeholder), making inline Rust nodes unexecutable because
-- "sandbox" is not a valid WIT world.

ALTER TABLE node_templates
    ADD COLUMN IF NOT EXISTS capability_world TEXT NOT NULL DEFAULT 'automation-node';

-- Back-fill existing sandbox rows. 'automation-node' is the default used at
-- compilation time for add_node_to_workflow; new compilations will store the
-- actual world passed by the caller.
UPDATE node_templates
    SET capability_world = 'automation-node'
    WHERE category = 'sandbox' AND capability_world = 'automation-node';

DO $$
BEGIN
    RAISE NOTICE 'Migration 20260319000300 completed: capability_world column added to node_templates';
END $$;
