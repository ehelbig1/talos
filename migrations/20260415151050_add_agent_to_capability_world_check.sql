-- wasm_modules.capability_world CHECK didn't include 'agent', so every
-- agent-node sandbox's wasm_modules INSERT silently failed (error was
-- only logged at tracing::error!, never surfaced to the caller). Those
-- modules have been running via the node_templates.precompiled_wasm
-- fallback path (Fallback 2 in engine/parallel.rs) which hardcodes
-- max_fuel = 1_000_000 — so agent-node modules' fuel_budget has been
-- silently ignored AND they can't call `integration_state::*` because
-- the host fn needs wasm_modules.integration_name to flow through the
-- JobRequest. Adding 'agent' to the allowed set unblocks both.
--
-- 'automation-node' maps to 'trusted' at the Rust layer (see the bind
-- in handle_compile_custom_sandbox) which is already in the list.

ALTER TABLE wasm_modules
    DROP CONSTRAINT IF EXISTS wasm_modules_capability_world_check;

ALTER TABLE wasm_modules
    ADD CONSTRAINT wasm_modules_capability_world_check
    CHECK (capability_world = ANY (ARRAY[
        'minimal',
        'http',
        'network',
        'secrets',
        'filesystem',
        'messaging',
        'cache',
        'database',
        'governance',
        'agent',
        'trusted',
        'unknown'
    ]));
