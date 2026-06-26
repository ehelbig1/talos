-- Documentation-only: make the "actor = execution principal, NOT ownership"
-- distinction discoverable at the schema level via COMMENT ON COLUMN.
--
-- The ownership model has three distinct edges that the word "owns" tends to
-- conflate (and undocumented schema semantics are how that conflation festers —
-- cf. the "DEK lineage is per-user" myth that lived only in prose):
--   * TENANCY / ownership  → user_id + org_id  (who edits/deletes/shares; RLS)
--   * EXECUTION PRINCIPAL   → actor_id          (what it runs AS: budget, tier,
--                                                memory, audit)
--   * CAPABILITY            → the world lattice  (what's permitted to run)
-- These COMMENTs pin that so `workflows.actor_id` isn't misread as ownership.
-- No data or behaviour change.

COMMENT ON COLUMN workflows.actor_id IS
    'Default execution PRINCIPAL — a BINDING, not ownership. The actor a trigger '
    'runs as when no explicit actor is passed; overridable per-trigger '
    '(effective = trigger_agent_id OR workflows.actor_id, then the user''s '
    'default actor). NULL = no default binding. Tenancy/ownership of the '
    'workflow is user_id + org_id, NOT this column.';

COMMENT ON COLUMN workflow_executions.actor_id IS
    'The owning actor this execution ran AS — the resolved execution principal '
    '(explicit trigger actor -> workflow''s default binding -> the user''s '
    'default actor). NOT NULL: every execution has an actor, auto-stamped by '
    'trg_set_default_actor when not supplied. This is the PRINCIPAL (budget / '
    'tier / memory / audit); tenancy is user_id + org_id.';

COMMENT ON COLUMN module_executions.actor_id IS
    'The owning actor this module execution ran AS (the resolved execution '
    'principal — same semantics as workflow_executions.actor_id). NOT NULL, '
    'auto-stamped by trg_set_default_actor. Principal, not tenancy; tenancy is '
    'user_id.';
