-- Add fine-grained SQL operation policies to agent roles.
-- When non-empty, restricts which SQL statement types an agent can execute
-- (e.g., ["SELECT"] for read-only agents, ["SELECT", "INSERT"] for data writers).
-- Empty array or NULL = allow all operations (backwards compatible).

ALTER TABLE agent_roles
    ADD COLUMN IF NOT EXISTS allowed_sql_operations TEXT[] DEFAULT '{}';

-- Examples:
-- Read-only analyst role:     allowed_sql_operations = '{SELECT}'
-- Data writer role:           allowed_sql_operations = '{SELECT,INSERT,UPDATE}'
-- Full access (default):      allowed_sql_operations = '{}'  (empty = allow all)
