-- Fix capability_world for all bundled module templates.
-- The column defaulted to 'automation-node' during initial seeding because
-- the seeder INSERT did not include capability_world. These updates set the
-- correct world for each template based on their actual I/O requirements.
-- The seeder was also updated to persist capability_world from talos.json going forward.

-- Pure computation — no external I/O
UPDATE node_templates SET capability_world = 'minimal-node'
WHERE name IN ('Echo/Debug', 'Data Validator', 'JSON Transform', 'Text Analyzer', 'Human Approval Gate')
  AND capability_world != 'minimal-node';

-- Outbound HTTP only (no secrets vault access)
UPDATE node_templates SET capability_world = 'http-node'
WHERE name IN ('HTTP Request')
  AND capability_world != 'http-node';

-- HTTP + secrets vault (reads API keys or OAuth tokens from vault)
UPDATE node_templates SET capability_world = 'secrets-node'
WHERE name IN ('LLM Inference', 'GitHub Repo Analyzer')
  AND capability_world != 'secrets-node';

-- Network access (HTTP to external APIs using config-supplied credentials)
UPDATE node_templates SET capability_world = 'network-node'
WHERE name IN (
    'Network Scanner',
    'Message Publisher',
    'Slack Message',
    'Gmail',
    'Google Calendar Event',
    'Gmail Webhook',
    'Google Calendar Webhook',
    'GitHub PR Reviewer',
    'Slack Webhook Listener',
    'PagerDuty Alert',
    'Microsoft Teams Message',
    'Redis Cache'
) AND capability_world != 'network-node';

-- Filesystem access
UPDATE node_templates SET capability_world = 'filesystem-node'
WHERE name IN ('File Transform')
  AND capability_world != 'filesystem-node';

-- Database access
UPDATE node_templates SET capability_world = 'database-node'
WHERE name IN ('Database Query', 'Data Pipeline ETL')
  AND capability_world != 'database-node';
