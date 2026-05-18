-- =============================================================================
-- SOC 2 Control Verification Queries
-- =============================================================================
--
-- Run against the Talos PostgreSQL database to verify security controls.
--
-- Usage:
--   psql "$DATABASE_URL" -f scripts/soc2/verify-controls.sql
--
-- Each section outputs a labeled result set for auditor review.
-- =============================================================================

\echo ''
\echo '============================================================'
\echo ' SOC 2 Control Verification Report'
\echo ' Generated: ' :TIMESTAMP
\echo '============================================================'
\echo ''

-- ---------------------------------------------------------------------------
-- 1. AUDIT TRIGGER VERIFICATION (CC7.1-01)
-- ---------------------------------------------------------------------------
\echo '--- 1. Audit Immutability Triggers ---'
\echo ''

SELECT
    t.trigger_name,
    t.event_object_table    AS protected_table,
    t.action_timing         AS timing,
    t.event_manipulation    AS blocked_operation,
    t.action_statement      AS action,
    CASE
        WHEN t.trigger_name IS NOT NULL THEN 'PRESENT'
        ELSE 'MISSING'
    END AS status
FROM (
    VALUES
        ('trg_audit_events_immutable',      'audit_events'),
        ('trg_auth_audit_log_immutable',    'auth_audit_log'),
        ('trg_secret_audit_log_immutable',  'secret_audit_log'),
        ('trg_admin_event_log_immutable',   'admin_event_log')
) AS expected(trigger_name, table_name)
LEFT JOIN information_schema.triggers t
    ON t.trigger_name = expected.trigger_name
ORDER BY expected.table_name;

-- Verify the shared trigger function exists
\echo ''
\echo 'Trigger function check:'

SELECT
    routine_name,
    routine_type,
    data_type AS return_type
FROM information_schema.routines
WHERE routine_name = 'prevent_audit_modification';

-- ---------------------------------------------------------------------------
-- 2. AUDIT LOG ENTRY COUNTS (CC7.1)
-- ---------------------------------------------------------------------------
\echo ''
\echo '--- 2. Audit Log Entry Counts (Last 90 Days) ---'
\echo ''

-- audit_events by category
\echo 'audit_events by event type (top 20):'

SELECT
    COALESCE(
        (details->>'event_type')::text,
        (details->>'action')::text,
        'unknown'
    ) AS event_category,
    COUNT(*) AS entry_count,
    MIN(created_at) AS earliest,
    MAX(created_at) AS latest
FROM audit_events
WHERE created_at >= NOW() - INTERVAL '90 days'
GROUP BY event_category
ORDER BY entry_count DESC
LIMIT 20;

\echo ''
\echo 'auth_audit_log summary:'

SELECT
    COUNT(*) AS total_entries,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '90 days') AS last_90_days,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days') AS last_30_days,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days')  AS last_7_days
FROM auth_audit_log;

\echo ''
\echo 'secret_audit_log summary:'

SELECT
    COUNT(*) AS total_entries,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '90 days') AS last_90_days,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days') AS last_30_days,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days')  AS last_7_days
FROM secret_audit_log;

\echo ''
\echo 'admin_event_log summary:'

SELECT
    COUNT(*) AS total_entries,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '90 days') AS last_90_days,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days') AS last_30_days,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days')  AS last_7_days
FROM admin_event_log;

-- ---------------------------------------------------------------------------
-- 3. PLAINTEXT SECRET CHECK (CC6.3)
-- ---------------------------------------------------------------------------
\echo ''
\echo '--- 3. Plaintext Secret Verification ---'
\echo ''

-- Check that no secrets have plaintext values stored
-- The secrets table should use encrypted_value, not a plaintext column.

\echo 'Checking for plaintext secret columns (should be zero or non-existent):'

SELECT
    column_name,
    data_type,
    CASE
        WHEN column_name IN ('value', 'plaintext_value', 'raw_value', 'secret_value')
            THEN 'POTENTIAL PLAINTEXT - REVIEW REQUIRED'
        WHEN column_name IN ('encrypted_value', 'encrypted_key')
            THEN 'OK - ENCRYPTED'
        ELSE 'OTHER'
    END AS assessment
FROM information_schema.columns
WHERE table_name = 'secrets'
  AND column_name LIKE '%value%'
   OR (table_name = 'secrets' AND column_name LIKE '%secret%' AND column_name != 'secret_audit_log')
ORDER BY column_name;

-- Check for plaintext OAuth tokens (should have been dropped in migration 036)
\echo ''
\echo 'Checking for plaintext OAuth token columns:'

SELECT
    table_name,
    column_name,
    CASE
        WHEN column_name LIKE 'encrypted_%' THEN 'OK - ENCRYPTED'
        WHEN column_name IN ('access_token', 'refresh_token', 'token')
            AND table_name IN ('oauth_credentials', 'integration_credentials', 'slack_installations', 'gmail_credentials')
            THEN 'POTENTIAL PLAINTEXT - REVIEW REQUIRED'
        ELSE 'OTHER'
    END AS assessment
FROM information_schema.columns
WHERE column_name LIKE '%token%'
  AND table_name IN (
      'oauth_credentials',
      'integration_credentials',
      'slack_installations',
      'gmail_credentials',
      'google_calendar_credentials'
  )
ORDER BY table_name, column_name;

-- ---------------------------------------------------------------------------
-- 4. ENCRYPTION KEY STATUS (CC6.3)
-- ---------------------------------------------------------------------------
\echo ''
\echo '--- 4. Encryption Key Rotation Status ---'
\echo ''

SELECT
    id AS key_id,
    algorithm,
    active,
    created_at,
    EXTRACT(DAY FROM NOW() - created_at)::int AS age_days,
    CASE
        WHEN active AND EXTRACT(DAY FROM NOW() - created_at) > 365
            THEN 'OVERDUE - ROTATE IMMEDIATELY'
        WHEN active AND EXTRACT(DAY FROM NOW() - created_at) > 90
            THEN 'AGING - ROTATION RECOMMENDED'
        WHEN active
            THEN 'OK'
        ELSE 'INACTIVE'
    END AS rotation_status
FROM encryption_keys
ORDER BY created_at DESC;

\echo ''
\echo 'Encryption key summary:'

SELECT
    COUNT(*) AS total_keys,
    COUNT(*) FILTER (WHERE active = true) AS active_keys,
    COUNT(*) FILTER (WHERE active = false) AS retired_keys,
    MIN(created_at) FILTER (WHERE active = true) AS active_key_created,
    EXTRACT(DAY FROM NOW() - MIN(created_at) FILTER (WHERE active = true))::int AS active_key_age_days
FROM encryption_keys;

-- ---------------------------------------------------------------------------
-- 5. RATE LIMIT CONFIGURATION CHECK (CC6.6)
-- ---------------------------------------------------------------------------
\echo ''
\echo '--- 5. Rate Limit and Security Configuration ---'
\echo ''

-- Check for webhook triggers with rate limiting configured
\echo 'Webhook triggers with rate limiting:'

SELECT
    COUNT(*) AS total_triggers,
    COUNT(*) FILTER (WHERE rate_limit IS NOT NULL AND rate_limit > 0) AS rate_limited,
    COUNT(*) FILTER (WHERE rate_limit IS NULL OR rate_limit = 0) AS unlimited,
    COUNT(*) FILTER (WHERE allowed_ips IS NOT NULL AND allowed_ips != '[]'::jsonb) AS ip_restricted
FROM webhook_triggers;

-- Check for modules with secret access
\echo ''
\echo 'Module secret access configuration:'

SELECT
    COUNT(*) AS total_modules,
    COUNT(*) FILTER (WHERE allowed_secrets IS NOT NULL AND allowed_secrets != '[]'::jsonb) AS with_secret_access,
    COUNT(*) FILTER (WHERE allowed_secrets IS NOT NULL AND allowed_secrets @> '"*"') AS wildcard_access,
    COUNT(*) FILTER (WHERE allowed_secrets IS NULL OR allowed_secrets = '[]'::jsonb) AS no_secret_access
FROM wasm_modules;

-- ---------------------------------------------------------------------------
-- 6. USER ACCOUNT STATUS (CC6.1, CC6.2)
-- ---------------------------------------------------------------------------
\echo ''
\echo '--- 6. User Account Status ---'
\echo ''

SELECT
    COUNT(*) AS total_users,
    COUNT(*) FILTER (WHERE is_active = true) AS active_users,
    COUNT(*) FILTER (WHERE is_active = false) AS inactive_users,
    COUNT(*) FILTER (WHERE locked_until IS NOT NULL AND locked_until > NOW()) AS currently_locked,
    COUNT(*) FILTER (WHERE totp_enabled = true) AS mfa_enabled,
    COUNT(*) FILTER (WHERE totp_enabled IS NULL OR totp_enabled = false) AS mfa_disabled,
    COUNT(*) FILTER (WHERE last_login_at IS NULL) AS never_logged_in,
    COUNT(*) FILTER (WHERE last_login_at < NOW() - INTERVAL '90 days') AS inactive_90_days
FROM users;

-- ---------------------------------------------------------------------------
-- 7. API KEY STATUS (CC6.1)
-- ---------------------------------------------------------------------------
\echo ''
\echo '--- 7. API Key Status ---'
\echo ''

SELECT
    COUNT(*) AS total_keys,
    COUNT(*) FILTER (WHERE is_active = true) AS active_keys,
    COUNT(*) FILTER (WHERE is_active = false) AS revoked_keys,
    COUNT(*) FILTER (WHERE expires_at IS NOT NULL AND expires_at < NOW()) AS expired_keys,
    COUNT(*) FILTER (WHERE expires_at IS NULL) AS no_expiry_set,
    COUNT(*) FILTER (WHERE last_used_at IS NULL) AS never_used
FROM api_keys;

-- ---------------------------------------------------------------------------
-- 8. CAPABILITY WORLD DISTRIBUTION (CC6.1)
-- ---------------------------------------------------------------------------
\echo ''
\echo '--- 8. WASM Module Capability Distribution ---'
\echo ''

SELECT
    COALESCE(capability_world, 'NULL/unset') AS capability_world,
    COUNT(*) AS module_count,
    ROUND(100.0 * COUNT(*) / NULLIF(SUM(COUNT(*)) OVER (), 0), 1) AS percentage
FROM node_templates
GROUP BY capability_world
ORDER BY module_count DESC;

-- ---------------------------------------------------------------------------
-- 9. MIGRATION INTEGRITY (CC8.1)
-- ---------------------------------------------------------------------------
\echo ''
\echo '--- 9. Migration Status ---'
\echo ''

SELECT
    version,
    description,
    installed_on,
    success,
    CASE
        WHEN success THEN 'OK'
        ELSE 'FAILED - REVIEW REQUIRED'
    END AS status
FROM _sqlx_migrations
ORDER BY installed_on DESC
LIMIT 20;

\echo ''
\echo 'Migration summary:'

SELECT
    COUNT(*) AS total_migrations,
    COUNT(*) FILTER (WHERE success = true) AS successful,
    COUNT(*) FILTER (WHERE success = false) AS failed,
    MAX(installed_on) AS last_migration
FROM _sqlx_migrations;

-- ---------------------------------------------------------------------------
-- 10. APPROVAL GATE STATUS (CC6.1)
-- ---------------------------------------------------------------------------
\echo ''
\echo '--- 10. Approval Gate Activity ---'
\echo ''

SELECT
    COUNT(*) AS total_approvals,
    COUNT(*) FILTER (WHERE status = 'approved') AS approved,
    COUNT(*) FILTER (WHERE status = 'denied') AS denied,
    COUNT(*) FILTER (WHERE status = 'pending') AS pending,
    COUNT(*) FILTER (WHERE status = 'pending' AND created_at < NOW() - INTERVAL '24 hours') AS stale_pending
FROM execution_approvals;

-- ---------------------------------------------------------------------------
-- SUMMARY
-- ---------------------------------------------------------------------------
\echo ''
\echo '============================================================'
\echo ' Verification Complete'
\echo '============================================================'
\echo ''
\echo ' Review the output above for any items marked as:'
\echo '   - MISSING         : Required control not found'
\echo '   - REVIEW REQUIRED : Potential issue needs investigation'
\echo '   - OVERDUE         : Action required (key rotation, etc.)'
\echo '   - FAILED          : Control check did not pass'
\echo ''
\echo ' All other items marked OK/PRESENT indicate passing controls.'
\echo '============================================================'
