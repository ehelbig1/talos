//! No index in the schema is redundant BY DEFINITION.
//!
//! Two shapes, both provable from `pg_index` alone and independent of usage
//! statistics (a two-day scan window on a one-user fleet is evidence of
//! nothing): an EXACT duplicate — same table, columns, operator classes, sort
//! options, predicate and access method as a sibling — costs a second identical
//! write per row change and buys nothing; a non-unique btree whose key is a
//! strict LEADING PREFIX of a sibling with the same predicate buys nothing
//! either, because Postgres answers a query on the leading columns from the
//! wider index. Measured 2026-09-12: 11 duplicates and 34 prefix twins, ~20 MB,
//! one extra index maintenance per write on the four hottest tables. Dropped
//! by migration `20260912120000`; this binary pins the 45 absent, every kept
//! sibling present, and the two invariants over the whole migrated schema so
//! the next duplicate cannot land unnoticed.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

const DROPPED: [&str; 45] = [
    "idx_execution_events_execution_created",
    "idx_module_execution_logs_execution_id",
    "idx_events_execution_id",
    "idx_module_executions_workflow_exec",
    "idx_module_executions_module_id",
    "idx_module_executions_user_id",
    "idx_module_executions_status",
    "idx_wf_executions_actor_id",
    "workflow_executions_archive_user_id_started_at_idx",
    "idx_executions_user_id",
    "idx_executions_workflow_id",
    "idx_executions_status",
    "workflow_executions_archive_status_idx",
    "workflow_executions_archive_user_id_idx",
    "workflow_executions_archive_workflow_id_idx",
    "idx_actor_memory_actor",
    "idx_actors_user_id",
    "idx_gmail_integrations_user_id",
    "idx_google_calendar_integrations_user_id",
    "idx_google_cloud_integrations_user_id",
    "idx_integration_credentials_user_id",
    "idx_org_members_org",
    "idx_secrets_namespace_keypath",
    "idx_secrets_user_id",
    "idx_ucg_user",
    "idx_user_sessions_user_id",
    "idx_user_sessions_user_id_expires_at",
    "idx_users_email",
    "idx_webhook_request_log_listener_id",
    "idx_webhook_triggers_lookup",
    "idx_workflow_schedules_next_trigger",
    "idx_workflows_user_id",
    "idx_api_keys_prefix",
    "idx_atlassian_integrations_user",
    "idx_execution_state_exec",
    "idx_oauth_accounts_provider_user",
    "idx_oauth_accounts_provider_user_id",
    "idx_oauth_accounts_user_id",
    "idx_oauth_state_tokens_state",
    "idx_resource_quotas_org",
    "idx_scratch_sessions_user_id",
    "idx_sla_thresholds_workflow",
    "idx_slack_integrations_user_id",
    "idx_wmr_module_id",
    "idx_workflow_execution_logs_exec",
];

// `idx_secrets_user_keypath` was the kept sibling of the dropped
// `idx_secrets_user_id` when this list was written; migration 20260912150000
// then dropped `secrets.user_id` itself (never written) and the index with it,
// so it is no longer a survivor to pin. Its replacement, `idx_secrets_owner_user_id`,
// is pinned by `secrets_owner_column_tests`.
const KEPT: [&str; 40] = [
    "agent_runtime_memory_agent_id_key_key",
    "atlassian_integrations_user_id_cloud_id_key",
    "gmail_integrations_user_id_email_address_key",
    "google_calendar_integrations_user_id_oauth_account_id_key",
    "idx_actors_user_name",
    "idx_api_keys_key_prefix",
    "idx_archive_user_started",
    "idx_events_created_at",
    "idx_execution_state_lookup",
    "idx_executions_actor_started",
    "idx_executions_user_started",
    "idx_google_cloud_integrations_user_pk_tier",
    "idx_module_execution_logs_created_at",
    "idx_module_executions_module_created",
    "idx_module_executions_status_created",
    "idx_module_executions_user_module_started",
    "idx_module_executions_wf_exec_status",
    "idx_user_sessions_user_expires",
    "idx_webhook_request_log_user_trigger",
    "idx_webhook_triggers_enabled_user",
    "idx_workflow_execution_logs_exec_level",
    "idx_workflow_executions_status_updated",
    "idx_workflow_executions_workflow_user",
    "idx_workflow_module_refs_module_id_workflow_id",
    "idx_workflow_schedules_enabled_trigger",
    "idx_workflows_user_status",
    "integration_credentials_user_id_provider_provider_key_key",
    "oauth_accounts_provider_provider_user_id_key",
    "oauth_accounts_user_id_provider_key",
    "oauth_state_tokens_state_token_key",
    "organization_members_org_id_user_id_key",
    "resource_quotas_org_id_metric_key",
    "scratch_sessions_user_id_name_key",
    "secrets_namespace_key_path_user_unique",
    "slack_integrations_user_id_team_id_key",
    "user_capability_grants_user_id_key",
    "users_email_key",
    "workflow_executions_archive_status_updated_at_idx",
    "workflow_executions_archive_workflow_id_created_at_idx",
    "workflow_sla_thresholds_workflow_id_user_id_key",
];

#[tokio::test]
async fn the_redundant_indexes_are_gone_and_their_siblings_remain() {
    let (pool, _db) = common::isolated_db_pool().await;
    for idx in DROPPED {
        let present: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(idx)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(!present, "{idx} must be gone");
    }
    for idx in KEPT {
        let present: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(idx)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(present, "{idx} is the surviving sibling and must remain");
    }
}

/// The invariant, over the WHOLE schema: no two non-primary indexes on one
/// table share columns, operator classes, sort options, predicate and access
/// method.
#[tokio::test]
async fn no_two_indexes_are_exact_duplicates() {
    let (pool, _db) = common::isolated_db_pool().await;
    let dups: Vec<(String, String)> = sqlx::query_as(
        "WITH ix AS ( \
           SELECT i.indexrelid, i.indrelid, c.relname AS idx, am.amname, \
                  i.indkey::text AS cols, i.indclass::text AS classes, i.indoption::text AS opts, \
                  coalesce(pg_get_expr(i.indpred, i.indrelid), '') AS pred \
           FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_class t ON t.oid = i.indrelid \
           JOIN pg_am am ON am.oid = c.relam JOIN pg_namespace n ON n.oid = t.relnamespace \
           WHERE n.nspname = 'public' AND i.indexprs IS NULL AND NOT i.indisprimary) \
         SELECT a.idx, b.idx FROM ix a JOIN ix b ON a.indrelid = b.indrelid AND a.idx < b.idx \
           AND a.cols = b.cols AND a.classes = b.classes AND a.opts = b.opts AND a.pred = b.pred AND a.amname = b.amname",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(dups.is_empty(), "exact-duplicate index pairs: {dups:?}");
}

/// The second invariant: no non-unique btree index is a strict leading prefix
/// of a sibling with the same predicate. (A UNIQUE prefix is a constraint, not
/// an access path, and is exempt.)
#[tokio::test]
async fn no_non_unique_btree_is_a_leading_prefix_of_a_sibling() {
    let (pool, _db) = common::isolated_db_pool().await;
    let twins: Vec<(String, String)> = sqlx::query_as(
        "WITH ix AS ( \
           SELECT i.indexrelid, i.indrelid, c.relname AS idx, am.amname, i.indisunique, \
                  string_to_array(i.indkey::text, ' ') AS cols, string_to_array(i.indclass::text, ' ') AS classes, \
                  string_to_array(i.indoption::text, ' ') AS opts, coalesce(pg_get_expr(i.indpred, i.indrelid), '') AS pred \
           FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_class t ON t.oid = i.indrelid \
           JOIN pg_am am ON am.oid = c.relam JOIN pg_namespace n ON n.oid = t.relnamespace \
           WHERE n.nspname = 'public' AND i.indexprs IS NULL AND NOT i.indisprimary AND am.amname = 'btree') \
         SELECT a.idx, b.idx FROM ix a JOIN ix b ON a.indrelid = b.indrelid AND a.indexrelid <> b.indexrelid \
           AND array_length(a.cols, 1) < array_length(b.cols, 1) \
           AND a.cols = b.cols[1:array_length(a.cols, 1)] \
           AND a.classes = b.classes[1:array_length(a.cols, 1)] \
           AND a.opts = b.opts[1:array_length(a.cols, 1)] \
           AND a.pred = b.pred AND NOT a.indisunique",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        twins.is_empty(),
        "leading-prefix redundant indexes: {twins:?}"
    );
}
