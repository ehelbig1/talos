-- Drop 45 indexes that are redundant BY DEFINITION: 11 exact duplicates and 34
-- leading-prefix twins of a wider (or unique) sibling on the same table with the
-- same predicate. Computed from pg_index on the reference database 2026-09-12,
-- not from usage statistics: the 2-day stats window since the 09-10 postmaster
-- start shows 234 unscanned indexes, which on a one-user fleet is not evidence
-- of anything, and none of THOSE is dropped here on that basis. A duplicate
-- costs a second identical write on every insert/update and buys nothing; a
-- leading-prefix index (a) beside (a, b) buys nothing either — Postgres uses a
-- multicolumn index for any query on its leading columns (the planner picked
-- the smaller prefix when both existed, which is why some carry scans below;
-- the wider sibling answers the same lookups). Every dropped index has a
-- surviving sibling named beside it. Total: 19.4 MB of index bytes and one
-- index maintenance per write on execution_events, module_executions,
-- module_execution_logs and workflow_executions — the four hottest tables.
-- All 45 are in the schema baseline; this is the post-cutpoint tail dropping
-- baseline objects (the 20260912100000 precedent). IF EXISTS for idempotency.
-- No code, doc or script names any of them (grep of the whole tree).
--
--   dropped                                              size      2d scans  why        kept sibling
--   idx_execution_events_execution_created               8.3 MB    12        duplicate  idx_events_created_at  [execution_events: USING btree (execution_id, created_at)]
--   idx_module_execution_logs_execution_id               4.5 MB    0         prefix     idx_module_execution_logs_created_at  [module_execution_logs: USING btree (execution_id)]
--   idx_events_execution_id                              2.1 MB    24308     prefix     idx_events_created_at  [execution_events: USING btree (execution_id)]
--   idx_module_executions_workflow_exec                  1.5 MB    49        prefix     idx_module_executions_wf_exec_status  [module_executions: USING btree (workflow_execution_id) WHERE (workflow_execution_id IS NOT NULL)]
--   idx_module_executions_module_id                      704 kB    8         prefix     idx_module_executions_module_created  [module_executions: USING btree (module_id)]
--   idx_module_executions_user_id                        552 kB    2         prefix     idx_module_executions_user_module_started  [module_executions: USING btree (user_id)]
--   idx_module_executions_status                         464 kB    309       prefix     idx_module_executions_status_created  [module_executions: USING btree (status)]
--   idx_wf_executions_actor_id                           168 kB    6         prefix     idx_executions_actor_started  [workflow_executions: USING btree (actor_id) WHERE (actor_id IS NOT NULL)]
--   workflow_executions_archive_user_id_started_at_idx   168 kB    0         duplicate  idx_archive_user_started  [workflow_executions_archive: USING btree (user_id, started_at DESC)]
--   idx_executions_user_id                               160 kB    0         prefix     idx_executions_user_started  [workflow_executions: USING btree (user_id)]
--   idx_executions_workflow_id                           152 kB    576       prefix     idx_workflow_executions_workflow_user  [workflow_executions: USING btree (workflow_id)]
--   idx_executions_status                                144 kB    1117      prefix     idx_workflow_executions_status_updated  [workflow_executions: USING btree (status)]
--   workflow_executions_archive_status_idx               48 kB     0         prefix     workflow_executions_archive_status_updated_at_idx  [workflow_executions_archive: USING btree (status)]
--   workflow_executions_archive_user_id_idx              40 kB     0         prefix     idx_archive_user_started  [workflow_executions_archive: USING btree (user_id)]
--   workflow_executions_archive_workflow_id_idx          40 kB     0         prefix     workflow_executions_archive_workflow_id_created_at_idx  [workflow_executions_archive: USING btree (workflow_id)]
--   idx_actor_memory_actor                               16 kB     0         prefix     agent_runtime_memory_agent_id_key_key  [actor_memory: USING btree (actor_id)]
--   idx_actors_user_id                                   16 kB     0         prefix     idx_actors_user_name  [actors: USING btree (user_id)]
--   idx_gmail_integrations_user_id                       16 kB     0         prefix     gmail_integrations_user_id_email_address_key  [gmail_integrations: USING btree (user_id)]
--   idx_google_calendar_integrations_user_id             16 kB     0         prefix     google_calendar_integrations_user_id_oauth_account_id_key  [google_calendar_integrations: USING btree (user_id)]
--   idx_google_cloud_integrations_user_id                16 kB     0         prefix     idx_google_cloud_integrations_user_pk_tier  [google_cloud_integrations: USING btree (user_id)]
--   idx_integration_credentials_user_id                  16 kB     0         prefix     integration_credentials_user_id_provider_provider_key_key  [integration_credentials: USING btree (user_id)]
--   idx_org_members_org                                  16 kB     0         prefix     organization_members_org_id_user_id_key  [organization_members: USING btree (org_id)]
--   idx_secrets_namespace_keypath                        16 kB     0         prefix     secrets_namespace_key_path_user_unique  [secrets: USING btree (namespace, key_path)]
--   idx_secrets_user_id                                  16 kB     0         prefix     idx_secrets_user_keypath  [secrets: USING btree (user_id)]
--   idx_ucg_user                                         16 kB     0         duplicate  user_capability_grants_user_id_key  [user_capability_grants: USING btree (user_id)]
--   idx_user_sessions_user_id                            16 kB     0         prefix     idx_user_sessions_user_expires  [user_sessions: USING btree (user_id)]
--   idx_user_sessions_user_id_expires_at                 16 kB     0         duplicate  idx_user_sessions_user_expires  [user_sessions: USING btree (user_id, expires_at)]
--   idx_users_email                                      16 kB     0         duplicate  users_email_key  [users: USING btree (email)]
--   idx_webhook_request_log_listener_id                  16 kB     0         prefix     idx_webhook_request_log_user_trigger  [webhook_request_log: USING btree (trigger_id)]
--   idx_webhook_triggers_lookup                          16 kB     0         prefix     idx_webhook_triggers_enabled_user  [webhook_triggers: USING btree (id) WHERE (enabled = true)]
--   idx_workflow_schedules_next_trigger                  16 kB     22        duplicate  idx_workflow_schedules_enabled_trigger  [workflow_schedules: USING btree (next_trigger_at) WHERE (is_enabled = true)]
--   idx_workflows_user_id                                16 kB     0         prefix     idx_workflows_user_status  [workflows: USING btree (user_id)]
--   idx_api_keys_prefix                                  8 kB      0         duplicate  idx_api_keys_key_prefix  [api_keys: USING btree (key_prefix)]
--   idx_atlassian_integrations_user                      8 kB      3         prefix     atlassian_integrations_user_id_cloud_id_key  [atlassian_integrations: USING btree (user_id)]
--   idx_execution_state_exec                             8 kB      0         prefix     idx_execution_state_lookup  [execution_state: USING btree (execution_id)]
--   idx_oauth_accounts_provider_user                     8 kB      0         duplicate  oauth_accounts_provider_provider_user_id_key  [oauth_accounts: USING btree (provider, provider_user_id)]
--   idx_oauth_accounts_provider_user_id                  8 kB      0         duplicate  oauth_accounts_provider_provider_user_id_key  [oauth_accounts: USING btree (provider, provider_user_id)]
--   idx_oauth_accounts_user_id                           8 kB      1         prefix     oauth_accounts_user_id_provider_key  [oauth_accounts: USING btree (user_id)]
--   idx_oauth_state_tokens_state                         8 kB      0         duplicate  oauth_state_tokens_state_token_key  [oauth_state_tokens: USING btree (state_token)]
--   idx_resource_quotas_org                              8 kB      1         prefix     resource_quotas_org_id_metric_key  [resource_quotas: USING btree (org_id)]
--   idx_scratch_sessions_user_id                         8 kB      0         prefix     scratch_sessions_user_id_name_key  [scratch_sessions: USING btree (user_id)]
--   idx_sla_thresholds_workflow                          8 kB      0         prefix     workflow_sla_thresholds_workflow_id_user_id_key  [workflow_sla_thresholds: USING btree (workflow_id)]
--   idx_slack_integrations_user_id                       8 kB      3         prefix     slack_integrations_user_id_team_id_key  [slack_integrations: USING btree (user_id)]
--   idx_wmr_module_id                                    8 kB      0         prefix     idx_workflow_module_refs_module_id_workflow_id  [workflow_module_refs: USING btree (module_id)]
--   idx_workflow_execution_logs_exec                     8 kB      0         prefix     idx_workflow_execution_logs_exec_level  [workflow_execution_logs: USING btree (execution_id)]

DROP INDEX IF EXISTS idx_execution_events_execution_created;
DROP INDEX IF EXISTS idx_module_execution_logs_execution_id;
DROP INDEX IF EXISTS idx_events_execution_id;
DROP INDEX IF EXISTS idx_module_executions_workflow_exec;
DROP INDEX IF EXISTS idx_module_executions_module_id;
DROP INDEX IF EXISTS idx_module_executions_user_id;
DROP INDEX IF EXISTS idx_module_executions_status;
DROP INDEX IF EXISTS idx_wf_executions_actor_id;
DROP INDEX IF EXISTS workflow_executions_archive_user_id_started_at_idx;
DROP INDEX IF EXISTS idx_executions_user_id;
DROP INDEX IF EXISTS idx_executions_workflow_id;
DROP INDEX IF EXISTS idx_executions_status;
DROP INDEX IF EXISTS workflow_executions_archive_status_idx;
DROP INDEX IF EXISTS workflow_executions_archive_user_id_idx;
DROP INDEX IF EXISTS workflow_executions_archive_workflow_id_idx;
DROP INDEX IF EXISTS idx_actor_memory_actor;
DROP INDEX IF EXISTS idx_actors_user_id;
DROP INDEX IF EXISTS idx_gmail_integrations_user_id;
DROP INDEX IF EXISTS idx_google_calendar_integrations_user_id;
DROP INDEX IF EXISTS idx_google_cloud_integrations_user_id;
DROP INDEX IF EXISTS idx_integration_credentials_user_id;
DROP INDEX IF EXISTS idx_org_members_org;
DROP INDEX IF EXISTS idx_secrets_namespace_keypath;
DROP INDEX IF EXISTS idx_secrets_user_id;
DROP INDEX IF EXISTS idx_ucg_user;
DROP INDEX IF EXISTS idx_user_sessions_user_id;
DROP INDEX IF EXISTS idx_user_sessions_user_id_expires_at;
DROP INDEX IF EXISTS idx_users_email;
DROP INDEX IF EXISTS idx_webhook_request_log_listener_id;
DROP INDEX IF EXISTS idx_webhook_triggers_lookup;
DROP INDEX IF EXISTS idx_workflow_schedules_next_trigger;
DROP INDEX IF EXISTS idx_workflows_user_id;
DROP INDEX IF EXISTS idx_api_keys_prefix;
DROP INDEX IF EXISTS idx_atlassian_integrations_user;
DROP INDEX IF EXISTS idx_execution_state_exec;
DROP INDEX IF EXISTS idx_oauth_accounts_provider_user;
DROP INDEX IF EXISTS idx_oauth_accounts_provider_user_id;
DROP INDEX IF EXISTS idx_oauth_accounts_user_id;
DROP INDEX IF EXISTS idx_oauth_state_tokens_state;
DROP INDEX IF EXISTS idx_resource_quotas_org;
DROP INDEX IF EXISTS idx_scratch_sessions_user_id;
DROP INDEX IF EXISTS idx_sla_thresholds_workflow;
DROP INDEX IF EXISTS idx_slack_integrations_user_id;
DROP INDEX IF EXISTS idx_wmr_module_id;
DROP INDEX IF EXISTS idx_workflow_execution_logs_exec;
