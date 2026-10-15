# The review's remaining findings (2026-10-15)

Package 15 of the 2026-10-14 security review remediation: the Medium and Low
findings that no earlier package's files covered, and the information items in
G-27 that have a narrow fix.

## Decided

- **B-7: a log line belongs to the execution its subject names.** The worker
  publishes on `wasm.log.<execution id>`, a subject it derives from the job. The
  `execution_id` in the payload is written by the guest. Both halves of the relay
  now read a message through one function, `talos_wasm_log_relay::parse_log_message`.
  It returns `SubjectMismatch` when the two ids differ, so the line is neither
  stored nor streamed. The line is counted on
  `talos_wasm_log_orphaned_total{kind="subject_mismatch"}`, which is pre-seeded,
  and the orphan alert's text names this kind.
- **B-10: the secret envelope's nonce is signed.** `JobRequest::signing_payload`
  appends `:sn=<hex nonce>` after `:fuel=`, and only when the job carries an
  envelope. A secret-less job is byte-identical to the old format. A job with
  secrets changes its signed bytes, so controller and worker roll together, as
  for `:fuel=`. The v2→v1 decrypt fallback for a per-job envelope is removed:
  every controller has sealed v2 since 2026-06-17. CLAUDE.md has a dated
  correction after the envelope deploy-ordering paragraph. There is a
  non-default wire snapshot (`job_request_non_default_secret_nonce_snapshot`).
- **B-12:** the `integration_name` doc comment said the field was not signed.
  It is signed, and the comment now says so.
- **B-8: a dry run or an actor-bound run is never chained.** `PipelineJobRequest`
  carries neither `dry_run` nor `actor_id`. Chain dispatch is still disabled in
  production; `chains_live` now also requires `!dry_run && actor_id.is_none()`,
  so enabling it later does not inherit the gap.
- **A-9: a quota is for a named org or the personal one.**
  `OrganizationService::quota_org_for(db, user, org, role)` resolves the org.
  When the caller names one, they need Admin to write and Viewer to read. When
  they name none, it is their personal org. This replaces
  `first_org_id_owned_by` (`LIMIT 1` over the orgs they own).
- **A-10 / D-9: the GraphQL `ModuleLoader` is scoped to the reader.** The key is
  `ModuleKey { user_id, module_id }`, and the read is
  `ModuleRepository::get_modules_by_ids_for_reader`. It returns the user's own
  modules, those of the orgs the user belongs to now, and catalog rows. The
  unscoped `get_modules_by_ids` is gone.
- **E-8: the worker's sandbox file system has a process-wide budget.** Each
  execution may write `MAX_FS_BYTES_PER_EXECUTION` (64 MiB). The process holds
  at most `MAX_FS_BYTES_PER_PROCESS` (768 MiB), under the chart's 1 Gi tmp. A
  write reserves through `reserve_process_fs_bytes`, and dropping the
  `TalosContext` releases it.
- **E-11 (the narrow half):** guest error text is defanged before the worker
  appends its own `reason_class=` / `after_host_failure=` markers
  (`runtime::defang_guest_markers`). A module can no longer forge the markers
  that steer a retry.
- **F-8:** `GithubAppConfig` no longer reads `GITHUB_APP_WEBHOOK_SECRET`. That
  value was read and never used. It is removed from the chart, compose and the
  docs as well.
- **F-9: Slack app creation stores the app's secrets in the vault.**
  `create_app_handler` stores `client_secret`, `signing_secret` and
  `verification_token` at `slack/app/<app id>/<credential>`
  (`slack_app_secret_path`). The response now carries their paths, never the
  values. The frontend shows `vault://` references.
- **F-11:** the notify / control / capture adapters for ntfy and Home Assistant
  refuse a base URL with `user:password@`. Each has
  `a_base_with_userinfo_is_refused`, and the notification contract block stays
  byte-identical.
- **G-20: an interpreted component is bounded like a Rust one.**
  `talos_compilation::max_component_bytes` sets the limit per language: Rust and
  Go 1 MiB, JavaScript and TypeScript 32 MiB, Python 64 MiB. The JavaScript and
  Python compile paths call `check_interpreted_component`, which refuses an
  oversized component, or one whose imports are wider than the requested world.
- **G-27, the items with a narrow fix:**
  - **Dry run** now stubs `email::send` and every non-query GraphQL document
    (`StubbedSurface::{Email, Graphql}`, `graphql_may_mutate`). The `dry_run`
    argument descriptions say so.
  - **A `vault://` reference in node config is resolved only when the module's
    grant admits it.** `secrets_pipeline::granted_vault_paths` filters it
    through `vault_path_permitted`, the matcher the worker uses. The chain path
    now passes the step module's grant instead of an empty one.
  - **An ops-alert resolve reaches only the alert its own source raised.**
    `talos_ops_alert_store::resolve_signal` matches on user, source and dedup
    key, and both the `__ops_alert__` envelope and `report_ops_alert` go through
    it. An ingest never rewrites a row's `source`. The platform's own
    key-only resolve (`resolve_by_dedup_key`, for the actor-suspension alert)
    is unchanged.
  - **A node with the id `__trigger__` is refused at graph load.** Until now it
    was adopted as the synthetic trigger and never ran.
  - **Rhai expression depth is pinned** at 64 / 32, which are the release
    defaults (`MAX_EXPR_DEPTH`, `MAX_FUNCTION_EXPR_DEPTH`). A debug build now
    parses the same depth as release.
  - **The registry sync reads at most `MAX_CONFIG_BLOB_BYTES` (4 MiB) of a
    config blob.** It checks the descriptor's declared size first, and a
    `CappedSink` also bounds the bytes actually read.

## Deliberately NOT done

- **E-11's signed field.** Carrying the host failure class in a signed result
  field would remove the text channel altogether. It is a wire change on the
  result path and is left for its own package; the defang closes the forgery
  meanwhile.
- **B-8 / G-15: neither of the review's two options.** The review offered
  carrying `dry_run`, `actor_id` and `dispatch_attempt` on `PipelineJobRequest`
  (and binding `module_id` in `step_hashes`), or deleting the chain path. The
  chain path has no production caller: only `run_with_transport` passes
  `ChainDispatch::Enabled`, and nothing outside tests calls it. So the narrow
  change is to gate. A run that the pipeline wire cannot represent is never
  chained, and the wire change waits for the day chaining is enabled. The
  unbound `module_id` in `step_hashes` is latent for the same reason.
- **The webhook → own-webhook hop counter (G-27).** A hop count would need the
  worker to add a header to outbound requests, and the worker cannot tell the
  platform's own public host from a third party's. Adding it to every request
  would announce the platform to every API a module calls. The loop is still
  bounded by `max_concurrent_executions` and the actor budget.
- **The remaining G-27 information items:** `capability_dispatch` ordering, the
  LLM-dispatch classifier input, the MCP agent registration cap, the
  `swap_node_module` ceiling pre-flight and `trigger_workflow_as_actors`
  supervision. Each is recorded by the review as acceptable or stated, and each
  is refused at dispatch where it matters.
- **A cap on the OCI manifest body.** `oci-client` reads a manifest whole, and
  it is fetched by a digest-pinned reference after the signature is verified.
  Bounding it would mean replacing the client's manifest fetch.

## Measured

- Every resolve signal in the tree already sends its `source`:
  `alert-normalize-gcp-monitoring`, `github-workflow-run`, the backup drill and
  `report_ops_alert`, where `source` is required. A resolve that names no source
  now resolves nothing.
- The chain path's step config comes from the module artifact
  (`fetch_module_artifact_cached`), not from node data.

## Stated limits

- `jco` and `componentize-py` are not installed on the machine this was built
  on. The G-20 check is tested on a hand-encoded component, not on a real
  JavaScript or Python build.
- The process file-system budget is per worker process. A second worker on the
  same node has its own.

## Mutations (each applied, the guarding test run, the file restored)

| gate | mutation | caught by |
|---|---|---|
| B-10 nonce signed | `:sn=` never appended | `job_request_non_default_secret_nonce_snapshot` |
| B-10 no v1 fallback | v1 key restored as a candidate | `a_per_job_envelope_does_not_open_under_the_v1_key` |
| B-8 dry run | `!self.dry_run` dropped | `a_dry_run_or_an_actor_bound_run_is_never_chained` |
| B-8 actor | `actor_id.is_none()` dropped | same |
| B-7 subject binding | the mismatch arm disabled | `a_line_belongs_to_the_execution_its_subject_names` |
| A-9 named org | role check dropped | `a_quota_is_for_the_named_org_or_the_callers_personal_one` |
| A-10 reader scope | owner / org / catalog predicate made always true | `a_module_resolves_only_for_a_reader_who_may_see_it_now` |
| E-8 process budget | admit always | `the_process_budget_admits_up_to_its_limit` |
| E-11 defang | markers passed through | `a_guest_cannot_write_the_workers_retry_markers` |
| F-11 userinfo | `@` check dropped (ntfy) | `notify_ntfy::tests::a_base_with_userinfo_is_refused` |
| G-20 world | ceiling check disabled | `an_interpreted_component_wider_than_its_world_is_refused` |
| G-20 size | size check disabled | `an_interpreted_component_is_bounded` |
| G-27 vault grant | filter admits everything | `a_loop_body_is_given_…`, `a_pipeline_step_is_given_only_…` |
| G-27 chain grant | empty grant passed | `a_pipeline_step_is_given_only_the_config_references_its_grant_admits` |
| G-27 ops-alert source | `source = $2` dropped | `a_resolve_reaches_only_the_alert_its_own_source_raised` |
| G-27 `__trigger__` id | refusal never matches | `a_node_with_the_trigger_id_is_refused_at_load` |

## One home

- `talos_wasm_log_relay::parse_log_message`: what a log message is, and whose.
- `JobRequest::signing_payload`: the `:sn=` segment.
- `OrganizationService::quota_org_for`: which org a quota is for.
- `ModuleRepository::get_modules_by_ids_for_reader`: the loader's read.
- `talos_worker_runtime::host::limits::{reserve,release}_process_fs_bytes`.
- `talos_compilation::{max_component_bytes, check_interpreted_component}`.
- `secrets_pipeline::granted_vault_paths`.
- `talos_ops_alert_store::resolve_signal`.
