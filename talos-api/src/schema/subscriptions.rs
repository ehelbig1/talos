//! GraphQL Subscription resolvers (SubscriptionRoot).

use async_graphql::{Context, Result, Subscription};
use futures::{Stream, StreamExt as _};
// MCP-852: `tracing::info` removed; the two callers in execution_updates
// now use `tracing::trace!` directly (qualified path) for the live + replay
// event logs so they don't ship to operator pipelines by default.
use uuid::Uuid;

use crate::schema::SafeErrorExtensions;
use talos_engine::events::{ExecutionEvent, ExecutionStatus};

#[derive(Default)]
pub struct SubscriptionRoot;

/// M T6-1: tenant-scope filter for `dlq_updates`. Pulled out as a
/// pure function so the visibility logic can be unit-tested without
/// spinning up a broadcast channel.
///
/// Visibility rules:
/// * Platform admins see everything.
/// * Non-admins see events whose `user_id` matches the subscriber, OR
///   whose `org_id` is in the subscriber's `accessible_org_ids`.
/// * Events with both `user_id` and `org_id` NULL are platform-admin-only
///   (orphaned trigger whose workflow was deleted; no ownership chain).
pub(crate) fn dlq_event_visible_to(
    event: &talos_engine::events::DlqEvent,
    subscriber_user_id: Uuid,
    accessible_org_ids: &[Uuid],
    is_platform_admin: bool,
) -> bool {
    if is_platform_admin {
        return true;
    }
    if event.user_id == Some(subscriber_user_id) {
        return true;
    }
    if let Some(org) = event.org_id {
        if accessible_org_ids.contains(&org) {
            return true;
        }
    }
    false
}

#[Subscription]
impl SubscriptionRoot {
    /// Real‑time updates for a specific execution ID.
    ///
    /// SECURITY: Authorization is enforced - users can only subscribe to their own executions.
    /// Events are replayed from the database before streaming new events, ensuring no events are lost.
    async fn execution_updates(
        &self,
        ctx: &Context<'_>,
        execution_id: Uuid,
    ) -> Result<impl Stream<Item = ExecutionEvent>> {
        // Get authenticated user
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        // SECURITY: Verify the execution belongs to this user or an org they're in.
        // Helper baked-in: every failure mode returns the same generic
        // "Execution not found" wording so callers can't enumerate IDs.
        crate::access_check::authorize_execution_subscription(db_pool, execution_id, *user_id)
            .await?;

        // Fetch historical events from database for replay.
        //
        // MCP-954 (2026-05-15): cap historical-event replay. Pre-fix
        // the SELECT had no LIMIT — for a long-running execution that
        // accumulates thousands of events (loops, iterations, batch-
        // dispatch nodes) the entire history was pulled into the
        // controller per new subscriber, with no upper bound on
        // memory or wire payload. `log_message` is TEXT (no DB-level
        // cap), so a single runaway node emitting MB-sized payloads
        // multiplied by hundreds of iterations is a real OOM
        // surface; multiple concurrent subscribers compound the
        // problem. Cap at the most recent EXECUTION_REPLAY_LIMIT
        // events (latest-first) and reverse to chronological order
        // for stream consumers — the client already replays from a
        // fresh subscribe, so tailing the recent window is the right
        // semantic. Live events continue from broadcast after the
        // replay window. The cap is loose enough (1000) that normal
        // executions are unaffected.
        const EXECUTION_REPLAY_LIMIT: i64 = 1000;
        let exec_repo = talos_execution_repository::ExecutionRepository::new(db_pool.clone());
        let mut historical_events = exec_repo
            .list_recent_execution_events(execution_id, EXECUTION_REPLAY_LIMIT)
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch events: {}", e);
                // MCP-1048: .extend_safe() so the message survives the
                // production scrubber whitelist (does not contain
                // Authentication / Access denied / Not found / Invalid /
                // Validation / Unauthorized substrings).
                async_graphql::Error::new("Failed to fetch events").extend_safe()
            })?;
        historical_events.reverse();

        // Convert database rows to ExecutionEvent structs
        let historical: Vec<ExecutionEvent> = historical_events
            .into_iter()
            .map(|row| {
                let status = match row.status.as_str() {
                    "Running" => ExecutionStatus::Running,
                    "Completed" => ExecutionStatus::Completed,
                    "Failed" => ExecutionStatus::Failed,
                    _ => ExecutionStatus::Running, // Default fallback
                };

                ExecutionEvent {
                    execution_id,
                    node_id: row.node_id,
                    status,
                    trace_id: None,
                    span_id: None,
                    log_message: row.log_message,
                    // MCP-961 (2026-05-15): clamp negatives to 0
                    // before casting i32 → u32. Pre-fix `i as u32`
                    // wrapped negative values to huge u32s — a
                    // negative `iteration_index` (engine bug, manual
                    // DB write, or row tampering) would render as
                    // ~4 billion in the UI. Loop counters are
                    // non-negative by construction in the engine,
                    // so clamping at the read boundary is a cheap
                    // defense-in-depth against schema-violation
                    // rows. Same family as MCP-960 (i64→i32
                    // wrap-vs-saturate fix in workflow_executions).
                    iteration_index: row.iteration_index.map(|i| i.max(0) as u32),
                    iteration_total: row.iteration_total.map(|i| i.max(0) as u32),
                    duration_ms: row.duration_ms,
                    output: None,
                }
            })
            .collect();

        // Subscribe to broadcast for new events
        let sender = ctx.data_unchecked::<tokio::sync::broadcast::Sender<ExecutionEvent>>();
        let mut rx = sender.subscribe();

        Ok(async_stream::stream! {
            // First, replay all historical events
            for event in historical {
                // MCP-852 (2026-05-14): downgrade from `info!("...{:?}", event)`
                // to a structured debug log without the full event payload.
                // The `Debug` of ExecutionEvent includes `log_message`,
                // which can be any string the workflow's nodes produced —
                // including HTTP response bodies, raw error text, partial
                // user input, etc. Pre-fix this fired at INFO level for
                // EVERY historical event replay, dumping potential PII
                // into the production log stream (no DLP redaction since
                // this is per-event Debug, not the DLP-aware persistence
                // path). Operational noise too — an execution with 500
                // historical events would fire 500 INFO lines per
                // subscriber. Drop down to TRACE so the log is available
                // for local dev but doesn't ship to operator log
                // pipelines by default; project the fields by name so
                // a future schema change can't accidentally widen the
                // log surface.
                tracing::trace!(
                    %execution_id,
                    node_id = ?event.node_id,
                    status = ?event.status,
                    "replaying historical execution event"
                );
                yield event;
            }

            // Then stream new events as they arrive.
            //
            // MCP-986 (2026-05-15): distinguish `RecvError::Lagged(n)` (channel
            // healthy, receiver was too slow — skip ahead and continue) from
            // `RecvError::Closed` (sender dropped — terminate). Pre-fix
            // `while let Ok(...)` collapsed both into stream termination, so
            // a slow client (busy tab, network blip) would get disconnected,
            // reconnect, AND re-run the historical-event replay SELECT against
            // execution_events on every cycle — a self-DoS amplifier on busy
            // controllers. Lagged just means n messages were dropped from
            // the in-channel queue; the next recv() returns the oldest
            // surviving message. Warn so operators can spot a chronically
            // slow subscriber, then continue.
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        if event.execution_id == execution_id {
                            tracing::trace!(
                                %execution_id,
                                node_id = ?event.node_id,
                                status = ?event.status,
                                "streaming live execution event"
                            );
                            yield event;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(
                            target: "talos_audit",
                            %execution_id,
                            skipped,
                            "execution_updates subscriber lagged behind broadcast channel; continuing"
                        );
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        })
    }

    /// Stream LLM completion tokens as they are generated.
    ///
    /// Subscribes to a NATS topic for the given execution and streams
    /// partial text chunks as they arrive from the worker. The worker
    /// publishes chunks to `talos.llm.stream.{execution_id}`.
    async fn llm_stream(
        &self,
        ctx: &Context<'_>,
        execution_id: Uuid,
    ) -> Result<impl Stream<Item = String>> {
        // Auth check
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        // SECURITY: verify the execution belongs to this user or an org they're in.
        // Same generic-error contract as subscribeExecution above.
        crate::access_check::authorize_execution_subscription(db_pool, execution_id, *user_id)
            .await?;

        // Subscribe to NATS topic for streaming tokens
        let nats_client = ctx
            .data_opt::<Option<std::sync::Arc<async_nats::Client>>>()
            .cloned()
            .flatten()
            // MCP-1048: .extend_safe() for scrubber whitelist parity.
            .ok_or_else(|| async_graphql::Error::new("Streaming not available").extend_safe())?;

        let topic = format!("talos.llm.stream.{}", execution_id);
        // MCP-873 (2026-05-14): log the NATS subscribe error before
        // collapsing to "Failed to subscribe". Pre-fix the `_` swallow
        // hid TLS/auth/permission failures behind a generic message,
        // so an operator-misconfigured topic ACL or broken connection
        // looked identical to a transient hiccup on the server side.
        // Subscriber-facing message stays generic — exposing the raw
        // NATS error would leak subject patterns and connection state
        // to the GraphQL caller.
        let mut subscriber = nats_client.subscribe(topic.clone()).await.map_err(|e| {
            tracing::error!(
                execution_id = %execution_id,
                topic = %topic,
                error = %e,
                "LLM stream subscription failed"
            );
            // MCP-1048: .extend_safe() — "Failed to subscribe" doesn't
            // match the scrubber whitelist substrings, so without
            // the explicit marker the client sees "Internal server
            // error" instead.
            async_graphql::Error::new("Failed to subscribe").extend_safe()
        })?;

        Ok(async_stream::stream! {
            while let Some(msg) = subscriber.next().await {
                if let Ok(text) = String::from_utf8(msg.payload.to_vec()) {
                    if text == "[DONE]" {
                        break;
                    }
                    yield text;
                }
            }
        })
    }

    /// Real-time stream of dead-letter queue entries.
    ///
    /// M T6-1 visibility model:
    /// * Platform admins (`users.is_platform_admin = TRUE`) see every
    ///   event regardless of ownership.
    /// * Regular users see events for workflows they own
    ///   (`event.user_id == subscriber`) AND events for workflows in
    ///   any organisation they're a member of (`event.org_id IN
    ///   subscriber's orgs`).
    /// * Events with both `user_id` and `org_id` NULL (orphan trigger
    ///   whose workflow was deleted) are platform-admin-only — the
    ///   ownership chain is gone, so no non-admin user can prove
    ///   they owned the underlying workflow.
    ///
    /// `DlqEvent.payload` is the raw trigger body (DLP-scrubbed at
    /// persistence time but still tenant-scoped); the per-tenant
    /// filter is what allows non-admin users to subscribe at all.
    async fn dlq_updates(
        &self,
        ctx: &Context<'_>,
    ) -> Result<impl Stream<Item = talos_engine::events::DlqEvent>> {
        let user_id = *ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?.clone();

        let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
        let is_admin = actor_repo.is_platform_admin(user_id).await.map_err(|e| {
            tracing::error!("dlq_updates admin check failed: {}", e);
            async_graphql::Error::new("Database error").extend_safe()
        })?;

        // Pre-load the subscriber's accessible org ids at subscribe time
        // and refresh periodically. Per-event SQL would be a hot loop
        // on a broadcast channel; one-shot-at-subscribe leaves a stale-
        // permission hole (MCP-985, fixed below).
        //
        // MCP-596 (2026-05-12): column name fix. Pre-fix the SELECT
        // used `organization_id` but the actual column on
        // `organization_members` is `org_id` (see the table definition
        // in migration `20260309000600_add_organizations.sql`). Every
        // non-admin subscribe attempt would have errored out with
        // `column "organization_id" does not exist`, surfacing as a
        // generic "Database error" to operators trying to subscribe to
        // `dlq_updates`. Sibling typo to MCP-595's `is_org_admin`
        // deletion; this one was in actively-exercised code.
        let accessible_org_ids: Vec<Uuid> = if is_admin {
            // Admins bypass the filter entirely; no need to load.
            Vec::new()
        } else {
            talos_organizations::OrganizationService::list_user_org_ids(&db_pool, user_id)
                .await
                .map_err(|e| {
                    tracing::error!("dlq_updates org membership lookup failed: {}", e);
                    async_graphql::Error::new("Database error").extend_safe()
                })?
        };

        let sender =
            ctx.data_unchecked::<tokio::sync::broadcast::Sender<talos_engine::events::DlqEvent>>();
        let mut rx = sender.subscribe();

        // MCP-985 (2026-05-15): refresh `is_admin` + `accessible_org_ids`
        // periodically inside the subscription. Pre-fix the
        // permissions were loaded ONCE at subscribe-time and never
        // refreshed — a user removed from an org during a long-lived
        // subscription (browser tab kept open, employee fired,
        // membership downgraded) would keep seeing DLQ events from
        // that org until they disconnected. DLQ payloads are
        // DLP-scrubbed but still tenant-scoped data (workflow names,
        // execution context, timing). Per-event SQL would burn the
        // broadcast hot loop; 60-second polling is the right middle
        // ground — matches the MCP-699 SSE revalidation cadence in
        // talos-mcp-handlers/src/lib.rs. On refresh failure (DB
        // hiccup), preserve the previous permission set rather than
        // failing closed — closing the stream every transient DB blip
        // would be a worse UX than the small window of stale-perm
        // residue we already accept between ticks.
        const PERM_REFRESH_INTERVAL_SECS: u64 = 60;
        Ok(async_stream::stream! {
            let mut is_admin = is_admin;
            let mut accessible_org_ids = accessible_org_ids;
            let mut refresh_ticker = tokio::time::interval(
                tokio::time::Duration::from_secs(PERM_REFRESH_INTERVAL_SECS),
            );
            // Skip the initial immediate tick — we just loaded
            // permissions a few lines above.
            refresh_ticker.tick().await;

            loop {
                tokio::select! {
                    event = rx.recv() => {
                        match event {
                            Ok(event) => {
                                if dlq_event_visible_to(&event, user_id, &accessible_org_ids, is_admin) {
                                    yield event;
                                }
                            }
                            // MCP-986 (2026-05-15): same Lagged/Closed split as
                            // execution_updates. Don't terminate the stream on
                            // Lagged — the broadcast channel is still healthy
                            // and the next recv() returns the oldest surviving
                            // message. Sibling for the MCP-985 dlq_updates rebuild.
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                tracing::warn!(
                                    target: "talos_audit",
                                    %user_id,
                                    skipped,
                                    "dlq_updates subscriber lagged behind broadcast channel; continuing"
                                );
                                continue;
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                    _ = refresh_ticker.tick() => {
                        match actor_repo.is_platform_admin(user_id).await {
                            Ok(new_is_admin) => {
                                is_admin = new_is_admin;
                                if new_is_admin {
                                    // Admins bypass the filter; clear the
                                    // org list so a future demotion forces
                                    // a re-fetch.
                                    accessible_org_ids = Vec::new();
                                } else {
                                    match talos_organizations::OrganizationService::list_user_org_ids(
                                        &db_pool, user_id,
                                    )
                                    .await
                                    {
                                        Ok(new_ids) => accessible_org_ids = new_ids,
                                        Err(e) => {
                                            tracing::warn!(
                                                target: "talos_audit",
                                                %user_id,
                                                error = %e,
                                                "dlq_updates org-membership refresh failed; keeping prior permission set"
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    target: "talos_audit",
                                    %user_id,
                                    error = %e,
                                    "dlq_updates is_platform_admin refresh failed; keeping prior permission set"
                                );
                            }
                        }
                    }
                }
            }
        })
    }

    /// Real-time notifications when any workflow execution status changes (started, completed, failed).
    ///
    /// Powers the global dashboard "recent executions" list without polling.
    async fn workflow_execution_updates(
        &self,
        ctx: &Context<'_>,
    ) -> Result<impl Stream<Item = talos_engine::events::WorkflowExecutionEvent>> {
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        let sender = ctx.data_unchecked::<tokio::sync::broadcast::Sender<talos_engine::events::WorkflowExecutionEvent>>();
        let mut rx = sender.subscribe();

        let user_id_val = *user_id;

        Ok(async_stream::stream! {
            // MCP-986: Lagged/Closed split. See execution_updates for the
            // full rationale.
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        // SECURITY: Only stream events for workflows owned by this user
                        if event.user_id == user_id_val {
                            yield event;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(
                            target: "talos_audit",
                            user_id = %user_id_val,
                            skipped,
                            "workflow_execution_updates subscriber lagged behind broadcast channel; continuing"
                        );
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        })
    }

    /// Real-time stream of compilation progress events.
    ///
    /// Subscribes to the global compilation event broadcast and filters by user ID.
    async fn compilation_updates(
        &self,
        ctx: &Context<'_>,
    ) -> Result<impl Stream<Item = talos_engine::events::CompilationEvent>> {
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        let sender = ctx.data_unchecked::<talos_engine::events::CompilationEventSender>();
        let mut rx = sender.subscribe();

        let user_id_val = *user_id;

        Ok(async_stream::stream! {
            // MCP-986: Lagged/Closed split. See execution_updates for the
            // full rationale.
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        // SECURITY: Only stream events for compilations owned by this user
                        if event.user_id == user_id_val {
                            yield event;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(
                            target: "talos_audit",
                            user_id = %user_id_val,
                            skipped,
                            "compilation_updates subscriber lagged behind broadcast channel; continuing"
                        );
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        })
    }
}

#[cfg(test)]
mod dlq_visibility_tests {
    //! M T6-1: tenant-scope filter for DLQ subscriptions. Each
    //! visibility rule pinned by a discrete test so a future change
    //! that loosens the filter (regression class) is caught at PR time.
    use super::dlq_event_visible_to;
    use talos_engine::events::DlqEvent;
    use uuid::Uuid;

    fn evt(user_id: Option<Uuid>, org_id: Option<Uuid>) -> DlqEvent {
        DlqEvent {
            id: Uuid::new_v4(),
            workflow_id: None,
            execution_id: None,
            node_id: None,
            error_message: Some("test".into()),
            payload: None,
            created_at: "2026-05-06T00:00:00Z".into(),
            replayed_at: None,
            user_id,
            org_id,
        }
    }

    #[test]
    fn platform_admin_sees_everything() {
        let subscriber = Uuid::new_v4();
        let foreign_user = Uuid::new_v4();
        let foreign_org = Uuid::new_v4();
        let event = evt(Some(foreign_user), Some(foreign_org));
        assert!(dlq_event_visible_to(&event, subscriber, &[], true));
    }

    #[test]
    fn owner_sees_own_event() {
        let subscriber = Uuid::new_v4();
        let event = evt(Some(subscriber), None);
        assert!(dlq_event_visible_to(&event, subscriber, &[], false));
    }

    #[test]
    fn org_member_sees_org_event() {
        let subscriber = Uuid::new_v4();
        let foreign_user = Uuid::new_v4();
        let shared_org = Uuid::new_v4();
        let event = evt(Some(foreign_user), Some(shared_org));
        assert!(dlq_event_visible_to(
            &event,
            subscriber,
            &[shared_org],
            false
        ));
    }

    #[test]
    fn outsider_does_not_see_foreign_event() {
        let subscriber = Uuid::new_v4();
        let foreign_user = Uuid::new_v4();
        let foreign_org = Uuid::new_v4();
        let event = evt(Some(foreign_user), Some(foreign_org));
        assert!(!dlq_event_visible_to(&event, subscriber, &[], false));
    }

    #[test]
    fn outsider_with_unrelated_orgs_does_not_see_foreign_event() {
        let subscriber = Uuid::new_v4();
        let foreign_user = Uuid::new_v4();
        let foreign_org = Uuid::new_v4();
        let unrelated_org_a = Uuid::new_v4();
        let unrelated_org_b = Uuid::new_v4();
        let event = evt(Some(foreign_user), Some(foreign_org));
        assert!(!dlq_event_visible_to(
            &event,
            subscriber,
            &[unrelated_org_a, unrelated_org_b],
            false
        ));
    }

    #[test]
    fn orphan_event_visible_only_to_platform_admin() {
        // Both user_id and org_id None — workflow was deleted before
        // the event fired. The ownership chain is gone, so non-admin
        // users cannot prove they should see this event. Admin sees
        // it for incident-response visibility.
        let subscriber = Uuid::new_v4();
        let event = evt(None, None);
        assert!(!dlq_event_visible_to(&event, subscriber, &[], false));
        assert!(dlq_event_visible_to(&event, subscriber, &[], true));
    }

    #[test]
    fn user_id_match_wins_even_without_org() {
        // Edge case: workflow has user_id set but org_id is null
        // (private workflow not shared with any org). Owner still
        // sees it.
        let subscriber = Uuid::new_v4();
        let event = evt(Some(subscriber), None);
        assert!(dlq_event_visible_to(&event, subscriber, &[], false));
    }

    #[test]
    fn org_match_wins_when_user_id_does_not() {
        let subscriber = Uuid::new_v4();
        let foreign_user = Uuid::new_v4();
        let shared_org = Uuid::new_v4();
        let event = evt(Some(foreign_user), Some(shared_org));
        assert!(dlq_event_visible_to(
            &event,
            subscriber,
            &[shared_org],
            false
        ));
    }
}
