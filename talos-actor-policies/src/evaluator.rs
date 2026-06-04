//! `PolicyEvaluator` — the runtime enforcer.
//!
//! Life of an evaluation:
//! 1. Fetch (or cache-hit) the actor's parsed policies.
//! 2. If empty, short-circuit → `Allow{fired:[]}`. (Common case.)
//! 3. Iterate in `created_at ASC` order (so "first matching block wins" is deterministic).
//! 4. For each policy:
//!    a. Built-in → run the relevant detector inside the caller's transaction.
//!    b. Custom Rhai → evaluate against the event's JSON context.
//! 5. On match, apply the policy's `mode`:
//!    - `log`   → append to actor_action_log.
//!    - `notify` → log AND fire-and-forget notification webhook (or
//!                 fallback action-log row if no webhook configured).
//!    - `block` → log + notify + create approval gate + short-circuit
//!                with `Blocked{..}`. Caller rolls back its tx.
//!
//! ## Security invariants
//! - Rhai evaluation is sandboxed (see `rhai_eval`).
//! - Detectors run inside the caller's tx, which holds advisory locks
//!   where required — no bypass-via-race.
//! - `block` creates a gate via the existing hardened approval-gate
//!   path. Gate tokens are 256-bit random.
//! - All policy rows are hidden from non-owners at the `ActorRepository` layer.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use talos_actor_repository::ActorRepository;
use talos_advanced_repository::AdvancedRepository;

use super::cache::{ParsedPolicy, PolicyCache};
use super::detectors::{detect as builtin_detect, DetectionResult};
use super::rhai_eval;
use super::types::{PolicyEvent, PolicyFiredRecord, PolicyMode, PolicyVerdict, TriggerCondition};

/// Default TTL for the policy cache. Short enough that remove/clone
/// operations propagate quickly; long enough that the happy path
/// never hits the DB. Matches LLM-key-cache TTL.
const DEFAULT_CACHE_TTL_SECS: u64 = 60;

/// How long after cache creation before we sweep expired entries.
const SWEEP_INTERVAL_SECS: u64 = 120;

/// A narrow hook passed into
/// `WorkflowVersionService::publish_version` so the evaluator can run
/// inside the caller's transaction. Re-exported here for backwards
/// compatibility; the canonical trait now lives in
/// `talos-actor-policy-hook` so downstream crates can depend on the
/// abstraction without pulling in this evaluator's transitive deps.
pub use talos_actor_policy_hook::PolicyPrePublishHook;

pub struct PolicyEvaluator {
    // Held for future SQL-touch helpers; reachable via `self.pool()` for
    // tests and downstream extension points that need direct access.
    #[allow(dead_code)]
    pool: PgPool,
    actor_repo: Arc<ActorRepository>,
    advanced_repo: Arc<AdvancedRepository>,
    cache: Arc<PolicyCache>,
    http: reqwest::Client,
    /// Optional platform-wide notification webhook, from
    /// `TALOS_POLICY_NOTIFICATION_WEBHOOK`. When absent, `notify` mode
    /// falls back to writing a `policy_notification_pending` row in
    /// actor_action_log.
    notification_webhook: Option<String>,
    /// Base URL for constructing approval-gate URLs. Same default as
    /// the rest of the codebase uses (`BASE_URL` env var).
    base_url: String,
}

impl PolicyEvaluator {
    pub fn new(
        pool: PgPool,
        actor_repo: Arc<ActorRepository>,
        advanced_repo: Arc<AdvancedRepository>,
    ) -> Arc<Self> {
        // MCP-695 (2026-05-13): =0 env footgun class (sibling of
        // MCP-665/689). `TALOS_POLICY_CACHE_TTL_SECS=0` would make every
        // cache entry expire immediately, so every approval-policy
        // evaluation falls through to the DB lookup. Not destructive but
        // a hot-path perf cliff that's silent at startup. Route through
        // `positive_env_or_default` so non-positive substitutes the
        // default + emits a WARN at process boot.
        let ttl_secs = talos_config::positive_env_or_default(
            "TALOS_POLICY_CACHE_TTL_SECS",
            DEFAULT_CACHE_TTL_SECS,
        );
        let cache = PolicyCache::new(actor_repo.clone(), Duration::from_secs(ttl_secs));

        // MCP-1170 (2026-05-17): SSRF-validate at env-load time.
        // Pre-fix `TALOS_POLICY_NOTIFICATION_WEBHOOK` was loaded with
        // only an empty-string filter — no URL validation, no SSRF
        // check, no scheme check. An operator misconfig like
        // `=http://169.254.169.254/latest/meta-data/` (cloud metadata
        // endpoint) or `=http://10.0.0.5:8080/admin` (internal admin
        // service) silently fired policy event payloads (which
        // include `actor_id`, `user_id`, `event_kind`,
        // `event_context`) at the misconfigured target on every
        // policy trigger. The webhook is operator-controlled so the
        // threat model is "operator misconfig", not "external
        // attacker" — but the same SSRF guard already applied to
        // every other outbound webhook surface (SLA breach,
        // approval gate, failure webhook) should apply here for
        // defense-in-depth + uniformity.
        //
        // Validate at env-load (not at fire-time) so the misconfig
        // is caught at controller startup with a clear log, not
        // observed after the first policy trigger. Invalid value
        // drops to `None` (no webhook configured) which falls back
        // to the action-log pending-notification path — operators
        // still see the policy triggered, just via the dashboard
        // instead of the misconfigured external destination.
        let notification_webhook = std::env::var("TALOS_POLICY_NOTIFICATION_WEBHOOK")
            .ok()
            .filter(|s| !s.is_empty())
            .and_then(
                |url| match talos_http_utils::ssrf::check_outbound_url_no_ssrf(&url) {
                    Ok(()) => Some(url),
                    Err(reason) => {
                        tracing::error!(
                            target: "talos_audit",
                            event_kind = "policy_notification_webhook_rejected",
                            reason,
                            "TALOS_POLICY_NOTIFICATION_WEBHOOK failed SSRF validation at startup; \
                             policy notifications will use the action-log fallback instead. \
                             Fix the env var to enable external webhook delivery."
                        );
                        None
                    }
                },
            );

        // MCP-1155: canonical `talos_config::get_base_url()` —
        // collapses MCP-653 empty-env handling AND the open-redirect-
        // misconfig defense (rejects `BASE_URL=https://attacker.com/x`
        // shapes) into one helper shared across every BASE_URL site.
        let base_url = talos_config::get_base_url();

        // MCP-518: outbound webhooks MUST disable HTTP redirect
        // following — a redirect-pivot SSRF (operator misconfigures
        // the webhook URL to attacker.com which then 302s to
        // 169.254.169.254 or the internal Prometheus/admin port)
        // would silently fetch the redirect target with no signal
        // because the request is fire-and-forget on tokio::spawn.
        // Same class as MCP-469/470/471. Threat model here is
        // weaker (env-var-configured rather than user-supplied)
        // but the fix is one line and removes the entire surface.
        // MCP-1058 (2026-05-15): pair `.timeout()` with
        // `.connect_timeout()`. Without it, a remote that accepts TCP
        // but stalls during TLS handshake eats into the request budget
        // (or the request can complete while the handshake phase has no
        // explicit upper bound). 5s matches the workspace-canonical
        // value (MCP-1034 sweep). Same sibling-drift class as the rest
        // of MCP-1034 — three sites slipped through that sweep
        // (this one, talos-engine/approval_gate, talos-graph-rag).
        // Built via the shared SSRF-safe builder: redirect(none) + the
        // connect-time ControllerSsrfResolver. The `notification_webhook`
        // (operator env `TALOS_POLICY_NOTIFICATION_WEBHOOK`) is SSRF-checked at
        // construction above, but that call-time check can't stop DNS rebinding
        // — exactly the gap PR #162 closed for the sibling A2A / approval-gate /
        // failure-webhook fire sites. This site shipped a plain client for the
        // same root cause (the resolver was unreachable from this crate before
        // it was hoisted into talos-http-utils).
        let http =
            talos_http_utils::outbound::build_outbound_webhook_client("talos-policy-webhook/1.0")
                .expect("reqwest client build — no custom TLS config");

        Arc::new(Self {
            pool,
            actor_repo,
            advanced_repo,
            cache,
            http,
            notification_webhook,
            base_url,
        })
    }

    /// Invalidate a single actor's cache entry. Called from add/remove/clone.
    pub fn invalidate(&self, actor_id: Uuid) {
        self.cache.invalidate(actor_id);
    }

    /// Spawn the background cache-sweeper. Idempotent per Arc<Self>
    /// (called once at startup).
    pub fn spawn_sweeper(self: Arc<Self>) {
        let cache = self.cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(SWEEP_INTERVAL_SECS));
            loop {
                interval.tick().await;
                cache.sweep_expired();
            }
        });
    }

    /// Main entry — evaluate every policy for `event.actor_id()` and
    /// return a verdict. Runs inside the provided transaction so
    /// built-in detectors can take advisory locks that release on
    /// commit/rollback.
    pub async fn evaluate(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        event: PolicyEvent,
    ) -> anyhow::Result<PolicyVerdict> {
        let actor_id = event.actor_id();
        let span = tracing::info_span!(
            target: "actor_policies",
            "policy.evaluate",
            actor_id = %actor_id,
            event_kind = event.kind(),
        );
        let _guard = span.enter();

        let mut policies = (*self.cache.get(actor_id).await?).clone();
        if policies.is_empty() {
            tracing::debug!(target: "actor_policies", "no policies for actor, allow");
            return Ok(PolicyVerdict::Allow { fired: vec![] });
        }
        policies.sort_by_key(|p| p.created_at_ns);

        let mut fired: Vec<PolicyFiredRecord> = Vec::new();

        for policy in policies.iter() {
            let is_match = match &policy.trigger {
                TriggerCondition::Custom(expr) => rhai_eval::evaluate(expr, &event),
                builtin => match builtin_detect(builtin, &event, tx).await? {
                    DetectionResult::Match => true,
                    DetectionResult::NoMatch => false,
                    DetectionResult::Inapplicable => {
                        tracing::debug!(
                            target: "actor_policies",
                            policy_id = %policy.policy_id,
                            trigger = policy.trigger.label(),
                            "trigger condition not applicable to this event (phase-2 stub)"
                        );
                        false
                    }
                },
            };
            if !is_match {
                continue;
            }

            // Record in action log first. All three modes log.
            if let Err(e) = self.log_policy_event(policy, &event).await {
                tracing::warn!(
                    target: "actor_policies",
                    policy_id = %policy.policy_id,
                    error = %e,
                    "policy action-log write failed",
                );
                // Non-fatal — continue. Failing to log shouldn't
                // silently let a block policy bypass.
            }

            match policy.mode {
                PolicyMode::Log => {
                    fired.push(PolicyFiredRecord {
                        policy_id: policy.policy_id,
                        mode: policy.mode,
                        trigger_label: policy.trigger.label().to_string(),
                    });
                }
                PolicyMode::Notify => {
                    self.send_notification(policy, &event).await;
                    fired.push(PolicyFiredRecord {
                        policy_id: policy.policy_id,
                        mode: policy.mode,
                        trigger_label: policy.trigger.label().to_string(),
                    });
                }
                PolicyMode::Block => {
                    // Notifications fire for block too — operators
                    // want to know an action got gated.
                    self.send_notification(policy, &event).await;
                    // Create the approval gate.
                    let (gate_id, approve_url, reject_url) =
                        self.create_block_gate(policy, &event).await?;
                    return Ok(PolicyVerdict::Blocked {
                        policy_id: policy.policy_id,
                        gate_id,
                        approve_url,
                        reject_url,
                        trigger_label: policy.trigger.label().to_string(),
                        approvers: policy.approvers.clone(),
                        reason: format!(
                            "Blocked by actor policy on trigger '{}'",
                            policy.trigger.label()
                        ),
                        fired,
                    });
                }
            }
        }

        Ok(PolicyVerdict::Allow { fired })
    }

    /// Insert a `policy_triggered` row into `actor_action_log`. Called
    /// for every matching policy regardless of mode.
    async fn log_policy_event(
        &self,
        policy: &ParsedPolicy,
        event: &PolicyEvent,
    ) -> anyhow::Result<()> {
        let (workflow_id, details) = match event {
            PolicyEvent::PublishVersion {
                workflow_id,
                actor_id,
                user_id,
            } => (
                Some(*workflow_id),
                json!({
                    "policy_id": policy.policy_id,
                    "policy_mode": policy.mode.as_str(),
                    "trigger_condition": policy.trigger.label(),
                    "event": "publish_version",
                    "workflow_id": workflow_id.to_string(),
                    "actor_id": actor_id.to_string(),
                    "user_id": user_id.to_string(),
                    "evaluated_at": chrono::Utc::now().to_rfc3339(),
                }),
            ),
        };
        let summary = format!(
            "Policy {} triggered on {} ({})",
            policy.policy_id,
            policy.trigger.label(),
            policy.mode.as_str(),
        );
        self.actor_repo
            .insert_action_log_entry(
                policy.actor_id,
                "policy_triggered",
                workflow_id,
                None,
                &summary,
                Some(&details),
            )
            .await?;
        Ok(())
    }

    /// Fire-and-forget notification. Never fails the caller — webhook
    /// errors surface in tracing. Falls back to an additional action-log
    /// row when no webhook is configured so operators can scrape a
    /// pending queue.
    async fn send_notification(&self, policy: &ParsedPolicy, event: &PolicyEvent) {
        let payload = json!({
            "event": "actor_policy_triggered",
            "policy_id": policy.policy_id,
            "actor_id": policy.actor_id,
            "mode": policy.mode.as_str(),
            "trigger_condition": policy.trigger.label(),
            "approvers": policy.approvers,
            "event_kind": event.kind(),
            "event_context": event.to_rhai_context(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        match &self.notification_webhook {
            Some(url) => {
                let url = url.clone();
                let http = self.http.clone();
                let policy_id = policy.policy_id;
                tokio::spawn(async move {
                    match http.post(&url).json(&payload).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            tracing::info!(
                                target: "actor_policies",
                                %policy_id,
                                status = resp.status().as_u16(),
                                "policy notification delivered",
                            );
                        }
                        Ok(resp) => {
                            tracing::warn!(
                                target: "actor_policies",
                                %policy_id,
                                status = resp.status().as_u16(),
                                "policy notification webhook returned non-success — event still logged",
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                target: "actor_policies",
                                %policy_id,
                                error = %e,
                                "policy notification webhook delivery failed — event still logged",
                            );
                        }
                    }
                });
            }
            None => {
                // No webhook — log a pending marker so operators can
                // still see who was supposed to be notified.
                let details = json!({
                    "policy_id": policy.policy_id,
                    "trigger_condition": policy.trigger.label(),
                    "approvers": policy.approvers,
                    "note": "No TALOS_POLICY_NOTIFICATION_WEBHOOK configured; operators must poll this log.",
                });
                let summary = format!(
                    "Policy {} notification pending (no webhook configured)",
                    policy.policy_id
                );
                if let Err(e) = self
                    .actor_repo
                    .insert_action_log_entry(
                        policy.actor_id,
                        "policy_notification_pending",
                        None,
                        None,
                        &summary,
                        Some(&details),
                    )
                    .await
                {
                    tracing::warn!(
                        target: "actor_policies",
                        policy_id = %policy.policy_id,
                        error = %e,
                        "failed to log pending-notification marker",
                    );
                }
            }
        }
    }

    /// Create an approval gate representing the blocked action.
    /// Returns `(gate_id, approve_url, reject_url)`.
    ///
    /// Phase-1 limitation: there is no continuation_workflow_id on
    /// these gates — resolving the gate does NOT auto-retry the
    /// blocked action. The caller is expected to retry
    /// `publish_version` manually after approval. The tool response
    /// spells this out.
    async fn create_block_gate(
        &self,
        policy: &ParsedPolicy,
        event: &PolicyEvent,
    ) -> anyhow::Result<(Uuid, String, String)> {
        let user_id = match event {
            PolicyEvent::PublishVersion { user_id, .. } => *user_id,
        };

        // 32-byte cryptographically-random token, hex-encoded. Same
        // shape as `create_approval_gate` callers in `mcp::advanced`
        // so the existing `/approvals/{token}/{action}` handlers
        // (GET preview, POST resolve) validate and match it.
        //
        // MCP-1054 (2026-05-15): switched `rand::thread_rng()` →
        // `rand::rngs::OsRng` to match every other approval-gate
        // token generation site (advanced.rs:3966 + advanced.rs:5525
        // + controller/main.rs:4711). Both RNGs are crypto-secure in
        // current rand 0.8, but the comment claims "same shape as
        // `create_approval_gate` callers" — those callers use OsRng,
        // so aligning here removes a subtle drift hazard: a future
        // rand-major-version change that demotes ThreadRng from
        // crypto-secure (or hardens OsRng exclusively) would
        // silently degrade THIS one path while leaving the sibling
        // sites secure. Same N-inline-copies-with-subtle-drift class
        // as MCP-1037..1053; smaller blast radius.
        use rand::RngCore;
        let mut token_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token_bytes);
        let token = hex::encode(token_bytes);

        let title = format!("Actor policy block: {}", policy.trigger.label());
        let description = format!(
            "Policy {} ({}) blocked action {} by user {}",
            policy.policy_id,
            policy.trigger.label(),
            event.kind(),
            user_id,
        );
        let payload = event.to_rhai_context();

        // Reuse the existing approval-gate write path so all downstream
        // handlers (list_approval_gates, resolve_approval_gate, the
        // HTTP approve_url + reject_url routes) work unchanged for
        // policy-created gates. Phase 1 leaves continuation_wf = None
        // — resolving unblocks the caller's next retry of the blocked
        // action, it does not auto-retry.
        let gate_id = self
            .advanced_repo
            .create_approval_gate(
                user_id,
                &title,
                Some(&description),
                &payload,
                &token,
                None,  // continuation_workflow_id
                168.0, // expires_in_hours, matches default
                None,  // notification_webhook (handled separately above)
            )
            .await?;

        let approve_url = format!("{}/approvals/{}/approve", self.base_url, token);
        let reject_url = format!("{}/approvals/{}/reject", self.base_url, token);
        Ok((gate_id, approve_url, reject_url))
    }
}

/// Concrete hook adapter used by the publish_version path. Wraps the
/// Arc<PolicyEvaluator> so it can be passed as `Option<&dyn
/// PolicyPrePublishHook>` without the version service needing to
/// depend on the actor_policies module.
pub struct PublishVersionPolicyHook {
    pub evaluator: Arc<PolicyEvaluator>,
}

#[async_trait::async_trait]
impl PolicyPrePublishHook for PublishVersionPolicyHook {
    async fn check(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        actor_id: Uuid,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> anyhow::Result<PolicyVerdict> {
        self.evaluator
            .evaluate(
                tx,
                PolicyEvent::PublishVersion {
                    actor_id,
                    workflow_id,
                    user_id,
                },
            )
            .await
    }
}

/// Access the pool for tests/bench. Not used by production callers —
/// they go through `evaluate`.
impl PolicyEvaluator {
    // Test-only accessor — production callers route through `evaluate`
    // and never need direct DB access.
    #[allow(dead_code)]
    #[doc(hidden)]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}
