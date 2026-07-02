use axum::{extract::Path, http::StatusCode, response::IntoResponse, Extension};
use sqlx::{Pool, Postgres};
use std::sync::Arc;

use talos_registry::ModuleRegistry;
use talos_secrets_manager::SecretsManager;

use serde::Deserialize;

#[derive(Deserialize)]
pub struct ApprovalPayload {
    pub approved: bool,
}

pub async fn approval_handler(
    Path(execution_id): Path<String>,
    Extension(user_id): Extension<uuid::Uuid>,
    Extension(db_pool): Extension<Pool<Postgres>>,
    Extension(redis_client): Extension<Option<std::sync::Arc<redis::Client>>>,
    Extension(nats_client): Extension<Option<std::sync::Arc<async_nats::Client>>>,
    axum::Json(payload): axum::Json<ApprovalPayload>,
) -> impl IntoResponse {
    // SECURITY: Verify the authenticated user owns this workflow execution before
    // allowing them to approve/reject it.  Without this check, any authenticated
    // user who knows (or guesses) an execution UUID can hijack another user's
    // approval gate.
    let exec_uuid = match uuid::Uuid::parse_str(&execution_id) {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid execution ID").into_response(),
    };

    // MCP-535: distinguish DB-error from row-missing. The previous
    // `.unwrap_or(None)` collapsed both into "owner = None" → 404. The
    // authorization decision is still fail-closed (DB error → 404 is
    // safe) but operators lost the signal: every approval lookup
    // returning 404 during a Postgres outage looked like users typing
    // bad UUIDs. Log the DB error explicitly so it surfaces in
    // metrics/alerts; behaviour is unchanged.
    let owner: Option<(uuid::Uuid,)> =
        match sqlx::query_as("SELECT user_id FROM workflow_executions WHERE id = $1")
            .bind(exec_uuid)
            .fetch_optional(&db_pool)
            .await
        {
            Ok(row) => row,
            Err(e) => {
                tracing::error!(
                    execution_id = %execution_id,
                    error = %e,
                    "approval_handler: workflow_executions ownership lookup failed; \
                     treating as not-found (fail-closed)"
                );
                None
            }
        };

    match owner {
        Some((owner_id,)) if owner_id == user_id => {} // authorised
        Some(_) => {
            // MCP-1102 (2026-05-16): return the same 404 + "Execution
            // not found" body as the genuine-missing branch below to
            // avoid leaking existence. Pre-fix, an attacker with a list
            // of execution UUIDs (leaked dashboard screenshot, log
            // exfiltration, predictable test-fixture IDs) could
            // distinguish "this UUID exists but belongs to someone
            // else" (403) from "this UUID does not exist" (404). For
            // workflow executions specifically this confirms cross-
            // tenant activity: an attacker probing 100 candidate UUIDs
            // learns which ones map to real users without ever passing
            // ownership. Same tenant-isolation discipline noted in
            // CLAUDE.md (`SECURITY: Verify the authenticated user owns
            // …` already enforced; the leak was the differentiated
            // status code, not the access check itself). Server-side
            // WARN retains the distinction for forensics.
            tracing::warn!(
                user_id = %user_id,
                execution_id = %execution_id,
                "Approval attempt rejected: execution belongs to a different user"
            );
            return (StatusCode::NOT_FOUND, "Execution not found").into_response();
        }
        None => {
            return (StatusCode::NOT_FOUND, "Execution not found").into_response();
        }
    }

    tracing::info!(
        user_id = %user_id,
        execution_id = %execution_id,
        "User is resolving approval for execution"
    );
    let redis = match redis_client {
        Some(r) => r,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, "Redis not available").into_response(),
    };
    let nats = match nats_client {
        Some(n) => n,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, "NATS not available").into_response(),
    };

    let mut con = match redis.get_multiplexed_tokio_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to get Redis connection: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Redis error").into_response();
        }
    };

    // The frontend UI calls this webhook with the workflow_execution_id, not the specific node's execution_id.
    let redis_key = format!("approval:{}", execution_id);
    // MCP-999 (2026-05-15): same MCP-535 distinction-of-failures rule
    // applied to the workflow_approval_gates lookups above, now on the
    // Redis side. Pre-fix `.unwrap_or(None)` silently collapsed an
    // Err(redis_error) into Ok(None), and the next branch returns 404
    // "Approval request not found or expired" — indistinguishable to
    // operators from a genuinely missing/expired key. During a Redis
    // outage every legitimate approval click hits this code path and
    // the only operator-facing signal is a "404 not found" without
    // correlation to Redis availability. Fail-closed posture preserved
    // (no key → 404), but the Err arm now logs at error! level with
    // structured context so monitoring can alert on the underlying
    // cause. Sibling site at talos-mcp-handlers/src/executions.rs:6136
    // (`submit_workflow_approval` MCP tool) fixed in the same commit.
    let reply_topic: Option<String> = match redis::cmd("GET")
        .arg(&redis_key)
        .query_async::<Option<String>>(&mut con)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                execution_id = %execution_id,
                error = %e,
                "approval_handler: Redis GET for approval reply-topic failed; \
                 returning not-found (fail-closed)"
            );
            None
        }
    };

    let topic = match reply_topic {
        Some(t) => t,
        None => {
            return (
                StatusCode::NOT_FOUND,
                "Approval request not found or expired",
            )
                .into_response()
        }
    };

    // SECURITY: validate topic before publishing. The topic is read from Redis, where it
    // was written by a WASM module. Reject wildcards (*,>) and enforce printable ASCII
    // to prevent NATS subject injection (publishing to unintended subjects).
    {
        let topic_bytes = topic.as_bytes();
        let is_safe = !topic.is_empty()
            && topic.len() <= 512
            && topic_bytes
                .iter()
                .all(|&b| b.is_ascii() && b >= 0x20 && b != b'*' && b != b'>');
        if !is_safe {
            tracing::error!(
                execution_id = %execution_id,
                "SECURITY: approval reply topic from Redis failed validation — aborting publish"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid approval routing data",
            )
                .into_response();
        }
    }

    let response_str = if payload.approved { "true" } else { "false" };

    if let Err(e) = nats.publish(topic, response_str.into()).await {
        tracing::error!("Failed to publish approval to NATS: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to send approval").into_response();
    }

    (StatusCode::OK, "Approval processed").into_response()
}

/// GET handler for approval gate URLs.
///
/// Returns a confirmation page with a POST form. The state-changing
/// resolution happens in [`approval_gate_handler`] (POST), never in
/// this GET — link previewers (Slack/Teams/Gmail unfurl workers),
/// browser prefetch, and corporate proxy scanners routinely GET
/// shared URLs, so approving on bare GET would silently auto-resolve
/// gates whenever the URL was shared. RFC 7231 §4.2.1: GET is a safe
/// method and must not have observable side effects.
///
/// The preview looks up the gate to show title + description so the
/// reviewer knows what they're about to decide on, and refuses to
/// show a form for gates that are expired / already resolved.
/// Constant-time comparison of an approval-gate token against the value
/// stored on the row the SHA-256 lookup returned. The lookup keys on
/// `token_hash` (a non-secret digest) so the indexed query never compares
/// the raw secret; this final `ct_eq` makes the auth decision itself
/// constant-time and defends against the (cryptographically negligible)
/// SHA-256 collision. An empty stored token can never authenticate —
/// guards the empty-string `ct_eq` bypass class (MCP-629).
fn approval_token_matches(stored: &str, provided: &str) -> bool {
    use subtle::ConstantTimeEq;
    if stored.is_empty() {
        return false;
    }
    stored.as_bytes().ct_eq(provided.as_bytes()).unwrap_u8() == 1
}

pub async fn approval_gate_preview(
    Path((token, action)): Path<(String, String)>,
    Extension(db_pool): Extension<Pool<Postgres>>,
) -> impl IntoResponse {
    let is_approve = match action.as_str() {
        "approve" => true,
        "reject" => false,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                axum::response::Html("<h1>Invalid action</h1><p>Use /approve or /reject.</p>"),
            )
                .into_response()
        }
    };
    if token.len() != 64 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            axum::response::Html("<h1>Invalid token</h1>"),
        )
            .into_response();
    }
    // Look up by the SHA-256 token hash (non-secret, indexed) rather than
    // the raw token, then constant-time-compare the stored token below.
    let token_hash = talos_text_util::sha256_hex(&token);
    let row: Option<(
        String,
        String,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
        String,
    )> = match sqlx::query_as(
        "SELECT status, title, description, expires_at, token \
             FROM workflow_approval_gates \
             WHERE token_hash = $1",
    )
    .bind(&token_hash)
    .fetch_optional(&db_pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            // MCP-535: don't mask DB errors as "gate not found". Renders
            // the same 404 page (we can't show the user a 500 without
            // breaking the approval-link UX), but the operator gets a
            // structured log to drive alerting on Postgres availability.
            tracing::error!(
                token_len = token.len(),
                error = %e,
                "approval gate preview: workflow_approval_gates lookup failed; \
                 returning not-found"
            );
            None
        }
    };
    let (status, title, description, expires_at, _) = match row {
        Some(r) if approval_token_matches(&r.4, &token) => r,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                axum::response::Html("<h1>Approval gate not found</h1><p>The link may have expired or already been used.</p>"),
            )
                .into_response()
        }
    };
    if status != "pending" {
        let msg = format!(
            "<h1>Already resolved</h1><p>This gate was already <strong>{}</strong>.</p>",
            status
        );
        return (StatusCode::CONFLICT, axum::response::Html(msg)).into_response();
    }
    if expires_at <= chrono::Utc::now() {
        return (
            StatusCode::GONE,
            axum::response::Html("<h1>Gate expired</h1>"),
        )
            .into_response();
    }

    let (verb, colour) = if is_approve {
        ("Approve", "#22c55e")
    } else {
        ("Reject", "#ef4444")
    };
    let title_safe = html_escape(&title);
    let description_safe = description.as_deref().map(html_escape).unwrap_or_default();

    // Auto-submitting forms are a footgun — require a human click to
    // POST. The `action` attribute posts back to the same URL.
    let html = format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Talos — Confirm {verb}</title>
<style>
  body{{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8fafc}}
  .card{{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:48px 56px;text-align:left;max-width:520px}}
  h1{{color:{colour};font-size:1.75rem;margin-bottom:8px}}
  h2{{color:#0f172a;font-size:1.125rem;margin:0 0 4px 0}}
  p.desc{{color:#475569;margin:8px 0 24px}}
  form{{display:inline-block;margin-top:8px}}
  button{{background:{colour};color:#fff;border:0;border-radius:8px;padding:12px 24px;font-size:1rem;cursor:pointer}}
  button:hover{{filter:brightness(0.95)}}
  .muted{{color:#94a3b8;font-size:.875rem;margin-top:16px}}
</style></head><body>
<div class="card">
  <h1>Confirm {verb}</h1>
  <h2>{title_safe}</h2>
  <p class="desc">{description_safe}</p>
  <form method="POST" action="">
    <button type="submit">{verb}</button>
  </form>
  <p class="muted">This action is final and cannot be undone.</p>
</div></body></html>"#
    );
    (StatusCode::OK, axum::response::Html(html)).into_response()
}

/// Minimal HTML escape for dynamic content embedded in the preview
/// page (gate title, description). The approval page is served with
/// a tight CSP, but defence in depth is cheap here and the gate fields
/// are user-provided at creation time.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Human-accessible approval gate handler (POST).
///
/// Called when a human submits the confirmation form rendered by
/// [`approval_gate_preview`]. Authentication is the cryptographically
/// random token embedded in the URL path. No session cookie or API
/// key is required.
///
/// On success returns a minimal HTML page confirming the decision.
pub async fn approval_gate_handler(
    Path((token, action)): Path<(String, String)>,
    Extension(db_pool): Extension<Pool<Postgres>>,
    Extension(nats_client): Extension<Option<Arc<async_nats::Client>>>,
    Extension(registry): Extension<Arc<ModuleRegistry>>,
    // Shared SecretsManager — wired into the axum router as
    // `Option<Arc<SecretsManager>>` (always Some on production startup).
    // Required so trigger_continuation_workflow can pass it through to
    // the engine instead of constructing per call.
    Extension(secrets_manager): Extension<Option<Arc<SecretsManager>>>,
) -> impl IntoResponse {
    // Validate action
    let is_approve = match action.as_str() {
        "approve" => true,
        "reject" => false,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                axum::response::Html("<h1>Invalid action</h1><p>Use /approve or /reject.</p>"),
            )
                .into_response()
        }
    };

    // Sanitise token: must be 64 hex chars (32 bytes)
    if token.len() != 64 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            axum::response::Html("<h1>Invalid token</h1>"),
        )
            .into_response();
    }

    // Look up by the SHA-256 token hash (non-secret, indexed via the
    // `token_hash` generated column) rather than the raw token, then
    // constant-time-compare the stored token below. Status + expiry are
    // re-checked atomically in the UPDATE. This is the hardening the
    // 2026-05-28 audit note deferred (migration 20260608140000): the
    // indexed lookup no longer compares the raw secret, and the auth
    // decision is constant-time — matching the `subtle::ConstantTimeEq`
    // discipline used for CSRF, API keys, TOTP, registry sigs, webhook HMAC.
    let token_hash = talos_text_util::sha256_hex(&token);
    let row: Option<(
        uuid::Uuid,
        String,
        Option<uuid::Uuid>,
        serde_json::Value,
        uuid::Uuid,
        String,
    )> = match sqlx::query_as(
        "SELECT id, status, continuation_workflow_id, payload, user_id, token \
         FROM workflow_approval_gates \
         WHERE token_hash = $1",
    )
    .bind(&token_hash)
    .fetch_optional(&db_pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            // MCP-535: see the preview-path comment above — same rationale.
            // Approve/reject is an action endpoint, so masking a DB error
            // as 404 also means the operator user thinks the link expired
            // when in fact Postgres just hiccupped. Log it.
            tracing::error!(
                token_len = token.len(),
                error = %e,
                "approval gate action: workflow_approval_gates lookup failed; \
                 returning not-found"
            );
            None
        }
    };

    let (gate_id, current_status, continuation_wf_id, payload, user_id) = match row {
        Some(r) if approval_token_matches(&r.5, &token) => (r.0, r.1, r.2, r.3, r.4),
        _ => {
            return (
                StatusCode::NOT_FOUND,
                axum::response::Html("<h1>Approval gate not found</h1><p>The link may have expired or already been used.</p>"),
            )
                .into_response()
        }
    };

    if current_status != "pending" {
        let msg = format!(
            "<h1>Already resolved</h1><p>This gate was already <strong>{}</strong>.</p>",
            current_status
        );
        return (StatusCode::CONFLICT, axum::response::Html(msg)).into_response();
    }

    let new_status = if is_approve { "approved" } else { "rejected" };

    let updated = sqlx::query(
        "UPDATE workflow_approval_gates \
         SET status = $1, resolved_at = NOW(), resolved_by_type = 'human_url' \
         WHERE id = $2 AND status = 'pending' AND expires_at > NOW()",
    )
    .bind(new_status)
    .bind(gate_id)
    .execute(&db_pool)
    .await
    .map(|r| r.rows_affected())
    .unwrap_or(0);

    if updated == 0 {
        return (
            StatusCode::GONE,
            axum::response::Html("<h1>Gate expired or already resolved</h1>"),
        )
            .into_response();
    }

    // Trigger the continuation workflow if approved.
    // Uses the same engine-dispatch path as trigger_workflow so the execution actually runs.
    let triggered_msg = if is_approve {
        if let Some(cwf_id) = continuation_wf_id {
            // Skip the trigger if the SecretsManager extension wasn't wired
            // — this path is exercised in tests with a stub router. In
            // production it's always Some(...) so this is just a safety guard.
            let Some(sm) = secrets_manager.clone() else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "SecretsManager extension missing",
                )
                    .into_response();
            };
            let exec_id = talos_continuation_trigger::trigger_continuation_workflow(
                &db_pool,
                registry,
                nats_client,
                sm,
                user_id,
                cwf_id,
                &payload,
                gate_id,
                talos_continuation_trigger::TriggerSourceKind::ApprovalGate,
            )
            .await;

            if exec_id.is_some() {
                "<p>The continuation workflow has been triggered.</p>"
            } else {
                "<p>Note: The continuation workflow could not be triggered automatically. Please start it manually.</p>"
            }
        } else {
            ""
        }
    } else {
        ""
    };

    let (icon, heading, colour) = if is_approve {
        ("✅", "Approved", "#22c55e")
    } else {
        ("❌", "Rejected", "#ef4444")
    };

    let html = format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Talos — Gate {heading}</title>
<style>
  body{{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8fafc}}
  .card{{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:48px 56px;text-align:center;max-width:480px}}
  h1{{color:{colour};font-size:2rem;margin-bottom:8px}}
  p{{color:#64748b;margin:0}}
</style></head><body>
<div class="card">
  <div style="font-size:4rem">{icon}</div>
  <h1>{heading}</h1>
  <p>The approval gate has been <strong>{new_status}</strong>.</p>
  {triggered_msg}
  <p style="margin-top:24px;font-size:.875rem">You may close this tab.</p>
</div></body></html>"#
    );

    (StatusCode::OK, axum::response::Html(html)).into_response()
}

#[cfg(test)]
mod approval_token_match_tests {
    use super::approval_token_matches;

    #[test]
    fn matches_identical_token() {
        let tok = "a".repeat(64);
        assert!(approval_token_matches(&tok, &tok));
    }

    #[test]
    fn rejects_different_token() {
        let stored = "a".repeat(64);
        let provided = format!("{}b", "a".repeat(63));
        assert!(!approval_token_matches(&stored, &provided));
    }

    #[test]
    fn rejects_length_mismatch() {
        assert!(!approval_token_matches("abcd", "abcde"));
        assert!(!approval_token_matches(&"a".repeat(64), "a"));
    }

    #[test]
    fn empty_stored_never_authenticates() {
        // Empty-string ct_eq bypass class (MCP-629): a row whose stored
        // token is "" must never match — not even an empty provided token.
        assert!(!approval_token_matches("", ""));
        assert!(!approval_token_matches("", "anything"));
    }

    #[test]
    fn matches_sha256_lookup_contract() {
        // The handler fetches the row WHERE token_hash = sha256_hex(provided),
        // so the stored token on a legitimately-matched row equals `provided`.
        let provided = "deadbeef".repeat(8); // 64 hex chars
        let _hash = talos_text_util::sha256_hex(&provided);
        assert!(approval_token_matches(&provided, &provided));
    }
}
