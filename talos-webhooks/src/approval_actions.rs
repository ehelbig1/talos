//! One-click approve/reject endpoints for SUSPENDED (`waiting`)
//! confidence-gate executions — the public HTTP face of
//! `talos_execution_repository::approval_links`.
//!
//! `/approval-actions/{token}/{action}` where `action` ∈ {approve, reject}:
//! * **GET** ([`approval_action_preview`]) renders a confirmation page
//!   with a POST form — the decision never fires on GET, so email link
//!   prefetchers (Gmail, Outlook SafeLinks, chat unfurlers, corporate
//!   proxy scanners) cannot silently approve or reject a run. RFC 7231
//!   §4.2.1: GET is safe and must have no observable side effects.
//! * **POST** ([`approval_action_apply`]) applies the decision through
//!   [`ExecutionOrchestrationService::apply_waiting_approval_decision`] —
//!   the SAME record-then-resume write path `submit_workflow_approval`
//!   uses (no resume logic is duplicated).
//!
//! Authentication is the 256-bit random capability token in the path
//! (hash-only at rest; see the repository module docs for the full model).
//! Tenancy rides the token row's `user_id`, never the request. Unknown,
//! malformed, and expired tokens all render ONE uniform page — no
//! existence oracle. Sibling of `approval.rs` and `correction.rs`; same
//! rate-limit stack (per-IP webhook limiter + global + governor).
//!
//! CSRF posture (documented, accepted — capability-URL semantics,
//! identical to `correction.rs`): the POST carries no CSRF token and no
//! session cookie. The URL token IS the credential; there is no ambient
//! authority for a cross-site POST to ride, so CSRF does not apply. The
//! GET→POST split is the only guard needed (it stops prefetch side
//! effects). "Already decided" is enforced server-side by the underlying
//! `execution_approvals` pending-row check, so a replayed POST is a
//! harmless no-op that renders the uniform decided page.

use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    response::IntoResponse,
};
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use talos_execution_orchestration::{
    ApprovalDecisionOutcome, ExecutionOrchestrationService, OrchestrationError,
};
use talos_execution_repository::{approval_links::ApprovalTokenContext, ExecutionRepository};

use crate::html_escape;

/// Uniform page for unknown / malformed / expired tokens.
fn invalid_link() -> axum::response::Response {
    (
        StatusCode::NOT_FOUND,
        axum::response::Html(
            "<h1>Link invalid or expired</h1><p>Approval links expire after a while, and each \
             is tied to a single pending approval. If you still need to act, open the Talos \
             approvals view.</p>",
        ),
    )
        .into_response()
}

/// Page shown when the execution is no longer awaiting a decision — a
/// re-clicked link after the run was already approved/rejected (here or
/// from the UI), or a run that timed out. Not an error: both approve and
/// reject links land here once a decision exists.
fn already_decided() -> axum::response::Response {
    (
        StatusCode::OK,
        axum::response::Html(
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>Talos — Already decided</title>\
<style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8fafc}\
.card{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:40px 48px;max-width:520px}\
h1{color:#0f172a;font-size:1.25rem;margin:0 0 12px}p{color:#475569;margin:0}</style></head><body>\
<div class=\"card\"><h1>Already decided &#10003;</h1>\
<p>This approval has already been resolved. No further action is needed — you can close this tab.</p>\
</div></body></html>",
        ),
    )
        .into_response()
}

fn parse_action(action: &str) -> Option<bool> {
    match action {
        "approve" => Some(true),
        "reject" => Some(false),
        _ => None,
    }
}

async fn resolve_token(
    db_pool: &Pool<Postgres>,
    token: &str,
) -> Result<Option<ApprovalTokenContext>, axum::response::Response> {
    let repo = ExecutionRepository::new(db_pool.clone());
    match repo.lookup_approval_token(token).await {
        Ok(ctx) => Ok(ctx),
        Err(e) => {
            // Same posture as approval.rs / correction.rs (MCP-535): the
            // clicker gets the uniform page, the operator gets a
            // structured log — never leak DB detail into a public
            // response, and never log the token.
            tracing::error!(
                target: "talos_approvals",
                error = %e,
                "approval token lookup failed (DB error)"
            );
            Err(invalid_link())
        }
    }
}

/// GET — confirmation page. Side-effect free by design.
pub async fn approval_action_preview(
    Path((token, action)): Path<(String, String)>,
    Extension(db_pool): Extension<Pool<Postgres>>,
) -> impl IntoResponse {
    let Some(is_approve) = parse_action(&action) else {
        // Malformed action segment → same uniform page (no oracle).
        return invalid_link();
    };
    let ctx = match resolve_token(&db_pool, &token).await {
        Ok(Some(ctx)) => ctx,
        Ok(None) => return invalid_link(),
        Err(resp) => return resp,
    };

    // The run must still be suspended to accept a decision. Anything else
    // (already approved/rejected, completed, failed) is "already decided".
    if ctx.execution_status != "waiting" {
        return already_decided();
    }

    let (verb, colour) = if is_approve {
        ("Approve", "#22c55e")
    } else {
        ("Reject", "#ef4444")
    };
    let wf_safe = html_escape(ctx.workflow_name.as_deref().unwrap_or("this workflow"));
    let consequence = if is_approve {
        "The paused workflow will resume from where it stopped and continue running."
    } else {
        "The paused workflow will be rejected and will stop with an approval-denied error."
    };
    // Sibling-relative href to the OTHER action: against the base
    // /approval-actions/{token}/{action} a bare "approve"/"reject"
    // replaces only the last segment, keeping the token. ("../x" would
    // strip the token per RFC 3986 and 404.)
    let other = if is_approve { "reject" } else { "approve" };
    let other_label = if is_approve {
        "reject instead"
    } else {
        "approve instead"
    };

    let html = format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Talos — Confirm {verb}</title>
<style>
  body{{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8fafc}}
  .card{{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:40px 48px;text-align:left;max-width:520px}}
  h1{{color:{colour};font-size:1.5rem;margin:0 0 8px}}
  h2{{color:#0f172a;font-size:1.05rem;margin:0 0 4px}}
  p.desc{{color:#475569;margin:8px 0 24px}}
  form{{display:inline-block}}
  button{{background:{colour};color:#fff;border:0;border-radius:8px;padding:12px 24px;font-size:1rem;cursor:pointer}}
  button:hover{{filter:brightness(0.95)}}
  .alt{{margin-top:20px;font-size:.875rem}}
  .alt a{{color:#2563eb;text-decoration:none}}
  .muted{{color:#94a3b8;font-size:.875rem;margin-top:16px}}
</style></head><body>
<div class="card">
  <h1>Confirm {verb}</h1>
  <h2>{wf_safe}</h2>
  <p class="desc">{consequence}</p>
  <form method="POST" action="">
    <button type="submit">{verb}</button>
  </form>
  <p class="alt">changed your mind? <a href="{other}">{other_label}</a></p>
  <p class="muted">This action is final and cannot be undone.</p>
</div></body></html>"#
    );
    (StatusCode::OK, axum::response::Html(html)).into_response()
}

/// POST — apply the decision via the shared record-then-resume path.
pub async fn approval_action_apply(
    Path((token, action)): Path<(String, String)>,
    Extension(db_pool): Extension<Pool<Postgres>>,
    Extension(orchestration): Extension<Option<Arc<ExecutionOrchestrationService>>>,
) -> impl IntoResponse {
    let Some(is_approve) = parse_action(&action) else {
        return invalid_link();
    };
    let ctx = match resolve_token(&db_pool, &token).await {
        Ok(Some(ctx)) => ctx,
        Ok(None) => return invalid_link(),
        Err(resp) => return resp,
    };

    // Wired as Some(...) on production startup; a stub router in tests may
    // omit it. Fail closed rather than pretend a decision landed.
    let Some(service) = orchestration else {
        tracing::error!(
            target: "talos_approvals",
            "approval-action apply: ExecutionOrchestrationService extension missing"
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::response::Html("<h1>Something went wrong</h1><p>Try again shortly.</p>"),
        )
            .into_response();
    };

    let reason = if is_approve {
        "Approved via one-click email link"
    } else {
        "Rejected via one-click email link"
    };

    match service
        .apply_waiting_approval_decision(ctx.execution_id, ctx.user_id, is_approve, Some(reason))
        .await
    {
        Ok(ApprovalDecisionOutcome {
            decision_recorded: false,
            ..
        }) => {
            // No pending approval row — already decided or not waiting.
            already_decided()
        }
        Ok(ApprovalDecisionOutcome { resumed, .. }) => {
            // Best-effort observability stamp; never fails the decision.
            let repo = ExecutionRepository::new(db_pool.clone());
            if let Err(e) = repo.touch_approval_token(&token).await {
                tracing::warn!(
                    target: "talos_approvals",
                    error = %e,
                    "failed to stamp approval token used_at"
                );
            }
            tracing::info!(
                target: "talos_approvals",
                execution_id = %ctx.execution_id,
                approved = is_approve,
                resumed,
                "approval decision applied via email link"
            );

            let (icon, heading, colour) = if is_approve {
                ("✅", "Approved", "#22c55e")
            } else {
                ("❌", "Rejected", "#ef4444")
            };
            let wf_safe = html_escape(ctx.workflow_name.as_deref().unwrap_or("The workflow"));
            let detail = if is_approve {
                "The workflow has resumed and will continue processing."
            } else {
                "The workflow has resumed and will stop with an approval-denied error."
            };
            let html = format!(
                r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Talos — {heading}</title>
<style>
  body{{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8fafc}}
  .card{{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:48px 56px;text-align:center;max-width:480px}}
  h1{{color:{colour};font-size:2rem;margin-bottom:8px}}
  p{{color:#64748b;margin:0}}
</style></head><body>
<div class="card">
  <div style="font-size:4rem">{icon}</div>
  <h1>{heading}</h1>
  <p>{wf_safe} — {detail}</p>
  <p style="margin-top:24px;font-size:.875rem">You may close this tab.</p>
</div></body></html>"#
            );
            (StatusCode::OK, axum::response::Html(html)).into_response()
        }
        // Execution vanished or ownership mismatch → uniform invalid page
        // (no existence oracle for a foreign / deleted execution).
        Err(OrchestrationError::ExecutionNotFound(_)) => invalid_link(),
        Err(OrchestrationError::AuthorizationDenied(msg)) => {
            // The decision was NOT recorded (the auth gate runs before the
            // resume claim only after the decision write; but a denied
            // resume here means the actor became ineligible). The row was
            // flipped but the run stays 'waiting' and is recoverable from
            // the UI once the actor is eligible. Operator-facing message.
            tracing::warn!(
                target: "talos_approvals",
                execution_id = %ctx.execution_id,
                reason = %msg,
                "approval-action apply: resume denied by actor authorization gate"
            );
            (
                StatusCode::CONFLICT,
                axum::response::Html(
                    "<h1>Decision recorded, resume blocked</h1><p>The decision was saved, but the \
                     workflow could not resume right now (its actor may be suspended or over \
                     budget). Resolve that and resume it from the Talos approvals view.</p>",
                ),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(
                target: "talos_approvals",
                execution_id = %ctx.execution_id,
                error = %e,
                "approval-action apply failed"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::response::Html("<h1>Something went wrong</h1><p>Try again shortly.</p>"),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_action;

    #[test]
    fn parse_action_maps_verbs() {
        assert_eq!(parse_action("approve"), Some(true));
        assert_eq!(parse_action("reject"), Some(false));
        assert_eq!(parse_action("APPROVE"), None); // case-sensitive
        assert_eq!(parse_action("delete"), None);
        assert_eq!(parse_action(""), None);
    }
}
