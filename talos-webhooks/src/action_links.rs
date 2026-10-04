//! Action-link endpoints — the public HTTP face of
//! `talos_execution_repository::action_links`.
//!
//! `/action-links/{token}`:
//! * **GET** ([`action_link_preview`]) renders a confirmation page naming
//!   the workflow and what the link does. Nothing happens on GET, so a mail
//!   scanner, link prefetcher or chat unfurler cannot start a workflow
//!   (RFC 7231 §4.2.1: GET is safe).
//! * **POST** ([`action_link_apply`]) claims the link and starts the
//!   workflow through [`ExecutionOrchestrationService::trigger`] — the same
//!   entry point `trigger_workflow` uses, so the platform pause, the
//!   workflow's liveness, its actor's authorization and budget, its input
//!   schema and its concurrency limit all apply unchanged.
//!
//! Authentication is the 256-bit capability token in the path (hash-only at
//! rest). Tenancy rides the token row's `user_id`. Unknown, malformed and
//! expired tokens render ONE page. Sibling of `approval_actions.rs`; same
//! rate-limit stack.
//!
//! CSRF posture (capability-URL semantics, identical to
//! `approval_actions.rs`): the POST carries no session cookie and needs no
//! CSRF token — the URL token is the credential and there is no ambient
//! authority for a cross-site POST to ride.
//!
//! SINGLE USE. The claim is taken BEFORE the start, so however many times a
//! link is submitted its workflow starts at most once. A refusal that is
//! known to precede any execution (paused platform, retired workflow, an
//! actor over budget, a concurrency limit) gives the claim back, so the
//! owner can use the link once the cause is gone. An error after which an
//! execution MAY exist keeps the claim: starting twice is the worse outcome.

use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    response::IntoResponse,
};
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use talos_execution_orchestration::{
    ExecutionOrchestrationService, OrchestrationError, TriggerInput, TriggerOutcome,
};
use talos_execution_repository::{
    action_links::{ActionClaim, ActionTokenContext},
    ExecutionRepository,
};

use crate::html_escape;

const PAGE_STYLE: &str = "body{font-family:system-ui,sans-serif;display:flex;align-items:center;\
justify-content:center;min-height:100vh;margin:0;background:#f8fafc}\
.card{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);\
padding:40px 48px;max-width:520px}\
h1{color:#0f172a;font-size:1.35rem;margin:0 0 8px}\
h2{color:#475569;font-size:.95rem;font-weight:500;margin:0 0 20px}\
p{color:#475569;margin:0 0 16px}\
button{background:#2563eb;color:#fff;border:0;border-radius:8px;padding:12px 24px;\
font-size:1rem;cursor:pointer}\
.muted{color:#94a3b8;font-size:.875rem;margin-top:16px}";

/// One page of the action-link surface. `body` is trusted markup built
/// here; every value that came from a token row is escaped by the caller.
fn page(status: StatusCode, title: &str, body: &str) -> axum::response::Response {
    let html = format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<meta name=\"referrer\" content=\"no-referrer\">\
<title>Talos — {title}</title><style>{PAGE_STYLE}</style></head><body>\
<div class=\"card\">{body}</div></body></html>"
    );
    (
        status,
        [
            // The page is addressed by a capability: it must not be cached
            // by a shared cache or handed to another origin as a referrer.
            (axum::http::header::CACHE_CONTROL, "no-store"),
            (axum::http::header::REFERRER_POLICY, "no-referrer"),
        ],
        axum::response::Html(html),
    )
        .into_response()
}

/// Uniform page for unknown / malformed / expired tokens — no oracle for
/// which of the three it was.
fn invalid_link() -> axum::response::Response {
    page(
        StatusCode::NOT_FOUND,
        "Link invalid or expired",
        "<h1>Link invalid or expired</h1><p>Action links work once and expire after a few \
         days. If you still need to do this, the next message will carry a fresh link.</p>",
    )
}

/// The link has done its one thing already.
fn already_used() -> axum::response::Response {
    page(
        StatusCode::OK,
        "Already done",
        "<h1>Already done &#10003;</h1><p>This link has been used. Nothing further was \
         started — you can close this tab.</p>",
    )
}

fn something_went_wrong() -> axum::response::Response {
    page(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong",
        "<h1>Something went wrong</h1><p>Try again shortly.</p>",
    )
}

/// Whether a refused start is known to have happened BEFORE any execution
/// existed — the only case in which a claimed link may be given back.
fn refused_before_any_execution(error: &OrchestrationError) -> bool {
    matches!(
        error,
        OrchestrationError::InvalidArgument(_)
            | OrchestrationError::WorkflowNotFound(_)
            | OrchestrationError::ExecutionPaused(_)
            | OrchestrationError::WorkflowDisabled(_)
            | OrchestrationError::WorkflowNotLive(_, _)
            | OrchestrationError::WorkflowArchived(_)
            | OrchestrationError::AuthorizationDenied(_)
            | OrchestrationError::ValidationFailed(_)
            | OrchestrationError::ConcurrencyLimitExceeded(_)
    )
}

/// What the owner is told when a start was refused before anything ran.
/// Says which kind of refusal it was; never the internal detail.
fn refusal_page(error: &OrchestrationError) -> axum::response::Response {
    let reason = match error {
        OrchestrationError::ExecutionPaused(_) => {
            "Talos is paused right now, so nothing was started."
        }
        OrchestrationError::WorkflowNotFound(_)
        | OrchestrationError::WorkflowDisabled(_)
        | OrchestrationError::WorkflowNotLive(_, _)
        | OrchestrationError::WorkflowArchived(_) => {
            "The workflow this link starts is switched off or has been retired, so nothing \
             was started."
        }
        OrchestrationError::AuthorizationDenied(_) => {
            "The workflow could not start right now (its actor may be suspended or over \
             budget), so nothing was started."
        }
        OrchestrationError::ConcurrencyLimitExceeded(_) => {
            "The workflow is already running as many times as it is allowed to, so nothing \
             was started."
        }
        _ => "The workflow refused this request, so nothing was started.",
    };
    page(
        StatusCode::CONFLICT,
        "Not started",
        &format!(
            "<h1>Not started</h1><p>{reason}</p><p class=\"muted\">The link has not been used \
             up: you can try it again.</p>"
        ),
    )
}

async fn resolve(
    db_pool: &Pool<Postgres>,
    token: &str,
) -> Result<Option<ActionTokenContext>, axum::response::Response> {
    match ExecutionRepository::new(db_pool.clone())
        .lookup_action_token(token)
        .await
    {
        Ok(context) => Ok(context),
        Err(e) => {
            // The clicker gets the uniform page, the operator a structured
            // log. The token is never logged.
            tracing::error!(
                target: "talos_action_links",
                error = %e,
                "action token lookup failed (database error)"
            );
            Err(invalid_link())
        }
    }
}

/// GET — the confirmation page. Side-effect free by design.
pub async fn action_link_preview(
    Path(token): Path<String>,
    Extension(db_pool): Extension<Pool<Postgres>>,
) -> impl IntoResponse {
    let context = match resolve(&db_pool, &token).await {
        Ok(Some(context)) => context,
        Ok(None) => return invalid_link(),
        Err(response) => return response,
    };
    if context.used {
        return already_used();
    }
    let label = html_escape(&context.label);
    let workflow = html_escape(&context.workflow_name);
    page(
        StatusCode::OK,
        "Confirm",
        &format!(
            "<h1>{label}</h1><h2>Starts the workflow &ldquo;{workflow}&rdquo;</h2>\
             <form method=\"POST\" action=\"\"><button type=\"submit\">Confirm</button></form>\
             <p class=\"muted\">This link works once.</p>"
        ),
    )
}

/// POST — claim the link and start its workflow.
pub async fn action_link_apply(
    Path(token): Path<String>,
    Extension(db_pool): Extension<Pool<Postgres>>,
    Extension(orchestration): Extension<Option<Arc<ExecutionOrchestrationService>>>,
) -> impl IntoResponse {
    // Wired as Some(...) on production startup; a stub router in tests may
    // omit it. Checked BEFORE the claim, so a missing service cannot burn a
    // link.
    let Some(service) = orchestration else {
        tracing::error!(
            target: "talos_action_links",
            "action-link apply: ExecutionOrchestrationService extension missing"
        );
        return something_went_wrong();
    };

    let repo = ExecutionRepository::new(db_pool.clone());
    let context = match repo.claim_action_token(&token).await {
        Ok(ActionClaim::Claimed(context)) => context,
        Ok(ActionClaim::AlreadyUsed) => return already_used(),
        Ok(ActionClaim::Invalid) => return invalid_link(),
        Err(e) => {
            tracing::error!(
                target: "talos_action_links",
                error = %e,
                "action token claim failed (database error)"
            );
            return invalid_link();
        }
    };

    let started = service
        .trigger(TriggerInput {
            workflow_id: context.workflow_id,
            user_id: context.user_id,
            trigger_input: context.payload.clone(),
            trigger_agent_id: None,
            inject_memory_context: false,
            dry_run: false,
            wait_ms: None,
        })
        .await;

    match started {
        Ok(TriggerOutcome::Dispatched(outcome)) => {
            if let Err(e) = repo
                .record_action_execution(context.id, outcome.execution_id)
                .await
            {
                tracing::warn!(
                    target: "talos_action_links",
                    error = %e,
                    execution_id = %outcome.execution_id,
                    "the started execution could not be recorded on its action token"
                );
            }
            tracing::info!(
                target: "talos_action_links",
                event_kind = "action_link_applied",
                workflow_id = %context.workflow_id,
                execution_id = %outcome.execution_id,
                "action link started its workflow"
            );
            page(
                StatusCode::OK,
                "Done",
                &format!(
                    "<h1>Done &#10003;</h1><p>{}</p><p class=\"muted\">You can close this tab.</p>",
                    html_escape(&context.label)
                ),
            )
        }
        // `dry_run: false` never yields a dry-run report. Treated as a
        // refusal before any execution: nothing ran.
        Ok(TriggerOutcome::DryRun(_)) => {
            release(&repo, &context).await;
            something_went_wrong()
        }
        Err(error) if refused_before_any_execution(&error) => {
            tracing::warn!(
                target: "talos_action_links",
                event_kind = "action_link_refused",
                workflow_id = %context.workflow_id,
                reason = %error,
                "action link's workflow refused to start; the link was given back"
            );
            release(&repo, &context).await;
            refusal_page(&error)
        }
        Err(error) => {
            // An execution may exist. Keep the claim.
            tracing::error!(
                target: "talos_action_links",
                event_kind = "action_link_failed",
                workflow_id = %context.workflow_id,
                error = %error,
                "action link's workflow failed to start; the link stays used"
            );
            page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                "<h1>Something went wrong</h1><p>The request reached Talos but may not have \
                 completed. The link has been used up so it cannot run twice; check Talos \
                 before doing this another way.</p>",
            )
        }
    }
}

async fn release(repo: &ExecutionRepository, context: &ActionTokenContext) {
    if let Err(e) = repo.release_action_token(context.id).await {
        tracing::error!(
            target: "talos_action_links",
            error = %e,
            "a claimed action token could not be released after a refused start"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::refused_before_any_execution;
    use talos_execution_orchestration::OrchestrationError;
    use uuid::Uuid;

    /// A link is given back only when the start is known to have been
    /// refused before any execution existed. Everything else keeps it used:
    /// starting a workflow twice is worse than asking the owner to look.
    #[test]
    fn a_claim_is_released_only_for_a_refusal_that_precedes_any_execution() {
        for released in [
            OrchestrationError::InvalidArgument("x".into()),
            OrchestrationError::WorkflowNotFound(Uuid::nil()),
            OrchestrationError::WorkflowDisabled(Uuid::nil()),
            OrchestrationError::WorkflowNotLive(Uuid::nil(), "archived"),
            OrchestrationError::WorkflowArchived(Uuid::nil()),
            OrchestrationError::AuthorizationDenied("budget".into()),
            OrchestrationError::ValidationFailed("x".into()),
            OrchestrationError::ConcurrencyLimitExceeded("x".into()),
        ] {
            assert!(refused_before_any_execution(&released), "{released}");
        }
        for kept in [
            OrchestrationError::DispatchFailed("nats".into()),
            OrchestrationError::GraphLoadFailed("x".into()),
            OrchestrationError::StatusConflict("x".into()),
            OrchestrationError::ExecutionNotFound(Uuid::nil()),
            OrchestrationError::Internal(anyhow::anyhow!("x")),
        ] {
            assert!(!refused_before_any_execution(&kept), "{kept}");
        }
    }
}
