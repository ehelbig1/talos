//! One-click ops-alert severity correction endpoints — the public HTTP
//! face of `talos_ops_alerts_repository::correction_links`.
//!
//! `/corrections/{token}/{severity}`:
//! * **GET** ([`correction_preview`]) renders a confirmation page with
//!   a POST form — the state change never fires on GET, so email link
//!   prefetchers (Gmail, Outlook SafeLinks, chat unfurlers) cannot
//!   mislabel training data. The page also offers the other severities
//!   so a "wrong link clicked" is a one-tap fix, not a dead end.
//! * **POST** ([`correction_apply`]) records the correction through
//!   [`OpsAlertRepository::correct_severity`] — the same validated
//!   single write path the MCP triage surface uses (corrections
//!   outrank classifiers; `unclassified` unassignable).
//!
//! Authentication is the 256-bit random capability token in the path
//! (hash-only at rest; see the repository module docs for the full
//! model). Tenancy rides the token row's `user_id`, never the request.
//! Unknown, malformed, and expired tokens all render ONE uniform page —
//! no existence oracle. Sibling of `approval.rs`; same rate-limit stack
//! (per-IP webhook limiter + global + governor).

use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    response::IntoResponse,
};
use sqlx::{Pool, Postgres};
use talos_ops_alerts_repository::{
    correction_links::CorrectionTokenContext, OpsAlertRepository, ASSIGNABLE_SEVERITIES,
};

/// Uniform page for unknown / malformed / expired tokens.
fn invalid_link() -> axum::response::Response {
    (
        StatusCode::NOT_FOUND,
        axum::response::Html(
            "<h1>Link invalid or expired</h1><p>Correction links expire after a while. \
             The next digest email will carry fresh ones.</p>",
        ),
    )
        .into_response()
}

use crate::html_escape;

fn severity_valid(sev: &str) -> bool {
    ASSIGNABLE_SEVERITIES.contains(&sev)
}

async fn resolve_token(
    db_pool: &Pool<Postgres>,
    token: &str,
    severity: &str,
) -> Result<Option<CorrectionTokenContext>, axum::response::Response> {
    if !severity_valid(severity) {
        // Bad severity segment is a malformed link, same uniform page.
        return Err(invalid_link());
    }
    let repo = OpsAlertRepository::new(db_pool.clone());
    match repo.lookup_correction_token(token).await {
        Ok(ctx) => Ok(ctx),
        Err(e) => {
            // Same posture as approval.rs (MCP-535): the clicker gets
            // the uniform page, the operator gets a structured log —
            // never leak DB detail into a public response.
            tracing::error!(
                target: "talos_corrections",
                error = %e,
                "correction token lookup failed (DB error)"
            );
            Err(invalid_link())
        }
    }
}

/// GET — confirmation page. Side-effect free by design.
pub async fn correction_preview(
    Path((token, severity)): Path<(String, String)>,
    Extension(db_pool): Extension<Pool<Postgres>>,
) -> impl IntoResponse {
    let ctx = match resolve_token(&db_pool, &token, &severity).await {
        Ok(Some(ctx)) => ctx,
        Ok(None) => return invalid_link(),
        Err(resp) => return resp,
    };

    let title_safe = html_escape(&ctx.alert_title);
    let current = html_escape(&ctx.current_severity);
    let target = html_escape(&severity);
    let corrected_note = if ctx.corrected_severity.is_some() {
        "<p class=\"muted\">This alert was already corrected once — submitting again \
         simply updates the label.</p>"
    } else {
        ""
    };
    // Alternative severities as small links (same token, different
    // path segment) so a mis-tapped email link is recoverable here.
    // Sibling-relative href: against the base /corrections/{token}/{sev}
    // a bare "{s}" replaces only the last segment, keeping the token.
    // ("../{s}" would strip the token per RFC 3986 and 404.)
    let alts = ASSIGNABLE_SEVERITIES
        .iter()
        .filter(|s| **s != severity)
        .map(|s| format!("<a href=\"{s}\">{s}</a>"))
        .collect::<Vec<_>>()
        .join(" · ");

    let html = format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Talos — Correct severity</title>
<style>
  body{{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8fafc}}
  .card{{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:40px 48px;text-align:left;max-width:520px}}
  h1{{color:#0f172a;font-size:1.25rem;margin:0 0 12px}}
  p.alert{{color:#475569;margin:0 0 20px}}
  form{{display:inline-block}}
  button{{background:#2563eb;color:#fff;border:0;border-radius:8px;padding:12px 24px;font-size:1rem;cursor:pointer}}
  button:hover{{filter:brightness(0.95)}}
  .muted{{color:#94a3b8;font-size:.875rem;margin-top:16px}}
  .alts{{margin-top:20px;font-size:.875rem;color:#64748b}}
  .alts a{{color:#2563eb;text-decoration:none}}
</style></head><body>
<div class="card">
  <h1>Correct severity to <strong>{target}</strong>?</h1>
  <p class="alert">{title_safe}<br><span class="muted">current label: {current}</span></p>
  <form method="POST" action="">
    <button type="submit">Confirm: {target}</button>
  </form>
  {corrected_note}
  <p class="alts">different call? {alts}</p>
  <p class="muted">Corrections train the alert-triage classifier.</p>
</div></body></html>"#
    );
    (StatusCode::OK, axum::response::Html(html)).into_response()
}

/// POST — apply the correction. Idempotent: re-submitting the same
/// severity re-stamps the same label.
pub async fn correction_apply(
    Path((token, severity)): Path<(String, String)>,
    Extension(db_pool): Extension<Pool<Postgres>>,
) -> impl IntoResponse {
    let ctx = match resolve_token(&db_pool, &token, &severity).await {
        Ok(Some(ctx)) => ctx,
        Ok(None) => return invalid_link(),
        Err(resp) => return resp,
    };

    let repo = OpsAlertRepository::new(db_pool.clone());
    match repo
        .correct_severity(ctx.user_id, ctx.alert_id, &severity)
        .await
    {
        Ok(Some(bridge)) => {
            // Fan the human label into any ML dataset already tracking this
            // alert (corrections→distillation bridge). Fire-and-forget: a
            // bridge failure must never fail the correction the operator made.
            talos_ml::spawn_ops_correction_bridge(
                ctx.user_id,
                bridge.example_key,
                bridge.features_text,
                severity.clone(),
            );
            if let Err(e) = repo.touch_correction_token(&token).await {
                tracing::warn!(
                    target: "talos_corrections",
                    error = %e,
                    "failed to stamp correction token last_used_at"
                );
            }
            tracing::info!(
                target: "talos_corrections",
                alert_id = %ctx.alert_id,
                severity = %severity,
                "severity correction applied via email link"
            );
            let title_safe = html_escape(&ctx.alert_title);
            let target = html_escape(&severity);
            let html = format!(
                r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Talos — Corrected</title>
<style>
  body{{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8fafc}}
  .card{{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:40px 48px;max-width:520px}}
  h1{{color:#16a34a;font-size:1.25rem;margin:0 0 12px}}
  p{{color:#475569}}
</style></head><body>
<div class="card">
  <h1>Corrected to {target} &#10003;</h1>
  <p>{title_safe}</p>
  <p style="color:#94a3b8;font-size:.875rem">This label now outranks the classifier and joins its training set.</p>
</div></body></html>"#
            );
            (StatusCode::OK, axum::response::Html(html)).into_response()
        }
        Ok(None) => invalid_link(), // alert vanished (cleanup) — same uniform page
        Err(e) => {
            tracing::error!(
                target: "talos_corrections",
                alert_id = %ctx.alert_id,
                error = %e,
                "severity correction failed"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::response::Html("<h1>Something went wrong</h1><p>Try again shortly.</p>"),
            )
                .into_response()
        }
    }
}
