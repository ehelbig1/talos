//! Per-USER throttle on the GraphQL resolvers whose cost is not the query's
//! own (an LLM round trip, a synchronous WASM run, an inline Rhai
//! evaluation) — 2026-09-10 review, package B1-3.
//!
//! The controller's per-IP limiter (`talos_rate_limit::rate_limit_middleware`)
//! is the only thing between an authenticated session and these resolvers,
//! and behind a shared egress IP it is shared with every other user of that
//! IP. This keys a token bucket on the authenticated `Uuid` instead.
//!
//! Two classes, two knobs (both read once per process, `0`/unset/unparseable
//! → default via `talos_rate_limit::env_rate_limit`):
//!
//! | env var                                   | default | gates                                                        |
//! |-------------------------------------------|---------|--------------------------------------------------------------|
//! | `GRAPHQL_HEAVY_MUTATION_PER_USER_PER_MIN` | 10      | `createWorkflowFromDescription`, `testModule`, `testWorkflow` |
//! | `GRAPHQL_RHAI_PER_USER_PER_MIN`           | 60      | `analyzeRhai`, `testRhaiExpression`                          |
//!
//! Both are PER CONTROLLER REPLICA (in-memory; see `PerUserThrottle`'s
//! module doc), so the fleet ceiling is `replicas × N`. A refusal is a
//! GraphQL error with `extensions.code = "RATE_LIMITED"` and
//! `extensions.retryAfterSecs`, marked `.extend_safe()` so the production
//! scrubber passes the message through.
//!
//! `testWorkflow` is included even though it carries the MCP-672 actor-budget
//! gate: that gate is `if let Some(actor_id) = wf.actor_id`, so a workflow
//! with NO bound actor spins a full real-LLM / real-HTTP execution with no
//! budget at all. The throttle is the floor under both cases.

use std::sync::LazyLock;

use async_graphql::{Context, ErrorExtensions, Result};
use talos_rate_limit::PerUserThrottle;
use uuid::Uuid;

use super::SafeErrorExtensions;

/// Env var for the LLM / compile class ceiling. Default 10 per user per minute.
pub const HEAVY_MUTATION_ENV: &str = "GRAPHQL_HEAVY_MUTATION_PER_USER_PER_MIN";
pub const HEAVY_MUTATION_DEFAULT_PER_MIN: u32 = 10;
/// Env var for the Rhai evaluation class ceiling. Default 60 per user per minute.
pub const RHAI_ENV: &str = "GRAPHQL_RHAI_PER_USER_PER_MIN";
pub const RHAI_DEFAULT_PER_MIN: u32 = 60;

static HEAVY_MUTATION: LazyLock<PerUserThrottle> = LazyLock::new(|| {
    PerUserThrottle::per_minute(talos_rate_limit::env_rate_limit(
        HEAVY_MUTATION_ENV,
        HEAVY_MUTATION_DEFAULT_PER_MIN,
    ))
});

static RHAI: LazyLock<PerUserThrottle> = LazyLock::new(|| {
    PerUserThrottle::per_minute(talos_rate_limit::env_rate_limit(
        RHAI_ENV,
        RHAI_DEFAULT_PER_MIN,
    ))
});

/// Which bucket a resolver draws from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleClass {
    /// An LLM call or a synchronous WASM compile/run: seconds to minutes each.
    HeavyMutation,
    /// An inline Rhai analysis/evaluation of a caller-supplied script (≤100 KB).
    RhaiEval,
}

impl ThrottleClass {
    fn throttle(self) -> &'static PerUserThrottle {
        match self {
            ThrottleClass::HeavyMutation => &HEAVY_MUTATION,
            ThrottleClass::RhaiEval => &RHAI,
        }
    }

    fn what(self) -> &'static str {
        match self {
            ThrottleClass::HeavyMutation => "LLM / compile operations",
            ThrottleClass::RhaiEval => "Rhai evaluations",
        }
    }
}

/// Extension code carried on every throttle refusal.
pub const RATE_LIMITED_CODE: &str = "RATE_LIMITED";

/// Admit one call of `class` for the authenticated user on `ctx`, or return
/// the `RATE_LIMITED` error. Call AFTER `require_scope` / `require_2fa`: an
/// unauthenticated request has no bucket to draw from and is refused here
/// too (fail closed), but the auth helpers give it the right message.
pub fn enforce_user_throttle(ctx: &Context<'_>, class: ThrottleClass) -> Result<()> {
    enforce_with(ctx, class.throttle(), class.what())
}

/// The testable core: same decision, caller-supplied bucket.
pub fn enforce_with(ctx: &Context<'_>, throttle: &PerUserThrottle, what: &str) -> Result<()> {
    let user_id = ctx
        .data_opt::<Uuid>()
        .copied()
        .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
    match throttle.check(user_id) {
        Ok(()) => Ok(()),
        Err(exceeded) => {
            tracing::warn!(
                target: "talos_rate_limit",
                event_kind = "graphql_user_throttle_refused",
                %user_id,
                per_minute = exceeded.per_minute,
                retry_after_secs = exceeded.retry_after_secs,
                what,
                "GraphQL per-user throttle refused a call"
            );
            Err(rate_limited_error(what, exceeded))
        }
    }
}

fn rate_limited_error(what: &str, e: talos_rate_limit::ThrottleExceeded) -> async_graphql::Error {
    async_graphql::Error::new(format!(
        "Rate limited: at most {} {} per minute per user; retry in {} s",
        e.per_minute, what, e.retry_after_secs
    ))
    .extend_with(|_, ext| {
        ext.set("code", RATE_LIMITED_CODE);
        ext.set("retryAfterSecs", e.retry_after_secs);
    })
    .extend_safe()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_graphql::{EmptyMutation, EmptySubscription, Object, Schema};
    use std::sync::Arc;

    struct ThrottledQuery;

    #[Object]
    impl ThrottledQuery {
        async fn expensive(&self, ctx: &Context<'_>) -> Result<bool> {
            let t = ctx.data::<Arc<PerUserThrottle>>()?;
            enforce_with(ctx, t, "test operations")?;
            Ok(true)
        }
    }

    fn schema(per_minute: u32) -> Schema<ThrottledQuery, EmptyMutation, EmptySubscription> {
        Schema::build(ThrottledQuery, EmptyMutation, EmptySubscription)
            .data(Arc::new(PerUserThrottle::per_minute(per_minute)))
            .finish()
    }

    #[tokio::test]
    async fn third_call_in_a_minute_is_rate_limited_with_code_and_safe_marker() {
        let schema = schema(2);
        let user = Uuid::new_v4();
        for _ in 0..2 {
            let res = schema
                .execute(async_graphql::Request::new("{ expensive }").data(user))
                .await;
            assert!(res.errors.is_empty(), "{:?}", res.errors);
        }
        let res = schema
            .execute(async_graphql::Request::new("{ expensive }").data(user))
            .await;
        assert_eq!(res.errors.len(), 1);
        let err = &res.errors[0];
        assert!(err.message.starts_with("Rate limited:"), "{}", err.message);
        let ext = err.extensions.as_ref().expect("extensions");
        assert_eq!(
            ext.get("code"),
            Some(&async_graphql::Value::String(RATE_LIMITED_CODE.into()))
        );
        assert!(
            matches!(
                ext.get("retryAfterSecs"),
                Some(async_graphql::Value::Number(_))
            ),
            "retryAfterSecs must be present: {ext:?}"
        );
        // `.extend_safe()` must survive the `extend_with` chain, or the
        // production scrubber replaces the message with a generic one.
        assert!(
            crate::schema::is_safe_error(err),
            "safe marker missing: {ext:?}"
        );

        // A different user is unaffected.
        let res = schema
            .execute(async_graphql::Request::new("{ expensive }").data(Uuid::new_v4()))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
    }

    #[tokio::test]
    async fn unauthenticated_request_is_refused_not_admitted() {
        let schema = schema(100);
        let res = schema
            .execute(async_graphql::Request::new("{ expensive }"))
            .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Authentication required"));
    }
}
