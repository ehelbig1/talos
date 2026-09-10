//! Rate-limiting primitives for Talos services.
//!
//! Two complementary modules:
//!
//! * [`middleware`] — in-memory governor-backed rate limiter, axum middleware
//!   for per-IP and global limits, IP whitelist + RFC 7239 X-Forwarded-For
//!   trusted-proxy walk. Used by the controller HTTP layer.
//!
//! * [`distributed`] — Redis-backed sliding-window / token-bucket limiter
//!   for cross-pod limits (per-user, per-tenant, per-endpoint). Atomic via
//!   Redis Lua scripts.
//!
//! * [`user_throttle`] — in-memory per-USER token bucket for expensive
//!   authenticated operations (the GraphQL LLM / compile / Rhai resolvers),
//!   self-sweeping so it can live in a `LazyLock` with no wiring.
//!
//! The middleware module's contents are re-exported at the crate root so
//! existing controller call sites that wrote `rate_limit::Foo` continue to
//! resolve. Distributed types are accessed through the `distributed::`
//! sub-module path because both modules expose a `RateLimitConfig` type
//! that would otherwise collide at the root namespace.

pub mod distributed;
pub mod governor_key;
mod middleware;
pub mod user_throttle;

pub use governor_key::TrustedProxyClientIpKeyExtractor;
pub use middleware::*;
pub use user_throttle::{PerUserThrottle, ThrottleExceeded};

// `is_production` now lives in `talos-config`; re-exported here as
// `pub(crate)` so the `crate::is_production()` callsites in middleware.rs
// continue to resolve unchanged.
pub(crate) use talos_config::is_production;
