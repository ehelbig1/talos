// Distributed (Redis-backed) rate limiter moved to the
// `talos-rate-limit` workspace crate. Re-export so existing
// `use crate::distributed_ratelimit::*` imports keep working.
// MCP-706: only `auth_rate_limiter` (built via the canonical
// `rate_limit::DistributedRateLimiter::auto`) actually consumes this
// type today; the lone API-tier boot allocation was dead and was
// removed.
#[allow(unused_imports)]
pub use talos_rate_limit::distributed::*;
