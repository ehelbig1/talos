use axum::{
    extract::{ConnectInfo, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct AgentIdentity {
    pub agent_id: Uuid,
    pub name: String,
    pub role_name: String,
    pub allowed_capabilities: Vec<String>,
}

/// Per-IP rate-limit state for MCP auth.
struct McpAuthRateState {
    count: u32,
    window_start: Instant,
}

/// Maximum MCP auth requests per minute per IP.
const MCP_AUTH_MAX_REQUESTS: u32 = 20;
/// Window duration for MCP auth rate limiting.
const MCP_AUTH_WINDOW_SECS: u64 = 60;

/// Global rate limiter for MCP auth (IP -> state).
static MCP_AUTH_RATE_LIMITER: OnceLock<DashMap<String, McpAuthRateState>> = OnceLock::new();

/// Check IP-based rate limit for MCP auth. Returns `Err(())` if rate limit exceeded.
fn check_mcp_auth_rate_limit(ip: &str) -> Result<(), ()> {
    let limiter = MCP_AUTH_RATE_LIMITER.get_or_init(DashMap::new);
    let now = Instant::now();

    // Periodic cleanup: remove expired entries when map grows large
    if limiter.len() > 10_000 {
        limiter.retain(|_, state| {
            now.duration_since(state.window_start).as_secs() < MCP_AUTH_WINDOW_SECS * 2
        });
    }

    let mut entry = limiter.entry(ip.to_string()).or_insert_with(|| McpAuthRateState {
        count: 0,
        window_start: now,
    });

    if now.duration_since(entry.window_start).as_secs() >= MCP_AUTH_WINDOW_SECS {
        // Reset the window
        entry.count = 1;
        entry.window_start = now;
        Ok(())
    } else {
        entry.count += 1;
        if entry.count > MCP_AUTH_MAX_REQUESTS {
            Err(())
        } else {
            Ok(())
        }
    }
}

pub async fn mcp_auth_middleware(
    State(db_pool): State<PgPool>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Rate limit by IP
    let ip = addr.ip().to_string();
    if check_mcp_auth_rate_limit(&ip).is_err() {
        tracing::warn!(ip = %ip, "MCP auth rate limit exceeded");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // 1. Extract Bearer Token
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .filter(|s| s.starts_with("Bearer "))
        .map(|s| s[7..].trim());

    let token = match auth_header {
        Some(t) => t.to_string(),
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    // 2. Compute SHA-256 lookup hash for efficient DB query
    let token_lookup_hash = format!("{:x}", Sha256::digest(token.as_bytes()));

    // 3. Look up Agent in Database using the lookup hash
    #[derive(sqlx::FromRow)]
    struct AgentRecord {
        id: Uuid,
        name: String,
        role_name: String,
        allowed_capabilities: Vec<String>,
        token_hash: String,
    }

    let record = sqlx::query_as::<_, AgentRecord>(
        r#"
        SELECT a.id, a.name, r.name as role_name, r.allowed_capabilities, a.token_hash
        FROM mcp_agents a
        JOIN agent_roles r ON a.role_id = r.id
        WHERE a.token_lookup_hash = $1 AND a.is_active = true
        "#,
    )
    .bind(&token_lookup_hash)
    .fetch_optional(&db_pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let agent = match record {
        Some(r) => {
            // 4. Verify bcrypt hash for security (lookup hash only narrows the search)
            let token_clone = token.clone();
            let bcrypt_hash = r.token_hash.clone();
            let is_valid = tokio::task::spawn_blocking(move || {
                bcrypt::verify(&token_clone, &bcrypt_hash)
            })
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

            if !is_valid {
                return Err(StatusCode::UNAUTHORIZED);
            }

            AgentIdentity {
                agent_id: r.id,
                name: r.name,
                role_name: r.role_name,
                allowed_capabilities: r.allowed_capabilities,
            }
        }
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    // Update last connected async (fire and forget)
    let pool_clone = db_pool.clone();
    let agent_id = agent.agent_id;
    tokio::spawn(async move {
        if let Err(db_err) =
            sqlx::query("UPDATE mcp_agents SET last_connected_at = NOW() WHERE id = $1")
                .bind(agent_id)
                .execute(&pool_clone)
                .await
        {
            tracing::error!("Database operation failed: {}", db_err);
        }
    });

    // 5. Inject AgentIdentity into Request extensions
    req.extensions_mut().insert(Arc::new(agent));

    Ok(next.run(req).await)
}
