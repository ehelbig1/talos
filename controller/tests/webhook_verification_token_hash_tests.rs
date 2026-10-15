//! A generic webhook's static verification token is stored as its SHA-256,
//! never in the clear (security review 2026-10-14, F-3 and G-25).
//!
//! Driven on real rows through both create paths' repository writes (the MCP
//! `create_webhook` lane and the GraphQL `createWebhookTrigger` lane): the
//! token each returns is nowhere in the stored row, the row holds the digest
//! the router compares against, and the plaintext column is gone. The
//! router's decision over that digest (`verification_token_matches`) is a
//! pure function tested in `talos-webhooks`; the router itself needs NATS,
//! which this harness has none of.
//!
//! `common` harness (a template clone per test), so the migrated-database job
//! runs it.

#[path = "common/mod.rs"]
mod common;

use talos_webhook_repository::{
    mint_verification_token, verification_token_hash, NewWebhookTrigger, WebhookRepository,
    MAX_WEBHOOKS_PER_USER,
};
use uuid::Uuid;

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@webhook-token-hash.test"))
    .execute(pool)
    .await
    .expect("user");
    user
}

async fn seed_module(pool: &sqlx::PgPool, user: Uuid) -> Uuid {
    let module = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, content_hash, wasm_bytes, size_bytes) \
         VALUES ($1, $2, 'token hash probe', 'sandbox', 'made-up-hash', $3, 10)",
    )
    .bind(module)
    .bind(user)
    .bind(vec![0u8; 10])
    .execute(pool)
    .await
    .expect("module");
    module
}

/// The whole stored row, as text, so an assertion covers every column —
/// including any column added later.
async fn row_text(pool: &sqlx::PgPool, id: Uuid) -> String {
    sqlx::query_scalar("SELECT to_jsonb(t)::text FROM webhook_triggers t WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("row")
}

async fn stored_hash(pool: &sqlx::PgPool, id: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT verification_token_hash FROM webhook_triggers WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("hash")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_stored_row_never_contains_the_returned_token() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let module = seed_module(&pool, user).await;
    let repo = WebhookRepository::new(pool.clone());
    let secrets = controller::secrets::SecretsManager::new(pool.clone()).expect("secrets manager");

    // The MCP lane: the handler mints with the shared function and hands the
    // token to the repository, which stores only its hash.
    let mcp_token = mint_verification_token();
    let mcp_id = Uuid::new_v4();
    repo.try_create_under_cap(
        mcp_id,
        user,
        "mcp lane",
        Some(module),
        None,
        &mcp_token,
        60,
        false,
        30,
        None,
        None,
        &secrets,
        MAX_WEBHOOKS_PER_USER,
    )
    .await
    .expect("create")
    .expect("under the cap");

    // The GraphQL lane: a caller may supply its own token (≥ 32 chars).
    let graphql_token = "made-up-caller-supplied-token-0123456789abcdef".to_string();
    let graphql_id = repo
        .insert_trigger(NewWebhookTrigger {
            id: Uuid::new_v4(),
            name: "graphql lane",
            module_id: module,
            verification_token: &graphql_token,
            signing_secret_enc: None,
            signing_key_id: None,
            signing_secret_format: 1,
            max_requests_per_minute: 60,
            enabled: true,
            allowed_ips: None,
            user_id: user,
            event_filter: None,
        })
        .await
        .expect("insert")
        .expect("under the cap");

    for (id, token) in [(mcp_id, &mcp_token), (graphql_id, &graphql_token)] {
        let text = row_text(&pool, id).await;
        assert!(
            !text.contains(token.as_str()),
            "the stored row carries the token it returned"
        );
        assert_eq!(
            stored_hash(&pool, id).await.as_deref(),
            Some(verification_token_hash(token).as_str()),
            "the row holds the digest the router compares against"
        );
    }

    // The plaintext column is gone, so no writer can put a token back in it.
    let plaintext_columns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns \
         WHERE table_name = 'webhook_triggers' AND column_name = 'verification_token'",
    )
    .fetch_one(&pool)
    .await
    .expect("columns");
    assert_eq!(plaintext_columns, 0);
}

/// The backfill (migration 20261014220000) hashed existing tokens in SQL; a
/// token issued before it keeps working only if that digest is the one the
/// router computes. Checked for a minted token and for the UUID-shaped
/// tokens the MCP path minted before G-25.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_backfill_digest_is_the_one_the_router_compares() {
    let (pool, _db) = common::isolated_db_pool().await;
    for token in [
        mint_verification_token(),
        Uuid::new_v4().to_string(),
        "made-up-token-with-unicode-é".to_string(),
    ] {
        let in_sql: String =
            sqlx::query_scalar("SELECT encode(sha256(convert_to($1, 'UTF8')), 'hex')")
                .bind(&token)
                .fetch_one(&pool)
                .await
                .expect("digest");
        assert_eq!(in_sql, verification_token_hash(&token));
    }
}
