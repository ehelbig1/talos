//! `test_secret_access` says a secret is stored exactly when a dispatch for
//! the asking user would read one (2026-10-13).
//!
//! Its presence gate asked `created_by = caller`. A dispatch reads with a
//! wider rule: the caller's own secrets and the ownerless ones. So for an
//! ownerless secret the tool answered "No secret stored at path … Add it in
//! the dashboard" about a path whose secret the module would be handed, and
//! reported `would_succeed: false` for a read that succeeds.
//!
//! The gate now asks under the dispatch's rule. What must NOT change with
//! that widening is pinned here too: another user's secret at the path reads
//! exactly as a path nobody holds.
//!
//! `common` harness (a template clone per test), so the migrated-database
//! job runs it.

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use mcp_common::{agent, mcp_state, text_json};
use serde_json::{json, Value};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'presence')",
    )
    .bind(id)
    .bind(format!("presence-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_module(pool: &Pool<Postgres>, user: Uuid, grants: &[&str]) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, wasm_bytes, capability_world, kind, allowed_secrets) \
         VALUES ($1, $2, $3, '\\x00'::bytea, 'secrets-node', 'sandbox', $4)",
    )
    .bind(id)
    .bind(user)
    .bind(format!("presence-module-{id}"))
    .bind(grants.iter().map(|g| (*g).to_string()).collect::<Vec<_>>())
    .execute(pool)
    .await
    .expect("seed module");
    id
}

/// A secret row as the secrets manager writes its two ownership columns: the
/// creator in both. `owner = None` is an ownerless row, which every user's
/// dispatch can read.
async fn seed_secret(pool: &Pool<Postgres>, key_id: Uuid, owner: Option<Uuid>, key_path: &str) {
    sqlx::query(
        "INSERT INTO secrets (id, name, key_path, encrypted_value, encryption_key_id, \
                              owner_user_id, created_by) \
         VALUES ($1, $2, $3, '\\x00'::bytea, $4, $5, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(format!("presence-{}", Uuid::new_v4().simple()))
    .bind(key_path)
    .bind(key_id)
    .bind(owner)
    .execute(pool)
    .await
    .expect("seed secret");
}

fn gate<'a>(body: &'a Value, name: &str) -> &'a Value {
    body["gates"]
        .as_array()
        .expect("gates")
        .iter()
        .find(|g| g["name"] == name)
        .unwrap_or_else(|| panic!("no `{name}` gate in {body}"))
}

const MINE: &str = "svc/token";
const OWNERLESS: &str = "shared/relay-key";
const A_STRANGERS: &str = "team/deploy-key";
const NOBODYS: &str = "void/deploy-key";

#[tokio::test]
async fn the_presence_gate_answers_what_a_dispatch_for_the_asking_user_would_read() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let key: Uuid = sqlx::query_scalar(
        "INSERT INTO encryption_keys (encrypted_key) VALUES ('\\x00'::bytea) RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed an encryption key row");
    seed_secret(&pool, key, Some(owner), MINE).await;
    seed_secret(&pool, key, None, OWNERLESS).await;
    seed_secret(&pool, key, Some(stranger), A_STRANGERS).await;

    let module = seed_module(&pool, owner, &[MINE, OWNERLESS, A_STRANGERS, NOBODYS]).await;
    let state = mcp_state(pool.clone()).await;

    // The function itself, for each user: the asking user's own secret and
    // the ownerless one, and never another user's.
    for (user, path, readable) in [
        (owner, MINE, true),
        (owner, OWNERLESS, true),
        (owner, A_STRANGERS, false),
        (owner, NOBODYS, false),
        (stranger, MINE, false),
        (stranger, OWNERLESS, true),
        (stranger, A_STRANGERS, true),
    ] {
        assert_eq!(
            state
                .secrets_manager
                .dispatch_readable_secret_exists(path, user)
                .await
                .expect("read"),
            readable,
            "{path} for {}",
            if user == owner {
                "the owner"
            } else {
                "the stranger"
            }
        );
    }

    let ask = |path: &'static str| {
        let state = &state;
        async move {
            let resp = controller::mcp::modules::dispatch(
                "test_secret_access",
                Some(json!(1)),
                &json!({ "module_id": module.to_string(), "secret_path": path }),
                state,
                agent(owner),
            )
            .await
            .expect("test_secret_access is dispatched");
            text_json(&resp)
        }
    };

    // The module is granted each exact path, so presence is what decides.
    for path in [MINE, OWNERLESS] {
        let body = ask(path).await;
        let presence = gate(&body, "vault_presence");
        assert_eq!(presence["passed"], true, "{path}: {body}");
        assert_eq!(presence["checked"], true, "{path}: {body}");
        assert_eq!(body["would_succeed"], true, "{path}: {body}");
        assert!(
            !presence["reason"]
                .as_str()
                .unwrap()
                .contains("Add it in the dashboard"),
            "{path}: told to add a secret a dispatch already delivers: {body}"
        );
    }

    // Another user's secret at the path: not stored, as far as this user is
    // told, and told in exactly the words used for a path nobody holds.
    let strangers = ask(A_STRANGERS).await;
    let nobodys = ask(NOBODYS).await;
    for (path, body) in [(A_STRANGERS, &strangers), (NOBODYS, &nobodys)] {
        let presence = gate(body, "vault_presence");
        assert_eq!(presence["passed"], false, "{path}: {body}");
        assert_eq!(presence["checked"], true, "{path}: {body}");
        assert_eq!(body["would_succeed"], false, "{path}: {body}");
    }
    // The reply lists the module's grants, which name both paths, so both
    // names are masked in both replies: what is left must be identical.
    let masked = |body: &Value| {
        body.to_string()
            .replace(A_STRANGERS, "<path>")
            .replace(NOBODYS, "<path>")
    };
    assert_eq!(
        masked(&strangers),
        masked(&nobodys),
        "a path another user holds must be indistinguishable from one nobody holds"
    );
}
