//! `secrets` after migration `20260912150000`: the never-written `user_id`
//! column and its three indexes are gone, the M3 org-stamp trigger — which for
//! this table would have reclassified every personal secret as org-shared
//! (RFC 0006 decision (b): `org_id IS NULL` IS "personal") — is gone from
//! `secrets` and still present on the three tables where it is right, and the
//! columns reads filter on are indexed. The behavioural pin is the one that
//! matters: a personal secret inserted without an org must STAY org-less.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use uuid::Uuid;

#[tokio::test]
async fn the_dead_user_id_column_and_its_indexes_are_gone() {
    let (pool, _db) = common::isolated_db_pool().await;
    let has_col: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'secrets' AND column_name = 'user_id')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!has_col, "secrets.user_id must be gone");
    for idx in [
        "idx_secrets_user_keypath",
        "idx_secrets_user_name",
        "idx_secrets_org",
    ] {
        let present: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(idx)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(!present, "{idx} must be gone");
    }
    for idx in ["idx_secrets_owner_user_id", "idx_secrets_org_id"] {
        let present: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(idx)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(present, "{idx} must exist");
    }
}

#[tokio::test]
async fn the_org_stamp_trigger_is_gone_from_secrets_and_kept_where_it_is_right() {
    let (pool, _db) = common::isolated_db_pool().await;
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid WHERE t.tgname = 'trg_set_org_id' ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        tables,
        vec!["actors", "modules", "webhook_triggers"],
        "trg_set_org_id must remain exactly on the tables where org_id IS NULL carries no meaning"
    );
}

/// The RFC 0006 invariant the dropped trigger would have broken: a secret
/// written without an org is PERSONAL and stays `org_id IS NULL`, even though
/// its owner has a personal organization the stamp would have found.
#[tokio::test]
async fn a_personal_secret_stays_org_less() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@secrets-owner.test"))
    .execute(&pool)
    .await
    .unwrap();
    let tag = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) VALUES ($1, $2, $3, true)",
    )
    .bind(format!("secorg-{tag}"))
    .bind(format!("secorg-{tag}"))
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    let key_id: Uuid = sqlx::query_scalar(
        "INSERT INTO encryption_keys (encrypted_key) VALUES ('\\x00'::bytea) RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO secrets (id, name, key_path, encrypted_value, encryption_key_id, owner_user_id, created_by) VALUES ($1, 'probe', $2, '\\x00'::bytea, $3, $4, $4)",
    )
    .bind(id)
    .bind(format!("probe/{id}"))
    .bind(key_id)
    .bind(user)
    .execute(&pool)
    .await
    .expect("insert a personal secret");
    let org: Option<Uuid> = sqlx::query_scalar("SELECT org_id FROM secrets WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        org, None,
        "a personal secret must stay org-less — a stamp here would switch its owner pin off"
    );
}
