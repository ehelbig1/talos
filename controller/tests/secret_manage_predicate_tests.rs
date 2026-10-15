//! Who may manage a secret, and whose dispatch may read it — the two rules of
//! security review 2026-10-14, C-2 (`talos_secrets_manager::may_manage_secret!`
//! and `may_dispatch_read_secret!`), with row security OUT of the picture so
//! the statements' own predicates are what is tested (the
//! `secret_delete_predicate_tests` arrangement: the role switch is off and the
//! connection bypasses row security).
//!
//! The scenario the review found: a member creates an org-shared secret and
//! LEAVES the org. Until this date every by-id statement matched `created_by`,
//! so they kept rotating, expiring, renaming and deleting it, and their
//! dispatches kept reading it.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use std::sync::Arc;

use controller::secrets::SecretsManager;
use uuid::Uuid;

fn leave_row_security_unenforced() {
    std::env::set_var("TALOS_RLS_SET_ROLE", "0");
}

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@secret-manage.test"))
    .execute(pool)
    .await
    .expect("seed user");
    user
}

async fn seed_org(pool: &sqlx::PgPool, owner: Uuid, members: &[Uuid]) -> Uuid {
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) \
         VALUES ($1, $1, $2, false) RETURNING id",
    )
    .bind(format!("org-{}", Uuid::new_v4().simple()))
    .bind(owner)
    .fetch_one(pool)
    .await
    .expect("seed org");
    for m in members {
        sqlx::query(
            "INSERT INTO organization_members (org_id, user_id, role) VALUES ($1, $2, 'member')",
        )
        .bind(org)
        .bind(m)
        .execute(pool)
        .await
        .expect("seed member");
    }
    org
}

async fn leave_org(pool: &sqlx::PgPool, org: Uuid, user: Uuid) {
    sqlx::query("DELETE FROM organization_members WHERE org_id = $1 AND user_id = $2")
        .bind(org)
        .bind(user)
        .execute(pool)
        .await
        .expect("leave org");
}

async fn manager(pool: &sqlx::PgPool) -> Arc<SecretsManager> {
    let secrets = Arc::new(SecretsManager::new(pool.clone()).expect("secrets manager"));
    secrets.initialize().await.expect("active DEK");
    secrets
}

async fn assert_row_security_is_bypassed(pool: &sqlx::PgPool, user: Uuid) {
    let mut tx = talos_db::begin_user_scoped(pool, user).await.expect("tx");
    let bypasses: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("role");
    assert!(
        bypasses,
        "this binary pins the statements' predicates, not the policy"
    );
}

/// The review's scenario: after leaving the org the creator can no longer
/// rotate, expire, rename or delete the org secret they created, and their
/// dispatch no longer reads it.
#[tokio::test]
async fn a_member_who_left_the_org_cannot_manage_or_read_the_secrets_they_created() {
    leave_row_security_unenforced();
    let (pool, _db) = common::isolated_db_pool().await;
    let secrets = manager(&pool).await;
    let creator = seed_user(&pool).await;
    let admin = seed_user(&pool).await;
    assert_row_security_is_bypassed(&pool, creator).await;
    let org = seed_org(&pool, admin, &[creator, admin]).await;
    let path = "manage/org-shared";
    let id = secrets
        .create_secret("org-shared", path, "v1", None, creator, vec![], Some(org))
        .await
        .expect("create org secret");

    // While a member: the creator manages it and their dispatch reads it.
    assert!(secrets
        .list_dispatch_readable_key_paths(creator)
        .await
        .expect("list")
        .contains(&path.to_string()));
    assert!(secrets
        .rotate_secret_value_by_id(creator, id, "v2")
        .await
        .expect("rotate")
        .is_some());

    leave_org(&pool, org, creator).await;

    assert!(
        secrets
            .rotate_secret_value_by_id(creator, id, "attacker-value")
            .await
            .expect("a refused rotate is not an error")
            .is_none(),
        "rotate after leaving"
    );
    assert!(
        !secrets
            .set_secret_expiry_by_id(creator, id, chrono::Utc::now(), 1)
            .await
            .expect("a refused expiry is not an error"),
        "expiry after leaving"
    );
    assert!(
        !secrets
            .set_secret_namespace_by_id(creator, id, "elsewhere")
            .await
            .expect("a refused rename is not an error"),
        "namespace after leaving"
    );
    assert!(
        !secrets
            .delete_secret_by_id(creator, id)
            .await
            .expect("a refused delete is not an error"),
        "delete after leaving"
    );
    assert!(
        !secrets
            .list_dispatch_readable_key_paths(creator)
            .await
            .expect("list")
            .contains(&path.to_string()),
        "a dispatch for the departed creator does not read it"
    );
    assert!(
        secrets
            .get_secrets_by_paths(&[path.to_string()], Some(creator))
            .await
            .expect("read")
            .is_empty(),
        "nor by path"
    );

    // The org still has it, unchanged by any refused call, and a current
    // member manages it.
    assert!(secrets
        .set_secret_namespace_by_id(admin, id, "team")
        .await
        .expect("a member renames"));
    let still: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(still, 1);
}

/// The personal rules are unchanged: the owner manages and reads their own
/// secret, a stranger does neither.
#[tokio::test]
async fn a_personal_secret_is_its_owners_alone() {
    leave_row_security_unenforced();
    let (pool, _db) = common::isolated_db_pool().await;
    let secrets = manager(&pool).await;
    let owner = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    assert_row_security_is_bypassed(&pool, owner).await;
    let path = "manage/personal";
    let id = secrets
        .create_secret("personal", path, "v", None, owner, vec![], None)
        .await
        .expect("create");

    assert!(secrets
        .rotate_secret_value_by_id(stranger, id, "x")
        .await
        .expect("refused")
        .is_none());
    assert!(!secrets
        .list_dispatch_readable_key_paths(stranger)
        .await
        .expect("list")
        .contains(&path.to_string()));
    assert!(secrets
        .rotate_secret_value_by_id(owner, id, "v2")
        .await
        .expect("rotate")
        .is_some());
    assert!(secrets
        .list_dispatch_readable_key_paths(owner)
        .await
        .expect("list")
        .contains(&path.to_string()));
    assert_eq!(
        secrets
            .get_secrets_by_paths(&[path.to_string()], Some(owner))
            .await
            .expect("read")
            .get(path)
            .map(|v| v.as_str()),
        Some("v2")
    );
}

/// D-4 (operator decision, not built): another member's org secret is NOT read
/// into a member's dispatch — only its owner's. Pinned so that changing it is
/// a decision, not a drift.
#[tokio::test]
async fn another_members_org_secret_is_not_read_into_a_dispatch() {
    leave_row_security_unenforced();
    let (pool, _db) = common::isolated_db_pool().await;
    let secrets = manager(&pool).await;
    let a = seed_user(&pool).await;
    let b = seed_user(&pool).await;
    assert_row_security_is_bypassed(&pool, a).await;
    let org = seed_org(&pool, a, &[a, b]).await;
    let path = "manage/members-own";
    secrets
        .create_secret("members-own", path, "v", None, a, vec![], Some(org))
        .await
        .expect("create");
    assert!(!secrets
        .list_dispatch_readable_key_paths(b)
        .await
        .expect("list")
        .contains(&path.to_string()));
}

/// C-7 (2026-10-14): a row is decrypted only under a DEK its scope allows.
/// The unscoped decrypt refuses a v3 label on an org DEK (a row claiming the
/// global scope); the scoped one also refuses a v4 row naming ANOTHER org's
/// DEK, and opens the honest row.
#[tokio::test]
async fn a_row_naming_a_dek_outside_its_scope_does_not_open() {
    leave_row_security_unenforced();
    let (pool, _db) = common::isolated_db_pool().await;
    let secrets = manager(&pool).await;
    let a = seed_user(&pool).await;
    let org_a = seed_org(&pool, a, &[a]).await;
    let org_b = seed_org(&pool, a, &[a]).await;
    let aad = b"c7-scope-test";
    let (kid, ct, version) = secrets
        .encrypt_value_aad_v4_or_global("payload", Some(org_a), aad)
        .await
        .expect("encrypt under org A");
    assert_eq!(version, SecretsManager::AAD_FORMAT_V4_ORG_DERIVED);

    // The honest reads.
    assert_eq!(
        secrets
            .decrypt_versioned(kid, &ct, aad, version)
            .await
            .expect("open")
            .as_str(),
        "payload"
    );
    assert_eq!(
        secrets
            .decrypt_versioned_scoped(kid, &ct, aad, version, Some(org_a))
            .await
            .expect("open scoped")
            .as_str(),
        "payload"
    );
    // A v3 label on org A's DEK.
    assert!(matches!(
        secrets
            .decrypt_versioned(kid, &ct, aad, SecretsManager::AAD_FORMAT_V3_DERIVED)
            .await,
        Err(talos_secrets_manager::SecretsError::Aead)
    ));
    // The row says org B; the key is org A's.
    assert!(matches!(
        secrets
            .decrypt_versioned_scoped(kid, &ct, aad, version, Some(org_b))
            .await,
        Err(talos_secrets_manager::SecretsError::Aead)
    ));
    assert!(matches!(
        secrets
            .decrypt_versioned_scoped(kid, &ct, aad, version, None)
            .await,
        Err(talos_secrets_manager::SecretsError::Aead)
    ));
}

/// C-4 (2026-10-14): every secret a dispatch is handed leaves one
/// `dispatch_read` audit row naming the user and the path's hash — by path
/// grant and by module grant — and the counter moves with it.
#[tokio::test]
async fn a_dispatch_records_one_audit_row_per_delivered_secret() {
    leave_row_security_unenforced();
    let (pool, _db) = common::isolated_db_pool().await;
    let secrets = manager(&pool).await;
    let user = seed_user(&pool).await;
    let paths = ["audit/a", "audit/b", "audit/c"];
    for p in paths {
        secrets
            .create_secret(p, p, "v", None, user, vec![], None)
            .await
            .expect("create");
    }
    let got = secrets
        .get_secrets_by_paths(
            &paths.iter().map(|p| (*p).to_string()).collect::<Vec<_>>(),
            Some(user),
        )
        .await
        .expect("read");
    assert_eq!(got.len(), 3);

    let rows: Vec<(String, String, Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT l.action, l.actor_type, l.actor_id, l.key_hash FROM secret_audit_log l \
         WHERE l.action = 'dispatch_read' ORDER BY l.key_hash",
    )
    .fetch_all(&pool)
    .await
    .expect("audit rows");
    assert_eq!(rows.len(), 3, "one row per delivered secret");
    let mut want: Vec<String> = paths
        .iter()
        .map(|p| {
            use sha2::Digest as _;
            hex::encode(sha2::Sha256::digest(p.as_bytes()))
        })
        .collect();
    want.sort();
    let got_hashes: Vec<String> = rows
        .iter()
        .map(|r| r.3.clone().expect("key_hash"))
        .collect();
    assert_eq!(got_hashes, want);
    assert!(rows
        .iter()
        .all(|r| r.0 == "dispatch_read" && r.1 == "dispatch" && r.2 == Some(user)));
    let counted: i64 =
        sqlx::query_scalar("SELECT sum(access_count)::bigint FROM secrets WHERE created_by = $1")
            .bind(user)
            .fetch_one(&pool)
            .await
            .expect("counter");
    assert_eq!(counted, 3);
}
