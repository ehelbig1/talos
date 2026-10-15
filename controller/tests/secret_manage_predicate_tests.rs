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

    // The upsert path (C2-1, 2026-10-15): the creator's upsert of an org
    // secret they made works while they are a member…
    let up_path = "manage/org-upserted";
    let (up_id, inserted) = secrets
        .upsert_secret(
            "org-upserted",
            up_path,
            "u1",
            "default",
            None,
            creator,
            vec![],
            Some(org),
        )
        .await
        .expect("upsert while a member");
    assert!(inserted);
    secrets
        .upsert_secret(
            "org-upserted",
            up_path,
            "u2",
            "default",
            None,
            creator,
            vec![],
            Some(org),
        )
        .await
        .expect("re-upsert while a member");

    leave_org(&pool, org, creator).await;

    // …and after leaving it is refused, the stored value untouched.
    let ciphertext = |pool: sqlx::PgPool| async move {
        sqlx::query_scalar::<_, Vec<u8>>("SELECT encrypted_value FROM secrets WHERE id = $1")
            .bind(up_id)
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    let before = ciphertext(pool.clone()).await;
    assert!(
        secrets
            .upsert_secret(
                "org-upserted",
                up_path,
                "attacker-value",
                "default",
                None,
                creator,
                vec![],
                Some(org)
            )
            .await
            .is_err(),
        "upsert after leaving"
    );
    assert_eq!(
        ciphertext(pool.clone()).await,
        before,
        "the value is unchanged"
    );

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
            .get_secrets_by_paths(
                &[path.to_string()],
                Some(creator),
                talos_secrets_manager::PathReadAudit::Dispatch
            )
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
            .get_secrets_by_paths(
                &[path.to_string()],
                Some(owner),
                talos_secrets_manager::PathReadAudit::Dispatch
            )
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
            talos_secrets_manager::PathReadAudit::Dispatch,
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

    // C2-2 (2026-10-15): the controller's own read is recorded as such, and
    // the LLM-key cache fill records nothing.
    secrets
        .get_secrets_by_paths(
            &["audit/a".to_string()],
            Some(user),
            talos_secrets_manager::PathReadAudit::Controller,
        )
        .await
        .expect("controller read");
    secrets
        .get_secrets_by_paths(
            &["audit/b".to_string()],
            Some(user),
            talos_secrets_manager::PathReadAudit::NotRecorded,
        )
        .await
        .expect("unrecorded read");
    let labels: Vec<(String, String)> = sqlx::query_as(
        "SELECT action, actor_type FROM secret_audit_log \
         WHERE action IN ('dispatch_read', 'controller_read') ORDER BY action",
    )
    .fetch_all(&pool)
    .await
    .expect("labels");
    assert_eq!(
        labels
            .iter()
            .filter(|(a, t)| a == "controller_read" && t == "system")
            .count(),
        1,
        "the controller's read: {labels:?}"
    );
    assert_eq!(
        labels.iter().filter(|(a, _)| a == "dispatch_read").count(),
        3,
        "nothing more for the dispatch, nothing for the cache fill: {labels:?}"
    );
}

/// C2-6 (2026-10-15): the two readers of "may this user use this module" —
/// a secret's `allowed_modules` check and `ModuleRepository`'s reader — are
/// one fragment (`talos_tenancy::module_visible_to!`), and agree over a
/// module the user owns, a catalog row, one of an org they belong to, a
/// stranger's and an id that names nothing.
#[tokio::test]
async fn the_two_module_visibility_readers_agree() {
    leave_row_security_unenforced();
    let (pool, _db) = common::isolated_db_pool().await;
    let secrets = manager(&pool).await;
    let user = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let colleague = seed_user(&pool).await;
    let org = seed_org(&pool, colleague, &[user, colleague]).await;
    let module = |owner: Option<Uuid>, org: Option<Uuid>, kind: &'static str| {
        let pool = pool.clone();
        async move {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO modules (id, name, kind, user_id, org_id) VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(id)
            .bind(format!("visibility-{}", id.simple()))
            .bind(kind)
            .bind(owner)
            .bind(org)
            .execute(&pool)
            .await
            .expect("seed module");
            id
        }
    };
    let own = module(Some(user), None, "sandbox").await;
    let catalog = module(None, None, "catalog").await;
    let shared = module(Some(colleague), Some(org), "sandbox").await;
    let foreign = module(Some(stranger), None, "sandbox").await;
    let missing = Uuid::new_v4();
    let all = [own, catalog, shared, foreign, missing];

    let repo = talos_module_repository::ModuleRepository::new(pool.clone());
    let read: std::collections::HashSet<Uuid> = repo
        .get_modules_by_ids_for_reader(&all, user, &[org])
        .await
        .expect("reader")
        .into_iter()
        .map(|m| m.id)
        .collect();
    for (i, id) in all.iter().enumerate() {
        let granted = secrets
            .create_secret(
                "visibility",
                &format!("visibility/m{i}"),
                "v",
                None,
                user,
                vec![*id],
                None,
            )
            .await
            .is_ok();
        assert_eq!(
            granted,
            read.contains(id),
            "the two readers disagree on case {i}"
        );
    }
    assert_eq!(
        read,
        [own, catalog, shared].into_iter().collect(),
        "own, catalog and org modules; not a stranger's, not a missing id"
    );
}
