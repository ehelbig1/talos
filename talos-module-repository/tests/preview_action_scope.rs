//! Does the module cleanup/restore ACTION touch the set its PREVIEW showed?
//!
//! Two defects, both found by auditing every preview→act pair in the repo after
//! #655 fixed the `fix_all` instance of the same class:
//!
//! * **`restore_pinned_modules`** read the user's pins under
//!   `begin_user_scoped` and then wrote `UPDATE modules … WHERE name = $2` with
//!   no owner predicate. `modules.name` is unique only PER USER
//!   (`modules_user_name_uniq (user_id, name) WHERE user_id IS NOT NULL`), so
//!   the write landed on every tenant's row of that name plus the shared
//!   catalog row — a user-scoped read reporting a cross-tenant write.
//! * **`cleanup_modules`** deleted with no age predicate while
//!   `find_unreferenced_modules` — the only survey an operator has, and the tool
//!   whose description says "useful for cleanup" — selects
//!   `compiled_at < NOW() - N days`. A module compiled minutes ago was invisible
//!   in the survey and destroyed by the cleanup.
//!
//! Every test here FAILS on the pre-fix tree and passes on the fix. They need a
//! real Postgres because the property at stake IS the SQL predicate: a
//! behavioural assertion about which rows a `WHERE` clause reaches cannot be
//! made without the database evaluating it.
//!
//! Gated on `TALOS_TEST_DATABASE_URL` (a MIGRATED database). CI-wired as
//! `talos-module-repository:preview_action_scope:migrated` in
//! `scripts/test-integration.sh`; skips with a printed note when unset.
//!
//! ```sh
//! export TALOS_TEST_DATABASE_URL="postgres://talos:<pw>@localhost:5432/talos"
//! cargo test -p talos-module-repository --test preview_action_scope -- --nocapture
//! ```

use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres, Row};
use talos_module_repository::ModuleRepository;
use uuid::Uuid;

async fn pool_or_skip() -> Option<Pool<Postgres>> {
    let url = match std::env::var("TALOS_TEST_DATABASE_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!("SKIP: set TALOS_TEST_DATABASE_URL to run preview_action_scope");
            return None;
        }
    };
    Some(
        PgPoolOptions::new()
            .max_connections(3)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(&url)
            .await
            .expect("TALOS_TEST_DATABASE_URL connect"),
    )
}

async fn seed_user(pool: &Pool<Postgres>, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', $3) \
         ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(format!("mod-scope-{tag}-{id}@test.invalid"))
    .bind(format!("mod-scope-{tag}"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// Insert a user-owned module row. `compiled_days_ago` also drives
/// `compiled_at`, which is the axis `cleanup_modules` lost.
async fn seed_module(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    name: &str,
    wasm: Option<&[u8]>,
    compiled_days_ago: i64,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, wasm_bytes, compiled_at) \
         VALUES ($1, $2, $3, 'sandbox', $4, NOW() - make_interval(days => $5::int))",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(wasm)
    .bind(compiled_days_ago as i32)
    .execute(pool)
    .await
    .expect("seed module");
    id
}

async fn wasm_of(pool: &Pool<Postgres>, module_id: Uuid) -> Option<Vec<u8>> {
    sqlx::query("SELECT wasm_bytes FROM modules WHERE id = $1")
        .bind(module_id)
        .fetch_one(pool)
        .await
        .expect("read wasm_bytes")
        .try_get::<Option<Vec<u8>>, _>("wasm_bytes")
        .expect("wasm_bytes column")
}

async fn module_exists(pool: &Pool<Postgres>, module_id: Uuid) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM modules WHERE id = $1")
        .bind(module_id)
        .fetch_one(pool)
        .await
        .expect("count module")
        > 0
}

async fn drop_users(pool: &Pool<Postgres>, users: &[Uuid]) {
    // modules.user_id and user_module_pins.user_id are both ON DELETE CASCADE.
    let _ = sqlx::query("DELETE FROM users WHERE id = ANY($1)")
        .bind(users)
        .execute(pool)
        .await;
}

// ── M1: restore_pinned_modules — the cross-tenant write ─────────────────────

/// **The defect, verbatim.** `update_template_precompiled_wasm` wrote
/// `WHERE name = $2`. Two tenants each holding a module called
/// `pa-scope-shared-<uuid>` is the ordinary case — every user who installs the
/// same catalog template has one — and user A restoring their pin overwrote
/// user B's compiled bytes. A tenant who had `hot_update_module`'d their copy
/// silently lost it, with no history row and no audit event.
///
/// On the pre-fix tree B's bytes become A's and this assertion fails.
#[tokio::test]
async fn restore_wasm_write_does_not_reach_another_tenants_module() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let user_a = seed_user(&pool, "a").await;
    let user_b = seed_user(&pool, "b").await;
    let shared_name = format!("pa-scope-shared-{}", Uuid::new_v4());

    let a_mod = seed_module(&pool, user_a, &shared_name, Some(b"A-ORIGINAL"), 1).await;
    let b_mod = seed_module(&pool, user_b, &shared_name, Some(b"B-CUSTOMISED"), 1).await;

    let repo = ModuleRepository::new(pool.clone());
    let affected = repo
        .update_template_precompiled_wasm(&shared_name, b"A-REBUILT", user_a)
        .await
        .expect("update wasm");

    assert_eq!(
        affected, 1,
        "the write must land on exactly ONE row — this user's install. \
         2 means it reached another tenant; 0 means it reached nobody"
    );
    assert_eq!(
        wasm_of(&pool, a_mod).await.as_deref(),
        Some(&b"A-REBUILT"[..]),
        "the requesting user's own module must be the one restored"
    );
    assert_eq!(
        wasm_of(&pool, b_mod).await.as_deref(),
        Some(&b"B-CUSTOMISED"[..]),
        "another tenant's module of the same name must be untouched — this is the \
         cross-tenant clobber the unscoped `WHERE name = $2` performed"
    );

    drop_users(&pool, &[user_a, user_b]).await;
}

/// The shared CATALOG row (`user_id IS NULL`) is the other victim of the
/// unscoped write, and it is a distinct case from a peer tenant: it is global by
/// construction, so nothing about per-user uniqueness protects it.
#[tokio::test]
async fn restore_wasm_write_does_not_reach_the_shared_catalog_row() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let user_a = seed_user(&pool, "cat").await;
    let shared_name = format!("pa-scope-catalog-{}", Uuid::new_v4());

    let catalog_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, wasm_bytes, compiled_at) \
         VALUES ($1, NULL, $2, 'catalog', $3, NOW())",
    )
    .bind(catalog_id)
    .bind(&shared_name)
    .bind(&b"CATALOG-BYTES"[..])
    .execute(&pool)
    .await
    .expect("seed catalog row");

    let a_mod = seed_module(&pool, user_a, &shared_name, Some(b"A-ORIGINAL"), 1).await;

    let repo = ModuleRepository::new(pool.clone());
    let affected = repo
        .update_template_precompiled_wasm(&shared_name, b"A-REBUILT", user_a)
        .await
        .expect("update wasm");

    assert_eq!(
        affected, 1,
        "only the user's own install row may be written"
    );
    assert_eq!(
        wasm_of(&pool, catalog_id).await.as_deref(),
        Some(&b"CATALOG-BYTES"[..]),
        "the shared catalog row must be untouched by one user's restore"
    );
    assert_eq!(
        wasm_of(&pool, a_mod).await.as_deref(),
        Some(&b"A-REBUILT"[..])
    );

    let _ = sqlx::query("DELETE FROM modules WHERE id = $1")
        .bind(catalog_id)
        .execute(&pool)
        .await;
    drop_users(&pool, &[user_a]).await;
}

/// A pin with no install row for this user must report zero rows written, not
/// silent success. The handler turns `Ok(0)` into an explicit `failed` entry —
/// reporting it as `restored` would tell the operator a module is usable when
/// the write went nowhere, which is this same class one level down.
#[tokio::test]
async fn restore_wasm_write_reports_zero_when_this_user_has_no_install_row() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let user_a = seed_user(&pool, "noinstall").await;
    let user_b = seed_user(&pool, "hasinstall").await;
    let name = format!("pa-scope-absent-{}", Uuid::new_v4());

    // Only B has a row under this name. A has none.
    let b_mod = seed_module(&pool, user_b, &name, Some(b"B-BYTES"), 1).await;

    let repo = ModuleRepository::new(pool.clone());
    let affected = repo
        .update_template_precompiled_wasm(&name, b"A-REBUILT", user_a)
        .await
        .expect("update wasm");

    assert_eq!(
        affected, 0,
        "A owns no row under this name, so the write must land nowhere and say so. \
         Pre-fix this returned 1 — having written B's module."
    );
    assert_eq!(
        wasm_of(&pool, b_mod).await.as_deref(),
        Some(&b"B-BYTES"[..]),
        "B's module must be untouched by a restore A had no row for"
    );

    drop_users(&pool, &[user_a, user_b]).await;
}

/// The READ leg of the same defect. `list_user_pinned_modules` joined
/// `modules m ON m.name = pm.module_name` with no owner predicate, so the
/// LEFT JOIN fanned out one row per tenant holding the name and `has_wasm` read
/// true when ANY tenant's row had bytes. Net: a user whose own copy is empty was
/// reported `already_present` and never restored — the tool failing silently in
/// exactly the case it exists for.
#[tokio::test]
async fn pinned_listing_reports_this_users_own_install_state_only() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let user_a = seed_user(&pool, "pinA").await;
    let user_b = seed_user(&pool, "pinB").await;
    let name = format!("pa-scope-pin-{}", Uuid::new_v4());

    // A's copy is EMPTY (needs restoring). B's copy is compiled.
    seed_module(&pool, user_a, &name, None, 1).await;
    seed_module(&pool, user_b, &name, Some(b"B-BYTES"), 1).await;

    let repo = ModuleRepository::new(pool.clone());
    repo.pin_user_module(user_a, &name).await.expect("pin");

    let rows = repo
        .list_user_pinned_modules(user_a)
        .await
        .expect("list pins");
    let mine: Vec<_> = rows.iter().filter(|r| r.module_name == name).collect();

    assert_eq!(
        mine.len(),
        1,
        "one pin must yield exactly one row; more than one is the cross-tenant \
         LEFT JOIN fan-out, which over-counts the pin list and recompiles the \
         same module once per tenant"
    );
    assert!(
        !mine[0].has_wasm,
        "has_wasm must describe THIS user's row. A's copy is empty, so it needs \
         restoring; pre-fix B's compiled copy made this true and A's module was \
         reported already_present and silently never restored"
    );

    drop_users(&pool, &[user_a, user_b]).await;
}

// ── M2: cleanup_modules — the age predicate the DELETE dropped ───────────────

/// **The defect, verbatim.** `find_unreferenced_modules(days)` selects
/// `compiled_at < NOW() - days`; `cleanup_unreferenced_modules` had no age
/// predicate at all. So a module compiled today and not yet wired into a
/// workflow — exactly what `compile_custom_sandbox` produces — could not appear
/// in the survey and was deleted by the cleanup the survey invited.
///
/// On the pre-fix tree this module is deleted and the assertion fails.
#[tokio::test]
async fn cleanup_spares_a_module_too_recent_to_appear_in_the_survey() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let user = seed_user(&pool, "recent").await;
    let prefix = format!("pa-scope-recent-{}", Uuid::new_v4().simple());
    let fresh = seed_module(&pool, user, &format!("{prefix}-mod"), Some(b"W"), 0).await;

    let repo = ModuleRepository::new(pool.clone());

    // The survey an operator would run first, at the default window.
    let surveyed = repo
        .find_unreferenced_modules(user, 30)
        .await
        .expect("survey");
    assert!(
        !surveyed.iter().any(|m| m.id == fresh),
        "precondition: a module compiled today is NOT in a 30-day survey"
    );

    let deleted = repo
        .cleanup_unreferenced_modules(user, Some(&prefix), 30)
        .await
        .expect("cleanup");

    assert_eq!(
        deleted, 0,
        "cleanup must not delete what the survey could not show. Pre-fix the \
         DELETE carried no age predicate and removed this row."
    );
    assert!(
        module_exists(&pool, fresh).await,
        "the freshly-compiled module must survive a cleanup run at the same \
         `days` the operator surveyed with"
    );

    drop_users(&pool, &[user]).await;
}

/// The complement, so the age filter is not merely blocking everything: a module
/// old enough to be surveyed IS deleted, and the two sets agree.
#[tokio::test]
async fn cleanup_deletes_exactly_what_the_survey_listed() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let user = seed_user(&pool, "aged").await;
    let prefix = format!("pa-scope-aged-{}", Uuid::new_v4().simple());
    let aged = seed_module(&pool, user, &format!("{prefix}-old"), Some(b"W"), 60).await;
    let fresh = seed_module(&pool, user, &format!("{prefix}-new"), Some(b"W"), 0).await;

    let repo = ModuleRepository::new(pool.clone());
    let surveyed: Vec<Uuid> = repo
        .find_unreferenced_modules(user, 30)
        .await
        .expect("survey")
        .into_iter()
        .filter(|m| m.name.starts_with(&prefix))
        .map(|m| m.id)
        .collect();
    assert_eq!(
        surveyed,
        vec![aged],
        "the survey lists the aged module and only the aged module"
    );

    let deleted = repo
        .cleanup_unreferenced_modules(user, Some(&prefix), 30)
        .await
        .expect("cleanup");

    assert_eq!(
        deleted, 1,
        "cleanup deletes exactly the one row the survey listed"
    );
    assert!(!module_exists(&pool, aged).await, "the aged module is gone");
    assert!(
        module_exists(&pool, fresh).await,
        "the fresh module, absent from the survey, survives"
    );

    drop_users(&pool, &[user]).await;
}
