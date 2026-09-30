// ci-store: migrated — scripts/test-integration.sh runs this with that store (scripts/ci_test_targets.py)
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
use talos_module_repository::{ModuleRepository, PushBoundModules};
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

// ── M1: restore_pinned_modules — the restore write ──────────────────────────
//
// The restore writer is keyed by module id AND owner since 2026-09-30
// (`restore_missing_module_wasm`). The name-keyed writer it replaced once wrote
// `WHERE name = $2` and clobbered every tenant's module of that name plus the
// shared catalog row; these tests keep that guarantee on the new shape, and
// add the two it gained: the hash is written with the bytes, and present bytes
// are never overwritten.

async fn hash_of(pool: &Pool<Postgres>, module_id: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT content_hash FROM modules WHERE id = $1")
        .bind(module_id)
        .fetch_one(pool)
        .await
        .expect("hash")
}

/// Another tenant's module id writes nothing, even though the caller holds a
/// module of the same name.
#[tokio::test]
async fn restore_wasm_write_does_not_reach_another_tenants_module() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let user_a = seed_user(&pool, "a").await;
    let user_b = seed_user(&pool, "b").await;
    let shared_name = format!("pa-scope-shared-{}", Uuid::new_v4());
    seed_module(&pool, user_a, &shared_name, None, 1).await;
    let b_mod = seed_module(&pool, user_b, &shared_name, None, 1).await;

    let repo = ModuleRepository::new(pool.clone());
    let affected = repo
        .restore_missing_module_wasm(b_mod, user_a, b"A-REBUILT", "hash-a")
        .await
        .expect("restore");
    assert_eq!(affected, 0, "A may not write B's module by id");
    assert_eq!(wasm_of(&pool, b_mod).await, None, "B's module is untouched");

    drop_users(&pool, &[user_a, user_b]).await;
}

/// The shared CATALOG row (`user_id IS NULL`) is never a restore target.
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
         VALUES ($1, NULL, $2, 'catalog', NULL, NOW())",
    )
    .bind(catalog_id)
    .bind(&shared_name)
    .execute(&pool)
    .await
    .expect("seed catalog row");

    let repo = ModuleRepository::new(pool.clone());
    let affected = repo
        .restore_missing_module_wasm(catalog_id, user_a, b"A-REBUILT", "hash-a")
        .await
        .expect("restore");
    assert_eq!(
        affected, 0,
        "the shared catalog row is no user's restore target"
    );
    assert_eq!(wasm_of(&pool, catalog_id).await, None);

    let _ = sqlx::query("DELETE FROM modules WHERE id = $1")
        .bind(catalog_id)
        .execute(&pool)
        .await;
    drop_users(&pool, &[user_a]).await;
}

/// The owner's evicted module is restored WITH the hash of the bytes written
/// (the old writer left the previous hash), and a module whose bytes are
/// present is never overwritten.
#[tokio::test]
async fn restore_writes_the_hash_and_never_overwrites_present_bytes() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let user_a = seed_user(&pool, "own").await;
    let evicted = seed_module(
        &pool,
        user_a,
        &format!("pa-evicted-{}", Uuid::new_v4()),
        None,
        1,
    )
    .await;
    let present = seed_module(
        &pool,
        user_a,
        &format!("pa-present-{}", Uuid::new_v4()),
        Some(b"FRESH"),
        1,
    )
    .await;

    // The evicted row still carries the hash of the bytes it USED to hold —
    // the eviction sweep keeps `content_hash`.
    sqlx::query("UPDATE modules SET content_hash = 'hash-before-eviction' WHERE id = $1")
        .bind(evicted)
        .execute(&pool)
        .await
        .expect("seed old hash");
    let repo = ModuleRepository::new(pool.clone());
    assert_eq!(
        repo.restore_missing_module_wasm(evicted, user_a, b"REBUILT", "hash-rebuilt")
            .await
            .expect("restore"),
        1
    );
    assert_eq!(
        wasm_of(&pool, evicted).await.as_deref(),
        Some(&b"REBUILT"[..])
    );
    assert_eq!(
        hash_of(&pool, evicted).await.as_deref(),
        Some("hash-rebuilt")
    );

    assert_eq!(
        repo.restore_missing_module_wasm(present, user_a, b"STALE", "hash-stale")
            .await
            .expect("restore"),
        0,
        "present bytes are never replaced by a restore"
    );
    assert_eq!(
        wasm_of(&pool, present).await.as_deref(),
        Some(&b"FRESH"[..])
    );

    drop_users(&pool, &[user_a]).await;
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
        .find_unreferenced_modules(user, 30, &PushBoundModules::default())
        .await
        .expect("survey");
    assert!(
        !surveyed.iter().any(|m| m.id == fresh),
        "precondition: a module compiled today is NOT in a 30-day survey"
    );

    let deleted = repo
        .cleanup_unreferenced_modules(user, Some(&prefix), 30, &PushBoundModules::default())
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
        .find_unreferenced_modules(user, 30, &PushBoundModules::default())
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
        .cleanup_unreferenced_modules(user, Some(&prefix), 30, &PushBoundModules::default())
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

// ── Defect (2026-09-25): "unreferenced" meant "not in a workflow graph" ──────

/// A module a webhook trigger binds directly (`webhook_triggers.module_id`).
async fn bind_webhook(pool: &Pool<Postgres>, user_id: Uuid, module_id: Uuid) {
    sqlx::query(
        "INSERT INTO webhook_triggers (name, module_id, verification_token, user_id) \
         VALUES ('bound', $1, $2, $3)",
    )
    .bind(module_id)
    .bind(Uuid::new_v4().to_string())
    .bind(user_id)
    .execute(pool)
    .await
    .expect("seed webhook trigger");
}

/// Give a module one row of execution history.
async fn record_run(pool: &Pool<Postgres>, user_id: Uuid, module_id: Uuid) {
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, $3)")
        .bind(actor)
        .bind(user_id)
        .bind(format!("mod-scope-actor-{actor}"))
        .execute(pool)
        .await
        .expect("seed actor");
    sqlx::query(
        "INSERT INTO module_executions (module_id, user_id, status, trigger_type, actor_id) \
         VALUES ($1, $2, 'completed', 'manual', $3)",
    )
    .bind(module_id)
    .bind(user_id)
    .bind(actor)
    .execute(pool)
    .await
    .expect("seed module execution");
}

async fn run_count(pool: &Pool<Postgres>, module_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM module_executions WHERE module_id = $1")
        .bind(module_id)
        .fetch_one(pool)
        .await
        .expect("count runs")
}

/// **The defect, verbatim.** `cleanup_unreferenced_modules` excluded only
/// modules named in a workflow graph. A module bound to a webhook trigger, one
/// a push channel dispatches, and one with run history were all "unreferenced"
/// — the delete made every later webhook / push delivery fail, and the
/// `module_executions` CASCADE took the run history with it. Now none of the
/// three is surveyed or deleted, while an aged module referenced by nothing
/// still is (the control that the exclusions are not blocking everything).
///
/// On the pre-fix tree all three bound modules are deleted and this fails.
#[tokio::test]
async fn cleanup_spares_webhook_push_and_history_bound_modules() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let user = seed_user(&pool, "bound").await;
    let prefix = format!("pa-scope-bound-{}", Uuid::new_v4().simple());
    let webhook = seed_module(&pool, user, &format!("{prefix}-webhook"), Some(b"W"), 60).await;
    let pushed = seed_module(&pool, user, &format!("{prefix}-push"), Some(b"W"), 60).await;
    let ran = seed_module(&pool, user, &format!("{prefix}-ran"), Some(b"W"), 60).await;
    let unbound = seed_module(&pool, user, &format!("{prefix}-unbound"), Some(b"W"), 60).await;
    bind_webhook(&pool, user, webhook).await;
    record_run(&pool, user, ran).await;
    let push_bound = PushBoundModules::from_ids(vec![pushed]);

    let repo = ModuleRepository::new(pool.clone());
    let surveyed: Vec<Uuid> = repo
        .find_unreferenced_modules(user, 30, &push_bound)
        .await
        .expect("survey")
        .into_iter()
        .filter(|m| m.name.starts_with(&prefix))
        .map(|m| m.id)
        .collect();
    assert_eq!(
        surveyed,
        vec![unbound],
        "the survey lists only the module referenced by nothing"
    );

    let deleted = repo
        .cleanup_unreferenced_modules(user, Some(&prefix), 30, &push_bound)
        .await
        .expect("cleanup");
    assert_eq!(deleted, 1, "cleanup deletes exactly what the survey listed");
    assert!(
        !module_exists(&pool, unbound).await,
        "the unbound module is gone"
    );
    assert!(
        module_exists(&pool, webhook).await,
        "a webhook-bound module must survive cleanup"
    );
    assert!(
        module_exists(&pool, pushed).await,
        "a push-channel-bound module must survive cleanup"
    );
    assert!(
        module_exists(&pool, ran).await,
        "a module with execution history must survive cleanup"
    );
    assert_eq!(
        run_count(&pool, ran).await,
        1,
        "its run history must survive too (module_executions CASCADEs)"
    );

    drop_users(&pool, &[user]).await;
}

/// The hygiene `fix_all` delete had the same hole with a different query: it
/// deleted whatever ids the report's graph-only orphan query listed. It now
/// re-checks every reference at DELETE time, so even ids handed to it verbatim
/// are kept when something binds them.
#[tokio::test]
async fn hygiene_orphan_delete_rechecks_every_binding_at_delete_time() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let user = seed_user(&pool, "hygiene").await;
    let prefix = format!("pa-scope-hyg-{}", Uuid::new_v4().simple());
    let webhook = seed_module(&pool, user, &format!("{prefix}-webhook"), Some(b"W"), 0).await;
    let pushed = seed_module(&pool, user, &format!("{prefix}-push"), Some(b"W"), 0).await;
    let ran = seed_module(&pool, user, &format!("{prefix}-ran"), Some(b"W"), 0).await;
    let unbound = seed_module(&pool, user, &format!("{prefix}-unbound"), Some(b"W"), 0).await;
    bind_webhook(&pool, user, webhook).await;
    record_run(&pool, user, ran).await;

    let repo = ModuleRepository::new(pool.clone());
    let deleted = repo
        .delete_orphaned_modules(
            &[webhook, pushed, ran, unbound],
            user,
            &PushBoundModules::from_ids(vec![pushed]),
        )
        .await
        .expect("hygiene delete");
    assert_eq!(deleted, 1);
    assert!(!module_exists(&pool, unbound).await);
    for (label, id) in [("webhook", webhook), ("push", pushed), ("history", ran)] {
        assert!(
            module_exists(&pool, id).await,
            "{label}-bound module was deleted"
        );
    }
    assert_eq!(run_count(&pool, ran).await, 1);

    drop_users(&pool, &[user]).await;
}
