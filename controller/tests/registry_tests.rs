mod test_helpers;

use controller::registry::{ModuleRegistry, WasmModule};
use serde_json::json;
use sqlx::{Pool, Postgres};
use talos_worker_runtime::CapabilityWorld;
use uuid::Uuid;

async fn setup_registry() -> (ModuleRegistry, Pool<Postgres>) {
    let db_pool = test_helpers::get_test_db_pool().await;
    let registry = ModuleRegistry::new(db_pool.clone(), None);
    (registry, db_pool)
}

/// Registry on a database of this test's own. `enforce_cache_limits` asserts
/// on GLOBAL aggregates (total cached rows / total cached bytes), so a peer
/// test mutating `modules` concurrently can flip the verdict either way —
/// including to a vacuous pass. Isolation is what makes those guards mean
/// something.
async fn setup_isolated_registry() -> (ModuleRegistry, Pool<Postgres>) {
    let db_pool = test_helpers::get_isolated_db_pool().await;
    let registry = ModuleRegistry::new(db_pool.clone(), None);
    (registry, db_pool)
}

/// Helper to create a real user to satisfy foreign key constraints
async fn create_test_user(db: &Pool<Postgres>) -> Uuid {
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, $3, $4)")
        .bind(user_id)
        .bind(format!("user-{}@example.com", user_id))
        .bind("hash")
        .bind("Test User")
        .execute(db)
        .await
        .unwrap();
    user_id
}

#[tokio::test]
async fn test_list_templates() {
    let (registry, db) = setup_registry().await;

    // Clean up. Phase 5: `list_templates` reads from the unified `modules`
    // table (the old node_templates + wasm_modules pair was dropped).
    sqlx::query("DELETE FROM modules")
        .execute(&db)
        .await
        .unwrap();

    // Insert catalog templates directly. `list_templates` maps modules →
    // NodeTemplate as: category = COALESCE(category, kind),
    // code_template = COALESCE(source_code, ''), precompiled_wasm = wasm_bytes.
    // Catalog entries are user_id IS NULL with kind = 'catalog'.
    let id1 = Uuid::new_v4();
    let id2 = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO modules (id, name, kind, category, description, config_schema, source_code, wasm_bytes)
         VALUES ($1, $2, 'catalog', $3, $4, $5, $6, $7), ($8, $9, 'catalog', $10, $11, $12, $13, $14)"
    )
    .bind(id1).bind("Template A").bind("cat1").bind("desc1").bind(json!({})).bind("code1").bind(vec![1u8, 2, 3])
    .bind(id2).bind("Template B").bind("cat2").bind("desc2").bind(json!({})).bind("code2").bind(vec![4u8, 5, 6])
    .execute(&db).await.unwrap();

    // Test listing all templates
    let templates = registry.list_templates(None).await.unwrap();
    assert!(templates.len() >= 2);

    let a = templates.iter().find(|t| t.name == "Template A").unwrap();
    assert_eq!(a.category, "cat1");

    // Test filtering by category
    let filtered = registry.list_templates(Some("cat1")).await.unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "Template A");
}

#[tokio::test]
async fn test_module_storage_and_retrieval() {
    let (registry, db) = setup_registry().await;
    let user_id = create_test_user(&db).await;

    let module = WasmModule {
        name: "Test Module".to_string(),
        content_hash: format!("hash-{}", Uuid::new_v4()),
        wasm_bytes: vec![0, 1, 2, 3],
        source_code: Some("fn main() {}".to_string()),
        template_id: None,
        config: Some(json!({"key": "val"})),
        size_bytes: 4,
        max_fuel: 1000,
        max_memory_mb: 64,
        allowed_hosts: vec!["api.example.com".to_string()],
        allowed_secrets: vec![],
        requires_approval_for: vec![],
        allowed_methods: vec!["GET".to_string()],
        user_id: Some(user_id),
        capability_world: CapabilityWorld::Network,
        imported_interfaces: vec!["talos:core/http".to_string()],
        dependencies: None,
        oci_url: None,
        language: "rust".to_string(),
        integration_name: None,
    };

    // Store module
    let module_id = registry
        .store_module(module.clone())
        .await
        .expect("Failed to store module");

    // Retrieve module
    let retrieved = registry
        .get_module(module_id, user_id)
        .await
        .expect("Failed to get module");
    assert_eq!(retrieved.name, "Test Module");
    assert_eq!(retrieved.wasm_bytes, vec![0, 1, 2, 3]);
    assert_eq!(retrieved.capability_world, CapabilityWorld::Network);
    assert_eq!(retrieved.allowed_hosts, vec!["api.example.com"]);

    // Test access denial
    let other_user = Uuid::new_v4();
    let result = registry.get_module(module_id, other_user).await;
    assert!(result.is_err(), "Access should be denied for other user");
}

#[tokio::test]
async fn test_get_execution_info() {
    let (registry, db) = setup_registry().await;
    let user_id = create_test_user(&db).await;

    let module = WasmModule {
        name: "Execution Info Module".to_string(),
        content_hash: format!("hash-exec-{}", Uuid::new_v4()),
        wasm_bytes: vec![1, 1, 1],
        source_code: None,
        template_id: None,
        config: None,
        size_bytes: 3,
        max_fuel: 100,
        max_memory_mb: 32,
        allowed_hosts: vec![], // explicit empty — no implicit host grants
        allowed_secrets: vec![],
        requires_approval_for: vec![],
        allowed_methods: vec![],
        user_id: Some(user_id),
        capability_world: CapabilityWorld::Secrets,
        imported_interfaces: vec!["custom:ext/v1".to_string()],
        dependencies: None,
        oci_url: None,
        language: "rust".to_string(),
        integration_name: None,
    };

    let module_id = registry.store_module(module).await.unwrap();

    let info = registry
        .get_execution_info(module_id, user_id)
        .await
        .unwrap();

    // allowed_hosts is returned exactly as declared — no implicit fallback
    // list. The old "empty → default github/googleapis allow-list" behavior was
    // removed: a module only reaches the hosts it explicitly requested (granting
    // un-requested hosts is an egress-policy hole). Empty in → empty out.
    assert!(
        info.allowed_hosts.is_empty(),
        "empty allowed_hosts must stay empty (no implicit host grants), got {:?}",
        info.allowed_hosts
    );

    // module_uri is USER-SCOPED (`redis:wasm:{user_id}:{module_id}`) — the
    // cross-tenant cache-key isolation fix; the old unscoped `redis:wasm:{id}`
    // form let loop/sub-workflow re-dispatches miss the user-scoped cache key.
    assert_eq!(
        info.module_uri,
        format!("redis:wasm:{}:{}", user_id, module_id)
    );
}

#[tokio::test]
async fn test_cache_limits_eviction() {
    // Isolated: this asserts on GLOBAL cache aggregates (rows deleted, total
    // cached rows), so any peer test holding rows in `modules` changes the
    // answer. Observed: with peers' rows present the sweep correctly sheds 5
    // rows instead of 1 and the assertion below fails — a pre-existing
    // shared-state race, not an eviction defect.
    let (registry, db) = setup_isolated_registry().await;

    // Clean up (Phase 5: unified `modules` table replaces `wasm_modules`).
    sqlx::query("DELETE FROM modules")
        .execute(&db)
        .await
        .unwrap();

    let user_id = create_test_user(&db).await;

    // Store 3 modules
    for i in 0..3 {
        let m = WasmModule {
            name: format!("M{}", i),
            content_hash: format!("h{}", i),
            wasm_bytes: vec![0; 100],
            source_code: None,
            template_id: None,
            config: None,
            size_bytes: 100,
            max_fuel: 0,
            max_memory_mb: 0,
            allowed_hosts: vec![],
            allowed_secrets: vec![],
            requires_approval_for: vec![],
            allowed_methods: vec![],
            user_id: Some(user_id),
            capability_world: CapabilityWorld::Minimal,
            imported_interfaces: vec![],
            dependencies: None,
            oci_url: None,
            language: "rust".to_string(),
            integration_name: None,
        };
        let id = registry.store_module(m).await.unwrap();
        // Manually set last_used_at to ensure deterministic eviction order
        // (enforce_cache_limits evicts ORDER BY last_used_at ASC NULLS FIRST).
        // Modules added with i=0 (oldest), i=1, i=2 (newest).
        sqlx::query(
            "UPDATE modules SET last_used_at = NOW() - INTERVAL '1 hour' * $1 WHERE id = $2",
        )
        .bind(10 - i)
        .bind(id)
        .execute(&db)
        .await
        .unwrap();
    }

    // Enforce limit of 2 modules. Should delete the oldest one (i=0).
    let outcome = registry.enforce_cache_limits(2, 500).await.unwrap();
    assert_eq!(outcome.modules_deleted, 1);
    assert_eq!(outcome.unevictable_count_overage, 0);

    let stats = registry.get_cache_stats().await.unwrap();
    assert_eq!(stats.module_count, 2);

    // Verify M0 is deleted
    let remaining = sqlx::query_scalar::<_, String>("SELECT name FROM modules ORDER BY name ASC")
        .fetch_all(&db)
        .await
        .unwrap();
    assert_eq!(remaining, vec!["M1", "M2"]);
}

// ─────────────────────────────────────────────────────────────────────────
// Cache-eviction scoping guards.
//
// `enforce_cache_limits` is a CACHE sweep over a REGISTRY table. Every row in
// `modules` carries `source_code`, and rows with `user_id IS NULL` are the
// shared catalog every tenant installs from — they are not cache entries and
// no tenant owns them, so aggregate cache pressure must never delete one.
//
// Both guards below reproduce the PRODUCTION state faithfully: every row is
// left with `last_used_at IS NULL`, because nothing in the workspace ever
// writes that column (`ModuleRegistry::increment_usage` has zero callers).
// Do NOT "fix" these tests by stamping `last_used_at` — that manufactures a
// precondition production never supplies and is exactly what hid this defect.
// ─────────────────────────────────────────────────────────────────────────

/// Insert a shared catalog row: `user_id IS NULL`, `kind = 'catalog'`,
/// carrying compiled bytes (this deployment disk-seeds and compiles, so its
/// catalog rows DO hold `wasm_bytes` — 112 of 112 live rows do).
async fn insert_catalog_row(db: &Pool<Postgres>, name: &str, size_bytes: i32) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, name, kind, config_schema, source_code, wasm_bytes, size_bytes)
         VALUES ($1, $2, 'catalog', $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(name)
    .bind(json!({}))
    .bind("catalog source")
    .bind(vec![0u8; 8])
    .bind(size_bytes)
    .execute(db)
    .await
    .unwrap();
    id
}

/// Insert a user-owned sandbox row — the only class this sweep owns.
async fn insert_user_row(db: &Pool<Postgres>, user_id: Uuid, name: &str, size_bytes: i32) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, config_schema, source_code, wasm_bytes, size_bytes)
         VALUES ($1, $2, $3, 'sandbox', $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(json!({}))
    .bind("user source")
    .bind(vec![0u8; 8])
    .bind(size_bytes)
    .execute(db)
    .await
    .unwrap();
    id
}

/// COUNT-CAP GUARD. 6 shared catalog rows + 2 user rows, cap 2 ⇒ the sweep
/// must shed 6. Only 2 rows are evictable, so by pigeonhole the pre-fix code
/// has to reach into the catalog for at least 4 of them — the assertion is
/// decisive regardless of which arbitrary tie order Postgres picks.
#[tokio::test]
async fn enforce_cache_limits_never_evicts_shared_catalog_rows() {
    let (registry, db) = setup_isolated_registry().await;
    sqlx::query("DELETE FROM modules")
        .execute(&db)
        .await
        .unwrap();
    let user_id = create_test_user(&db).await;

    let mut catalog_ids = Vec::new();
    for i in 0..6 {
        catalog_ids.push(insert_catalog_row(&db, &format!("Shared Template {}", i), 1024).await);
    }
    for i in 0..2 {
        insert_user_row(&db, user_id, &format!("User Module {}", i), 1024).await;
    }

    let outcome = registry.enforce_cache_limits(2, 500).await.unwrap();

    // The cap asked for 6 rows to go; only the 2 user rows are evictable. The
    // shortfall must SURFACE as a value rather than vanish — an over-cap
    // registry whose excess is all shared catalog is a real operational
    // condition, and silently doing nothing about it is how the pre-fix code
    // would have "passed" a naive check.
    assert_eq!(outcome.modules_deleted, 2);
    assert_eq!(outcome.unevictable_count_overage, 4);

    let surviving: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM modules WHERE id = ANY($1) AND user_id IS NULL")
            .bind(&catalog_ids)
            .fetch_one(&db)
            .await
            .unwrap();

    assert_eq!(
        surviving,
        6,
        "cache eviction deleted {} shared catalog row(s); a sweep driven by \
         aggregate cache pressure must never delete a row no tenant owns",
        6 - surviving
    );
}

/// SIZE-CAP GUARD. Every row ties on `last_used_at`, so the pre-fix window
/// `SUM(size_bytes) OVER (ORDER BY last_used_at ASC NULLS FIRST)` uses its
/// DEFAULT `RANGE` frame and assigns EVERY peer row the FULL sum rather than a
/// prefix sum. `running_total <= current_size - max_size_bytes` is then false
/// for every row, so the size cap sheds nothing and stays over cap forever.
#[tokio::test]
async fn enforce_cache_limits_size_cap_sheds_bytes_when_keys_tie() {
    let (registry, db) = setup_isolated_registry().await;
    sqlx::query("DELETE FROM modules")
        .execute(&db)
        .await
        .unwrap();
    let user_id = create_test_user(&db).await;

    // 4 evictable rows of 1 MiB each = 4 MiB against a 2 MiB cap.
    for i in 0..4 {
        insert_user_row(&db, user_id, &format!("Bulky {}", i), 1_048_576).await;
    }

    registry.enforce_cache_limits(1000, 2).await.unwrap();

    let remaining_bytes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(size_bytes), 0)::bigint FROM modules WHERE wasm_bytes IS NOT NULL",
    )
    .fetch_one(&db)
    .await
    .unwrap();

    assert!(
        remaining_bytes <= 2 * 1_048_576,
        "size cap not enforced: {} bytes remain against a 2 MiB cap",
        remaining_bytes
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Cache-eviction ORDER guards.
//
// #681 scoped WHAT this sweep may delete. These two guard WHICH. The sort key
// is now derived from `module_executions` (the engine writes a row per
// dispatch) because `modules.last_used_at` has no writer — see
// `evictable_candidates!` / `eviction_order!`.
//
// As in the scoping guards above, every row is left with
// `last_used_at IS NULL`, faithfully reproducing production. Do NOT "fix"
// these by stamping that column.
// ─────────────────────────────────────────────────────────────────────────

/// Insert a user-owned sandbox row with an explicit `created_at`, so a test can
/// make creation order DISAGREE with usage order — which is the whole point.
async fn insert_user_row_created_at(
    db: &Pool<Postgres>,
    user_id: Uuid,
    name: &str,
    size_bytes: i32,
    created_days_ago: i32,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, config_schema, source_code, wasm_bytes, size_bytes, created_at)
         VALUES ($1, $2, $3, 'sandbox', $4, $5, $6, $7, NOW() - make_interval(days => $8::int))",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(json!({}))
    .bind("user source")
    .bind(vec![0u8; 8])
    .bind(size_bytes)
    .bind(created_days_ago)
    .execute(db)
    .await
    .unwrap();
    id
}

/// A user plus the default actor `module_executions.actor_id` requires.
///
/// `actor_id` is NOT NULL and is filled by the `trg_set_default_actor` BEFORE
/// INSERT trigger, which resolves `actors WHERE user_id = … AND is_default`.
/// Without the actor the INSERT fails on the NOT NULL constraint — which makes
/// the guard below red for the wrong reason, i.e. proves nothing.
async fn create_test_user_with_default_actor(db: &Pool<Postgres>) -> Uuid {
    let user_id = create_test_user(db).await;
    sqlx::query("INSERT INTO actors (id, user_id, name, is_default) VALUES ($1, $2, $3, true)")
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind("Default Test Actor")
        .execute(db)
        .await
        .unwrap();
    user_id
}

/// Record one module execution `days_ago` in the past — the same fact
/// `PostgresModuleExecutionStore::record_started` writes on every dispatch.
async fn record_execution_days_ago(
    db: &Pool<Postgres>,
    module_id: Uuid,
    user_id: Uuid,
    days_ago: i32,
) {
    sqlx::query(
        "INSERT INTO module_executions (id, module_id, user_id, status, trigger_type, started_at)
         VALUES ($1, $2, $3, 'completed', 'manual', NOW() - make_interval(days => $4::int))",
    )
    .bind(Uuid::new_v4())
    .bind(module_id)
    .bind(user_id)
    .bind(days_ago)
    .execute(db)
    .await
    .unwrap();
}

/// ORDER GUARD. Creation order is the exact REVERSE of usage order, so the two
/// candidate keys disagree on every row and the assertion cannot pass by luck.
///
/// This reproduces the live shape rather than inventing one: over the 29
/// evictable rows on the deployment, `created_at ASC` put the three busiest
/// modules on the platform at the front of the delete queue, because the
/// modules built earliest are the ones in production longest.
#[tokio::test]
async fn enforce_cache_limits_evicts_the_least_recently_executed() {
    let (registry, db) = setup_isolated_registry().await;
    sqlx::query("DELETE FROM modules")
        .execute(&db)
        .await
        .unwrap();
    let user_id = create_test_user_with_default_actor(&db).await;

    // created OLDEST, used TODAY  -> must survive
    let hot = insert_user_row_created_at(&db, user_id, "Hot", 1024, 90).await;
    let mid = insert_user_row_created_at(&db, user_id, "Mid", 1024, 60).await;
    // created NEWEST, unused for 45 days -> must be the first to go
    let cold = insert_user_row_created_at(&db, user_id, "Cold", 1024, 30).await;

    record_execution_days_ago(&db, hot, user_id, 0).await;
    record_execution_days_ago(&db, hot, user_id, 40).await; // MAX, not MIN, is the key
    record_execution_days_ago(&db, mid, user_id, 10).await;
    record_execution_days_ago(&db, cold, user_id, 45).await;

    let outcome = registry.enforce_cache_limits(2, 500).await.unwrap();
    assert_eq!(outcome.modules_deleted, 1);
    assert_eq!(outcome.unevictable_count_overage, 0);

    let survivors: Vec<String> = sqlx::query_scalar("SELECT name FROM modules ORDER BY name")
        .fetch_all(&db)
        .await
        .unwrap();

    assert_eq!(
        survivors,
        vec!["Hot".to_string(), "Mid".to_string()],
        "eviction deleted the wrong row: ordering on creation time rather than \
         on last execution deletes the module that ran today and keeps the one \
         idle for 45 days"
    );
}

/// INVERSION GUARD (the retention trap).
///
/// `module_executions` has no retention sweep today, but it is unbounded and
/// growing, and the sweep next door on `workflow_executions` deletes at 30
/// days. If a COUNT- or bulk-based prune is ever added there, a module in
/// active use can lose every execution row and present as never used.
///
/// A row with NO execution evidence must fall back to `created_at` — the
/// position it held before this key existed — NOT to the front of the delete
/// queue. Rewriting the order as a bare `last_exec ASC NULLS FIRST` fails here,
/// and so does deleting a module compiled seconds ago that has not had a chance
/// to run yet.
#[tokio::test]
async fn enforce_cache_limits_does_not_treat_missing_execution_rows_as_coldest() {
    let (registry, db) = setup_isolated_registry().await;
    sqlx::query("DELETE FROM modules")
        .execute(&db)
        .await
        .unwrap();
    let user_id = create_test_user_with_default_actor(&db).await;

    // Genuinely idle for 50 days, and its evidence survives.
    let stale = insert_user_row_created_at(&db, user_id, "Stale", 1024, 90).await;
    record_execution_days_ago(&db, stale, user_id, 50).await;

    // In active use, but its execution rows are gone (pruned) — or it was
    // compiled a moment ago and has not run yet. Both look identical here, and
    // both must be protected.
    insert_user_row_created_at(&db, user_id, "EvidenceLost", 1024, 0).await;

    let outcome = registry.enforce_cache_limits(1, 500).await.unwrap();
    assert_eq!(outcome.modules_deleted, 1);

    let survivors: Vec<String> = sqlx::query_scalar("SELECT name FROM modules ORDER BY name")
        .fetch_all(&db)
        .await
        .unwrap();

    assert_eq!(
        survivors,
        vec!["EvidenceLost".to_string()],
        "a module with no surviving execution rows sorted as coldest; absence of \
         evidence is not evidence of disuse, and this sweep's deletions are \
         irreversible"
    );
}
