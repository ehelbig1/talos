mod test_helpers;

use controller::registry::{ModuleRegistry, WasmModule};
use serde_json::json;
use sqlx::{Pool, Postgres};
use uuid::Uuid;
use worker::CapabilityWorld;

async fn setup_registry() -> (ModuleRegistry, Pool<Postgres>) {
    let db_pool = test_helpers::get_test_db_pool().await;
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

#[ignore = "references dropped wasm_modules/node_templates tables — port fixtures to unified `modules` table (Phase 5)"]
#[tokio::test]
async fn test_list_templates() {
    let (registry, db) = setup_registry().await;

    // Clean up
    sqlx::query("DELETE FROM node_templates")
        .execute(&db)
        .await
        .unwrap();

    // Insert test templates
    let id1 = Uuid::new_v4();
    let id2 = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO node_templates (id, name, category, description, config_schema, code_template, precompiled_wasm)
         VALUES ($1, $2, $3, $4, $5, $6, $7), ($8, $9, $10, $11, $12, $13, $14)"
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

#[ignore = "references dropped wasm_modules/node_templates tables — port fixtures to unified `modules` table (Phase 5)"]
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

#[ignore = "references dropped wasm_modules/node_templates tables — port fixtures to unified `modules` table (Phase 5)"]
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
        allowed_hosts: vec![], // Should trigger fallback
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

    // Check fallback hosts (empty allowed_hosts triggers default list)
    assert!(info.allowed_hosts.contains(&"api.github.com".to_string()));
    assert!(info
        .allowed_hosts
        .contains(&"www.googleapis.com".to_string()));

    assert_eq!(info.module_uri, format!("redis:wasm:{}", module_id));
}

#[ignore = "references dropped wasm_modules/node_templates tables — port fixtures to unified `modules` table (Phase 5)"]
#[tokio::test]
async fn test_cache_limits_eviction() {
    let (registry, db) = setup_registry().await;

    // Clean up wasm_modules
    sqlx::query("DELETE FROM wasm_modules")
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
        // Manually set last_used to ensure deterministic eviction order
        // Modules added with i=0 (oldest), i=1, i=2 (newest)
        sqlx::query(
            "UPDATE wasm_modules SET last_used = NOW() - INTERVAL '1 hour' * $1 WHERE id = $2",
        )
        .bind(10 - i)
        .bind(id)
        .execute(&db)
        .await
        .unwrap();
    }

    // Enforce limit of 2 modules. Should delete the oldest one (i=0).
    let (deleted, _) = registry.enforce_cache_limits(2, 500).await.unwrap();
    assert_eq!(deleted, 1);

    let stats = registry.get_cache_stats().await.unwrap();
    assert_eq!(stats.module_count, 2);

    // Verify M0 is deleted
    let remaining =
        sqlx::query_scalar::<_, String>("SELECT name FROM wasm_modules ORDER BY name ASC")
            .fetch_all(&db)
            .await
            .unwrap();
    assert_eq!(remaining, vec!["M1", "M2"]);
}
