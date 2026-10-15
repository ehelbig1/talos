//! GraphQL `testModule` runs for its CALLER (security review 2026-10-15,
//! D2-8 / A-16): a module's secrets are resolved as a dispatch resolves them,
//! through `talos_oauth::resolver::resolve_for_standalone_run` for the
//! caller's own user, and the run is attributed to that user — until then it
//! carried no secrets and the nil user. A module the caller does not own
//! resolves nothing: the owner-scoped load refuses it first.
//!
//! The module's bytes are not a component, so nothing executes; what is
//! observed is whether a `vault://` reference in the input resolved — the
//! check that refuses an unresolvable one runs before the runtime does.
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use std::sync::Arc;

use controller::api::schema::{IsTwoFactorVerified, SecondFactorVerified};
use uuid::Uuid;

async fn seed_module(pool: &sqlx::PgPool, user: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, capability_world, allowed_secrets, \
                              allowed_hosts, wasm_bytes) \
         VALUES ($1, $2, $3, 'sandbox', 'http-node', ARRAY['svc/a'], \
                 ARRAY['api.example.test'], '\\x0061736d'::bytea)",
    )
    .bind(id)
    .bind(user)
    .bind(format!("caller-probe-{}", &id.to_string()[..8]))
    .execute(pool)
    .await
    .expect("seed module");
    id
}

async fn test_module(
    ctx: &common::TestContext,
    caller: Uuid,
    module: Uuid,
) -> async_graphql::Response {
    // The input names the module's granted secret by reference.
    let input = r#"{\"AUTH_HEADER\": \"vault://svc/a\"}"#;
    let req = async_graphql::Request::new(format!(
        r#"mutation {{ testModule(moduleId: "{module}", input: "{input}") {{ success error }} }}"#
    ))
    .data(caller)
    .data(IsTwoFactorVerified(true))
    .data(SecondFactorVerified(true))
    .data(Arc::new(
        talos_worker_runtime::runtime::TalosRuntime::new().expect("runtime"),
    ))
    .data(Arc::new(talos_registry::ModuleRegistry::new(
        ctx.db_pool.clone(),
        None,
    )))
    .data(ctx.secrets_manager.clone());
    ctx.schema.execute(req).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_module_resolves_the_callers_secrets_and_nothing_of_a_module_it_does_not_own() {
    let ctx = common::setup_test_context().await;
    ctx.secrets_manager.initialize().await.expect("active DEK");
    let alice = common::create_test_user(&ctx.auth_service, "caller-alice@example.com").await;
    let bob = common::create_test_user(&ctx.auth_service, "caller-bob@example.com").await;
    ctx.secrets_manager
        .create_secret("a", "svc/a", "made-up-value", None, alice, Vec::new(), None)
        .await
        .expect("alice's secret");
    let alices = seed_module(&ctx.db_pool, alice).await;
    let bobs = seed_module(&ctx.db_pool, bob).await;

    // Alice's own module: her secret resolves (the reference check passes,
    // and the run fails later, on bytes that are not a component). Run as
    // the nil user, as before, it did not.
    let resp = test_module(&ctx, alice, alices).await;
    assert!(resp.errors.is_empty(), "{:?}", resp.errors);
    let body = resp.data.into_json().expect("json").to_string();
    assert!(!body.contains("svc/a"), "the reference resolved: {body}");
    assert!(!body.contains("made-up-value"), "no value in the answer");

    // Bob's own module granted the same path: Alice's secret is not his.
    let resp = test_module(&ctx, bob, bobs).await;
    let refused = format!("{:?}", resp.errors);
    assert!(refused.contains("svc/a"), "{refused}");
    assert!(!refused.contains("made-up-value"));

    // Alice's module, called by Bob: refused before anything is resolved.
    let resp = test_module(&ctx, bob, alices).await;
    let refused = format!("{:?}", resp.errors);
    assert!(
        refused.contains("Module not found or access denied"),
        "{refused}"
    );
    assert!(!refused.contains("made-up-value"));
}
