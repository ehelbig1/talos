//! A loop body receives the secrets its node config names (2026-10-04).
//!
//! The loop resolves its body's secrets once, through
//! `build_dispatch_secrets`. That helper took ONE id and used it for two
//! lookups: the node's config (keyed by node) and the module's secrets
//! (keyed by module). The loop passed the module's id, so the config lookup
//! found nothing and a `vault://` reference in the body's config was never
//! fetched — the module then failed at the worker with a missing secret. It
//! also passed no grant, so an exact-path grant delivered nothing either.
//!
//! Driven through a real engine with a resolver that records what it is
//! asked for.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::json;
use talos_workflow_engine::WorkflowGraphBuilder;
use talos_workflow_engine_core::{
    BoxError, SecretsResolver, SystemNodeKind, WasmModuleArtifact, WorkerSharedKey,
};
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher, memory::InMemoryModuleFetcher, minimal_engine,
};
use uuid::Uuid;

#[derive(Default)]
struct RecordingResolver {
    paths: Mutex<Vec<String>>,
    module_ids: Mutex<Vec<Uuid>>,
    /// The user each module-grant read was asked for.
    module_users: Mutex<Vec<Option<Uuid>>>,
}

#[async_trait]
impl SecretsResolver for RecordingResolver {
    async fn resolve_module_secrets(
        &self,
        node_id: Uuid,
        user_id: Option<Uuid>,
    ) -> Result<talos_workflow_engine_core::SecretMap, BoxError> {
        self.module_ids.lock().unwrap().push(node_id);
        self.module_users.lock().unwrap().push(user_id);
        Ok(HashMap::new())
    }

    async fn resolve_by_paths(
        &self,
        paths: &[String],
        _user_id: Option<Uuid>,
    ) -> Result<talos_workflow_engine_core::SecretMap, BoxError> {
        self.paths.lock().unwrap().extend(paths.iter().cloned());
        Ok(paths
            .iter()
            .map(|p| (p.clone(), zeroize::Zeroizing::new("value".to_string())))
            .collect())
    }
}

#[tokio::test]
async fn a_loop_body_is_given_the_secrets_its_config_and_grant_name() {
    let body_module = Uuid::new_v4();
    let mut graph = WorkflowGraphBuilder::new()
        .add_system_node(
            "loop",
            SystemNodeKind::Loop {
                max_iterations: 2,
                condition: "true".into(),
            },
        )
        .add_module(
            "body",
            body_module,
            Some(json!({ "AUTH": "Bearer vault://svc/from_config" })),
        )
        .edge("loop", "body")
        .build()
        .expect("graph builds");
    let loop_node = graph["nodes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|n| n["id"] == "loop")
        .unwrap();
    loop_node["data"]["body_node_id"] = json!("body");

    let resolver = Arc::new(RecordingResolver::default());
    let mut engine = minimal_engine();
    let user = Uuid::new_v4();
    engine.set_user_id(user);
    engine.set_secrets_resolver(resolver.clone());
    engine.set_module_fetcher(Arc::new(InMemoryModuleFetcher::new().with_module(
        body_module,
        WasmModuleArtifact {
            module_id: body_module,
            content_hash: "stub".into(),
            wasm_bytes: vec![],
            oci_url: None,
            max_fuel: 1_000_000,
            capability_world: "http-node".into(),
            allowed_hosts: vec!["api.example.com".into()],
            allowed_methods: vec!["GET".into()],
            allowed_secrets: vec!["svc/from_grant".into()],
            requires_approval_for: vec![],
            integration_name: None,
            config: None,
        },
    )));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load");
    let dispatcher =
        Arc::new(ScriptedDispatcher::new().with_response(body_module, json!({ "ok": true })));
    engine
        .run_with_trigger_input_transport(
            dispatcher,
            Some(WorkerSharedKey::new(vec![7u8; 32])),
            json!({}),
            Uuid::new_v4(),
        )
        .await
        .expect("run");

    // The body node is an ordinary node too, so it also runs once on its
    // own after the loop and asks for its secrets then. What the LOOP adds is
    // one more ask (resolved once, reused by both iterations): two in all.
    // Before the fix the loop's ask found no config and passed no grant, so
    // each path was asked for once — by the body's own run only.
    let paths = resolver.paths.lock().unwrap().clone();
    let asks = |path: &str| paths.iter().filter(|p| p.as_str() == path).count();
    assert_eq!(
        asks("svc/from_config"),
        2,
        "the loop did not ask for its body's config reference: {paths:?}"
    );
    assert_eq!(
        asks("svc/from_grant"),
        2,
        "the loop did not ask for its body module's exact-path grant: {paths:?}"
    );
    // The module's own secrets are looked up by the MODULE's id.
    let module_ids = resolver.module_ids.lock().unwrap().clone();
    assert!(module_ids.contains(&body_module), "{module_ids:?}");
    // ...and for the user the run is for: a module id is shared by every
    // user who dispatches it, so a grant read without the user would hand
    // one user's secret to another (security review 2026-10-14, C-1).
    let module_users = resolver.module_users.lock().unwrap().clone();
    assert!(!module_users.is_empty());
    assert!(
        module_users.iter().all(|u| *u == Some(user)),
        "a module-grant read was not scoped to the run's user: {module_users:?}"
    );
}
