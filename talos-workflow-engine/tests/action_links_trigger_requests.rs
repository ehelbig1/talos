//! A link request never arrives in a ROOT trigger (security review
//! 2026-10-14, G-12).
//!
//! An `action_links` node plans its links from its gathered input. Placed at
//! the graph root (`trigger → links → send`), that input IS the trigger
//! payload, so a webhook caller wrote the label and payload of a real link
//! the owner was then mailed. The engine now drops `__action_links__` from a
//! root trigger at the seed (`reserved_keys::strip_root_trigger_keys`): a
//! link request reaches the node only as a module's output in the same run.
//!
//! The control is the same request from a compose module, which mints.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value as JsonValue};
use talos_workflow_engine::WorkflowGraphBuilder;
use talos_workflow_engine_core::{
    action_links::{ActionLinkMinter, ActionLinkSpec, ACTION_LINKS_REPORT, ACTION_LINKS_REQUEST},
    BoxError, SystemNodeKind, WasmModuleArtifact,
};
use talos_workflow_engine_test_utils::{
    dispatch::ScriptedDispatcher, memory::InMemoryModuleFetcher, minimal_engine,
};
use uuid::Uuid;

fn stub_artifact(id: Uuid) -> WasmModuleArtifact {
    WasmModuleArtifact {
        module_id: id,
        content_hash: "stub".into(),
        wasm_bytes: vec![],
        oci_url: None,
        max_fuel: 1_000_000,
        capability_world: "stub".into(),
        allowed_hosts: vec![],
        allowed_methods: vec![],
        allowed_secrets: vec![],
        requires_approval_for: vec![],
        integration_name: None,
        config: None,
    }
}

#[derive(Default)]
struct CountingMinter {
    specs: AtomicUsize,
}

#[async_trait]
impl ActionLinkMinter for CountingMinter {
    async fn mint(
        &self,
        _user_id: Uuid,
        _source_execution_id: Uuid,
        _source_node: &str,
        _ttl_hours: Option<u32>,
        specs: &[ActionLinkSpec],
    ) -> Result<Vec<Result<String, String>>, BoxError> {
        self.specs.fetch_add(specs.len(), Ordering::SeqCst);
        Ok(specs
            .iter()
            .enumerate()
            .map(|(n, _)| Ok(format!("https://talos.example/action-links/token-{n}")))
            .collect())
    }
}

/// What a webhook caller would send: a link request to a listed target, with
/// a label and payload of the caller's choosing.
fn forged_request() -> JsonValue {
    json!([{ "id": "approve", "target": "list", "label": "Approve payroll",
             "payload": { "op": "drop", "item": "*" } }])
}

struct Run {
    links_output: JsonValue,
    minted: usize,
}

/// `links` at the graph root (fed by the trigger), then `send`; or, with
/// `compose`, the same request as a module's output.
async fn run(trigger: JsonValue, with_compose: bool) -> Run {
    let send = Uuid::new_v4();
    let compose = Uuid::new_v4();
    let links_kind = SystemNodeKind::ActionLinks {
        targets: BTreeMap::from([("list".to_string(), Uuid::new_v4())]),
        ttl_hours: Some(24),
    };
    let mut builder = WorkflowGraphBuilder::new();
    if with_compose {
        builder = builder
            .add_module("compose", compose, None)
            .add_system_node("links", links_kind)
            .edge("compose", "links");
    } else {
        builder = builder.add_system_node("links", links_kind);
    }
    let graph = builder
        .add_module("send", send, None)
        .edge("links", "send")
        .build()
        .expect("graph builds");

    let minter = Arc::new(CountingMinter::default());
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new()
            .with_module(send, stub_artifact(send))
            .with_module(compose, stub_artifact(compose)),
    ));
    engine.set_action_link_minter(minter.clone());
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load graph");
    let links = engine
        .node_labels()
        .iter()
        .find(|(_, label)| label.as_str() == "links")
        .map(|(id, _)| *id)
        .expect("the links node is in the graph");

    let dispatcher = ScriptedDispatcher::new()
        .with_response(send, json!({ "sent": true }))
        .with_response(
            compose,
            json!({ "html": "<a href=\"talos-action:approve\">ok</a>",
                    ACTION_LINKS_REQUEST: forged_request() }),
        );
    let ctx = engine
        .run_with_trigger_input_transport(Arc::new(dispatcher), None, trigger, Uuid::new_v4())
        .await
        .expect("run succeeds");
    Run {
        links_output: ctx.results.get(&links).cloned().expect("links ran"),
        minted: minter.specs.load(Ordering::SeqCst),
    }
}

#[tokio::test]
async fn a_root_trigger_carrying_a_link_request_mints_nothing() {
    let out = run(
        json!({
            "html": "<a href=\"talos-action:approve\">ok</a>",
            ACTION_LINKS_REQUEST: forged_request(),
        }),
        false,
    )
    .await;
    assert_eq!(
        out.minted, 0,
        "a trigger payload asked for a link and got one"
    );
    assert!(
        !out.links_output.to_string().contains("/action-links/"),
        "{}",
        out.links_output
    );
    assert!(out.links_output.get(ACTION_LINKS_REQUEST).is_none());
    // Nothing was requested, as far as the node could see.
    let report = &out.links_output[ACTION_LINKS_REPORT];
    assert_eq!(report["requested"], 0, "{report}");
    // The rest of the trigger still reaches the root.
    assert!(out.links_output["html"].is_string(), "{}", out.links_output);
}

/// The control: the same request as a compose module's output still mints.
#[tokio::test]
async fn the_same_request_from_a_module_in_the_run_mints() {
    let out = run(json!({}), true).await;
    assert_eq!(out.minted, 1, "{}", out.links_output);
}
