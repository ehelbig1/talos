//! A dry run mints no action link.
//!
//! An action link is a capability: opened and confirmed, it starts a real
//! workflow. `test_workflow(dry_run: true)` reached the `action_links` node
//! with the engine's dry-run flag set and the node minted anyway, because
//! the flag was read only where a module job is built. The node's output then
//! carried live single-use URLs composed from rehearsal data.
//!
//! These drive the real reactor with a minter that counts its calls. The
//! ordinary run is the control: the same graph, the flag off, mints exactly
//! as before.

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

/// What a minted link looks like, so a test can tell one from a fallback.
const MINTED_MARK: &str = "/action-links/";

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

/// Mints a link for every spec and counts how many it was asked for.
#[derive(Default)]
struct CountingMinter {
    calls: AtomicUsize,
    links: AtomicUsize,
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
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(specs
            .iter()
            .map(|_| {
                let n = self.links.fetch_add(1, Ordering::SeqCst);
                Ok(format!("https://talos.example{MINTED_MARK}token-{n}"))
            })
            .collect())
    }
}

/// What the compose module returns: two links wanted for a listed target
/// (one with a fallback), and one for a target the author never listed.
fn composed() -> JsonValue {
    json!({
        "subject": "Morning",
        "html": "<a href=\"talos-action:done-1\">done</a> \
                 <a href=\"talos-action:keep-1\">keep</a> \
                 <a href=\"talos-action:other\">other</a>",
        ACTION_LINKS_REQUEST: [
            { "id": "done-1", "target": "list", "label": "Done", "payload": { "op": "done" } },
            { "id": "keep-1", "target": "list", "label": "Keep", "payload": { "op": "keep" },
              "fallback": "mailto:me@example.com?subject=keep" },
            { "id": "other", "target": "nowhere", "label": "Other", "payload": {} },
        ],
    })
}

/// Run `compose → links` and return the `links` node's output and the minter.
async fn run_links(dry_run: bool) -> (JsonValue, Arc<CountingMinter>) {
    let compose = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_module("compose", compose, None)
        .add_system_node(
            "links",
            SystemNodeKind::ActionLinks {
                targets: BTreeMap::from([("list".to_string(), Uuid::new_v4())]),
                ttl_hours: Some(24),
            },
        )
        .edge("compose", "links")
        .build()
        .expect("graph builds");

    let minter = Arc::new(CountingMinter::default());
    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_dry_run(dry_run);
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new().with_module(compose, stub_artifact(compose)),
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

    let ctx = engine
        .run_with_trigger_input_transport(
            Arc::new(ScriptedDispatcher::new().with_response(compose, composed())),
            None,
            json!({}),
            Uuid::new_v4(),
        )
        .await
        .expect("run succeeds");
    let output = ctx
        .results
        .get(&links)
        .cloned()
        .expect("the links node produced a result");
    (output, minter)
}

#[tokio::test]
async fn a_dry_run_asks_the_minter_for_nothing_and_every_link_falls_back() {
    let (output, minter) = run_links(true).await;

    assert_eq!(
        minter.calls.load(Ordering::SeqCst),
        0,
        "a dry run reached the link store"
    );
    assert!(
        !output.to_string().contains(MINTED_MARK),
        "a dry run's output carries a minted link: {output}"
    );

    // The message is still whole: the request is gone and each placeholder
    // is its fallback, or a dead link.
    assert!(output.get(ACTION_LINKS_REQUEST).is_none(), "{output}");
    let html = output["html"].as_str().expect("html");
    assert!(!html.contains("talos-action:"), "{html}");
    assert!(html.contains("href=\"#\">done<"), "{html}");
    assert!(
        html.contains("href=\"mailto:me@example.com?subject=keep\">keep<"),
        "{html}"
    );
    assert!(html.contains("href=\"#\">other<"), "{html}");

    // And the report says why, per request. A request that would have been
    // refused anyway keeps its own reason.
    let report = &output[ACTION_LINKS_REPORT];
    assert_eq!(report["requested"], 3, "{report}");
    assert_eq!(report["minted"], 0, "{report}");
    assert_eq!(
        report["not_minted"],
        json!([
            { "id": "done-1", "reason": "dry_run", "fell_back": false },
            { "id": "keep-1", "reason": "dry_run", "fell_back": true },
            { "id": "other", "reason": "unknown_target", "fell_back": false },
        ]),
        "{report}"
    );
}

/// The control: the flag off, the same graph mints as it always has.
#[tokio::test]
async fn an_ordinary_run_mints_as_before() {
    let (output, minter) = run_links(false).await;

    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
    assert_eq!(minter.links.load(Ordering::SeqCst), 2);
    assert_eq!(
        output,
        json!({
            "subject": "Morning",
            "html": "<a href=\"https://talos.example/action-links/token-0\">done</a> \
                     <a href=\"https://talos.example/action-links/token-1\">keep</a> \
                     <a href=\"#\">other</a>",
            ACTION_LINKS_REPORT: {
                "available": true,
                "requested": 3,
                "minted": 2,
                "not_minted": [
                    { "id": "other", "reason": "unknown_target", "fell_back": false },
                ],
            },
        }),
        "an ordinary run's output changed"
    );
}
