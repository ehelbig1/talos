//! The `for_each_connection` node: one module node, run once per connection
//! of a service, each run given that connection's config by the engine
//! (2026-10-04).
//!
//! What must hold:
//! * every run goes through the ordinary single-node dispatch with ITS OWN
//!   connection's reference and nobody else's — in the config it receives
//!   and in the vault paths the engine asks the secrets resolver for;
//! * a connection the module's own grant does not admit is never dispatched;
//! * the listing is read for the running user and no one else;
//! * one run failing is a gap in the output, none read fails the node;
//! * each run's output goes through the same output handling as a node's —
//!   a returned memory write reaches the hook, and a `readonly` ceiling
//!   removes it.
//!
//! The write-ceiling switch is read once per process, so this binary sets it
//! on before any engine runs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Once};

use async_trait::async_trait;
use serde_json::{json, Value};
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowGraphBuilder};
use talos_workflow_engine_core::{
    BoxError, ChainDispatchRequest, ChainDispatchResult, ConnectionsReader, DispatchJob,
    DispatchResult, NodeDispatcher, SecretsResolver, StepStatus, WasmModuleArtifact,
    WorkerSharedKey, WriteCeiling,
};
use talos_workflow_engine_test_utils::{
    capture::{CaptureNodeLifecycleHook, LifecycleCall},
    memory::InMemoryModuleFetcher,
    minimal_engine,
};
use uuid::Uuid;

fn enforce_write_ceiling() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| std::env::set_var("TALOS_WRITE_CEILING_ENFORCED", "true"));
}

/// Answers by the bank the job was configured for, and keeps every job.
#[derive(Default)]
struct BankDispatcher {
    jobs: Mutex<Vec<DispatchJob>>,
    failing: Vec<&'static str>,
}

#[async_trait]
impl NodeDispatcher for BankDispatcher {
    async fn dispatch(&self, job: DispatchJob) -> Result<DispatchResult, BoxError> {
        let bank = job.input_payload["INSTITUTION"]
            .as_str()
            .unwrap_or("")
            .to_string();
        self.jobs.lock().unwrap().push(job);
        if self.failing.contains(&bank.as_str()) {
            return Err(format!("{bank}: HTTP 500").into());
        }
        Ok(DispatchResult {
            output: json!({
                "bank": bank,
                "__memory_write__": { "key": format!("bank/{bank}"), "value": { "seen": true } },
            }),
        })
    }

    async fn dispatch_chain(
        &self,
        _request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        Ok(ChainDispatchResult {
            steps: vec![],
            final_output: Value::Null,
            overall_status: StepStatus::Failed,
        })
    }
}

/// Lists the same connections for `owner` only, and records who asked.
struct Listing {
    owner: Uuid,
    connections: Value,
    asked: Mutex<Vec<(Uuid, Option<String>)>>,
}

#[async_trait]
impl ConnectionsReader for Listing {
    async fn connections(&self, user_id: Uuid, provider: Option<&str>) -> Result<Value, BoxError> {
        self.asked
            .lock()
            .unwrap()
            .push((user_id, provider.map(str::to_string)));
        let connections = if user_id == self.owner {
            self.connections.clone()
        } else {
            json!([])
        };
        Ok(json!({ "truncated": false, "connections": connections }))
    }
}

/// Records every set of vault paths the engine asks for.
#[derive(Default)]
struct RecordingResolver {
    asked: Mutex<Vec<Vec<String>>>,
}

#[async_trait]
impl SecretsResolver for RecordingResolver {
    async fn resolve_module_secrets(
        &self,
        _node_id: Uuid,
    ) -> Result<HashMap<String, String>, BoxError> {
        Ok(HashMap::new())
    }

    async fn resolve_by_paths(
        &self,
        paths: &[String],
        _user_id: Option<Uuid>,
    ) -> Result<HashMap<String, String>, BoxError> {
        if !paths.is_empty() {
            self.asked.lock().unwrap().push(paths.to_vec());
        }
        Ok(paths
            .iter()
            .map(|p| (p.clone(), format!("value-of-{p}")))
            .collect())
    }
}

fn bank(account: &str, item: &str) -> Value {
    json!({
        "service": "plaid", "account": account, "connected_at": "2026-10-03T00:00:00+00:00",
        "vault_reference": format!("vault://plaid/access_token/{item}"),
        "stored": true, "module_readable": true,
    })
}

fn artifact(id: Uuid, allowed_secrets: &[&str]) -> WasmModuleArtifact {
    WasmModuleArtifact {
        module_id: id,
        content_hash: "stub".into(),
        wasm_bytes: vec![],
        oci_url: None,
        max_fuel: 1_000_000,
        capability_world: "http-node".into(),
        allowed_hosts: vec!["bank.example.com".into()],
        allowed_methods: vec!["POST".into()],
        allowed_secrets: allowed_secrets.iter().map(|s| (*s).to_string()).collect(),
        requires_approval_for: vec![],
        integration_name: None,
        config: None,
    }
}

/// One module node, `banks`, fanned out over `plaid` connections, feeding a
/// plain `summary` module node.
fn graph(reader_module: Uuid, summary_module: Uuid) -> String {
    let g = WorkflowGraphBuilder::new()
        .add_raw_node(json!({
            "id": "banks",
            "type": reader_module.to_string(),
            "kind": "for_each_connection",
            "data": {
                // The node's own value for a bound key is replaced per run.
                "ACCESS_TOKEN": "vault://plaid/access_token/hand-written",
                "PLAID_ENV": "production",
                "for_each_connection": {
                    "provider": "plaid",
                    "bind": { "ACCESS_TOKEN": "vault_reference", "INSTITUTION": "account" },
                },
            },
        }))
        .add_module("summary", summary_module, None)
        .edge("banks", "summary")
        .build()
        .expect("graph builds");
    serde_json::to_string(&g).unwrap()
}

struct World {
    engine: ParallelWorkflowEngine,
    dispatcher: Arc<BankDispatcher>,
    listing: Arc<Listing>,
    resolver: Arc<RecordingResolver>,
    hook: Arc<CaptureNodeLifecycleHook>,
    reader_module: Uuid,
    summary_module: Uuid,
}

async fn world(
    running_as_owner: bool,
    connections: Value,
    grant: &[&str],
    failing: Vec<&'static str>,
) -> World {
    enforce_write_ceiling();
    let owner = Uuid::new_v4();
    let (reader_module, summary_module) = (Uuid::new_v4(), Uuid::new_v4());
    let listing = Arc::new(Listing {
        owner,
        connections,
        asked: Mutex::new(vec![]),
    });
    let resolver = Arc::new(RecordingResolver::default());
    let hook = Arc::new(CaptureNodeLifecycleHook::new());
    let mut engine = minimal_engine();
    engine.set_user_id(if running_as_owner {
        owner
    } else {
        Uuid::new_v4()
    });
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new()
            .with_module(reader_module, artifact(reader_module, grant))
            .with_module(summary_module, artifact(summary_module, &[])),
    ));
    engine.set_connections_reader(listing.clone());
    engine.set_secrets_resolver(resolver.clone());
    engine.set_node_hook(hook.clone());
    engine
        .load_graph_from_json(&graph(reader_module, summary_module))
        .await
        .expect("load");
    World {
        engine,
        dispatcher: Arc::new(BankDispatcher {
            jobs: Mutex::new(vec![]),
            failing,
        }),
        listing,
        resolver,
        hook,
        reader_module,
        summary_module,
    }
}

impl World {
    async fn run(&mut self) -> Result<Value, String> {
        let banks = self.node("banks");
        self.engine
            .run_with_trigger_input_transport(
                self.dispatcher.clone(),
                Some(WorkerSharedKey::new(vec![7u8; 32])),
                json!({}),
                Uuid::new_v4(),
            )
            .await
            .map(|ctx| {
                ctx.results
                    .get(&banks)
                    .cloned()
                    .expect("banks has a result")
            })
            .map_err(|e| e.to_string())
    }
    fn node(&self, label: &str) -> Uuid {
        *self
            .engine
            .node_labels()
            .iter()
            .find(|(_, l)| l.as_str() == label)
            .expect("node")
            .0
    }
    fn reader_jobs(&self) -> Vec<DispatchJob> {
        let jobs = self.dispatcher.jobs.lock().unwrap();
        jobs.iter()
            .filter(|j| j.module_id == self.reader_module)
            .cloned()
            .collect()
    }
    fn summary_jobs(&self) -> usize {
        let jobs = self.dispatcher.jobs.lock().unwrap();
        jobs.iter()
            .filter(|j| j.module_id == self.summary_module)
            .count()
    }
}

const GRANT: &[&str] = &["plaid/client_id", "plaid/secret", "plaid/access_token/*"];

#[tokio::test]
async fn each_run_gets_its_own_connection_and_nothing_of_the_others() {
    let mut w = world(
        true,
        json!([
            bank("First Bank", "item-a"),
            bank("Second Bank", "item-b"),
            bank("Third Bank", "item-c")
        ]),
        GRANT,
        vec![],
    )
    .await;
    let out = w.run().await.expect("run");
    assert_eq!(out["count"], json!(3), "{out}");
    assert_eq!(out["connections"]["read"], json!(3));
    let banks: Vec<&str> = out["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["bank"].as_str().unwrap())
        .collect();
    assert_eq!(
        banks,
        ["First Bank", "Second Bank", "Third Bank"],
        "listing order"
    );

    let mut jobs = w.reader_jobs();
    assert_eq!(jobs.len(), 3);
    jobs.sort_by_key(|j| j.input_payload["INSTITUTION"].as_str().unwrap().to_string());
    for (job, item) in jobs.iter().zip(["item-a", "item-b", "item-c"]) {
        let own = format!("vault://plaid/access_token/{item}");
        assert_eq!(job.input_payload["ACCESS_TOKEN"], json!(own));
        assert_eq!(job.input_payload["config"]["ACCESS_TOKEN"], json!(own));
        // The node's other config is every run's; the fan-out settings are no
        // module's business; the hand-written reference is gone.
        assert_eq!(job.input_payload["PLAID_ENV"], json!("production"));
        let rendered = job.input_payload.to_string();
        assert!(!rendered.contains("for_each_connection"), "{rendered}");
        assert!(!rendered.contains("hand-written"), "{rendered}");
        for other in ["item-a", "item-b", "item-c"]
            .iter()
            .filter(|o| **o != item)
        {
            assert!(
                !rendered.contains(other),
                "{item}'s run carries {other}: {rendered}"
            );
        }
        // The grant the worker enforces is the module's, unchanged.
        assert_eq!(job.allowed_secrets, GRANT);
    }

    // What the engine asked the vault for, run by run: that run's path, and
    // the two exact paths the module's grant names. Never another run's.
    let asked = w.resolver.asked.lock().unwrap().clone();
    let token_asks: Vec<Vec<&String>> = asked
        .iter()
        .map(|paths| {
            paths
                .iter()
                // The grant's `/*` entry is asked for as written and names
                // no secret; a run's own path is the only token path.
                .filter(|p| p.starts_with("plaid/access_token/") && !p.ends_with("/*"))
                .collect::<Vec<_>>()
        })
        .filter(|tokens| !tokens.is_empty())
        .collect();
    assert_eq!(token_asks.len(), 3, "{asked:?}");
    for tokens in &token_asks {
        assert_eq!(
            tokens.len(),
            1,
            "one run asked for more than one token: {asked:?}"
        );
    }
    assert!(
        !asked.iter().flatten().any(|p| p.contains("hand-written")),
        "{asked:?}"
    );

    // The listing was read once, for the running user, for this service.
    let who = w.listing.asked.lock().unwrap().clone();
    assert_eq!(who.len(), 1);
    assert_eq!(who[0].1.as_deref(), Some("plaid"));
    // And the next node ran once, on the gathered output.
    assert_eq!(w.summary_jobs(), 1);
}

#[tokio::test]
async fn a_connection_the_modules_grant_does_not_admit_is_never_dispatched() {
    // The module is granted ONE bank's token by exact path.
    let mut w = world(
        true,
        json!([bank("First Bank", "item-a"), bank("Second Bank", "item-b")]),
        &["plaid/access_token/item-a"],
        vec![],
    )
    .await;
    let out = w.run().await.expect("run");
    assert_eq!(out["connections"]["read"], json!(1), "{out}");
    assert_eq!(
        out["connections"]["skipped"],
        json!([{ "account": "Second Bank", "reason": "not_granted" }])
    );
    let jobs = w.reader_jobs();
    assert_eq!(jobs.len(), 1);
    assert!(!jobs[0].input_payload.to_string().contains("item-b"));
    let asked = w.resolver.asked.lock().unwrap().clone();
    assert!(
        !asked.iter().flatten().any(|p| p.contains("item-b")),
        "{asked:?}"
    );
}

#[tokio::test]
async fn nothing_is_granted_so_nothing_runs_and_the_node_fails() {
    let mut w = world(true, json!([bank("First Bank", "item-a")]), &[], vec![]).await;
    let err = w.run().await.expect_err("no connection could be read");
    assert!(
        err.contains("none of the 1 plaid connection(s) could be read"),
        "{err}"
    );
    assert!(w.reader_jobs().is_empty());
    assert_eq!(w.summary_jobs(), 0);
}

#[tokio::test]
async fn another_users_run_reads_none_of_the_owners_connections() {
    let mut w = world(false, json!([bank("First Bank", "item-a")]), GRANT, vec![]).await;
    let out = w.run().await.expect("an empty read is not a failure");
    assert_eq!(out["count"], json!(0), "{out}");
    assert_eq!(out["connections"]["listed"], json!(0));
    assert!(w.reader_jobs().is_empty());
    assert!(w
        .resolver
        .asked
        .lock()
        .unwrap()
        .iter()
        .flatten()
        .all(|p| !p.contains("item-a")));
}

#[tokio::test]
async fn one_bank_failing_is_a_gap_and_every_bank_failing_fails_the_node() {
    let mut w = world(
        true,
        json!([bank("First Bank", "item-a"), bank("Second Bank", "item-b")]),
        GRANT,
        vec!["Second Bank"],
    )
    .await;
    let out = w.run().await.expect("a partial read completes");
    assert_eq!(out["connections"]["read"], json!(1), "{out}");
    assert_eq!(out["items"][1]["__error"], json!(true));
    assert_eq!(out["items"][1]["account"], json!("Second Bank"));
    assert_eq!(
        out["connections"]["failed"][0]["account"],
        json!("Second Bank")
    );
    assert_eq!(
        w.summary_jobs(),
        1,
        "the summary still runs, told what is missing"
    );

    let mut all = world(
        true,
        json!([bank("First Bank", "item-a"), bank("Second Bank", "item-b")]),
        GRANT,
        vec!["First Bank", "Second Bank"],
    )
    .await;
    let err = all.run().await.expect_err("nothing was read");
    assert!(
        err.contains("none of the 2 plaid connection(s) could be read"),
        "{err}"
    );
    assert_eq!(all.summary_jobs(), 0);
}

#[tokio::test]
async fn each_runs_output_is_handled_as_a_nodes_output_is() {
    // Permitted: every run's memory write reaches the completion hook.
    let mut w = world(
        true,
        json!([bank("First Bank", "item-a"), bank("Second Bank", "item-b")]),
        GRANT,
        vec![],
    )
    .await;
    w.run().await.expect("run");
    let banks = w.node("banks");
    let mut keys: Vec<String> = w
        .hook
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            LifecycleCall::Completed {
                node_id, output, ..
            } if node_id == banks => output["__memory_write__"]["key"]
                .as_str()
                .map(str::to_string),
            _ => None,
        })
        .collect();
    keys.sort();
    assert_eq!(keys, ["bank/First Bank", "bank/Second Bank"]);

    // A `readonly` actor: each run's envelope is removed before anything
    // can persist it, and each refusal is reported.
    let mut ro = world(
        true,
        json!([bank("First Bank", "item-a"), bank("Second Bank", "item-b")]),
        GRANT,
        vec![],
    )
    .await;
    ro.engine.set_max_write_ceiling(WriteCeiling::ReadOnly);
    let out = ro.run().await.expect("run");
    let banks_node = ro.node("banks");
    for item in out["items"].as_array().unwrap() {
        assert!(item.get("__memory_write__").is_none(), "{item}");
        assert!(item.get("__memory_write_refused__").is_some(), "{item}");
    }
    let refused = ro
        .hook
        .calls()
        .into_iter()
        .filter(|c| {
            matches!(c, LifecycleCall::MemoryWriteRefused { node_id, .. } if *node_id == Some(banks_node))
        })
        .count();
    assert_eq!(refused, 2);
    let persisted = ro.hook.calls().into_iter().any(|c| match c {
        LifecycleCall::Completed { output, .. } => output.get("__memory_write__").is_some(),
        _ => false,
    });
    assert!(!persisted, "a refused envelope reached the completion hook");
}

#[tokio::test]
async fn bound_keys_are_config_keys_never_engine_keys() {
    // A hand-written graph binds an engine-authored key. It is dropped at
    // parse, so no run can have its actor context or trigger input replaced
    // by a connection's label.
    let (reader_module, summary_module) = (Uuid::new_v4(), Uuid::new_v4());
    let mut g: Value = serde_json::from_str(&graph(reader_module, summary_module)).unwrap();
    g["nodes"][0]["data"]["for_each_connection"]["bind"] = json!({
        "INSTITUTION": "account", "__actor_context__": "account", "__trigger_input__": "account",
    });
    let parsed = talos_workflow_engine_core::connections_reader::parse_for_each_connection(
        &g["nodes"][0]["data"],
    )
    .expect("usable");
    assert_eq!(parsed.1.keys().collect::<Vec<_>>(), ["INSTITUTION"]);
}
