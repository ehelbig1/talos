use futures::stream::{FuturesUnordered, StreamExt};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use serde_json::{Map, Value as JsonValue};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;

// Alias to silence Clippy's `type_complexity` warning and improve readability.
// Represents a boxed future that resolves to a node index and its execution result.
// Generic alias allowing the future to live for any lifetime `'a`.
type ExecFuture<'a> =
    Pin<Box<dyn Future<Output = (NodeIndex, Result<JsonValue, String>)> + Send + 'a>>;
use std::sync::Arc;
use uuid::Uuid;

use crate::registry::ModuleRegistry;
use crate::secrets::SecretsManager;
use crate::workflow_engine::{EdgeLogic, WorkflowContext};

use job_protocol::{
    JobRequest, JobResult, JobStatus, PipelineJobRequest, PipelineJobResult, PipelineStep,
};

// NATS edge routing helpers
fn get_single_job_topic(user_id: Option<Uuid>) -> String {
    if std::env::var("ENABLE_EDGE_ROUTING").unwrap_or_else(|_| "false".to_string()) == "true" {
        if let Some(uid) = user_id {
            return format!("talos.jobs.{}", uid);
        }
    }
    "talos.jobs".to_string()
}

fn get_pipeline_job_topic(user_id: Option<Uuid>) -> String {
    if std::env::var("ENABLE_EDGE_ROUTING").unwrap_or_else(|_| "false".to_string()) == "true" {
        if let Some(uid) = user_id {
            return format!("talos.pipeline.jobs.{}", uid);
        }
    }
    "talos.pipeline.jobs".to_string()
}

/// Create a temporary sandboxed directory for a workflow execution.
/// Returns an Arc-wrapped cap-std Dir for secure file access.
/// The directory will be created under /tmp/talos-sandboxes/{execution_id}
/// and should be cleaned up after workflow execution completes.
fn create_execution_sandbox(execution_id: Uuid) -> Result<Arc<cap_std::fs::Dir>, String> {
    let sandbox_base = std::path::PathBuf::from("/tmp/talos-sandboxes");

    // Create base directory if it doesn't exist
    std::fs::create_dir_all(&sandbox_base)
        .map_err(|e| format!("Failed to create sandbox base directory: {}", e))?;

    // Create execution-specific sandbox directory
    let sandbox_path = sandbox_base.join(execution_id.to_string());
    std::fs::create_dir_all(&sandbox_path)
        .map_err(|e| format!("Failed to create execution sandbox directory: {}", e))?;

    // Open directory with cap-std for capability-based security
    cap_std::fs::Dir::open_ambient_dir(&sandbox_path, cap_std::ambient_authority())
        .map(Arc::new)
        .map_err(|e| format!("Failed to open sandbox directory with cap-std: {}", e))
}

/// RAII guard that removes the execution sandbox directory when dropped.
/// This ensures cleanup happens even if the execution task panics.
struct SandboxGuard {
    execution_id: Uuid,
}

impl Drop for SandboxGuard {
    fn drop(&mut self) {
        let sandbox_path =
            std::path::PathBuf::from("/tmp/talos-sandboxes").join(self.execution_id.to_string());
        if let Err(e) = std::fs::remove_dir_all(&sandbox_path) {
            tracing::warn!(
                "Failed to cleanup execution sandbox {}: {}",
                self.execution_id,
                e
            );
        } else {
            tracing::debug!("Cleaned up execution sandbox: {}", self.execution_id);
        }
    }
}

// ============================================================================
// LINEAR CHAIN DETECTION (Superpower 2)
// ============================================================================

/// Detect all maximal linear chains in `graph`.
///
/// A *linear chain* is a maximal sequence of nodes `[v₀, v₁, …, vₙ]` where:
/// - Every interior node has in-degree = 1 and out-degree = 1.
/// - The source `v₀` can have any in-degree, but out-degree = 1.
/// - The sink `vₙ` can have any out-degree, but in-degree = 1.
///
/// Chains of length ≥ 2 benefit from pipeline dispatch: the worker executes all
/// steps in a single NATS round-trip without intermediate serialisation.
///
/// Returns a `Vec` of chains, each chain being a `Vec<NodeIndex>` in topological
/// order (source → sink).
pub fn detect_linear_chains(graph: &DiGraph<Uuid, EdgeLogic>) -> Vec<Vec<NodeIndex>> {
    // Find all potential chain *starts*: nodes with out-degree = 1 whose
    // predecessor either has out-degree ≠ 1 or is absent.
    let mut chain_starts: Vec<NodeIndex> = Vec::new();

    for idx in graph.node_indices() {
        let out_deg = graph.neighbors_directed(idx, Direction::Outgoing).count();
        if out_deg != 1 {
            continue; // Can't be an interior node or start of a 2+ chain.
        }
        let in_deg = graph.neighbors_directed(idx, Direction::Incoming).count();
        // A chain starts if:
        // - it has no predecessor (source), OR
        // - its predecessor has out-degree ≠ 1 (branches out, so chain starts here).
        if in_deg == 0 {
            chain_starts.push(idx);
        } else {
            let parent_out_deg = graph
                .neighbors_directed(idx, Direction::Incoming)
                .next()
                .map(|p| graph.neighbors_directed(p, Direction::Outgoing).count())
                .unwrap_or(0);
            if parent_out_deg != 1 {
                chain_starts.push(idx);
            }
        }
    }

    // Expand each start into its maximal chain.
    let mut visited: HashSet<NodeIndex> = HashSet::new();
    let mut chains: Vec<Vec<NodeIndex>> = Vec::new();

    for start in chain_starts {
        if visited.contains(&start) {
            continue;
        }

        let mut chain = vec![start];
        let mut current = start;

        loop {
            visited.insert(current);
            // Move to the single successor, if it qualifies as an interior node.
            let next = graph
                .neighbors_directed(current, Direction::Outgoing)
                .next();
            let Some(next_idx) = next else { break };

            let next_in_deg = graph
                .neighbors_directed(next_idx, Direction::Incoming)
                .count();
            let next_out_deg = graph
                .neighbors_directed(next_idx, Direction::Outgoing)
                .count();

            // The next node can continue the chain only if it has exactly one
            // incoming edge (from `current`).  Out-degree can be anything for the
            // sink, but if it branches we stop — those children start new chains.
            if next_in_deg != 1 {
                break; // Fan-in: `next_idx` belongs to a different sub-graph.
            }
            chain.push(next_idx);
            current = next_idx;

            if next_out_deg != 1 {
                break; // Sink or fan-out — chain ends here.
            }
        }

        if chain.len() >= 2 {
            chains.push(chain);
        }
    }

    chains
}

// Many helper methods are currently unused in the codebase, but are part of the public API.
// Suppress dead‑code warnings to keep the CI passing.
#[allow(dead_code)]
/// Parallel execution engine based on Kahn's algorithm.
pub struct ParallelWorkflowEngine {
    graph: DiGraph<Uuid, EdgeLogic>,
    node_map: HashMap<Uuid, NodeIndex>,
    registry: Option<Arc<ModuleRegistry>>,
    secrets_manager: Option<Arc<SecretsManager>>,
    /// Owner of the workflow execution — required to enforce module ownership
    /// when fetching WASM bytes/config from the registry. `None` means the
    /// engine is running in a test/fallback context without a real registry.
    user_id: Option<Uuid>,
}

impl Default for ParallelWorkflowEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ParallelWorkflowEngine {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
            registry: None,
            secrets_manager: None,
            user_id: None,
        }
    }

    pub fn with_registry(registry: Arc<ModuleRegistry>) -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
            registry: Some(registry),
            secrets_manager: None,
            user_id: None,
        }
    }

    pub fn with_services(
        registry: Arc<ModuleRegistry>,
        secrets_manager: Arc<SecretsManager>,
        user_id: Uuid,
    ) -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
            registry: Some(registry),
            secrets_manager: Some(secrets_manager),
            user_id: Some(user_id),
        }
    }

    pub fn add_node(&mut self, id: Uuid) {
        let idx = self.graph.add_node(id);
        self.node_map.insert(id, idx);
    }

    #[allow(dead_code)]
    pub fn add_edge(&mut self, from: Uuid, to: Uuid, logic: EdgeLogic) {
        let from_idx = self.node_map[&from];
        let to_idx = self.node_map[&to];
        self.graph.add_edge(from_idx, to_idx, logic);
    }

    /// Gather inputs for a node based on completed parent results.
    fn gather_inputs(&self, node_idx: NodeIndex, results: &HashMap<Uuid, JsonValue>) -> JsonValue {
        let mut map = Map::new();
        for parent_idx in self.graph.neighbors_directed(node_idx, Direction::Incoming) {
            let parent_id = self.graph[parent_idx];
            if let Some(parent_output) = results.get(&parent_id) {
                // Simple mapping: parent output is placed under a generic key.
                map.insert(parent_id.to_string(), parent_output.clone());
            }
        }
        JsonValue::Object(map)
    }

    /// Load the Wasm bytecode for a given node ID (enforces user ownership).
    async fn fetch_module(&self, node_id: Uuid) -> Result<crate::registry::WasmModule, String> {
        let Some(registry) = &self.registry else {
            // Fallback MVP
            let bytes = std::fs::read("example-node/target/wasm32-wasi/release/my_first_node.wasm")
                .map_err(|e| format!("failed to read wasm module: {}", e))?;

            return Ok(crate::registry::WasmModule {
                name: "example".to_string(),
                content_hash: "example".to_string(),
                wasm_bytes: bytes,
                source_code: None,
                template_id: None,
                config: None,
                size_bytes: 0,
                max_fuel: 1_000_000,
                max_memory_mb: 128,
                allowed_hosts: vec![],
                allowed_methods: vec![],
                user_id: None,
                capability_world: worker::CapabilityWorld::Unknown,
                imported_interfaces: vec![],
                dependencies: None,
                oci_url: None,
            });
        };
        let user_id = self.user_id.ok_or_else(|| {
            "Module execution requires user context (user_id not set)".to_string()
        })?;
        registry
            .get_module(node_id, user_id)
            .await
            .map_err(|e| format!("failed to get module: {}", e))
    }

    /// Execute the graph in parallel using the provided TalosRuntime.
    ///
    /// Linear chains (maximal sequences of nodes with in-degree=1 / out-degree=1)
    /// are dispatched as a single `execute_pipeline()` call, eliminating per-node
    /// NATS round-trips and intermediate result serialisation.
    pub async fn run(
        &self,
        nats_client: Arc<async_nats::Client>,
        worker_shared_key: Option<Arc<Vec<u8>>>,
        execution_id: Uuid,
    ) -> Result<WorkflowContext, String> {
        // Create temporary sandboxed directory for this execution.
        // _sandbox_guard ensures the directory is removed even if this task panics.
        let (execution_sandbox, _sandbox_guard) = match create_execution_sandbox(execution_id) {
            Ok(sandbox) => {
                tracing::debug!("Created execution sandbox: {}", execution_id);
                (Some(sandbox), Some(SandboxGuard { execution_id }))
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to create execution sandbox: {}. File I/O will be unavailable.",
                    e
                );
                (None, None)
            }
        };

        // Verify DAG – simple cycle check.
        if petgraph::algo::is_cyclic_directed(&self.graph) {
            return Err("Workflow contains a cycle".into());
        }

        // Detect linear chains for pipeline optimisation.
        let chains = detect_linear_chains(&self.graph);

        // Build a lookup: NodeIndex → chain index (for O(1) chain membership check).
        let mut node_to_chain: HashMap<NodeIndex, usize> = HashMap::new();
        // Track which node is the *head* of each chain (for ready-queue dedup).
        let mut chain_heads: HashSet<NodeIndex> = HashSet::new();
        for (chain_idx, chain) in chains.iter().enumerate() {
            chain_heads.insert(chain[0]);
            for &n in chain {
                node_to_chain.insert(n, chain_idx);
            }
        }

        // In-degree counter.
        let mut pending: HashMap<NodeIndex, usize> = HashMap::new();
        let mut ready: VecDeque<NodeIndex> = VecDeque::new();
        for idx in self.graph.node_indices() {
            let deps = self
                .graph
                .neighbors_directed(idx, Direction::Incoming)
                .count();
            pending.insert(idx, deps);
            if deps == 0 {
                ready.push_back(idx);
            }
        }

        let mut results: HashMap<Uuid, JsonValue> = HashMap::new();
        // Use trait objects so we can push both pipeline-chain futures and
        // single-node futures (which are different concrete async block types).
        let mut executing: FuturesUnordered<ExecFuture<'_>> = FuturesUnordered::new();

        // Main reactor loop.
        while !ready.is_empty() || !executing.is_empty() {
            // Spawn ready nodes / chains.
            while let Some(node_idx) = ready.pop_front() {
                // ── Pipeline dispatch (chain head) ───────────────────────────
                if let Some(&chain_idx) = node_to_chain.get(&node_idx) {
                    // Only dispatch when we're at the chain head.
                    if chain_heads.contains(&node_idx) {
                        let chain = &chains[chain_idx];
                        let chain_node_ids: Vec<Uuid> =
                            chain.iter().map(|&n| self.graph[n]).collect();

                        // Gather input for the chain's first node.
                        let chain_input = self.gather_inputs(node_idx, &results);
                        let nats_client_clone = nats_client.clone();
                        let user_id_clone = self.user_id;
                        let registry = self.registry.clone();
                        let secrets_manager = self.secrets_manager.clone();
                        let chain_clone = chain.clone();
                        let chain_user_id = self.user_id;
                        let worker_shared_key_clone = worker_shared_key.clone();

                        let fut = async move {
                            // Resolve user_id early — required for all registry calls.
                            let uid_for_chain: Option<Uuid> = if registry.is_some() {
                                match chain_user_id {
                                    Some(u) => Some(u),
                                    None => {
                                        return (
                                            chain_clone[chain_clone.len() - 1],
                                            Err("Module execution requires user context (user_id not set)".to_string()),
                                        )
                                    }
                                }
                            } else {
                                None
                            };

                            // Build PipelineSteps for every node in the chain.
                            let mut step_specs: Vec<PipelineStep> =
                                Vec::with_capacity(chain_clone.len());

                            for (i, &_step_idx) in chain_clone.iter().enumerate() {
                                let step_node_id = chain_node_ids[i];

                                let uid = match uid_for_chain {
                                    Some(u) => u,
                                    None => {
                                        return (
                                            chain_clone[chain_clone.len() - 1],
                                            Err(format!(
                                                "Missing user ID for module {} in chain",
                                                step_node_id
                                            )),
                                        )
                                    }
                                };

                                let (exec_info, module_config) = match registry.as_ref() {
                                    Some(reg) => {
                                        match reg.get_execution_info(step_node_id, uid).await {
                                            Ok(info) => {
                                                let config = info
                                                    .config
                                                    .clone()
                                                    .unwrap_or_else(|| serde_json::json!({}));
                                                (Some(info), config)
                                            }
                                            Err(e) => {
                                                return (
                                                    chain_clone[chain_clone.len() - 1],
                                                    Err(format!("Failed to prepare module: {}", e)),
                                                )
                                            }
                                        }
                                    }
                                    None => (None, serde_json::json!({})),
                                };

                                step_specs.push(PipelineStep {
                                    module_id: step_node_id,
                                    module_uri: exec_info
                                        .as_ref()
                                        .map(|info| info.module_uri.clone())
                                        .unwrap_or_else(|| format!("redis:wasm:{}", step_node_id)),
                                    config: module_config,
                                    allowed_hosts: exec_info
                                        .as_ref()
                                        .map(|info| info.allowed_hosts.clone())
                                        .unwrap_or_default(),
                                    allowed_methods: exec_info
                                        .as_ref()
                                        .map(|info| info.allowed_methods.clone())
                                        .unwrap_or_default(),
                                    timeout_ms: 30000,
                                    wasm_bytes: None,
                                    encrypted_secrets: {
                                        let mut es = Default::default();
                                        if let (Some(sm), Some(key)) =
                                            (secrets_manager.as_ref(), &worker_shared_key_clone)
                                        {
                                            if let Ok(secrets_map) =
                                                sm.get_module_secrets(step_node_id).await
                                            {
                                                if let Ok(encrypted) =
                                                    job_protocol::EncryptedSecrets::encrypt(
                                                        &secrets_map,
                                                        key,
                                                    )
                                                {
                                                    es = encrypted;
                                                }
                                            }
                                        }
                                        es
                                    },
                                    max_fuel: 1_000_000,
                                    max_memory_mb: 128,
                                });
                            }

                            // For the first step, inject the gathered inputs as
                            // initial input (wrap it the same way as single-node does).
                            if let Some(first) = step_specs.first_mut() {
                                first.config = serde_json::json!({
                                    "pipeline_input": chain_input,
                                    "config": first.config,
                                });
                            }

                            let mut req = PipelineJobRequest {
                                job_id: Uuid::new_v4(),
                                workflow_execution_id: execution_id,
                                steps: step_specs,
                                total_timeout_ms: 300_000,
                                share_sandbox: true,
                                signature: vec![],
                                job_nonce: String::new(),
                            };

                            if let Some(key) = &worker_shared_key_clone {
                                if let Err(e) = req.sign(key) {
                                    return (
                                        chain_clone[chain_clone.len() - 1],
                                        Err(format!("Failed to sign pipeline request: {}", e)),
                                    );
                                }
                            }
                            let payload_res = serde_json::to_vec(&req).map_err(|e| {
                                format!("Failed to serialize pipeline request: {}", e)
                            });
                            let payload = match payload_res {
                                Ok(p) => p,
                                Err(e) => return (chain_clone[chain_clone.len() - 1], Err(e)),
                            };

                            let mut step_exec_ids = Vec::new();
                            if let Some(ref reg) = registry {
                                for (i, &step_node_id) in chain_node_ids.iter().enumerate() {
                                    let step_exec_id = Uuid::new_v4();
                                    step_exec_ids.push(step_exec_id);
                                    let input_for_db = if i == 0 {
                                        serde_json::json!({ "input": chain_input })
                                    } else {
                                        serde_json::json!(null)
                                    };
                                    if let Err(db_err) = sqlx::query(
                                        "INSERT INTO module_executions (id, module_id, user_id, status, input_data, workflow_execution_id, trigger_type, started_at)
                                         VALUES ($1, $2, $3, 'running', $4, $5, 'webhook', NOW())
                                         ON CONFLICT DO NOTHING"
                                    )
                                    .bind(step_exec_id)
                                    .bind(step_node_id)
                                    .bind(uid_for_chain.unwrap_or_else(Uuid::new_v4))
                                    .bind(&input_for_db)
                                    .bind(execution_id)
                                    .execute(&reg.db_pool)
                                    .await {
    tracing::error!("Database operation failed in engine: {}", db_err);
}
                                }
                            }

                            let topic = get_pipeline_job_topic(user_id_clone);

                            let response_res = tokio::time::timeout(
                                std::time::Duration::from_secs(86400 * 7), // 7 days max for governance nodes
                                nats_client_clone.request(topic, payload.into()),
                            )
                            .await
                            .map_err(|_| "Pipeline execution timed out via NATS".to_string());

                            match response_res {
                                Ok(Ok(msg)) => {
                                    match serde_json::from_slice::<PipelineJobResult>(&msg.payload)
                                    {
                                        Ok(result) => {
                                            if let Some(key) = &worker_shared_key_clone {
                                                if let Err(e) = result.verify(key, 300) {
                                                    return (
                                                        chain_clone[chain_clone.len() - 1],
                                                        Err(format!("Pipeline result signature verification failed: {}", e)),
                                                    );
                                                }
                                            }

                                            if let Some(ref reg) = registry {
                                                for (i, step_result) in
                                                    result.step_results.iter().enumerate()
                                                {
                                                    if let Some(&step_exec_id) =
                                                        step_exec_ids.get(i)
                                                    {
                                                        let status_str = match step_result.status {
                                                            JobStatus::Success => "completed",
                                                            JobStatus::TimedOut => "timeout",
                                                            _ => "failed",
                                                        };
                                                        let error_msg = step_result.error.clone();
                                                        if let Err(db_err) = sqlx::query(
                                                            "UPDATE module_executions 
                                                             SET status = $1, output_data = $2, duration_ms = $3, error_message = $4, completed_at = NOW() 
                                                             WHERE id = $5"
                                                        )
                                                        .bind(status_str)
                                                        .bind(&step_result.output)
                                                        .bind(step_result.execution_time_ms as i32)
                                                        .bind(error_msg)
                                                        .bind(step_exec_id)
                                                        .execute(&reg.db_pool)
                                                        .await {
    tracing::error!("Database operation failed in engine: {}", db_err);
}
                                                    }
                                                }
                                                for i in
                                                    result.step_results.len()..step_exec_ids.len()
                                                {
                                                    if let Some(&step_exec_id) =
                                                        step_exec_ids.get(i)
                                                    {
                                                        if let Err(db_err) = sqlx::query(
                                                            "UPDATE module_executions 
                                                             SET status = 'failed', error_message = 'Pipeline aborted before this step', completed_at = NOW() 
                                                             WHERE id = $1"
                                                        )
                                                        .bind(step_exec_id)
                                                        .execute(&reg.db_pool)
                                                        .await {
    tracing::error!("Database operation failed in engine: {}", db_err);
}
                                                    }
                                                }
                                            }

                                            match result.overall_status {
                                                JobStatus::Success => (
                                                    chain_clone[chain_clone.len() - 1],
                                                    Ok(result.final_output),
                                                ),
                                                _ => (
                                                    chain_clone[chain_clone.len() - 1],
                                                    Err(format!(
                                                        "Pipeline execution failed: {:?}",
                                                        result.final_output
                                                    )),
                                                ),
                                            }
                                        }
                                        Err(e) => (
                                            chain_clone[chain_clone.len() - 1],
                                            Err(format!("Failed to parse pipeline result: {}", e)),
                                        ),
                                    }
                                }
                                Ok(Err(e)) => (
                                    chain_clone[chain_clone.len() - 1],
                                    Err(format!("NATS request failed: {}", e)),
                                ),
                                Err(e) => (chain_clone[chain_clone.len() - 1], Err(e.to_string())),
                            }
                        };
                        executing.push(Box::pin(fut)
                            as Pin<
                                Box<
                                    dyn Future<Output = (NodeIndex, Result<JsonValue, String>)>
                                        + Send,
                                >,
                            >);
                        continue;
                    }
                    // Non-head chain nodes are handled when the chain completes — skip them.
                    continue;
                }

                // ── Single-node dispatch ─────────────────────────────────────
                let node_id = self.graph[node_idx];
                let inputs = self.gather_inputs(node_idx, &results);
                let nats_client_clone = nats_client.clone();
                let user_id_clone = self.user_id;
                let fetch_fut = self.fetch_module(node_id);
                let secrets_manager = self.secrets_manager.clone();
                let registry = self.registry.clone();
                let _exec_sandbox = execution_sandbox.clone();
                let single_user_id = self.user_id;
                let worker_shared_key_clone = worker_shared_key.clone();

                let fut = async move {
                    let wasm_module = match fetch_fut.await {
                        Ok(m) => m,
                        Err(e) => return (node_idx, Err(e)),
                    };

                    let module_config = match registry {
                        Some(ref reg) => {
                            let uid = match single_user_id {
                                Some(u) => u,
                                None => return (
                                    node_idx,
                                    Err("Module execution requires user context (user_id not set)"
                                        .to_string()),
                                ),
                            };
                            if let Err(e) = reg.ensure_module_in_cache(node_id, uid).await {
                                return (
                                    node_idx,
                                    Err(format!(
                                        "Failed to load module {} into cache: {}",
                                        node_id, e
                                    )),
                                );
                            }
                            match reg.get_module_config(node_id, uid).await {
                                Ok(Some(config)) => config,
                                Ok(None) => serde_json::json!({}),
                                Err(e) => {
                                    return (
                                        node_idx,
                                        Err(format!("Failed to get module config: {}", e)),
                                    )
                                }
                            }
                        }
                        None => serde_json::json!({}),
                    };

                    let wrapped_input = serde_json::json!({
                        "config": module_config,
                        "input": inputs
                    });

                    let job_id = Uuid::new_v4();

                    if let Some(ref reg) = registry {
                        if let Err(db_err) = sqlx::query(
                            "INSERT INTO module_executions (id, module_id, user_id, status, input_data, workflow_execution_id, trigger_type, started_at)
                             VALUES ($1, $2, $3, 'running', $4, $5, 'webhook', NOW())
                             ON CONFLICT DO NOTHING"
                        )
                        .bind(job_id)
                        .bind(node_id)
                        .bind(single_user_id.unwrap_or_else(Uuid::new_v4))
                        .bind(&inputs)
                        .bind(execution_id)
                        .execute(&reg.db_pool)
                        .await {
    tracing::error!("Database operation failed in engine: {}", db_err);
}
                    }

                    let mut req = JobRequest {
                        job_id,
                        workflow_execution_id: execution_id,
                        module_uri: wasm_module
                            .oci_url
                            .clone()
                            .unwrap_or_else(|| format!("redis:wasm:{}", node_id)),
                        input_payload: wrapped_input,
                        encrypted_secrets: {
                            let mut es = Default::default();
                            if let (Some(sm), Some(key)) =
                                (secrets_manager.as_ref(), &worker_shared_key_clone)
                            {
                                if let Ok(secrets_map) = sm.get_module_secrets(node_id).await {
                                    if let Ok(encrypted) =
                                        job_protocol::EncryptedSecrets::encrypt(&secrets_map, key)
                                    {
                                        es = encrypted;
                                    }
                                }
                            }
                            es
                        },
                        timeout_ms: 30000,
                        allowed_hosts: wasm_module.allowed_hosts.clone(),
                        allowed_methods: wasm_module.allowed_methods.clone(),
                        signature: vec![],
                        job_nonce: String::new(),
                        wasm_bytes: None,
                    };

                    if let Some(key) = &worker_shared_key_clone {
                        if let Err(e) = req.sign(key) {
                            return (node_idx, Err(format!("Failed to sign job request: {}", e)));
                        }
                    }
                    let payload_res = serde_json::to_vec(&req)
                        .map_err(|e| format!("Failed to serialize job request: {}", e));
                    let payload = match payload_res {
                        Ok(p) => p,
                        Err(e) => return (node_idx, Err(e)),
                    };

                    let topic = get_single_job_topic(user_id_clone);

                    let response_res = tokio::time::timeout(
                        std::time::Duration::from_secs(86400 * 7), // 7 days max for governance nodes
                        nats_client_clone.request(topic, payload.into()),
                    )
                    .await
                    .map_err(|_| "Job execution timed out via NATS".to_string());

                    match response_res {
                        Ok(Ok(msg)) => match serde_json::from_slice::<JobResult>(&msg.payload) {
                            Ok(result) => {
                                if let Some(key) = &worker_shared_key_clone {
                                    if let Err(e) = result.verify(key, 300) {
                                        return (
                                            node_idx,
                                            Err(format!(
                                                "Job result signature verification failed: {}",
                                                e
                                            )),
                                        );
                                    }
                                }
                                match result.status {
                                    JobStatus::Success => (node_idx, Ok(result.output_payload)),
                                    _ => (
                                        node_idx,
                                        Err(format!(
                                            "Job execution failed: {:?}",
                                            result.output_payload
                                        )),
                                    ),
                                }
                            }
                            Err(e) => (node_idx, Err(format!("Failed to parse job result: {}", e))),
                        },
                        Ok(Err(e)) => (node_idx, Err(format!("NATS request failed: {}", e))),
                        Err(e) => (node_idx, Err(e.to_string())),
                    }
                };
                executing.push(Box::pin(fut));
            }

            // Await next finished task.
            if let Some((finished_idx, exec_result)) = executing.next().await {
                let finished_id = self.graph[finished_idx];
                match exec_result {
                    Ok(output) => {
                        // For a pipeline result, mark ALL chain nodes as complete so
                        // their successors become ready.  The result is stored only for
                        // the last node (which is what `finished_idx` points to).
                        results.insert(finished_id, output);

                        // If this was a chain execution, also clear pending for
                        // interior chain nodes (they have already run in the pipeline).
                        if let Some(&chain_idx) = node_to_chain.get(&finished_idx) {
                            for &n in &chains[chain_idx] {
                                pending.insert(n, 0); // Mark all chain nodes as done.
                            }
                        }

                        // Decrement children counters for finished_idx's successors.
                        for child in self
                            .graph
                            .neighbors_directed(finished_idx, Direction::Outgoing)
                        {
                            if let Some(cnt) = pending.get_mut(&child) {
                                *cnt -= 1;
                                if *cnt == 0 {
                                    ready.push_back(child);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        return Err(format!("node {} failed: {}", finished_id, e));
                    }
                }
            }
        }

        Ok(WorkflowContext { results })
    }

    /// Execute the graph with pre-seeded node results (e.g., from a webhook trigger).
    ///
    /// `initial_results` maps node UUIDs to their pre-computed output.  Nodes in
    /// this map are treated as already completed; only their successors (and
    /// successors' successors) are executed.
    ///
    /// Uses single-node dispatch — the pipeline chain optimisation is not applied,
    /// keeping the implementation simple for trigger-based workflow runs.
    pub async fn run_with_seed(
        &self,
        nats_client: Arc<async_nats::Client>,
        worker_shared_key: Option<Arc<Vec<u8>>>,
        initial_results: HashMap<Uuid, JsonValue>,
        execution_id: Uuid,
    ) -> Result<WorkflowContext, String> {
        let (execution_sandbox, _sandbox_guard) = match create_execution_sandbox(execution_id) {
            Ok(sandbox) => {
                tracing::debug!("Created execution sandbox: {}", execution_id);
                (Some(sandbox), Some(SandboxGuard { execution_id }))
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to create execution sandbox: {}. File I/O will be unavailable.",
                    e
                );
                (None, None)
            }
        };

        if petgraph::algo::is_cyclic_directed(&self.graph) {
            return Err("Workflow contains a cycle".into());
        }

        // Initialise Kahn's in-degree counter.
        let mut pending: HashMap<NodeIndex, usize> = HashMap::new();
        for idx in self.graph.node_indices() {
            let deps = self
                .graph
                .neighbors_directed(idx, Direction::Incoming)
                .count();
            pending.insert(idx, deps);
        }

        // Pre-seed results and propagate pending counts to unblock successors.
        let mut results: HashMap<Uuid, JsonValue> = initial_results;
        let seeded: HashSet<Uuid> = results.keys().cloned().collect();
        for &node_id in &seeded {
            if let Some(&node_idx) = self.node_map.get(&node_id) {
                pending.insert(node_idx, 0);
                for child in self.graph.neighbors_directed(node_idx, Direction::Outgoing) {
                    if let Some(cnt) = pending.get_mut(&child) {
                        if *cnt > 0 {
                            *cnt -= 1;
                        }
                    }
                }
            }
        }

        // Build initial ready queue: nodes with 0 pending deps that were NOT pre-seeded.
        let mut ready: VecDeque<NodeIndex> = VecDeque::new();
        for idx in self.graph.node_indices() {
            let node_id = self.graph[idx];
            if pending.get(&idx).copied().unwrap_or(1) == 0 && !seeded.contains(&node_id) {
                ready.push_back(idx);
            }
        }

        let mut executing: FuturesUnordered<ExecFuture<'_>> = FuturesUnordered::new();

        // Main reactor loop — single-node dispatch (no pipeline chain optimisation).
        while !ready.is_empty() || !executing.is_empty() {
            while let Some(node_idx) = ready.pop_front() {
                let node_id = self.graph[node_idx];
                let inputs = self.gather_inputs(node_idx, &results);
                let nats_client_clone = nats_client.clone();
                let user_id_clone = self.user_id;
                let fetch_fut = self.fetch_module(node_id);
                let secrets_manager = self.secrets_manager.clone();
                let registry = self.registry.clone();
                let _exec_sandbox = execution_sandbox.clone();
                let seed_user_id = self.user_id;
                let worker_shared_key_clone = worker_shared_key.clone();

                let fut = async move {
                    let wasm_module = match fetch_fut.await {
                        Ok(m) => m,
                        Err(e) => return (node_idx, Err(e)),
                    };

                    let module_config = match registry {
                        Some(ref reg) => {
                            let uid = match seed_user_id {
                                Some(u) => u,
                                None => return (
                                    node_idx,
                                    Err("Module execution requires user context (user_id not set)"
                                        .to_string()),
                                ),
                            };
                            if let Err(e) = reg.ensure_module_in_cache(node_id, uid).await {
                                return (
                                    node_idx,
                                    Err(format!(
                                        "Failed to load module {} into cache: {}",
                                        node_id, e
                                    )),
                                );
                            }
                            match reg.get_module_config(node_id, uid).await {
                                Ok(Some(config)) => config,
                                Ok(None) => serde_json::json!({}),
                                Err(e) => {
                                    return (
                                        node_idx,
                                        Err(format!("Failed to get module config: {}", e)),
                                    )
                                }
                            }
                        }
                        None => serde_json::json!({}),
                    };

                    let wrapped_input = serde_json::json!({
                        "config": module_config,
                        "input": inputs
                    });

                    let job_id = Uuid::new_v4();

                    if let Some(ref reg) = registry {
                        if let Err(db_err) = sqlx::query(
                            "INSERT INTO module_executions (id, module_id, user_id, status, input_data, workflow_execution_id, trigger_type, started_at)
                             VALUES ($1, $2, $3, 'running', $4, $5, 'webhook', NOW())
                             ON CONFLICT DO NOTHING"
                        )
                        .bind(job_id)
                        .bind(node_id)
                        .bind(seed_user_id.unwrap_or_else(Uuid::new_v4))
                        .bind(&inputs)
                        .bind(execution_id)
                        .execute(&reg.db_pool)
                        .await {
    tracing::error!("Database operation failed in engine: {}", db_err);
}
                    }

                    let mut req = JobRequest {
                        job_id,
                        workflow_execution_id: execution_id,
                        module_uri: wasm_module
                            .oci_url
                            .clone()
                            .unwrap_or_else(|| format!("redis:wasm:{}", node_id)),
                        input_payload: wrapped_input,
                        encrypted_secrets: {
                            let mut es = Default::default();
                            if let (Some(sm), Some(key)) =
                                (secrets_manager.as_ref(), &worker_shared_key_clone)
                            {
                                if let Ok(secrets_map) = sm.get_module_secrets(node_id).await {
                                    if let Ok(encrypted) =
                                        job_protocol::EncryptedSecrets::encrypt(&secrets_map, key)
                                    {
                                        es = encrypted;
                                    }
                                }
                            }
                            es
                        },
                        timeout_ms: 30000,
                        allowed_hosts: wasm_module.allowed_hosts.clone(),
                        allowed_methods: wasm_module.allowed_methods.clone(),
                        signature: vec![],
                        job_nonce: String::new(),
                        wasm_bytes: None,
                    };

                    if let Some(key) = &worker_shared_key_clone {
                        if let Err(e) = req.sign(key) {
                            return (node_idx, Err(format!("Failed to sign job request: {}", e)));
                        }
                    }
                    let payload_res = serde_json::to_vec(&req)
                        .map_err(|e| format!("Failed to serialize job request: {}", e));
                    let payload = match payload_res {
                        Ok(p) => p,
                        Err(e) => return (node_idx, Err(e)),
                    };

                    let topic = get_single_job_topic(user_id_clone);

                    let response_res = tokio::time::timeout(
                        std::time::Duration::from_secs(86400 * 7), // 7 days max for governance nodes
                        nats_client_clone.request(topic, payload.into()),
                    )
                    .await
                    .map_err(|_| "Job execution timed out via NATS".to_string());

                    match response_res {
                        Ok(Ok(msg)) => match serde_json::from_slice::<JobResult>(&msg.payload) {
                            Ok(result) => {
                                if let Some(key) = &worker_shared_key_clone {
                                    if let Err(e) = result.verify(key, 300) {
                                        return (
                                            node_idx,
                                            Err(format!(
                                                "Job result signature verification failed: {}",
                                                e
                                            )),
                                        );
                                    }
                                }
                                match result.status {
                                    JobStatus::Success => (node_idx, Ok(result.output_payload)),
                                    _ => (
                                        node_idx,
                                        Err(format!(
                                            "Job execution failed: {:?}",
                                            result.output_payload
                                        )),
                                    ),
                                }
                            }
                            Err(e) => (node_idx, Err(format!("Failed to parse job result: {}", e))),
                        },
                        Ok(Err(e)) => (node_idx, Err(format!("NATS request failed: {}", e))),
                        Err(e) => (node_idx, Err(e.to_string())),
                    }
                };
                executing.push(Box::pin(fut)
                    as Pin<
                        Box<dyn Future<Output = (NodeIndex, Result<JsonValue, String>)> + Send>,
                    >);
            }

            if let Some((finished_idx, exec_result)) = executing.next().await {
                let finished_id = self.graph[finished_idx];
                match exec_result {
                    Ok(output) => {
                        results.insert(finished_id, output.clone());

                        for child in self
                            .graph
                            .neighbors_directed(finished_idx, Direction::Outgoing)
                        {
                            if let Some(cnt) = pending.get_mut(&child) {
                                *cnt -= 1;
                                if *cnt == 0 {
                                    ready.push_back(child);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        return Err(format!("node {} failed: {}", finished_id, e));
                    }
                }
            }
        }

        Ok(WorkflowContext { results })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow_engine::EdgeLogic;

    fn make_graph(edges: &[(usize, usize)], num_nodes: usize) -> DiGraph<Uuid, EdgeLogic> {
        let mut g: DiGraph<Uuid, EdgeLogic> = DiGraph::new();
        let nodes: Vec<NodeIndex> = (0..num_nodes).map(|_| g.add_node(Uuid::new_v4())).collect();
        for &(from, to) in edges {
            g.add_edge(
                nodes[from],
                nodes[to],
                EdgeLogic {
                    source_handle: "output".to_string(),
                    target_handle: "input".to_string(),
                },
            );
        }
        g
    }

    #[test]
    fn linear_chain_simple_3_nodes() {
        // A → B → C
        let g = make_graph(&[(0, 1), (1, 2)], 3);
        let chains = detect_linear_chains(&g);
        assert_eq!(chains.len(), 1, "should detect exactly one chain");
        assert_eq!(chains[0].len(), 3, "chain should include all 3 nodes");
    }

    #[test]
    fn no_chain_for_fork() {
        // A → B, A → C
        let g = make_graph(&[(0, 1), (0, 2)], 3);
        let chains = detect_linear_chains(&g);
        assert!(
            chains.is_empty(),
            "Fork has no 2+ linear chain: {:?}",
            chains
        );
    }

    #[test]
    fn no_chain_for_join() {
        // A → C, B → C
        let g = make_graph(&[(0, 2), (1, 2)], 3);
        let chains = detect_linear_chains(&g);
        assert!(chains.is_empty(), "Join has no 2+ linear chain");
    }

    #[test]
    fn chain_with_single_edge() {
        // A → B (trivial 2-node chain)
        let g = make_graph(&[(0, 1)], 2);
        let chains = detect_linear_chains(&g);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].len(), 2);
    }

    #[test]
    fn single_node_no_chain() {
        let g = make_graph(&[], 1);
        let chains = detect_linear_chains(&g);
        assert!(chains.is_empty(), "Single node produces no chain");
    }

    #[test]
    fn diamond_graph_no_full_chain() {
        // A → B → D, A → C → D
        // B and C each have in-degree=1, out-degree=1 — but D has in-degree=2
        let g = make_graph(&[(0, 1), (0, 2), (1, 3), (2, 3)], 4);
        let chains = detect_linear_chains(&g);
        // A→B could be a chain (A out-degree=2 breaks it), so no chain >= 2.
        // Actually A has out-degree=2, so neither B nor C's predecessors qualify
        // as chain starts... let's just verify no chain spans the diamond.
        for chain in &chains {
            assert!(chain.len() < 3, "No chain of length >=3 in diamond graph");
        }
    }

    #[test]
    fn parallel_chains() {
        // A → B → C and D → E (two independent chains)
        let g = make_graph(&[(0, 1), (1, 2), (3, 4)], 5);
        let chains = detect_linear_chains(&g);
        assert_eq!(chains.len(), 2, "should find exactly 2 chains");
        let lengths: Vec<usize> = chains.iter().map(|c| c.len()).collect();
        assert!(lengths.contains(&3), "one chain of length 3");
        assert!(lengths.contains(&2), "one chain of length 2");
    }
}
