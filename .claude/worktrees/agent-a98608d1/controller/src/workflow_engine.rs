use async_trait::async_trait;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::Topo;
use petgraph::Direction;
use serde_json::{Map, Value as JsonValue};
use std::collections::HashMap;
use uuid::Uuid;

// Several methods are currently unused but form the intended public API.
// Suppress dead‑code warnings to keep the lint step clean.
#[allow(dead_code)]
/// Represents the data flowing through the workflow.
#[derive(Clone, Debug, Default)]
pub struct WorkflowContext {
    /// Mapping from a node's UUID to its output payload.
    pub results: HashMap<Uuid, JsonValue>,
}

/// Edge metadata – for now we simply record which handle names map between nodes.
#[derive(Clone, Debug)]
pub struct EdgeLogic {
    pub source_handle: String,
    pub target_handle: String,
}

/// The core engine that holds a directed acyclic graph of node IDs.
// The engine is primarily exercised via integration tests; suppress dead‑code warnings for the struct.
#[allow(dead_code)]
pub struct WorkflowEngine {
    graph: DiGraph<Uuid, EdgeLogic>,
    node_map: HashMap<Uuid, NodeIndex>,
}

impl WorkflowEngine {
    /// Create an empty engine.
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
        }
    }

    /// Add a node identified by its UUID.
    pub fn add_node(&mut self, id: Uuid) {
        let idx = self.graph.add_node(id);
        self.node_map.insert(id, idx);
    }

    /// Connect two nodes with edge logic.
    pub fn add_edge(&mut self, from: Uuid, to: Uuid, logic: EdgeLogic) {
        let from_idx = self.node_map[&from];
        let to_idx = self.node_map[&to];
        self.graph.add_edge(from_idx, to_idx, logic);
    }

    /// Validate the graph contains no cycles.
    pub fn validate(&self) -> Result<(), String> {
        if petgraph::algo::is_cyclic_directed(&self.graph) {
            Err("Workflow contains a cycle! Infinite loops are forbidden.".to_string())
        } else {
            Ok(())
        }
    }

    /// Gather inputs for a node by examining incoming edges and the current context.
    fn gather_inputs(&self, node_idx: NodeIndex, ctx: &WorkflowContext) -> JsonValue {
        let mut map = Map::new();
        for parent_idx in self.graph.neighbors_directed(node_idx, Direction::Incoming) {
            let parent_id = self.graph[parent_idx];
            if let Some(edge_idx) = self.graph.find_edge(parent_idx, node_idx) {
                let edge = &self.graph[edge_idx];
                if let Some(parent_output) = ctx.results.get(&parent_id) {
                    // Use the target_handle as the key for the child input.
                    map.insert(edge.target_handle.clone(), parent_output.clone());
                }
            }
        }
        JsonValue::Object(map)
    }

    /// Placeholder for loading a Wasm module for a given node.
    async fn fetch_module_for_node(&self, _node_id: Uuid) -> Result<Vec<u8>, String> {
        // In a real system this would query a DB or registry.
        // For the MVP we just read the example node compiled earlier.
        std::fs::read("example-node/target/wasm32-wasi/release/my_first_node.wasm")
            .map_err(|e| format!("failed to read wasm module: {}", e))
    }

    /// Execute the workflow using a supplied executor.
    pub async fn run<E: Executor + Sync>(&self, executor: &E) -> Result<WorkflowContext, String> {
        // Ensure the graph is acyclic before execution.
        self.validate()?;

        let mut ctx = WorkflowContext::default();
        let mut topo = Topo::new(&self.graph);

        while let Some(node_idx) = topo.next(&self.graph) {
            let node_id = self.graph[node_idx];
            let inputs = self.gather_inputs(node_idx, &ctx);
            println!("Executing node {}", node_id);

            let wasm_bytes = self.fetch_module_for_node(node_id).await?;
            let output = executor
                .execute(&wasm_bytes, inputs)
                .await
                .map_err(|e| format!("execution error: {}", e))?;
            ctx.results.insert(node_id, output);
        }
        Ok(ctx)
    }
}

// Provide a Default implementation for convenience and to satisfy lint checks.
impl Default for WorkflowEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait abstracting over a runtime that can execute a Wasm component.
#[async_trait]
pub trait Executor {
    async fn execute(&self, wasm_bytes: &[u8], input: JsonValue) -> Result<JsonValue, String>;
}

/// A very simple executor used for testing – it just echoes the input.
pub struct EchoExecutor;

#[async_trait]
impl Executor for EchoExecutor {
    async fn execute(&self, _wasm_bytes: &[u8], input: JsonValue) -> Result<JsonValue, String> {
        // In a real implementation this would invoke the Wasmtime runtime.
        Ok(input)
    }
}
