//! `create_workflow_from_spec` orchestration.
//!
//! Takes a fully-specified workflow (nodes + edges, where each node is
//! either a module UUID, a catalog name, or inline Rust source) and:
//!
//! 1. Resolves every node to a stored module_id, compiling inline-Rust
//!    nodes through `talos-compilation` along the way.
//! 2. Validates that all edge endpoints reference resolved nodes.
//! 3. Builds the React-Flow-compatible graph_json shape.
//! 4. Inserts the workflow row.
//!
//! The pre-extraction call site
//! (`handle_create_workflow_from_spec` in `talos-mcp-handlers`) was
//! 498 LoC of interleaved validation, three-way module resolution,
//! compilation orchestration, edge validation, and JSON-RPC formatting
//! at 5 levels of nesting. This module pulls everything except the
//! JSON-RPC envelope into a typed surface that GraphQL/REST can call
//! against the same shape.

use std::collections::HashSet;

use serde_json::Value;
use uuid::Uuid;

/// Maximum nodes accepted per spec. Mirrors the pre-extraction limit.
pub const MAX_SPEC_NODES: usize = 100;
/// Maximum chars in `description`. Mirrors the pre-extraction limit.
pub const MAX_SPEC_DESCRIPTION_LEN: usize = 2_000;
/// Maximum chars in `name`. Mirrors the pre-extraction limit.
pub const MAX_SPEC_NAME_LEN: usize = 200;
/// Maximum chars in any edge's `condition` field. Mirrors the
/// pre-extraction limit.
pub const MAX_EDGE_CONDITION_LEN: usize = 2_000;
/// Maximum chars in `capability_world` for inline-rust nodes. Mirrors
/// the pre-extraction limit.
pub const MAX_CAPABILITY_WORLD_LEN: usize = 100;

/// Input to [`super::WorkflowCreationService::create_from_spec`].
///
/// Borrowed — the service does not retain input state past the call.
pub struct CreateFromSpecRequest<'a> {
    pub user_id: Uuid,
    pub name: &'a str,
    pub description: &'a str,
    pub spec_nodes: &'a [Value],
    pub spec_edges: &'a [Value],
}

/// Synchronous outcome of the create-from-spec flow.
///
/// Hard infrastructure failures (DB unavailable, etc.) flow as
/// `Err(anyhow::Error)`. Soft failures with actionable user feedback
/// (a missing UUID, a catalog miss, lint errors, compilation failures)
/// are explicit variants here so the caller can shape an
/// appropriately structured response.
#[derive(Debug)]
pub enum CreateFromSpecOutcome {
    /// Workflow created successfully. Caller spawns post-create
    /// background tasks (auto_embed_workflow, auto_suggest_capabilities)
    /// and shapes the success response.
    Created(SpecCreatedOutcome),
    /// One or more inline-rust nodes failed lint/compile/store. Caller
    /// surfaces the per-node breakdown.
    NodeBuildErrors { errors: Vec<NodeBuildError> },
    /// `name` exceeds [`MAX_SPEC_NAME_LEN`].
    NameTooLong,
    /// `description` exceeds [`MAX_SPEC_DESCRIPTION_LEN`].
    DescriptionTooLong,
    /// `spec_nodes.len()` exceeds [`MAX_SPEC_NODES`].
    TooManyNodes,
    /// A node referenced an explicit `module_id` that didn't parse
    /// as a UUID. `node_id` and `module_id_value` are echoed back so
    /// the caller can highlight the offender.
    InvalidModuleId {
        node_id: String,
        module_id_value: String,
    },
    /// A node had `module_name` set but no template matched, even
    /// after symmetric normalisation. `suggestions` carries up to 5
    /// near-matches the caller can surface in a "did you mean" hint.
    UnknownCatalogModule {
        node_id: String,
        module_name: String,
        suggestions: Vec<String>,
    },
    /// A node had none of `module_id`, `module_name`, or `rust_code`.
    NodeMissingResolutionField { node_id: String },
    /// Inline-rust node specified a `capability_world` over
    /// [`MAX_CAPABILITY_WORLD_LEN`].
    CapabilityWorldTooLong { node_id: String },
    /// An edge had an endpoint not present in the resolved node set.
    /// `endpoint` is "source" or "target".
    EdgeReferencesUnknownNode {
        endpoint: &'static str,
        value: String,
    },
    /// An edge's `condition` exceeds [`MAX_EDGE_CONDITION_LEN`].
    EdgeConditionTooLong,
}

/// Per-node breakdown for the build-error path. Each variant of `stage`
/// corresponds to a distinct failure point in the inline-rust pipeline:
/// `lint` (static analysis caught issues before compile), `compile`
/// (cargo-component returned errors or no WASM), `store` (the post-
/// compile DB upsert failed).
#[derive(Debug, Clone)]
pub struct NodeBuildError {
    pub node_id: String,
    pub stage: BuildStage,
    pub messages: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildStage {
    Lint,
    Compile,
    Store,
}

impl BuildStage {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Lint => "lint",
            Self::Compile => "compile",
            Self::Store => "store",
        }
    }
}

/// Created-workflow payload.
#[derive(Debug)]
pub struct SpecCreatedOutcome {
    pub workflow_id: Uuid,
    pub workflow_name: String,
    pub node_count: usize,
    pub edge_count: usize,
    /// One entry per inline-rust node that compiled fresh, in the
    /// shape "compiled <node_id> → <template_uuid>". Pre-existing
    /// templates (UUID + catalog paths) contribute nothing here.
    pub compilation_notes: Vec<String>,
}

/// Internal type — public so unit tests can construct it.
#[derive(Debug, Clone)]
pub struct ResolvedSpecNode {
    pub id: String,
    pub module_id: String,
    pub config: Value,
    pub compilation_note: Option<String>,
}

impl super::WorkflowCreationService {
    /// Create a workflow from a fully-specified node + edge list.
    ///
    /// Calling pattern:
    /// ```ignore
    /// let outcome = service
    ///     .create_from_spec(CreateFromSpecRequest {
    ///         user_id, name, description, spec_nodes, spec_edges,
    ///     })
    ///     .await?;
    /// match outcome { ... }
    /// ```
    pub async fn create_from_spec(
        &self,
        req: CreateFromSpecRequest<'_>,
    ) -> anyhow::Result<CreateFromSpecOutcome> {
        // ── Phase 0: Cheap input validation ──────────────────────────
        if req.name.len() > MAX_SPEC_NAME_LEN {
            return Ok(CreateFromSpecOutcome::NameTooLong);
        }
        if req.description.len() > MAX_SPEC_DESCRIPTION_LEN {
            return Ok(CreateFromSpecOutcome::DescriptionTooLong);
        }
        if req.spec_nodes.len() > MAX_SPEC_NODES {
            return Ok(CreateFromSpecOutcome::TooManyNodes);
        }

        // ── Phase 1: Resolve each node ───────────────────────────────
        let resolution = self.resolve_spec_nodes(req.user_id, req.spec_nodes).await?;
        let resolved = match resolution {
            ResolveResult::Resolved(r) => r,
            ResolveResult::Outcome(o) => return Ok(o),
        };

        // ── Phase 2: Validate edges ──────────────────────────────────
        let resolved_ids: HashSet<&str> = resolved.iter().map(|r| r.id.as_str()).collect();
        for edge in req.spec_edges {
            let src = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let tgt = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
            if !resolved_ids.contains(src) {
                return Ok(CreateFromSpecOutcome::EdgeReferencesUnknownNode {
                    endpoint: "source",
                    value: src.to_string(),
                });
            }
            if !resolved_ids.contains(tgt) {
                return Ok(CreateFromSpecOutcome::EdgeReferencesUnknownNode {
                    endpoint: "target",
                    value: tgt.to_string(),
                });
            }
            if let Some(cond) = edge.get("condition").and_then(|v| v.as_str()) {
                if cond.len() > MAX_EDGE_CONDITION_LEN {
                    return Ok(CreateFromSpecOutcome::EdgeConditionTooLong);
                }
            }
        }

        // ── Phase 3: Build graph JSON ────────────────────────────────
        let graph_nodes = build_spec_graph_nodes(&resolved);
        let graph_edges = build_spec_graph_edges(req.spec_edges);
        let graph_json_str = serde_json::json!({
            "nodes": graph_nodes,
            "edges": graph_edges,
        })
        .to_string();

        // ── Phase 4: Insert workflow row ─────────────────────────────
        let description_opt = if req.description.is_empty() {
            None
        } else {
            Some(req.description)
        };
        let workflow_id = self
            .workflow_repo
            .create_workflow(
                req.user_id,
                req.name,
                &graph_json_str,
                description_opt,
                &[],
                &[],
                None,
                None,
                None,
                None,
            )
            .await?;

        let compilation_notes: Vec<String> = resolved
            .iter()
            .filter_map(|r| r.compilation_note.clone())
            .collect();

        Ok(CreateFromSpecOutcome::Created(SpecCreatedOutcome {
            workflow_id,
            workflow_name: req.name.to_string(),
            node_count: resolved.len(),
            edge_count: req.spec_edges.len(),
            compilation_notes,
        }))
    }

    async fn resolve_spec_nodes(
        &self,
        user_id: Uuid,
        spec_nodes: &[Value],
    ) -> anyhow::Result<ResolveResult> {
        let mut resolved: Vec<ResolvedSpecNode> = Vec::new();
        let mut build_errors: Vec<NodeBuildError> = Vec::new();

        for spec_node in spec_nodes {
            let node_id = spec_node
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("node")
                .to_string();
            let config = spec_node
                .get("config")
                .cloned()
                .unwrap_or(serde_json::json!({}));

            // Path A — explicit module_id.
            if let Some(mid_str) = spec_node.get("module_id").and_then(|v| v.as_str()) {
                if mid_str.parse::<Uuid>().is_ok() {
                    resolved.push(ResolvedSpecNode {
                        id: node_id,
                        module_id: mid_str.to_string(),
                        config,
                        compilation_note: None,
                    });
                    continue;
                }
                return Ok(ResolveResult::Outcome(
                    CreateFromSpecOutcome::InvalidModuleId {
                        node_id,
                        module_id_value: mid_str.to_string(),
                    },
                ));
            }

            // Path B — catalog name lookup.
            if let Some(module_name) = spec_node.get("module_name").and_then(|v| v.as_str()) {
                // MCP-886 (2026-05-14): log DB errors before collapsing
                // to None. Pre-fix the swallow turned a transient sqlx
                // failure into "module not found, here are similar
                // names" — operator-facing error misdirected the user
                // to fix their spec when the actual issue was infra.
                // Behaviour preserved (still falls through to the
                // None branch) since spec resolution has its own
                // operator-actionable surface; telemetry-only fix.
                let resolved_id = match self
                    .module_repo
                    .find_template_id_by_name_normalised(module_name)
                    .await
                {
                    Ok(opt) => opt,
                    Err(e) => {
                        tracing::warn!(
                            module_name = %module_name,
                            error = %e,
                            "spec: find_template_id_by_name_normalised failed — \
                             falling through to 'module not found' suggestion path. \
                             User will see 'module not found' but actual cause is DB."
                        );
                        None
                    }
                };
                match resolved_id {
                    Some(tid) => {
                        resolved.push(ResolvedSpecNode {
                            id: node_id,
                            module_id: tid.to_string(),
                            config,
                            compilation_note: None,
                        });
                    }
                    None => {
                        let suggestions = self
                            .module_repo
                            .suggest_template_names_for_miss(module_name, user_id, 5)
                            .await;
                        return Ok(ResolveResult::Outcome(
                            CreateFromSpecOutcome::UnknownCatalogModule {
                                node_id,
                                module_name: module_name.to_string(),
                                suggestions,
                            },
                        ));
                    }
                }
                continue;
            }

            // Path C — inline rust_code compile.
            if let Some(rust_code) = spec_node.get("rust_code").and_then(|v| v.as_str()) {
                let world = spec_node
                    .get("capability_world")
                    .and_then(|v| v.as_str())
                    .unwrap_or("minimal-node");
                if world.len() > MAX_CAPABILITY_WORLD_LEN {
                    return Ok(ResolveResult::Outcome(
                        CreateFromSpecOutcome::CapabilityWorldTooLong { node_id },
                    ));
                }
                let allowed_secrets: Vec<String> = spec_node
                    .get("allowed_secrets")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|s| s.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();

                match self
                    .build_inline_rust_node(user_id, &node_id, rust_code, world, &allowed_secrets)
                    .await
                {
                    BuildOutcome::Resolved(template_id) => {
                        resolved.push(ResolvedSpecNode {
                            id: node_id.clone(),
                            module_id: template_id.to_string(),
                            config,
                            compilation_note: Some(format!(
                                "compiled {} → {}",
                                node_id, template_id
                            )),
                        });
                    }
                    BuildOutcome::Failed(err) => build_errors.push(err),
                }
                continue;
            }

            return Ok(ResolveResult::Outcome(
                CreateFromSpecOutcome::NodeMissingResolutionField { node_id },
            ));
        }

        if !build_errors.is_empty() {
            return Ok(ResolveResult::Outcome(
                CreateFromSpecOutcome::NodeBuildErrors {
                    errors: build_errors,
                },
            ));
        }
        Ok(ResolveResult::Resolved(resolved))
    }

    async fn build_inline_rust_node(
        &self,
        user_id: Uuid,
        node_id: &str,
        rust_code: &str,
        world: &str,
        allowed_secrets: &[String],
    ) -> BuildOutcome {
        // Inject `#[talos_module]` attribute before `fn run` if the
        // user's source didn't already include it. Pre-extraction this
        // was an inline regex+match; now centralised in `inject_module_macro`.
        let wrapped = inject_module_macro(rust_code, world);

        // Lint pre-flight (catches the common authoring errors before
        // we burn a compilation slot).
        let lint_world = if world.ends_with("-node") {
            world.to_string()
        } else {
            format!("{}-node", world)
        };
        if let Ok(lint_errors) = self
            .compiler
            .lint_code(node_id, &wrapped, &lint_world, None)
            .await
        {
            if !lint_errors.is_empty() {
                let msgs: Vec<String> = lint_errors
                    .iter()
                    .map(|e| match (e.line, e.column) {
                        (Some(l), Some(c)) => format!("Line {}:{}: {}", l, c, e.message),
                        _ => e.message.clone(),
                    })
                    .collect();
                return BuildOutcome::Failed(NodeBuildError {
                    node_id: node_id.to_string(),
                    stage: BuildStage::Lint,
                    messages: msgs,
                });
            }
        }

        // Full compile.
        let job_id = Uuid::new_v4();
        let compile_result = self
            .compiler
            .compile_to_wasm_with_config(
                user_id,
                job_id,
                node_id,
                &wrapped,
                &serde_json::json!({}),
                None,
            )
            .await;

        let (wasm_bytes, _content_hash) = match compile_result {
            Ok(res) if res.success => match res.wasm_bytes {
                Some(b) => (b, res.content_hash),
                None => {
                    return BuildOutcome::Failed(NodeBuildError {
                        node_id: node_id.to_string(),
                        stage: BuildStage::Compile,
                        messages: vec!["Compiled successfully but no WASM bytes returned".into()],
                    });
                }
            },
            Ok(res) => {
                let msgs: Vec<String> = res.errors.iter().map(|e| e.message.clone()).collect();
                return BuildOutcome::Failed(NodeBuildError {
                    node_id: node_id.to_string(),
                    stage: BuildStage::Compile,
                    messages: if msgs.is_empty() {
                        vec!["Compilation failed (no output)".into()]
                    } else {
                        msgs
                    },
                });
            }
            Err(e) => {
                return BuildOutcome::Failed(NodeBuildError {
                    node_id: node_id.to_string(),
                    stage: BuildStage::Compile,
                    messages: vec![e.to_string()],
                });
            }
        };

        // Determine allowed_hosts from capability_world: any of the
        // network-capable worlds gets `["*"]`, others nothing.
        let allowed_hosts: Vec<String> = if world.contains("http")
            || world.contains("network")
            || world.contains("secrets")
            || world.contains("automation")
            || world.contains("database")
        {
            vec!["*".to_string()]
        } else {
            vec![]
        };

        // Upsert into modules table by (name, user_id).
        //
        // MCP-886 (2026-05-14): log DB errors before collapsing to
        // None. Pre-fix `.unwrap_or(None)` made a sqlx failure look
        // like "no existing template" — the upsert path then took the
        // INSERT branch instead of UPDATE. On a (node_id, user_id)
        // unique-constraint, the INSERT would fail with its own
        // error so the corruption was bounded; without that
        // constraint, a duplicate row could be silently created. Log
        // here so post-incident review can correlate the upstream
        // DB blip with the downstream upsert failure.
        let existing = match self
            .workflow_repo
            .find_node_template_by_name_and_user(node_id, user_id)
            .await
        {
            Ok(opt) => opt,
            Err(e) => {
                tracing::warn!(
                    node_id = %node_id,
                    user_id = %user_id,
                    error = %e,
                    "spec build_inline_rust_node: find_node_template_by_name_and_user failed — \
                     falling through to INSERT (will surface as a unique-constraint error \
                     downstream if the row actually exists)"
                );
                None
            }
        };
        let integration_name_ref: Option<&str> = None;
        let template_id = if let Some(eid) = existing {
            if let Err(e) = self
                .workflow_repo
                .update_node_template_wasm(
                    eid,
                    &wasm_bytes,
                    rust_code,
                    world,
                    allowed_secrets,
                    &allowed_hosts,
                    integration_name_ref,
                )
                .await
            {
                return BuildOutcome::Failed(NodeBuildError {
                    node_id: node_id.to_string(),
                    stage: BuildStage::Store,
                    messages: vec![e.to_string()],
                });
            }
            eid
        } else {
            let new_id = Uuid::new_v4();
            if let Err(e) = self
                .workflow_repo
                .insert_node_template(
                    new_id,
                    node_id,
                    &wasm_bytes,
                    rust_code,
                    world,
                    allowed_secrets,
                    &allowed_hosts,
                    user_id,
                    integration_name_ref,
                )
                .await
            {
                return BuildOutcome::Failed(NodeBuildError {
                    node_id: node_id.to_string(),
                    stage: BuildStage::Store,
                    messages: vec![e.to_string()],
                });
            }
            new_id
        };

        BuildOutcome::Resolved(template_id)
    }
}

/// Internal control-flow helper — distinguishes a fully-resolved node
/// list from an early-return outcome. Lets `resolve_spec_nodes` exit
/// the loop on the first hard failure without using `Result`-flavoured
/// short-circuits (the outcome enum is an Ok-class result, not Err).
enum ResolveResult {
    Resolved(Vec<ResolvedSpecNode>),
    Outcome(CreateFromSpecOutcome),
}

enum BuildOutcome {
    Resolved(Uuid),
    Failed(NodeBuildError),
}

/// Inject `#[talos_sdk_macros::talos_module(world = "<world>")]` on
/// the line above `fn run(`, unless the source already carries the
/// attribute. Pure helper — exported so unit tests cover the macro-
/// rewriting logic without round-tripping through the compiler.
pub(crate) fn inject_module_macro(rust_code: &str, world: &str) -> String {
    if rust_code.contains("#[talos_module") || rust_code.contains("talos_sdk_macros::talos_module")
    {
        return rust_code.to_string();
    }
    static RE_RUN_FN_SPEC: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?m)^[ \t]*(pub[ \t]+)?fn[ \t]+run[ \t]*\(").unwrap()
    });
    match RE_RUN_FN_SPEC.find(rust_code) {
        Some(m) => format!(
            "{}#[talos_sdk_macros::talos_module(world = \"{}\")]\n{}",
            &rust_code[..m.start()],
            world,
            &rust_code[m.start()..]
        ),
        None => rust_code.to_string(),
    }
}

/// Build the React-Flow node array. Pure projection — exposed for
/// tests so the layout/positioning math is verified without going
/// through the service.
pub(crate) fn build_spec_graph_nodes(resolved: &[ResolvedSpecNode]) -> Vec<Value> {
    let mut y = 100.0_f64;
    resolved
        .iter()
        .map(|r| {
            y += 130.0;
            serde_json::json!({
                "id": r.id,
                "type": r.module_id,
                "position": { "x": 250.0, "y": y },
                "data": r.config,
            })
        })
        .collect()
}

/// Build the React-Flow edge array. Pure projection over
/// caller-supplied edge specs. Carries through `condition` and
/// `edge_type` (default `on_success` if omitted).
pub(crate) fn build_spec_graph_edges(spec_edges: &[Value]) -> Vec<Value> {
    spec_edges
        .iter()
        .map(|e| {
            let src = e.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let tgt = e.get("target").and_then(|v| v.as_str()).unwrap_or("");
            let edge_type = e
                .get("edge_type")
                .and_then(|v| v.as_str())
                .unwrap_or("on_success");
            let mut ej = serde_json::json!({
                "id": format!("{}-{}", src, tgt),
                "source": src,
                "target": tgt,
                "type": "default",
                "data": { "edge_type": edge_type },
            });
            if let Some(cond) = e.get("condition").and_then(|v| v.as_str()) {
                if let Some(obj) = ej.as_object_mut() {
                    obj.insert("condition".to_string(), serde_json::json!(cond));
                }
            }
            ej
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_macro_skips_when_already_present_attribute_form() {
        let src = "#[talos_module(world = \"http-node\")]\nfn run() {}";
        assert_eq!(inject_module_macro(src, "http-node"), src);
    }

    #[test]
    fn inject_macro_skips_when_already_present_path_form() {
        let src = "#[talos_sdk_macros::talos_module(world = \"http-node\")]\nfn run() {}";
        assert_eq!(inject_module_macro(src, "http-node"), src);
    }

    #[test]
    fn inject_macro_inserts_above_pub_fn_run() {
        let src = "use foo;\npub fn run() {}\n";
        let out = inject_module_macro(src, "minimal-node");
        assert!(out.contains("#[talos_sdk_macros::talos_module(world = \"minimal-node\")]"));
        assert!(out.contains("pub fn run() {}"));
        // Macro is on the line directly above `pub fn run`.
        let macro_idx = out.find("#[talos_sdk_macros::talos_module").unwrap();
        let fn_idx = out.find("pub fn run").unwrap();
        assert!(macro_idx < fn_idx);
    }

    #[test]
    fn inject_macro_inserts_above_bare_fn_run() {
        let src = "fn run() {}";
        let out = inject_module_macro(src, "http-node");
        assert!(out.starts_with("#[talos_sdk_macros::talos_module(world = \"http-node\")]"));
    }

    #[test]
    fn inject_macro_returns_unchanged_when_no_run_fn() {
        let src = "fn other() {}";
        // No run fn → can't safely inject; return as-is.
        assert_eq!(inject_module_macro(src, "minimal-node"), src);
    }

    #[test]
    fn build_spec_graph_nodes_lays_out_vertically() {
        let resolved = vec![
            ResolvedSpecNode {
                id: "a".into(),
                module_id: "tid-1".into(),
                config: serde_json::json!({}),
                compilation_note: None,
            },
            ResolvedSpecNode {
                id: "b".into(),
                module_id: "tid-2".into(),
                config: serde_json::json!({"k": "v"}),
                compilation_note: None,
            },
        ];
        let nodes = build_spec_graph_nodes(&resolved);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0]["id"], "a");
        assert_eq!(nodes[0]["type"], "tid-1");
        assert_eq!(nodes[0]["position"]["y"], 230.0); // 100 + 130
        assert_eq!(nodes[1]["position"]["y"], 360.0); // 230 + 130
        assert_eq!(nodes[1]["data"]["k"], "v");
    }

    #[test]
    fn build_spec_graph_edges_default_edge_type() {
        let edges = vec![serde_json::json!({"source": "a", "target": "b"})];
        let out = build_spec_graph_edges(&edges);
        assert_eq!(out[0]["data"]["edge_type"], "on_success");
        assert_eq!(out[0]["id"], "a-b");
        assert!(out[0].get("condition").is_none());
    }

    #[test]
    fn build_spec_graph_edges_passes_through_condition_and_edge_type() {
        let edges = vec![serde_json::json!({
            "source": "a",
            "target": "b",
            "edge_type": "on_failure",
            "condition": "ctx.error == \"timeout\""
        })];
        let out = build_spec_graph_edges(&edges);
        assert_eq!(out[0]["data"]["edge_type"], "on_failure");
        assert_eq!(out[0]["condition"], "ctx.error == \"timeout\"");
    }

    #[test]
    fn build_stage_tags() {
        assert_eq!(BuildStage::Lint.tag(), "lint");
        assert_eq!(BuildStage::Compile.tag(), "compile");
        assert_eq!(BuildStage::Store.tag(), "store");
    }
}
