//! `create_workflow_from_spec` orchestration.
//!
//! Takes a fully-specified workflow (nodes + edges, where each node is
//! either a module UUID, a catalog name, or inline Rust source) and:
//!
//! 1. Validates the spec's STRUCTURE with no I/O: node ids unique, every
//!    inline node's name / size / grants well-formed (never `"*"` hosts),
//!    every edge endpoint a node of this spec.
//! 2. Resolves every node to a module: an explicit `module_id` the caller can
//!    see, a catalog name, or inline Rust compiled through
//!    `talos_inline_compile_service::InlineCompileService::compile_checked` —
//!    the same gates (`is_compilable_world`, dependency allowlist, lint) as
//!    `add_node_to_workflow`, and NO write yet.
//! 3. Persists the compiled modules (only once every node compiled), refusing
//!    a name that is already taken rather than overwriting it.
//! 4. Builds the React-Flow-compatible graph_json shape and inserts the
//!    workflow row.
//!
//! The per-node ROLE gate (`require_agent_role_permits_world`) needs the
//! caller's agent identity, which is a protocol concern: the MCP handler runs
//! it over [`inline_compile_worlds`] BEFORE calling in, so it sees exactly the
//! nodes this module will compile.
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
/// Maximum bytes of inline `rust_code` per node — `add_node_to_workflow`'s
/// cap. Before 2026-09-25 the spec path had none.
pub const MAX_INLINE_RUST_BYTES: usize = 512 * 1024;
/// Maximum chars in an inline node's `id`, which doubles as the MODULE name —
/// `add_node_to_workflow`'s cap.
pub const MAX_INLINE_NODE_ID_LEN: usize = 200;
/// The closed HTTP verb set (`wit/talos.wit`'s `enum method`). An inline
/// node's `allowed_methods` may name only these.
const HTTP_VERBS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];

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
    /// Two nodes in the spec share an `id`. The graph would carry two nodes
    /// under one id, and for inline nodes the second would collide with the
    /// module the first creates.
    DuplicateNodeId { node_id: String },
    /// An inline-rust node's name, size or grants are malformed — including
    /// an `allowed_hosts` containing `"*"`, which a spec never grants.
    InvalidInlineNode { node_id: String, reason: String },
    /// A node's explicit `module_id` names no module the caller can see.
    /// Absent and foreign are ONE answer (a module-UUID existence oracle
    /// otherwise — `add_node_to_workflow`'s rule).
    ModuleNotAccessible { node_id: String, module_id: Uuid },
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
    /// A pre-compile gate refused (invalid world, dependency allowlist).
    Validate,
    Lint,
    Compile,
    /// A module with this name already exists; nothing was written for it.
    NameCollision,
    Store,
}

impl BuildStage {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Validate => "validate",
            Self::Lint => "lint",
            Self::Compile => "compile",
            Self::NameCollision => "name_collision",
            Self::Store => "store",
        }
    }
}

/// How one spec node resolves to a module. The ONE place the precedence
/// (`module_id` > `module_name` > `rust_code`) is written, shared by the
/// service and by the MCP handler's role gate ([`inline_compile_worlds`]) so
/// the gate sees exactly the nodes that will compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecNodeSource<'a> {
    ModuleId(&'a str),
    ModuleName(&'a str),
    InlineRust {
        rust_code: &'a str,
        /// Defaulted to `"minimal-node"` when absent.
        capability_world: &'a str,
    },
    Missing,
}

/// Classify a spec node by the resolution precedence.
#[must_use]
pub fn classify_spec_node(spec_node: &Value) -> SpecNodeSource<'_> {
    if let Some(mid) = spec_node.get("module_id").and_then(|v| v.as_str()) {
        return SpecNodeSource::ModuleId(mid);
    }
    if let Some(name) = spec_node.get("module_name").and_then(|v| v.as_str()) {
        return SpecNodeSource::ModuleName(name);
    }
    if let Some(rust_code) = spec_node.get("rust_code").and_then(|v| v.as_str()) {
        let capability_world = spec_node
            .get("capability_world")
            .and_then(|v| v.as_str())
            .unwrap_or("minimal-node");
        return SpecNodeSource::InlineRust {
            rust_code,
            capability_world,
        };
    }
    SpecNodeSource::Missing
}

/// A spec node's `id` (defaulted to `"node"`, the pre-extraction default).
#[must_use]
pub fn spec_node_id(spec_node: &Value) -> &str {
    spec_node
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("node")
}

/// `(node_id, capability_world)` for every node the spec will COMPILE — the
/// input to the caller's per-world role gate.
#[must_use]
pub fn inline_compile_worlds(spec_nodes: &[Value]) -> Vec<(&str, &str)> {
    spec_nodes
        .iter()
        .filter_map(|n| match classify_spec_node(n) {
            SpecNodeSource::InlineRust {
                capability_world, ..
            } => Some((spec_node_id(n), capability_world)),
            _ => None,
        })
        .collect()
}

/// The grants an inline node's module is created with. Always explicit —
/// the world-derived `["*"]` host default is never reached from a spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InlineGrants {
    pub(crate) allowed_hosts: Vec<String>,
    pub(crate) allowed_secrets: Vec<String>,
    pub(crate) allowed_methods: Vec<String>,
}

/// Parse an optional array-of-strings field strictly: absent / null is empty,
/// a non-array or a non-string element is an error (before 2026-09-25 a
/// non-string secret was silently dropped).
fn strict_str_array(spec_node: &Value, field: &str) -> Result<Vec<String>, String> {
    match spec_node.get(field) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(arr)) => arr
            .iter()
            .enumerate()
            .map(|(i, v)| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{field}[{i}] must be a string"))
            })
            .collect(),
        Some(_) => Err(format!("{field} must be an array of strings")),
    }
}

/// Validate an inline-rust node with no I/O and return the grants its module
/// is created with. Pure, so every refusal is unit-tested.
pub(crate) fn validate_inline_spec_node(
    node_id: &str,
    spec_node: &Value,
    rust_code: &str,
) -> Result<InlineGrants, String> {
    // The id IS the module name: `add_node_to_workflow`'s charset and length.
    if node_id.is_empty() || node_id.len() > MAX_INLINE_NODE_ID_LEN {
        return Err(format!(
            "id must be 1-{MAX_INLINE_NODE_ID_LEN} characters (it becomes the module name)"
        ));
    }
    if !node_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(
            "id may only contain ASCII alphanumeric characters, hyphens, underscores, and dots \
             (it becomes the module name)"
                .to_string(),
        );
    }
    if rust_code.len() > MAX_INLINE_RUST_BYTES {
        return Err("rust_code exceeds maximum size of 512 KiB".to_string());
    }
    let allowed_hosts = strict_str_array(spec_node, "allowed_hosts")?;
    if allowed_hosts.iter().any(|h| h.trim() == "*") {
        return Err(
            "allowed_hosts may not contain \"*\": a spec grants egress by host NAME. \
             List the hosts this module calls; granting every host is a deliberate \
             act for update_module_hosts, not a side effect of authoring a workflow."
                .to_string(),
        );
    }
    if let Some(h) = allowed_hosts.iter().find(|h| h.trim().is_empty()) {
        return Err(format!("allowed_hosts entry {h:?} is empty"));
    }
    let allowed_secrets = strict_str_array(spec_node, "allowed_secrets")?;
    let allowed_methods: Vec<String> = strict_str_array(spec_node, "allowed_methods")?
        .into_iter()
        .map(|m| m.to_ascii_uppercase())
        .collect();
    if let Some(bad) = allowed_methods
        .iter()
        .find(|m| !HTTP_VERBS.contains(&m.as_str()))
    {
        return Err(format!(
            "allowed_methods entry {bad:?} is not one of {}",
            HTTP_VERBS.join(", ")
        ));
    }
    Ok(InlineGrants {
        allowed_hosts,
        allowed_secrets,
        allowed_methods,
    })
}

/// Everything about a spec that can be refused with no I/O: node ids unique,
/// each node resolvable in shape, inline nodes well-formed, every edge
/// endpoint a node of this spec. Runs BEFORE any compile or write, so a spec
/// with a bad edge no longer leaves compiled modules behind.
pub(crate) fn validate_spec_structure(
    spec_nodes: &[Value],
    spec_edges: &[Value],
) -> Option<CreateFromSpecOutcome> {
    let mut ids: HashSet<&str> = HashSet::with_capacity(spec_nodes.len());
    for spec_node in spec_nodes {
        let node_id = spec_node_id(spec_node);
        if !ids.insert(node_id) {
            return Some(CreateFromSpecOutcome::DuplicateNodeId {
                node_id: node_id.to_string(),
            });
        }
        match classify_spec_node(spec_node) {
            SpecNodeSource::ModuleId(mid) => {
                if mid.parse::<Uuid>().is_err() {
                    return Some(CreateFromSpecOutcome::InvalidModuleId {
                        node_id: node_id.to_string(),
                        module_id_value: mid.to_string(),
                    });
                }
            }
            SpecNodeSource::ModuleName(_) => {}
            SpecNodeSource::InlineRust {
                rust_code,
                capability_world,
            } => {
                if capability_world.len() > MAX_CAPABILITY_WORLD_LEN {
                    return Some(CreateFromSpecOutcome::CapabilityWorldTooLong {
                        node_id: node_id.to_string(),
                    });
                }
                if let Err(reason) = validate_inline_spec_node(node_id, spec_node, rust_code) {
                    return Some(CreateFromSpecOutcome::InvalidInlineNode {
                        node_id: node_id.to_string(),
                        reason,
                    });
                }
            }
            SpecNodeSource::Missing => {
                return Some(CreateFromSpecOutcome::NodeMissingResolutionField {
                    node_id: node_id.to_string(),
                });
            }
        }
    }
    for edge in spec_edges {
        let src = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let tgt = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
        if !ids.contains(src) {
            return Some(CreateFromSpecOutcome::EdgeReferencesUnknownNode {
                endpoint: "source",
                value: src.to_string(),
            });
        }
        if !ids.contains(tgt) {
            return Some(CreateFromSpecOutcome::EdgeReferencesUnknownNode {
                endpoint: "target",
                value: tgt.to_string(),
            });
        }
        if let Some(cond) = edge.get("condition").and_then(|v| v.as_str()) {
            if cond.len() > MAX_EDGE_CONDITION_LEN {
                return Some(CreateFromSpecOutcome::EdgeConditionTooLong);
            }
        }
    }
    None
}

/// Map a compile/persist refusal onto the per-node breakdown. Uses the
/// service's `user_facing_message`, so an internal error stays generic.
fn node_build_error(
    node_id: &str,
    e: &talos_inline_compile_service::InlineCompileError,
    persisting: bool,
) -> NodeBuildError {
    use talos_inline_compile_service::InlineCompileError as E;
    let stage = match e {
        E::InvalidArg(_) | E::DependencyValidation(_) | E::CapabilityCeilingViolation(_) => {
            BuildStage::Validate
        }
        E::LintFailed(_) => BuildStage::Lint,
        E::CompilationFailed(_) | E::NoWasmEmitted => BuildStage::Compile,
        E::NameCollision(_) | E::SharedModuleOverwrite(_) | E::PermissionDrift(_) => {
            BuildStage::NameCollision
        }
        E::Internal(_) if persisting => BuildStage::Store,
        E::Internal(_) => BuildStage::Compile,
    };
    NodeBuildError {
        node_id: node_id.to_string(),
        stage,
        messages: vec![e.user_facing_message()],
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
    ///
    /// The caller must have run its per-world role gate over
    /// [`inline_compile_worlds`] first — this service has no agent identity.
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

        // ── Phase 1: Structure — no I/O, before anything is compiled ─
        if let Some(outcome) = validate_spec_structure(req.spec_nodes, req.spec_edges) {
            return Ok(outcome);
        }

        // ── Phase 2: Resolve + compile every node, write nothing ─────
        let resolved = match self.resolve_spec_nodes(req.user_id, req.spec_nodes).await? {
            ResolveResult::Resolved(r) => r,
            ResolveResult::Outcome(o) => return Ok(o),
        };

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

    /// Resolve every node; compile every inline node through
    /// `InlineCompileService::compile_checked`; and only when ALL of them
    /// compiled, persist the compiled modules. A failure anywhere before the
    /// persist step writes nothing, so a retry after fixing node 3 does not
    /// collide with modules nodes 1 and 2 left behind.
    ///
    /// Assumes [`validate_spec_structure`] passed.
    async fn resolve_spec_nodes(
        &self,
        user_id: Uuid,
        spec_nodes: &[Value],
    ) -> anyhow::Result<ResolveResult> {
        struct Compiled<'a> {
            id: String,
            config: Value,
            input: talos_inline_compile_service::InlineCompileInput<'a>,
            compiled: talos_inline_compile_service::CompiledInline,
        }
        // Boxed: the compiled arm carries the WASM and the whole input, ~4x
        // the resolved arm (clippy `large_enum_variant`).
        enum Slot<'a> {
            Done(ResolvedSpecNode),
            Compiled(Box<Compiled<'a>>),
        }
        let mut slots: Vec<Slot<'_>> = Vec::with_capacity(spec_nodes.len());
        let mut build_errors: Vec<NodeBuildError> = Vec::new();

        for spec_node in spec_nodes {
            let node_id = spec_node_id(spec_node).to_string();
            let config = spec_node
                .get("config")
                .cloned()
                .unwrap_or(serde_json::json!({}));

            match classify_spec_node(spec_node) {
                // Path A — explicit module_id. Visibility-gated like
                // `add_node_to_workflow` (2026-09-25): before this a spec
                // accepted any tenant's module UUID at authoring time.
                SpecNodeSource::ModuleId(mid_str) => {
                    let mid: Uuid = mid_str.parse()?;
                    if !self
                        .module_repo
                        .module_accessible_by_user(mid, user_id)
                        .await?
                    {
                        return Ok(ResolveResult::Outcome(
                            CreateFromSpecOutcome::ModuleNotAccessible {
                                node_id,
                                module_id: mid,
                            },
                        ));
                    }
                    slots.push(Slot::Done(ResolvedSpecNode {
                        id: node_id,
                        module_id: mid_str.to_string(),
                        config,
                        compilation_note: None,
                    }));
                }
                // Path B — catalog name lookup.
                SpecNodeSource::ModuleName(module_name) => {
                    // MCP-886 (2026-05-14): log DB errors before collapsing
                    // to None. Behaviour preserved (still falls through to
                    // the None branch) since spec resolution has its own
                    // operator-actionable surface; telemetry-only fix.
                    let resolved_id = match self
                        .module_repo
                        .find_template_id_by_name_normalised(module_name, user_id)
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
                        Some(tid) => slots.push(Slot::Done(ResolvedSpecNode {
                            id: node_id,
                            module_id: tid.to_string(),
                            config,
                            compilation_note: None,
                        })),
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
                }
                // Path C — inline rust_code, through the SAME service
                // `add_node_to_workflow` uses (world allowlist, dependency
                // allowlist, lint, compile), with EXPLICIT grants — never the
                // world-derived `["*"]` host default — and a refusal, not an
                // overwrite, on a taken name.
                SpecNodeSource::InlineRust {
                    rust_code,
                    capability_world,
                } => {
                    let grants = match validate_inline_spec_node(
                        spec_node_id(spec_node),
                        spec_node,
                        rust_code,
                    ) {
                        Ok(g) => g,
                        // Unreachable after `validate_spec_structure`; kept
                        // total rather than `expect`ed.
                        Err(reason) => {
                            return Ok(ResolveResult::Outcome(
                                CreateFromSpecOutcome::InvalidInlineNode { node_id, reason },
                            ))
                        }
                    };
                    let input = talos_inline_compile_service::InlineCompileInput {
                        user_id,
                        // The workflow row does not exist yet. The id scopes
                        // only the shared-module guard, which `Refuse` never
                        // reaches.
                        workflow_id: Uuid::nil(),
                        // Spec workflows are created unbound.
                        workflow_actor_id: None,
                        node_id: spec_node_id(spec_node),
                        rust_code,
                        capability_world,
                        explicit_allowed_hosts: Some(grants.allowed_hosts),
                        explicit_allowed_secrets: Some(grants.allowed_secrets),
                        explicit_allowed_methods: Some(grants.allowed_methods),
                        dependencies: None,
                        integration_name: None,
                        fuel_budget: None,
                        on_name_collision: talos_inline_compile_service::NameCollision::Refuse,
                    };
                    match self.inline_compile.compile_checked(&input).await {
                        Ok(compiled) => slots.push(Slot::Compiled(Box::new(Compiled {
                            id: node_id,
                            config,
                            input,
                            compiled,
                        }))),
                        Err(e) => build_errors.push(node_build_error(&node_id, &e, false)),
                    }
                }
                // Refused by `validate_spec_structure`.
                SpecNodeSource::Missing => {
                    return Ok(ResolveResult::Outcome(
                        CreateFromSpecOutcome::NodeMissingResolutionField { node_id },
                    ));
                }
            }
        }

        if !build_errors.is_empty() {
            return Ok(ResolveResult::Outcome(
                CreateFromSpecOutcome::NodeBuildErrors {
                    errors: build_errors,
                },
            ));
        }

        // Every node compiled: persist. A failure HERE (a name taken since
        // the pre-compile check, a database error) can leave earlier nodes'
        // modules written — the one window this ordering does not close.
        let mut resolved = Vec::with_capacity(slots.len());
        for slot in slots {
            match slot {
                Slot::Done(r) => resolved.push(r),
                Slot::Compiled(boxed) => {
                    let Compiled {
                        id,
                        config,
                        input,
                        compiled,
                    } = *boxed;
                    match self.inline_compile.persist_compiled(&input, compiled).await {
                        Ok(outcome) => resolved.push(ResolvedSpecNode {
                            compilation_note: Some(format!(
                                "compiled {} → {}",
                                id, outcome.module_id
                            )),
                            id,
                            module_id: outcome.module_id.to_string(),
                            config,
                        }),
                        Err(e) => build_errors.push(node_build_error(&id, &e, true)),
                    }
                }
            }
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
}

/// Internal control-flow helper — distinguishes a fully-resolved node
/// list from an early-return outcome. Lets `resolve_spec_nodes` exit
/// the loop on the first hard failure without using `Result`-flavoured
/// short-circuits (the outcome enum is an Ok-class result, not Err).
enum ResolveResult {
    Resolved(Vec<ResolvedSpecNode>),
    Outcome(CreateFromSpecOutcome),
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
        assert_eq!(BuildStage::Validate.tag(), "validate");
        assert_eq!(BuildStage::Lint.tag(), "lint");
        assert_eq!(BuildStage::Compile.tag(), "compile");
        assert_eq!(BuildStage::NameCollision.tag(), "name_collision");
        assert_eq!(BuildStage::Store.tag(), "store");
    }

    fn inline(id: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut n = serde_json::json!({
            "id": id,
            "rust_code": "fn run() {}",
            "capability_world": "http-node",
        });
        for (k, v) in extra.as_object().unwrap() {
            n[k] = v.clone();
        }
        n
    }

    fn reason(o: Option<CreateFromSpecOutcome>) -> String {
        match o {
            Some(CreateFromSpecOutcome::InvalidInlineNode { reason, .. }) => reason,
            other => panic!("expected InvalidInlineNode, got {other:?}"),
        }
    }

    /// 2026-09-25: a spec never grants every host. Pre-fix the world alone
    /// decided, and every network-capable world got `["*"]`.
    #[test]
    fn a_wildcard_host_is_refused() {
        for hosts in [
            serde_json::json!(["*"]),
            serde_json::json!(["api.example.com", " * "]),
        ] {
            let r = reason(validate_spec_structure(
                &[inline("n1", serde_json::json!({ "allowed_hosts": hosts }))],
                &[],
            ));
            assert!(r.contains("\"*\""), "{r}");
        }
    }

    /// Absent grants are EMPTY, not the world default — an http-node module
    /// created by a spec with no `allowed_hosts` can reach nothing until its
    /// hosts are named.
    #[test]
    fn absent_grants_are_empty_not_the_world_default() {
        let n = inline("n1", serde_json::json!({}));
        let g = validate_inline_spec_node("n1", &n, "fn run() {}").unwrap();
        assert!(g.allowed_hosts.is_empty());
        assert!(g.allowed_methods.is_empty());
        assert!(g.allowed_secrets.is_empty());
        // Control: named hosts and verbs pass through (verbs uppercased).
        let n = inline(
            "n1",
            serde_json::json!({ "allowed_hosts": ["api.example.com"], "allowed_methods": ["get", "POST"] }),
        );
        let g = validate_inline_spec_node("n1", &n, "fn run() {}").unwrap();
        assert_eq!(g.allowed_hosts, vec!["api.example.com".to_string()]);
        assert_eq!(
            g.allowed_methods,
            vec!["GET".to_string(), "POST".to_string()]
        );
    }

    #[test]
    fn inline_node_names_sizes_and_grants_are_validated() {
        for (node, needle) in [
            (
                inline("bad name", serde_json::json!({})),
                "may only contain",
            ),
            (inline(&"x".repeat(201), serde_json::json!({})), "1-200"),
            (
                inline("n1", serde_json::json!({ "allowed_secrets": ["ok", 7] })),
                "allowed_secrets[1]",
            ),
            (
                inline("n1", serde_json::json!({ "allowed_methods": ["FETCH"] })),
                "FETCH",
            ),
            (
                inline(
                    "n1",
                    serde_json::json!({ "allowed_hosts": "api.example.com" }),
                ),
                "must be an array",
            ),
        ] {
            let r = reason(validate_spec_structure(&[node], &[]));
            assert!(r.contains(needle), "{needle}: {r}");
        }
        let big = serde_json::json!({
            "id": "n1",
            "rust_code": "x".repeat(MAX_INLINE_RUST_BYTES + 1),
        });
        assert!(reason(validate_spec_structure(&[big], &[])).contains("512 KiB"));
    }

    /// Two nodes sharing an id are refused before anything compiles — for
    /// inline nodes the second would otherwise collide with the first's
    /// module.
    #[test]
    fn duplicate_node_ids_are_refused() {
        let out = validate_spec_structure(
            &[
                inline("n1", serde_json::json!({})),
                inline("n1", serde_json::json!({})),
            ],
            &[],
        );
        assert!(matches!(
            out,
            Some(CreateFromSpecOutcome::DuplicateNodeId { node_id }) if node_id == "n1"
        ));
    }

    /// Edges are checked against the SPEC's ids before anything compiles, so a
    /// bad edge no longer leaves compiled modules behind.
    #[test]
    fn edges_are_validated_before_compile() {
        let out = validate_spec_structure(
            &[inline("n1", serde_json::json!({}))],
            &[serde_json::json!({ "source": "n1", "target": "ghost" })],
        );
        assert!(matches!(
            out,
            Some(CreateFromSpecOutcome::EdgeReferencesUnknownNode {
                endpoint: "target",
                ..
            })
        ));
        // Control: a well-formed spec passes.
        assert!(validate_spec_structure(
            &[
                inline("n1", serde_json::json!({})),
                inline("n2", serde_json::json!({}))
            ],
            &[serde_json::json!({ "source": "n1", "target": "n2" })],
        )
        .is_none());
    }

    /// The role gate's input follows the SAME precedence the service resolves
    /// by: a node carrying `module_id` AND `rust_code` compiles nothing.
    #[test]
    fn inline_compile_worlds_follows_resolution_precedence() {
        let nodes = vec![
            inline("a", serde_json::json!({})),
            serde_json::json!({ "id": "b", "rust_code": "fn run() {}" }),
            serde_json::json!({
                "id": "c",
                "module_id": "00000000-0000-0000-0000-000000000001",
                "rust_code": "fn run() {}",
                "capability_world": "automation-node",
            }),
            serde_json::json!({ "id": "d", "module_name": "x", "rust_code": "fn run() {}" }),
        ];
        assert_eq!(
            inline_compile_worlds(&nodes),
            vec![("a", "http-node"), ("b", "minimal-node")]
        );
    }
}
