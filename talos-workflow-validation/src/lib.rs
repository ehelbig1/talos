//! Workflow validation service.
//!
//! Extracted from the `validate_workflow` MCP handler so the same checks can be
//! applied automatically during `publish_version` and after `hot_update_module`.

use anyhow::Result;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use talos_workflow_repository::{NodeTemplateRow, WorkflowRepository};

// Re-use the vault path permission check from the MCP module.
use talos_workflow_job_protocol::vault_path_permitted as _vpp;

// ── Types ────────────────────────────────────────────────────────────────────

/// Severity of a validation issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationSeverity {
    /// Blocks publication — the workflow will fail at runtime.
    Error,
    /// Informational — the workflow may work, but there is a concern.
    Warning,
}

/// A single validation finding.
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub severity: ValidationSeverity,
    pub message: String,
    pub node_id: Option<String>,
    pub category: String,
}

/// Aggregate result of validating a workflow.
#[derive(Debug)]
pub struct ValidationResult {
    /// `true` when there are zero `Error`-severity issues.
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
}

impl ValidationResult {
    pub fn errors(&self) -> Vec<&ValidationIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity == ValidationSeverity::Error)
            .collect()
    }

    pub fn warnings(&self) -> Vec<&ValidationIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity == ValidationSeverity::Warning)
            .collect()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Detect Rhai expressions that are statically guaranteed to evaluate to
/// `true` — the canonical "infinite loop without an exit condition" pattern.
///
/// MCP-1211 (2026-05-18): added when a workflow's `condition: "true"` loop
/// was silently hitting `max_iterations` on every run with no operator
/// signal. The check is intentionally CONSERVATIVE — a runtime evaluator
/// (Rhai) could prove more truthy expressions but would risk false
/// positives on legitimate dynamic conditions. We flag only forms that a
/// human reader would also call "trivially true":
///
/// * `true` (case-insensitive)
/// * `1` (Rhai integer truthy)
/// * `!false`
///
/// Each may be surrounded by whitespace and any number of matched parens.
/// Multi-token expressions (`x == x`, `1 == 1`, etc.) are intentionally
/// NOT matched — they require a parser to disambiguate from legitimate
/// dynamic checks, and the false-positive risk outweighs the value.
pub(crate) fn is_trivially_true_condition(raw: &str) -> bool {
    // Strip whitespace + balanced enclosing parens until we reach the core.
    let mut s = raw.trim();
    loop {
        if !(s.starts_with('(') && s.ends_with(')')) {
            break;
        }
        // Confirm the leading `(` matches the trailing `)` (not a case like
        // `(a) || (b)` where the outer parens aren't a single group).
        let bytes = s.as_bytes();
        let mut depth: i32 = 0;
        let mut matches_outer = true;
        for (i, &b) in bytes.iter().enumerate() {
            match b {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 && i != bytes.len() - 1 {
                        matches_outer = false;
                        break;
                    }
                }
                _ => {}
            }
        }
        if !matches_outer {
            break;
        }
        s = s[1..s.len() - 1].trim();
    }
    let lower = s.to_ascii_lowercase();
    matches!(lower.as_str(), "true" | "1" | "!false")
}

// ── Service ──────────────────────────────────────────────────────────────────

pub struct WorkflowValidationService;

impl WorkflowValidationService {
    /// Validate a workflow's graph for structural correctness, module existence,
    /// config completeness, and vault permission compliance.
    ///
    /// Returns `Ok(ValidationResult)` — callers decide how to handle errors vs.
    /// warnings.  Database failures bubble up as `Err`.
    pub async fn validate(
        workflow_repo: &WorkflowRepository,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<ValidationResult> {
        let graph_json_str = workflow_repo
            .get_workflow_graph(workflow_id, user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Workflow not found or access denied"))?;

        let graph: serde_json::Value = serde_json::from_str(&graph_json_str)
            .unwrap_or_else(|_| serde_json::json!({"nodes":[],"edges":[]}));

        let mut issues: Vec<ValidationIssue> = Vec::new();

        let nodes = graph
            .get("nodes")
            .and_then(|n| n.as_array())
            .cloned()
            .unwrap_or_default();
        let edges = graph
            .get("edges")
            .and_then(|e| e.as_array())
            .cloned()
            .unwrap_or_default();

        // ── Module existence (batch) ─────────────────────────────────────
        let module_ids: Vec<Uuid> = nodes
            .iter()
            .filter_map(|n| {
                n.get("type")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse().ok())
            })
            .collect();

        if !module_ids.is_empty() {
            let existing: HashSet<Uuid> = workflow_repo
                .modules_exist(&module_ids)
                .await
                .unwrap_or_default()
                .into_iter()
                .collect();

            for mid in &module_ids {
                if !existing.contains(mid) {
                    issues.push(ValidationIssue {
                        severity: ValidationSeverity::Error,
                        message: format!(
                            "Module '{}' not found in templates or compiled modules",
                            mid
                        ),
                        node_id: None,
                        category: "missing_module".into(),
                    });
                }
            }
        }

        // ── Graph structure (cycle + edge validation) ────────────────────
        let node_ids: Vec<&str> = nodes
            .iter()
            .filter_map(|n| n.get("id").and_then(|v| v.as_str()))
            .collect();

        let node_index_map: HashMap<&str, usize> = node_ids
            .iter()
            .enumerate()
            .map(|(i, id)| (*id, i))
            .collect();

        let mut digraph = petgraph::graph::DiGraph::<&str, ()>::new();
        let graph_indices: Vec<petgraph::graph::NodeIndex> =
            node_ids.iter().map(|id| digraph.add_node(id)).collect();

        for edge in &edges {
            let src = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let tgt = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
            if let (Some(&si), Some(&ti)) = (node_index_map.get(src), node_index_map.get(tgt)) {
                digraph.add_edge(graph_indices[si], graph_indices[ti], ());
            }
        }

        if petgraph::algo::is_cyclic_directed(&digraph) {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::Error,
                message: "Graph contains a cycle".into(),
                node_id: None,
                category: "cycle".into(),
            });
        }

        let node_id_set: HashSet<&str> = node_ids.iter().copied().collect();
        for edge in &edges {
            let src = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let tgt = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
            if !node_id_set.contains(src) {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Error,
                    message: format!("Edge source '{}' does not match any node", src),
                    node_id: None,
                    category: "edge".into(),
                });
            }
            if !node_id_set.contains(tgt) {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Error,
                    message: format!("Edge target '{}' does not match any node", tgt),
                    node_id: None,
                    category: "edge".into(),
                });
            }
        }

        // ── Config completeness + vault permission check ─────────────────
        if !module_ids.is_empty() {
            let (template_rows, installed_secrets) = tokio::join!(
                workflow_repo.get_templates_by_ids(&module_ids),
                workflow_repo.get_installed_secrets_by_template_ids(&module_ids, user_id),
            );
            let template_rows: Vec<NodeTemplateRow> = template_rows.unwrap_or_default();
            let installed_secrets: HashMap<Uuid, Vec<String>> =
                installed_secrets.unwrap_or_default();

            let template_schemas: HashMap<Uuid, (String, serde_json::Value, Vec<String>)> =
                template_rows
                    .into_iter()
                    .map(|r| {
                        let effective_secrets = installed_secrets
                            .get(&r.id)
                            .cloned()
                            .unwrap_or(r.allowed_secrets);
                        (r.id, (r.name, r.config_schema, effective_secrets))
                    })
                    .collect();

            for node in &nodes {
                let node_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                let node_data = node.get("data").cloned().unwrap_or(serde_json::json!({}));
                let node_config = node_data
                    .get("config")
                    .cloned()
                    .unwrap_or_else(|| node_data.clone());
                let tid: Option<Uuid> = node
                    .get("type")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse().ok());

                if let Some(tid) = tid {
                    if let Some((module_name, schema, allowed_secrets)) = template_schemas.get(&tid)
                    {
                        // Required config fields
                        let required: Vec<String> = schema
                            .get("required")
                            .and_then(|r| r.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();

                        let missing: Vec<String> = required
                            .iter()
                            .filter(|f| {
                                node_config
                                    .get(f.as_str())
                                    .map(|v| {
                                        v.is_null()
                                            || v.as_str().map(|s| s.is_empty()).unwrap_or(false)
                                    })
                                    .unwrap_or(true)
                            })
                            .cloned()
                            .collect();

                        if !missing.is_empty() {
                            issues.push(ValidationIssue {
                                severity: ValidationSeverity::Error,
                                message: format!(
                                    "Node '{}' (module: {}) missing required config: {}. \
                                     Set with update_node_config before triggering.",
                                    node_id,
                                    module_name,
                                    missing
                                        .iter()
                                        .map(|s| format!("'{}'", s))
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                ),
                                node_id: Some(node_id.to_string()),
                                category: "config".into(),
                            });
                        }

                        // Vault path permission check
                        let has_wildcard = allowed_secrets.iter().any(|s| s == "*");
                        if let Some(cfg_obj) = node_config.as_object() {
                            for (field_key, field_val) in cfg_obj {
                                if let Some(val_str) = field_val.as_str() {
                                    if let Some(path) = val_str.strip_prefix("vault://") {
                                        if path.is_empty() {
                                            issues.push(ValidationIssue {
                                                severity: ValidationSeverity::Error,
                                                message: format!(
                                                    "Node '{}' (module: {}) config field '{}' has an empty \
                                                     vault:// reference. Must be 'vault://path/to/key'.",
                                                    node_id, module_name, field_key
                                                ),
                                                node_id: Some(node_id.to_string()),
                                                category: "vault".into(),
                                            });
                                            continue;
                                        }
                                        if path.starts_with("vault://") {
                                            issues.push(ValidationIssue {
                                                severity: ValidationSeverity::Error,
                                                message: format!(
                                                    "Node '{}' (module: {}) config field '{}' has a nested \
                                                     vault:// prefix (value: '{}'). Use a single prefix.",
                                                    node_id, module_name, field_key, val_str
                                                ),
                                                node_id: Some(node_id.to_string()),
                                                category: "vault".into(),
                                            });
                                            continue;
                                        }
                                        if !has_wildcard && !_vpp(allowed_secrets, path) {
                                            issues.push(ValidationIssue {
                                                severity: ValidationSeverity::Error,
                                                message: format!(
                                                    "Node '{}' (module: {}) config field '{}' references \
                                                     vault path '{}' which is blocked by the module's \
                                                     allowed_secrets [{}].",
                                                    node_id,
                                                    module_name,
                                                    field_key,
                                                    path,
                                                    if allowed_secrets.is_empty() {
                                                        "deny-all — no secrets granted".to_string()
                                                    } else {
                                                        allowed_secrets.join(", ")
                                                    }
                                                ),
                                                node_id: Some(node_id.to_string()),
                                                category: "vault".into(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── LLM I/O enforcement-key advisory (Warning) ──────────────────
        // These config keys gate input sanitization (SANITIZE_FOR_LLM /
        // BLOCKED_PATTERNS) and output guardrails (OUTPUT_SCHEMA /
        // MAX_OUTPUT_CHARS_ENFORCED / MAX_OUTPUT_TOKENS_ENFORCED) inside
        // LLM-inference modules. Earlier compiled module bytes ignored
        // these keys silently; reinstalling the module recompiles against
        // the current template, which honours them.
        const LLM_ENFORCEMENT_KEYS: &[&str] = &[
            "SANITIZE_FOR_LLM",
            "BLOCKED_PATTERNS",
            "OUTPUT_SCHEMA",
            "MAX_OUTPUT_CHARS_ENFORCED",
            "MAX_OUTPUT_TOKENS_ENFORCED",
        ];
        for node in &nodes {
            let node_label = node.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
            let node_config = node
                .get("config")
                .or_else(|| node.get("data").and_then(|d| d.get("config")));
            if let Some(cfg) = node_config {
                let keys_present: Vec<&str> = LLM_ENFORCEMENT_KEYS
                    .iter()
                    .copied()
                    .filter(|k| cfg.get(k).is_some())
                    .collect();
                if !keys_present.is_empty() {
                    issues.push(ValidationIssue {
                        severity: ValidationSeverity::Warning,
                        message: format!(
                            "Node '{}' configures LLM input/output enforcement key(s) {:?}. \
                             If the underlying module was compiled before these keys were honoured, \
                             they will be silently ignored at runtime — reinstall via \
                             reinstall_module_from_catalog (or recompile via hot_update_module) \
                             to pick up the current enforcement behaviour.",
                            node_label, keys_present
                        ),
                        node_id: Some(node_label.to_string()),
                        category: "llm-enforcement".into(),
                    });
                }
            }
        }

        // ── Reachability analysis (Warning) ──────────────────────────────
        let has_cycle = issues.iter().any(|i| i.category == "cycle");
        if !has_cycle && nodes.len() > 1 {
            let mut reachable: HashSet<petgraph::graph::NodeIndex> = HashSet::new();
            for (&idx, _) in graph_indices.iter().zip(node_ids.iter()) {
                if digraph
                    .edges_directed(idx, petgraph::Direction::Incoming)
                    .next()
                    .is_none()
                {
                    let mut dfs = petgraph::visit::Dfs::new(&digraph, idx);
                    while let Some(visited) = dfs.next(&digraph) {
                        reachable.insert(visited);
                    }
                }
            }
            let unreachable: Vec<&str> = graph_indices
                .iter()
                .zip(node_ids.iter())
                .filter_map(|(&idx, &id)| {
                    if !reachable.contains(&idx) {
                        Some(id)
                    } else {
                        None
                    }
                })
                .collect();
            if !unreachable.is_empty() {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    message: format!(
                        "Unreachable node(s) detected — will never execute: [{}].",
                        unreachable.join(", ")
                    ),
                    node_id: None,
                    category: "reachability".into(),
                });
            }
        }

        // ── Isolated-node detection (Warning) ─────────────────────────────
        // MCP-1211 (2026-05-18): the reachability check above treats any
        // node with no incoming edges as a DFS root, so a node with ZERO
        // edges (no incoming AND no outgoing) is "reachable from itself"
        // and slips through. In practice an isolated node runs every
        // execution but contributes nothing to the data flow — wasted
        // fuel with no operator signal. The daily-brief workflow has run
        // an isolated probe-loop node for 19 consecutive days, burning
        // ~46.5M fuel total with no warning surfaced. Flag isolated
        // non-trivial graphs (skip for single-node workflows, which are
        // legitimately edge-less).
        if nodes.len() > 1 {
            let isolated: Vec<&str> = graph_indices
                .iter()
                .zip(node_ids.iter())
                .filter_map(|(&idx, &id)| {
                    let no_in = digraph
                        .edges_directed(idx, petgraph::Direction::Incoming)
                        .next()
                        .is_none();
                    let no_out = digraph
                        .edges_directed(idx, petgraph::Direction::Outgoing)
                        .next()
                        .is_none();
                    if no_in && no_out {
                        Some(id)
                    } else {
                        None
                    }
                })
                .collect();
            if !isolated.is_empty() {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    message: format!(
                        "Isolated node(s) with no incoming or outgoing edges — they run on every \
                         execution but contribute nothing to the data flow: [{}]. \
                         Either connect them with add_edge or remove them.",
                        isolated.join(", ")
                    ),
                    node_id: None,
                    category: "isolated".into(),
                });
            }
        }

        // ── Loop-condition trivially-true detection (Warning) ─────────────
        // MCP-1211 (2026-05-18): a loop node with `condition: "true"`
        // (or any trivially-true Rhai expression) will always hit its
        // max_iterations safety cap. The execution still reports success,
        // so operators have no signal that the loop is misconfigured.
        // Conservative match: only flag literal-true forms — `"true"`,
        // `"1"`, `"!false"`, with optional whitespace and surrounding
        // parens. More complex Rhai expressions may evaluate truthy but
        // a static check would have false positives.
        for node in &nodes {
            let node_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            let kind = node.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            if kind != "loop" {
                continue;
            }
            let condition = node
                .get("data")
                .and_then(|d| d.get("condition"))
                .and_then(|c| c.as_str())
                .unwrap_or("");
            if is_trivially_true_condition(condition) {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    message: format!(
                        "Loop node '{}' has a trivially-true condition ('{}'). The loop will run \
                         until max_iterations and terminate via the safety cap on every \
                         execution — almost certainly a misconfigured exit condition. Use a Rhai \
                         expression that references the body's output (e.g. \
                         `output.finished != true`).",
                        node_id, condition
                    ),
                    node_id: Some(node_id.to_string()),
                    category: "loop-condition".into(),
                });
            }
        }

        let valid = !issues
            .iter()
            .any(|i| i.severity == ValidationSeverity::Error);
        Ok(ValidationResult { valid, issues })
    }

    /// Trigger-time input-schema check: fetch the workflow's declared
    /// `input_schema`, validate `trigger_input` against it, and return a
    /// typed [`InputSchemaCheck`] outcome the caller maps to JSON-RPC.
    ///
    /// `validate_only=true` requests dry-run mode — the result is returned
    /// even when validation fails, instead of short-circuiting. The caller
    /// (handler) shapes the dry-run JSON response from [`InputSchemaCheck::DryRun`].
    ///
    /// Database fetch errors degrade to `NoSchema` (logged at error level)
    /// — matching pre-extraction handler behavior, which intentionally
    /// allowed triggers to proceed when schema-fetch failed rather than
    /// rejecting all triggers on a transient DB hiccup.
    pub async fn check_trigger_input(
        workflow_repo: &WorkflowRepository,
        workflow_id: Uuid,
        user_id: Uuid,
        trigger_input: &serde_json::Value,
        validate_only: bool,
    ) -> InputSchemaCheck {
        let input_schema = match workflow_repo
            .get_workflow_input_schema(workflow_id, user_id)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("get_workflow_input_schema error: {}", e);
                None
            }
        };

        match (input_schema, validate_only) {
            (None, false) => InputSchemaCheck::NoSchema,
            (None, true) => InputSchemaCheck::DryRun {
                schema: None,
                errors: vec![],
            },
            (Some(schema), validate_only) => {
                let errors = validate_input_against_schema(&schema, trigger_input);
                if validate_only {
                    InputSchemaCheck::DryRun {
                        schema: Some(schema),
                        errors,
                    }
                } else if errors.is_empty() {
                    InputSchemaCheck::Valid
                } else {
                    InputSchemaCheck::Invalid(errors)
                }
            }
        }
    }
}

/// Trigger-time outcome of [`WorkflowValidationService::check_trigger_input`].
///
/// The variants split into "continue" (NoSchema, Valid), "block" (Invalid),
/// and "early-return-with-result" (DryRun) buckets — the handler picks a
/// JSON-RPC response shape per bucket.
#[derive(Debug)]
pub enum InputSchemaCheck {
    /// No `input_schema` is set on the workflow. Triggers proceed; any
    /// input is accepted.
    NoSchema,
    /// Schema is set and the trigger input passes. Caller continues to
    /// dispatch.
    Valid,
    /// Schema is set and the trigger input failed validation. Caller maps
    /// to MCP `-32602` with the joined error list.
    Invalid(Vec<String>),
    /// `validate_input=true` was supplied — return the validation result
    /// instead of dispatching. `schema` is `None` when no schema is set
    /// (the dry-run still reports valid=true with a "no schema" hint).
    DryRun {
        schema: Option<serde_json::Value>,
        errors: Vec<String>,
    },
}

/// Validate a JSON value against a JSON-Schema-flavored schema document.
///
/// Lifted from the inline `talos_mcp_handlers::workflows::validate_against_schema`
/// helper in May 2026; the move enables reuse from
/// [`WorkflowValidationService::check_trigger_input`] and any future
/// trigger-time validation surface (GraphQL, REST). Pure function — no
/// I/O, no shared state — recursion handles `anyOf` / `oneOf` / `allOf`
/// and nested-object descent.
///
/// Supports a deliberately-limited subset of JSON Schema:
/// * Top-level: `type`, `enum`, `minimum`/`maximum`, `minLength`/`maxLength`,
///   `pattern`, `anyOf`/`oneOf`/`allOf`, `required`, `additionalProperties: false`,
///   `properties`.
/// * Per-property: same constraint set as top-level, evaluated under the
///   property name for diagnostic prefixing.
///
/// Pattern compilation is bounded — patterns over 500 chars are rejected
/// before regex compilation, and the compiled-automaton size is capped at
/// 256 KB to prevent pathologically-complex patterns from stalling the
/// trigger path.
///
/// MCP-158 (2026-05-08): meta-validate a JSON Schema document at save
/// time so an operator-typo'd schema doesn't produce false-positive
/// `valid: true` responses at evaluation time.
///
/// `validate_input_against_schema` (below) silently passes through
/// unknown `type` values (line: `_ => true`) — which means a schema
/// like `{"type": "stirng"}` accepts every input. That's a footgun:
/// the operator stores broken validation, then `validate_workflow_input`
/// confidently green-lights any payload, and only the next workflow
/// failure reveals the typo. Catch it here at save time instead.
///
/// Recursively walks the schema's `properties`, `items`, `allOf`,
/// `anyOf`, `oneOf`, and `not` slots — same shape the runtime
/// evaluator handles. Returns a list of human-readable problems,
/// empty when the schema is well-formed enough to be safe.
/// MCP-204 helper: human-readable name for a JSON value's type.
/// Used in schema-validation error messages so the operator sees
/// "got string" / "got array" / "got null" rather than the raw
/// JSON dump.
fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// MCP-558: maximum schema/input nesting depth. The `walk` and
/// `validate_input_against_schema` recursive paths previously had no
/// cap, so a user-supplied schema (set via `set_workflow_input_schema`)
/// or trigger input could nest deeply enough to overflow the tokio
/// worker thread's 2 MB stack (~16-32k frames at 64-128 bytes each).
/// A 1 MB JSON body of `[[[[[...]]]]]` is ~500k levels, which crashes
/// the controller for ALL users, not just the request's sender —
/// auth doesn't bound the blast radius.
///
/// 128 is well above any legitimate schema (JSON Schema dialect
/// authors recommend ≤ 10 levels) and well below the stack-overflow
/// threshold. Picked to match the `MAX_CANONICAL_DEPTH` used by
/// `talos-memory`'s signed-RPC canonical-bytes encoder so the two
/// related fail-closed depth limits agree.
const MAX_SCHEMA_DEPTH: usize = 128;

pub fn validate_schema_well_formed(schema: &serde_json::Value) -> Vec<String> {
    const VALID_TYPES: &[&str] = &[
        "null", "boolean", "object", "array", "number", "string", "integer",
    ];
    let mut errors = Vec::new();
    fn walk(node: &serde_json::Value, path: &str, errors: &mut Vec<String>, depth: usize) {
        const VALID_TYPES: &[&str] = &[
            "null", "boolean", "object", "array", "number", "string", "integer",
        ];
        if depth > MAX_SCHEMA_DEPTH {
            // MCP-558: short-circuit on excessive nesting. We push a
            // diagnostic so the operator can see what tripped the gate
            // (instead of a mysterious empty-errors result on what
            // should be an invalid schema).
            errors.push(format!(
                "Schema at '{}' exceeds maximum nesting depth of {} — refusing to walk further (possible DoS).",
                if path.is_empty() { "root" } else { path },
                MAX_SCHEMA_DEPTH
            ));
            return;
        }
        let obj = match node.as_object() {
            Some(o) => o,
            None => return,
        };
        if let Some(t) = obj.get("type") {
            // type can be a string OR an array of strings (JSON Schema allows
            // union types). Both shapes get validated against VALID_TYPES.
            match t {
                serde_json::Value::String(s) => {
                    if !VALID_TYPES.contains(&s.as_str()) {
                        errors.push(format!(
                            "Schema {} has unknown type '{}'. Valid types: {}.",
                            if path.is_empty() {
                                "root".to_string()
                            } else {
                                format!("at '{}'", path)
                            },
                            s,
                            VALID_TYPES.join(", ")
                        ));
                    }
                }
                serde_json::Value::Array(arr) => {
                    for v in arr {
                        if let Some(s) = v.as_str() {
                            if !VALID_TYPES.contains(&s) {
                                errors.push(format!(
                                    "Schema {} has unknown type '{}' in type-union. Valid types: {}.",
                                    if path.is_empty() { "root".to_string() } else { format!("at '{}'", path) },
                                    s,
                                    VALID_TYPES.join(", ")
                                ));
                            }
                        } else {
                            errors.push(format!(
                                "Schema {} type-union must contain only strings, got {}.",
                                if path.is_empty() {
                                    "root".to_string()
                                } else {
                                    format!("at '{}'", path)
                                },
                                v
                            ));
                        }
                    }
                }
                _ => {
                    errors.push(format!(
                        "Schema {} `type` must be a string or array of strings, got {}.",
                        if path.is_empty() {
                            "root".to_string()
                        } else {
                            format!("at '{}'", path)
                        },
                        t
                    ));
                }
            }
        }
        // MCP-204 (2026-05-08): validate each schema keyword's shape
        // explicitly. Pre-fix `obj.get(kw).and_then(|v| v.as_*())`
        // silently no-op'd when the keyword was present but the
        // wrong JSON type — e.g. `properties: "not-an-object"` or
        // `properties: ["not", "an", "object"]` would slip through
        // and produce confusing runtime behaviour.
        if let Some(props) = obj.get("properties") {
            match props.as_object() {
                Some(o) => {
                    for (k, sub) in o {
                        walk(sub, &format!("{}.properties.{}", path, k), errors, depth + 1);
                    }
                }
                None => errors.push(format!(
                    "Schema {} `properties` must be an object mapping field names to schemas, got {}.",
                    if path.is_empty() { "root".to_string() } else { format!("at '{}'", path) },
                    json_kind(props)
                )),
            }
        }
        if let Some(items) = obj.get("items") {
            // items may be a single schema OR an array of schemas (tuple form).
            match items {
                serde_json::Value::Object(_) => {
                    walk(items, &format!("{}.items", path), errors, depth + 1)
                }
                serde_json::Value::Array(arr) => {
                    for (i, sub) in arr.iter().enumerate() {
                        walk(sub, &format!("{}.items[{}]", path, i), errors, depth + 1);
                    }
                }
                _ => errors.push(format!(
                    "Schema {} `items` must be a schema object or array of schemas, got {}.",
                    if path.is_empty() {
                        "root".to_string()
                    } else {
                        format!("at '{}'", path)
                    },
                    json_kind(items)
                )),
            }
        }
        for kw in &["allOf", "anyOf", "oneOf"] {
            if let Some(v) = obj.get(*kw) {
                match v.as_array() {
                    Some(arr) => {
                        for (i, sub) in arr.iter().enumerate() {
                            walk(sub, &format!("{}.{}[{}]", path, kw, i), errors, depth + 1);
                        }
                    }
                    None => errors.push(format!(
                        "Schema {} `{}` must be an array of schemas, got {}.",
                        if path.is_empty() {
                            "root".to_string()
                        } else {
                            format!("at '{}'", path)
                        },
                        kw,
                        json_kind(v)
                    )),
                }
            }
        }
        if let Some(not) = obj.get("not") {
            if not.is_object() {
                walk(not, &format!("{}.not", path), errors, depth + 1);
            } else {
                errors.push(format!(
                    "Schema {} `not` must be a schema object, got {}.",
                    if path.is_empty() {
                        "root".to_string()
                    } else {
                        format!("at '{}'", path)
                    },
                    json_kind(not)
                ));
            }
        }
        if let Some(req) = obj.get("required") {
            if !req.is_array() {
                errors.push(format!(
                    "Schema {} `required` must be an array of strings.",
                    if path.is_empty() {
                        "root".to_string()
                    } else {
                        format!("at '{}'", path)
                    }
                ));
            } else if let Some(arr) = req.as_array() {
                for (i, v) in arr.iter().enumerate() {
                    if !v.is_string() {
                        errors.push(format!(
                            "Schema {} `required[{}]` must be a string, got {}.",
                            if path.is_empty() {
                                "root".to_string()
                            } else {
                                format!("at '{}'", path)
                            },
                            i,
                            v
                        ));
                    }
                }
            }
        }
    }
    walk(schema, "", &mut errors, 0);
    let _ = VALID_TYPES;
    errors
}

#[cfg(test)]
mod schema_meta_validation_tests {
    use super::validate_schema_well_formed;
    use serde_json::json;

    /// MCP-204 (2026-05-08): the validator silently no-op'd on
    /// `properties` / `items` / `allOf` / `anyOf` / `oneOf` / `not`
    /// when the keyword was present but the wrong JSON type, since
    /// the chained `as_*()` returned None and the if-let pattern
    /// matched nothing. Each shape now produces a specific error.
    #[test]
    fn rejects_properties_non_object() {
        for bad in [
            json!({"type": "object", "properties": "not-an-object"}),
            json!({"type": "object", "properties": ["not", "an", "object"]}),
            json!({"type": "object", "properties": null}),
            json!({"type": "object", "properties": 42}),
        ] {
            let errs = validate_schema_well_formed(&bad);
            assert!(
                errs.iter()
                    .any(|e| e.contains("`properties` must be an object")),
                "should reject {bad}; got {errs:?}"
            );
        }
    }

    #[test]
    fn rejects_items_wrong_type() {
        // items can be object OR array; null / string / number reject.
        for bad in [
            json!({"type": "array", "items": "string"}),
            json!({"type": "array", "items": null}),
            json!({"type": "array", "items": 5}),
        ] {
            let errs = validate_schema_well_formed(&bad);
            assert!(
                errs.iter()
                    .any(|e| e.contains("`items` must be a schema object or array")),
                "should reject {bad}; got {errs:?}"
            );
        }
    }

    #[test]
    fn accepts_items_array_form() {
        // Tuple form: items is an array of schemas.
        let schema = json!({
            "type": "array",
            "items": [{"type": "string"}, {"type": "integer"}]
        });
        assert!(validate_schema_well_formed(&schema).is_empty());
    }

    #[test]
    fn rejects_combinator_wrong_type() {
        for kw in ["allOf", "anyOf", "oneOf"] {
            let bad = json!({ kw: "not-array" });
            let errs = validate_schema_well_formed(&bad);
            assert!(
                errs.iter()
                    .any(|e| e.contains(&format!("`{kw}` must be an array"))),
                "should reject {bad}; got {errs:?}"
            );
        }
    }

    #[test]
    fn rejects_not_non_object() {
        let bad = json!({"not": "not-an-object"});
        let errs = validate_schema_well_formed(&bad);
        assert!(
            errs.iter()
                .any(|e| e.contains("`not` must be a schema object")),
            "got {errs:?}"
        );
    }

    #[test]
    fn accepts_canonical_schemas() {
        assert!(validate_schema_well_formed(&json!({})).is_empty());
        assert!(validate_schema_well_formed(&json!({"type": "object"})).is_empty());
        assert!(validate_schema_well_formed(&json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"},
                "tags": {"type": "array", "items": {"type": "string"}}
            }
        }))
        .is_empty());
    }

    #[test]
    fn rejects_unknown_type_typo() {
        let errs = validate_schema_well_formed(&json!({"type": "stirng"}));
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("stirng"));
    }

    #[test]
    fn rejects_nested_unknown_type() {
        let errs = validate_schema_well_formed(&json!({
            "type": "object",
            "properties": {
                "id": {"type": "uuid"}
            }
        }));
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("uuid"));
        assert!(errs[0].contains("properties.id"));
    }

    #[test]
    fn accepts_type_union() {
        assert!(validate_schema_well_formed(&json!({
            "type": ["string", "null"]
        }))
        .is_empty());
    }

    #[test]
    fn rejects_type_union_typo() {
        let errs = validate_schema_well_formed(&json!({
            "type": ["string", "nul"]
        }));
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("nul"));
    }

    #[test]
    fn rejects_required_non_array() {
        let errs = validate_schema_well_formed(&json!({
            "type": "object",
            "required": "name"
        }));
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("required"));
    }
}

/// MCP-467: validate each element of an array against the schema's
/// `items` clause. JSON Schema admits two forms:
///   * `items: {schema}` — every element validated against `schema`.
///   * `items: [s0, s1, ...]` — tuple form; element at index `i`
///     validated against `s_i`. Elements past the end of the schema
///     list are unconstrained (per JSON Schema draft-07).
///
/// Pre-fix, the runtime validator silently dropped the `items` clause
/// — operators who defined `{"type": "array", "items": {"type":
/// "integer"}}` had their array contents bypass validation at trigger
/// time. The meta-validator (`validate_schema_well_formed`) correctly
/// walked `items` to check schema well-formedness, but the runtime
/// path never enforced the items contract, so payloads like
/// `["not", "ints"]` flowed through unblocked.
///
/// `index_label` prefixes errors with the property name when this is
/// called from per-property validation, or `""` when called from the
/// top-level array path. Errors are surfaced as `<prefix>[i]: <err>`
/// to give operators an actionable diagnostic.
fn validate_array_items(
    items_schema: &serde_json::Value,
    arr: &[serde_json::Value],
    index_label: &str,
    depth: usize,
) -> Vec<String> {
    let mut out = Vec::new();
    let prefix = if index_label.is_empty() {
        String::new()
    } else {
        format!("Field '{}' ", index_label)
    };
    match items_schema {
        serde_json::Value::Object(_) => {
            for (i, item) in arr.iter().enumerate() {
                for err in validate_input_against_schema_depth(items_schema, item, depth + 1) {
                    out.push(format!("{}items[{}]: {}", prefix, i, err));
                }
            }
        }
        serde_json::Value::Array(tuple) => {
            for (i, item) in arr.iter().enumerate() {
                if let Some(sub) = tuple.get(i) {
                    for err in validate_input_against_schema_depth(sub, item, depth + 1) {
                        out.push(format!("{}items[{}]: {}", prefix, i, err));
                    }
                }
                // Elements past the tuple length are unconstrained.
            }
        }
        // Other shapes are caught by the meta-validator at save time;
        // be lenient here so a stored schema that slipped through (or
        // predates meta-validation) doesn't reject every input.
        _ => {}
    }
    out
}

/// Returns the (possibly-empty) list of human-readable error messages.
/// An empty Vec means the input passed.
pub fn validate_input_against_schema(
    schema: &serde_json::Value,
    input: &serde_json::Value,
) -> Vec<String> {
    // MCP-558: enter the depth-bounded path. The wrapper preserves the
    // existing public signature so every caller (handlers, MCP tools,
    // GraphQL) inherits the protection without explicit opt-in.
    validate_input_against_schema_depth(schema, input, 0)
}

fn validate_input_against_schema_depth(
    schema: &serde_json::Value,
    input: &serde_json::Value,
    depth: usize,
) -> Vec<String> {
    if depth > MAX_SCHEMA_DEPTH {
        // MCP-558: stop recursion before the tokio worker thread's 2 MB
        // stack runs out. anyOf/oneOf/allOf/items/properties are the
        // recursive surfaces; a deeply-nested schema OR a deeply-nested
        // INPUT (when paired with a permissive schema like
        // `{"type":"object"}`) both reach this gate. Surface a single
        // error string so the caller sees why validation cut short.
        return vec![format!(
            "Validation depth exceeded {} — refusing to recurse further (possible DoS).",
            MAX_SCHEMA_DEPTH
        )];
    }
    let mut errors = Vec::new();

    // ── Top-level type check ──────────────────────────────────────────────────
    // Must run BEFORE anyOf/oneOf/allOf so that sub-schemas like {type:"number"}
    // or {type:"string","enum":[...]} correctly reject mismatched values when called
    // recursively. Without this, a sub-schema with no `properties` block returns []
    // (no errors) for any input, making anyOf/oneOf/allOf effectively no-ops.
    if let Some(expected_type) = schema.get("type").and_then(|t| t.as_str()) {
        let type_ok = match expected_type {
            "string" => input.is_string(),
            "number" => input.is_number(),
            "integer" => input.is_i64() || input.is_u64(),
            "boolean" => input.is_boolean(),
            "array" => input.is_array(),
            "object" => input.is_object(),
            "null" => input.is_null(),
            _ => true,
        };
        if !type_ok {
            let actual = match input {
                serde_json::Value::Null => "null",
                serde_json::Value::Bool(_) => "boolean",
                serde_json::Value::Number(_) => "number",
                serde_json::Value::String(_) => "string",
                serde_json::Value::Array(_) => "array",
                serde_json::Value::Object(_) => "object",
            };
            // Early return: a type mismatch makes all further constraint checks meaningless.
            // MCP-1032: schema-author-supplied `expected_type` capped; `actual` is from
            // a fixed 6-string allowlist (null/boolean/number/string/array/object).
            errors.push(format!(
                "Expected type '{}' but got '{}'",
                talos_text_util::bounded_preview(expected_type, 64),
                actual
            ));
            return errors;
        }
    }

    // ── Top-level `items` (array element) validation — MCP-467 ──────────
    if let (Some(items_schema), Some(arr)) = (schema.get("items"), input.as_array()) {
        errors.extend(validate_array_items(items_schema, arr, "", depth));
    }

    // ── Top-level enum check ──────────────────────────────────────────────────
    if let Some(enum_values) = schema.get("enum").and_then(|e| e.as_array()) {
        if !enum_values.contains(input) {
            let valid_values: Vec<String> = enum_values
                .iter()
                .map(|v| match v.as_str() {
                    Some(s) => format!("\"{}\"", s),
                    None => v.to_string(),
                })
                .collect();
            errors.push(format!(
                "Value must be one of [{}] but got {}",
                valid_values.join(", "),
                input
            ));
        }
    }

    // ── Top-level numeric range checks ────────────────────────────────────────
    if let Some(n) = input.as_f64() {
        if let Some(min) = schema.get("minimum").and_then(|v| v.as_f64()) {
            if n < min {
                errors.push(format!("Value must be >= {}", min));
            }
        }
        if let Some(max) = schema.get("maximum").and_then(|v| v.as_f64()) {
            if n > max {
                errors.push(format!("Value must be <= {}", max));
            }
        }
    }

    // ── Top-level string constraint checks ────────────────────────────────────
    if let Some(s) = input.as_str() {
        let len = s.chars().count();
        if let Some(min_len) = schema.get("minLength").and_then(|v| v.as_u64()) {
            if len < min_len as usize {
                errors.push(format!(
                    "Value must be at least {} character(s) long",
                    min_len
                ));
            }
        }
        if let Some(max_len) = schema.get("maxLength").and_then(|v| v.as_u64()) {
            if len > max_len as usize {
                errors.push(format!(
                    "Value must be at most {} character(s) long",
                    max_len
                ));
            }
        }
        if let Some(pat) = schema.get("pattern").and_then(|p| p.as_str()) {
            if pat.len() > 500 {
                errors.push(
                    "Regex pattern in schema exceeds maximum length of 500 characters".into(),
                );
            } else {
                // Bound the compiled automaton size (default 10 MB → capped at 256 KB)
                // to prevent slow compilation of pathologically complex patterns.
                match regex::RegexBuilder::new(pat).size_limit(256 * 1024).build() {
                    Ok(re) if !re.is_match(s) => {
                        errors.push(format!("Value does not match pattern {:?}", pat));
                    }
                    Err(_) => {
                        errors.push(format!("Invalid or too-complex regex pattern {:?}", pat));
                    }
                    _ => {}
                }
            }
        }
    }

    // ── anyOf ─────────────────────────────────────────────────────────────────
    if let Some(any_of) = schema.get("anyOf").and_then(|v| v.as_array()) {
        if !any_of
            .iter()
            .any(|s| validate_input_against_schema_depth(s, input, depth + 1).is_empty())
        {
            errors.push("Value does not match any of the expected schemas (anyOf)".into());
        }
    }

    // ── oneOf ─────────────────────────────────────────────────────────────────
    if let Some(one_of) = schema.get("oneOf").and_then(|v| v.as_array()) {
        let n = one_of
            .iter()
            .filter(|s| validate_input_against_schema_depth(s, input, depth + 1).is_empty())
            .count();
        if n != 1 {
            errors.push(format!(
                "Value must match exactly one schema (oneOf) but matched {}",
                n
            ));
        }
    }

    // ── allOf ─────────────────────────────────────────────────────────────────
    if let Some(all_of) = schema.get("allOf").and_then(|v| v.as_array()) {
        for (i, sub) in all_of.iter().enumerate() {
            for err in validate_input_against_schema_depth(sub, input, depth + 1) {
                errors.push(format!("allOf[{}]: {}", i, err));
            }
        }
    }

    // Check required fields
    if let Some(required) = schema.get("required").and_then(|r| r.as_array()) {
        for req_field in required {
            let field = match req_field.as_str() {
                Some(f) => f,
                None => continue,
            };
            if input.get(field).is_none() {
                errors.push(format!("Missing required field: '{}'", field));
            }
        }
    }

    // ── additionalProperties: false ───────────────────────────────────────
    if schema.get("additionalProperties").and_then(|v| v.as_bool()) == Some(false) {
        if let (Some(props), Some(obj)) = (
            schema.get("properties").and_then(|p| p.as_object()),
            input.as_object(),
        ) {
            for key in obj.keys() {
                if !props.contains_key(key.as_str()) {
                    errors.push(format!(
                        "Field '{}' is not allowed (additionalProperties: false)",
                        key
                    ));
                }
            }
        }
    }

    // Check per-property constraints when both schema and input are objects
    if let (Some(props), Some(input_obj)) = (
        schema.get("properties").and_then(|p| p.as_object()),
        input.as_object(),
    ) {
        for (field, field_schema) in props {
            let Some(input_val) = input_obj.get(field) else {
                continue;
            };

            // ── type check ────────────────────────────────────────────────
            if let Some(expected_type) = field_schema.get("type").and_then(|t| t.as_str()) {
                let type_ok = match expected_type {
                    "string" => input_val.is_string(),
                    "number" => input_val.is_number(),
                    "integer" => input_val.is_i64() || input_val.is_u64(),
                    "boolean" => input_val.is_boolean(),
                    "array" => input_val.is_array(),
                    "object" => input_val.is_object(),
                    "null" => input_val.is_null(),
                    _ => true,
                };
                if !type_ok {
                    let actual = match input_val {
                        serde_json::Value::Null => "null",
                        serde_json::Value::Bool(_) => "boolean",
                        serde_json::Value::Number(_) => "number",
                        serde_json::Value::String(_) => "string",
                        serde_json::Value::Array(_) => "array",
                        serde_json::Value::Object(_) => "object",
                    };
                    // MCP-1032: schema-author-supplied `field` and `expected_type` capped;
                    // `actual` is from a fixed 6-string allowlist.
                    errors.push(format!(
                        "Field '{}' must be of type '{}' but got '{}'",
                        talos_text_util::bounded_preview(field, 64),
                        talos_text_util::bounded_preview(expected_type, 64),
                        actual
                    ));
                }
            }

            // ── enum check ────────────────────────────────────────────────
            if let Some(enum_values) = field_schema.get("enum").and_then(|e| e.as_array()) {
                if !enum_values.contains(input_val) {
                    let valid_values: Vec<String> = enum_values
                        .iter()
                        .map(|v| match v.as_str() {
                            Some(s) => format!("\"{}\"", s),
                            None => v.to_string(),
                        })
                        .collect();
                    errors.push(format!(
                        "Field '{}' must be one of [{}] but got {}",
                        field,
                        valid_values.join(", "),
                        input_val
                    ));
                }
            }

            // ── numeric range checks ──────────────────────────────────────
            if let Some(n) = input_val.as_f64() {
                if let Some(min) = field_schema.get("minimum").and_then(|v| v.as_f64()) {
                    if n < min {
                        errors.push(format!("Field '{}' must be >= {}", field, min));
                    }
                }
                if let Some(max) = field_schema.get("maximum").and_then(|v| v.as_f64()) {
                    if n > max {
                        errors.push(format!("Field '{}' must be <= {}", field, max));
                    }
                }
            }

            // ── string length + pattern checks ────────────────────────────
            if let Some(s) = input_val.as_str() {
                let len = s.chars().count();
                if let Some(min_len) = field_schema.get("minLength").and_then(|v| v.as_u64()) {
                    if len < min_len as usize {
                        errors.push(format!(
                            "Field '{}' must be at least {} character(s) long",
                            field, min_len
                        ));
                    }
                }
                if let Some(max_len) = field_schema.get("maxLength").and_then(|v| v.as_u64()) {
                    if len > max_len as usize {
                        errors.push(format!(
                            "Field '{}' must be at most {} character(s) long",
                            field, max_len
                        ));
                    }
                }

                // ── pattern ───────────────────────────────────────────────
                if let Some(pat) = field_schema.get("pattern").and_then(|p| p.as_str()) {
                    if pat.len() > 500 {
                        errors.push(format!(
                            "Field '{}' has a regex pattern exceeding maximum length of 500 characters",
                            field
                        ));
                    } else {
                        // Bound the compiled automaton size to prevent slow compilation
                        // of pathologically complex patterns.
                        match regex::RegexBuilder::new(pat).size_limit(256 * 1024).build() {
                            Ok(re) if !re.is_match(s) => {
                                errors.push(format!(
                                    "Field '{}' does not match pattern {:?}",
                                    field, pat
                                ));
                            }
                            Err(_) => {
                                errors.push(format!(
                                    "Field '{}' has invalid or too-complex regex pattern {:?}",
                                    field, pat
                                ));
                            }
                            _ => {}
                        }
                    }
                }
            }

            // ── anyOf / oneOf / allOf in field_schema ────────────────────
            // Must be evaluated explicitly here for all value types. The
            // nested-object block below only recurses when input_val.is_object();
            // without this block, combiner schemas on scalars (strings, numbers,
            // booleans) would silently pass regardless of sub-schema constraints.
            if let Some(any_of) = field_schema.get("anyOf").and_then(|v| v.as_array()) {
                if !any_of.iter().any(|s| {
                    validate_input_against_schema_depth(s, input_val, depth + 1).is_empty()
                }) {
                    errors.push(format!(
                        "Field '{}' does not match any of the expected schemas (anyOf)",
                        field
                    ));
                }
            }
            if let Some(one_of) = field_schema.get("oneOf").and_then(|v| v.as_array()) {
                let n = one_of
                    .iter()
                    .filter(|s| {
                        validate_input_against_schema_depth(s, input_val, depth + 1).is_empty()
                    })
                    .count();
                if n != 1 {
                    errors.push(format!(
                        "Field '{}' must match exactly one schema (oneOf) but matched {}",
                        field, n
                    ));
                }
            }
            if let Some(all_of) = field_schema.get("allOf").and_then(|v| v.as_array()) {
                for (i, sub) in all_of.iter().enumerate() {
                    for err in validate_input_against_schema_depth(sub, input_val, depth + 1) {
                        errors.push(format!("Field '{}' allOf[{}]: {}", field, i, err));
                    }
                }
            }

            // ── per-property `items` (array element) — MCP-467 ────────────
            if let (Some(items_schema), Some(arr)) =
                (field_schema.get("items"), input_val.as_array())
            {
                errors.extend(validate_array_items(items_schema, arr, field, depth));
            }

            // ── nested object ─────────────────────────────────────────────
            if input_val.is_object()
                && (field_schema.get("properties").is_some()
                    || field_schema.get("required").is_some())
            {
                for err in validate_input_against_schema_depth(field_schema, input_val, depth + 1) {
                    errors.push(format!("{}.{}", field, err));
                }
            }
        }
    }

    errors
}

/// Pure: numeric-aware JSON equality. Treats `5` and `5.0` as equal so
/// assertion checks pass against JSON serializers that emit
/// whole-number floats. Falls back to standard `PartialEq` for
/// non-numeric values.
pub fn json_values_equal_numeric_aware(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    match (a, b) {
        (serde_json::Value::Number(na), serde_json::Value::Number(nb)) => {
            na.as_f64() == nb.as_f64()
        }
        _ => a == b,
    }
}

/// Pure: look up a key in a workflow test-output value. Searches the
/// top level first; if missing, searches one level deep across the
/// object's values (the per-node-output map). Used by
/// `assert_output_contains` so callers can match either the top-level
/// shape or any single node's output without naming it.
pub fn lookup_test_output_key<'a>(
    output: &'a serde_json::Value,
    key: &str,
) -> Option<&'a serde_json::Value> {
    if let Some(v) = output.get(key) {
        return Some(v);
    }
    output
        .as_object()
        .and_then(|obj| obj.values().find_map(|v| v.get(key)))
}

/// Pure: build the per-assertion JSON list + overall pass/fail flag for
/// a `test_workflow` invocation. Composes the three currently-supported
/// assertion kinds — exact-status match, max-duration cap,
/// output-contains key/value matching — into the array shape MCP clients
/// expect. Returns `(assertions, all_passed)`; assertions are ordered
/// status → max_duration → output_contains.* (alphabetical by key).
///
/// This is the canonical implementation; `handle_test_workflow` calls
/// this directly so the assertion logic is unit-tested in isolation
/// rather than embedded in the handler.
pub fn build_test_assertions(
    actual_status: &str,
    expected_status: &str,
    duration_ms: u64,
    assert_max_duration_ms: Option<u64>,
    output_json: &serde_json::Value,
    assert_output_contains: Option<&serde_json::Map<String, serde_json::Value>>,
) -> (Vec<serde_json::Value>, bool) {
    let mut assertions = Vec::new();
    let mut all_passed = true;

    let status_passed = actual_status == expected_status;
    if !status_passed {
        all_passed = false;
    }
    assertions.push(serde_json::json!({
        "name": "status",
        "expected": expected_status,
        "actual": actual_status,
        "passed": status_passed,
    }));

    if let Some(max_ms) = assert_max_duration_ms {
        let duration_passed = duration_ms <= max_ms;
        if !duration_passed {
            all_passed = false;
        }
        assertions.push(serde_json::json!({
            "name": "max_duration_ms",
            "expected": format!("<= {}", max_ms),
            "actual": duration_ms,
            "passed": duration_passed,
        }));
    }

    if let Some(expected_kv) = assert_output_contains {
        for (key, expected_val) in expected_kv {
            let actual_val = lookup_test_output_key(output_json, key);
            let contains_passed = actual_val
                .map(|v| json_values_equal_numeric_aware(v, expected_val))
                .unwrap_or(false);
            if !contains_passed {
                all_passed = false;
            }
            assertions.push(serde_json::json!({
                "name": format!("output_contains.{}", key),
                "expected": expected_val,
                "actual": actual_val.unwrap_or(&serde_json::Value::Null),
                "passed": contains_passed,
            }));
        }
    }

    (assertions, all_passed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── is_trivially_true_condition (MCP-1211) ──────────────────────────
    #[test]
    fn trivially_true_matches_literal_true() {
        assert!(is_trivially_true_condition("true"));
        assert!(is_trivially_true_condition("TRUE"));
        assert!(is_trivially_true_condition("True"));
        assert!(is_trivially_true_condition("  true  "));
    }

    #[test]
    fn trivially_true_matches_literal_one() {
        assert!(is_trivially_true_condition("1"));
        assert!(is_trivially_true_condition(" 1 "));
    }

    #[test]
    fn trivially_true_matches_not_false() {
        assert!(is_trivially_true_condition("!false"));
        assert!(is_trivially_true_condition("!FALSE"));
        assert!(is_trivially_true_condition(" !false "));
    }

    #[test]
    fn trivially_true_strips_balanced_parens() {
        assert!(is_trivially_true_condition("(true)"));
        assert!(is_trivially_true_condition("((true))"));
        assert!(is_trivially_true_condition("( ( true ) )"));
    }

    #[test]
    fn trivially_true_rejects_dynamic_expressions() {
        assert!(!is_trivially_true_condition("output.finished != true"));
        assert!(!is_trivially_true_condition("x > 0"));
        assert!(!is_trivially_true_condition("output.iterations < 10"));
        assert!(!is_trivially_true_condition(""));
        assert!(!is_trivially_true_condition("false"));
        assert!(!is_trivially_true_condition("0"));
        assert!(!is_trivially_true_condition("!true"));
    }

    #[test]
    fn trivially_true_rejects_unbalanced_outer_parens() {
        // `(true) || (false)` has a leading `(` and trailing `)` but they
        // don't enclose the whole expression — the outer-paren strip must
        // NOT collapse this to `true) || (false`.
        assert!(!is_trivially_true_condition("(true) || (false)"));
        assert!(!is_trivially_true_condition("(true) || x"));
    }

    #[test]
    fn validates_top_level_type_match() {
        let schema = json!({"type": "string"});
        assert!(validate_input_against_schema(&schema, &json!("hi")).is_empty());
        let errs = validate_input_against_schema(&schema, &json!(42));
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("Expected type 'string' but got 'number'"));
    }

    #[test]
    fn validates_required_fields() {
        let schema = json!({"type": "object", "required": ["name", "id"]});
        let input = json!({"name": "alice"});
        let errs = validate_input_against_schema(&schema, &input);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("Missing required field: 'id'"));
    }

    #[test]
    fn validates_per_property_type_with_field_prefix() {
        let schema = json!({
            "type": "object",
            "properties": { "age": {"type": "integer"} }
        });
        let errs = validate_input_against_schema(&schema, &json!({"age": "old"}));
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("Field 'age'"));
        assert!(errs[0].contains("integer"));
        assert!(errs[0].contains("string"));
    }

    #[test]
    fn anyof_with_top_level_type_check_rejects_mismatched_scalar() {
        // Regression guard: pre-fix, sub-schemas without `properties` returned
        // [] for any input, making anyOf no-ops on scalars.
        let schema = json!({ "anyOf": [{"type": "string"}, {"type": "number"}] });
        let errs = validate_input_against_schema(&schema, &json!(true));
        assert!(
            !errs.is_empty(),
            "anyOf must reject boolean against [string,number]"
        );
    }

    #[test]
    fn additional_properties_false_rejects_unknown_keys() {
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": { "name": {"type": "string"} }
        });
        let errs = validate_input_against_schema(&schema, &json!({"name": "a", "extra": 1}));
        assert!(errs.iter().any(|e| e.contains("'extra' is not allowed")));
    }

    #[test]
    fn pattern_max_length_rejected_before_compile() {
        // Defense-in-depth: 600-char regex is rejected without compilation
        // — protects against pathologically-complex patterns stalling triggers.
        let big_pat = "a".repeat(600);
        let schema = json!({"type": "string", "pattern": big_pat});
        let errs = validate_input_against_schema(&schema, &json!("hello"));
        assert!(errs.iter().any(|e| e.contains("exceeds maximum length")));
    }

    // MCP-467: `items` validation at runtime. Pre-fix, the runtime
    // validator silently dropped the items clause — a schema like
    // `{"type": "array", "items": {"type": "integer"}}` accepted
    // `["not", "ints"]` as valid input. Operators had a false sense
    // of trigger-time input validation. All four tests below would
    // produce `errs.is_empty() == true` before the fix and reject
    // correctly after.

    #[test]
    fn items_validates_top_level_single_schema() {
        let schema = json!({"type": "array", "items": {"type": "integer"}});
        let errs = validate_input_against_schema(&schema, &json!(["a", "b"]));
        assert!(
            !errs.is_empty(),
            "items {{integer}} must reject array of strings; got no errors"
        );
        assert!(
            errs.iter().any(|e| e.contains("items[0]")),
            "expected index in error path: {:?}",
            errs
        );
    }

    #[test]
    fn items_accepts_matching_array() {
        let schema = json!({"type": "array", "items": {"type": "integer"}});
        let errs = validate_input_against_schema(&schema, &json!([1, 2, 3]));
        assert!(
            errs.is_empty(),
            "items {{integer}} must accept [1,2,3]: {:?}",
            errs
        );
    }

    #[test]
    fn items_validates_per_property() {
        let schema = json!({
            "type": "object",
            "properties": {
                "tags": {"type": "array", "items": {"type": "string"}}
            }
        });
        let errs = validate_input_against_schema(&schema, &json!({"tags": [1, 2]}));
        assert!(!errs.is_empty(), "tags items {{string}} must reject [1,2]");
        assert!(
            errs.iter()
                .any(|e| e.contains("Field 'tags'") && e.contains("items[0]")),
            "expected field+index prefix in error path: {:?}",
            errs
        );
    }

    #[test]
    fn items_validates_tuple_form() {
        // JSON Schema draft-07 tuple form: items[i] validated against
        // schema[i]; elements past schema list are unconstrained.
        let schema = json!({
            "type": "array",
            "items": [{"type": "string"}, {"type": "integer"}]
        });
        // Valid: [str, int, anything-extra]
        let errs =
            validate_input_against_schema(&schema, &json!(["a", 5, "extra-elements-allowed"]));
        assert!(
            errs.is_empty(),
            "tuple-extra should be unconstrained: {:?}",
            errs
        );
        // Invalid: position 0 must be string, got int
        let errs = validate_input_against_schema(&schema, &json!([5, 5]));
        assert!(errs.iter().any(|e| e.contains("items[0]")), "{:?}", errs);
    }

    #[test]
    fn nested_object_errors_are_dotted() {
        let schema = json!({
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": { "age": {"type": "integer"} }
                }
            }
        });
        let errs = validate_input_against_schema(&schema, &json!({"user": {"age": "old"}}));
        assert!(
            errs.iter().any(|e| e.starts_with("user.")),
            "nested errs should be dotted: {:?}",
            errs
        );
    }

    // -- json_values_equal_numeric_aware --

    #[test]
    fn numeric_eq_int_vs_whole_float() {
        assert!(json_values_equal_numeric_aware(&json!(5), &json!(5.0)));
        assert!(json_values_equal_numeric_aware(&json!(5.0), &json!(5)));
    }

    #[test]
    fn numeric_eq_distinguishes_unequal_numbers() {
        assert!(!json_values_equal_numeric_aware(&json!(5), &json!(6)));
        assert!(!json_values_equal_numeric_aware(&json!(5.0), &json!(5.1)));
    }

    #[test]
    fn numeric_eq_falls_back_for_non_numbers() {
        assert!(json_values_equal_numeric_aware(
            &json!("foo"),
            &json!("foo")
        ));
        assert!(!json_values_equal_numeric_aware(
            &json!("foo"),
            &json!("bar")
        ));
        assert!(json_values_equal_numeric_aware(&json!(true), &json!(true)));
        assert!(json_values_equal_numeric_aware(
            &json!({"a": 1}),
            &json!({"a": 1})
        ));
    }

    #[test]
    fn numeric_eq_number_vs_string_unequal() {
        // No coercion across types — "5" is not 5.
        assert!(!json_values_equal_numeric_aware(&json!(5), &json!("5")));
    }

    // -- lookup_test_output_key --

    #[test]
    fn lookup_finds_top_level_key() {
        let v = json!({"status": "ok", "count": 3});
        assert_eq!(lookup_test_output_key(&v, "status"), Some(&json!("ok")));
    }

    #[test]
    fn lookup_descends_one_level_when_top_misses() {
        let v = json!({
            "node_a": {"status": "ok"},
            "node_b": {"count": 7},
        });
        assert_eq!(lookup_test_output_key(&v, "count"), Some(&json!(7)));
    }

    #[test]
    fn lookup_returns_none_when_missing() {
        let v = json!({"node_a": {"status": "ok"}});
        assert!(lookup_test_output_key(&v, "missing").is_none());
    }

    #[test]
    fn lookup_top_level_shadows_nested() {
        // Top-level wins, even if a nested entry has the same key.
        let v = json!({
            "result": "top",
            "node_a": {"result": "nested"},
        });
        assert_eq!(lookup_test_output_key(&v, "result"), Some(&json!("top")));
    }

    // ─── build_test_assertions ───

    #[test]
    fn assertions_status_only_passes_when_status_matches() {
        let (asserts, all_passed) =
            build_test_assertions("completed", "completed", 100, None, &json!({}), None);
        assert!(all_passed);
        assert_eq!(asserts.len(), 1);
        assert_eq!(asserts[0]["name"], "status");
        assert_eq!(asserts[0]["passed"], true);
        assert_eq!(asserts[0]["expected"], "completed");
        assert_eq!(asserts[0]["actual"], "completed");
    }

    #[test]
    fn assertions_status_mismatch_marks_all_failed() {
        let (asserts, all_passed) =
            build_test_assertions("failed", "completed", 100, None, &json!({}), None);
        assert!(!all_passed);
        assert_eq!(asserts[0]["passed"], false);
    }

    #[test]
    fn assertions_max_duration_passes_within_cap() {
        let (asserts, all_passed) =
            build_test_assertions("completed", "completed", 50, Some(100), &json!({}), None);
        assert!(all_passed);
        assert_eq!(asserts.len(), 2);
        assert_eq!(asserts[1]["name"], "max_duration_ms");
        assert_eq!(asserts[1]["passed"], true);
        assert_eq!(asserts[1]["expected"], "<= 100");
        assert_eq!(asserts[1]["actual"], 50);
    }

    #[test]
    fn assertions_max_duration_fails_when_over() {
        let (asserts, all_passed) =
            build_test_assertions("completed", "completed", 200, Some(100), &json!({}), None);
        assert!(!all_passed);
        assert_eq!(asserts[1]["passed"], false);
    }

    #[test]
    fn assertions_max_duration_omitted_when_no_cap_provided() {
        let (asserts, _) =
            build_test_assertions("completed", "completed", 999_999, None, &json!({}), None);
        assert_eq!(asserts.len(), 1); // only status
    }

    #[test]
    fn assertions_output_contains_passes_top_level_key() {
        let output = json!({"status": "ok", "count": 7});
        let mut expected = serde_json::Map::new();
        expected.insert("status".to_string(), json!("ok"));
        let (asserts, all_passed) = build_test_assertions(
            "completed",
            "completed",
            100,
            None,
            &output,
            Some(&expected),
        );
        assert!(all_passed);
        assert_eq!(asserts.len(), 2); // status + output_contains.status
        assert_eq!(asserts[1]["name"], "output_contains.status");
        assert_eq!(asserts[1]["passed"], true);
    }

    #[test]
    fn assertions_output_contains_finds_nested_key() {
        let output = json!({"node_a": {"count": 5}});
        let mut expected = serde_json::Map::new();
        expected.insert("count".to_string(), json!(5));
        let (asserts, all_passed) = build_test_assertions(
            "completed",
            "completed",
            100,
            None,
            &output,
            Some(&expected),
        );
        assert!(all_passed);
        assert_eq!(asserts[1]["passed"], true);
        assert_eq!(asserts[1]["actual"], 5);
    }

    #[test]
    fn assertions_output_contains_numeric_aware_equality() {
        // 5 vs 5.0 must compare equal.
        let output = json!({"count": 5});
        let mut expected = serde_json::Map::new();
        expected.insert("count".to_string(), json!(5.0));
        let (asserts, all_passed) = build_test_assertions(
            "completed",
            "completed",
            100,
            None,
            &output,
            Some(&expected),
        );
        assert!(all_passed);
        assert_eq!(asserts[1]["passed"], true);
    }

    #[test]
    fn assertions_output_contains_missing_key_fails_with_null_actual() {
        let output = json!({"status": "ok"});
        let mut expected = serde_json::Map::new();
        expected.insert("missing".to_string(), json!("anything"));
        let (asserts, all_passed) = build_test_assertions(
            "completed",
            "completed",
            100,
            None,
            &output,
            Some(&expected),
        );
        assert!(!all_passed);
        assert_eq!(asserts[1]["passed"], false);
        assert_eq!(asserts[1]["actual"], serde_json::Value::Null);
    }

    #[test]
    fn assertions_output_contains_value_mismatch_fails() {
        let output = json!({"status": "ok"});
        let mut expected = serde_json::Map::new();
        expected.insert("status".to_string(), json!("error"));
        let (asserts, all_passed) = build_test_assertions(
            "completed",
            "completed",
            100,
            None,
            &output,
            Some(&expected),
        );
        assert!(!all_passed);
        assert_eq!(asserts[1]["passed"], false);
        assert_eq!(asserts[1]["expected"], "error");
        assert_eq!(asserts[1]["actual"], "ok");
    }

    #[test]
    fn assertions_compose_all_three_kinds() {
        let output = json!({"status": "ok"});
        let mut expected = serde_json::Map::new();
        expected.insert("status".to_string(), json!("ok"));
        let (asserts, all_passed) = build_test_assertions(
            "completed",
            "completed",
            50,
            Some(100),
            &output,
            Some(&expected),
        );
        assert!(all_passed);
        assert_eq!(asserts.len(), 3);
        assert_eq!(asserts[0]["name"], "status");
        assert_eq!(asserts[1]["name"], "max_duration_ms");
        assert_eq!(asserts[2]["name"], "output_contains.status");
    }

    // MCP-558: tripwire — confirm the recursive validators bail at
    // MAX_SCHEMA_DEPTH instead of stack-overflowing on a deeply
    // nested input. Previously a malicious user could submit a
    // `[[[[[...]]]]]` body (~500k levels per 1 MB axum body limit)
    // and crash the controller for ALL users.
    #[test]
    fn validate_input_against_schema_bails_on_deep_nesting() {
        // Schema with no `items` constraint but with allOf wrapping
        // itself N times: each allOf step recurses through
        // validate_input_against_schema_depth.
        let mut schema = json!({"type": "array"});
        for _ in 0..(super::MAX_SCHEMA_DEPTH + 10) {
            schema = json!({ "allOf": [schema] });
        }
        let errors = validate_input_against_schema(&schema, &json!([]));
        // We get exactly one "Validation depth exceeded" message at the
        // first level beyond MAX_SCHEMA_DEPTH; the recursive walk stops
        // and returns up through each allOf wrapper.
        assert!(
            errors.iter().any(|e| e.contains("depth exceeded")),
            "expected depth-bailout error, got {:?}",
            errors
        );
    }

    #[test]
    fn validate_schema_well_formed_bails_on_deep_nesting() {
        // Schema with N levels of nested `properties.x` chain.
        let mut schema = json!({ "type": "string" });
        for _ in 0..(super::MAX_SCHEMA_DEPTH + 10) {
            schema = json!({
                "type": "object",
                "properties": { "x": schema },
            });
        }
        let errors = validate_schema_well_formed(&schema);
        assert!(
            errors.iter().any(|e| e.contains("maximum nesting depth")),
            "expected depth-bailout error, got {:?}",
            errors
        );
    }
}
