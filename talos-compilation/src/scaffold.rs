//! # JSON → typed struct scaffold generator
//!
//! Pure-Rust utilities that turn a sample JSON payload into ready-to-compile
//! `serde::Deserialize` struct definitions. Used by the `generate_typed_scaffold`
//! MCP tool and by `compile_custom_sandbox` to steer module authors away from
//! the `let data: serde_json::Value = from_str(...)` anti-pattern that
//! dominates wasmtime fuel on large payloads.
//!
//! ## Design
//!
//! - **Single-pass inference.** We walk the sample once and emit struct
//!   definitions bottom-up. No second pass for dedupe; nested structs are
//!   named by their enclosing field path so structurally-identical shapes
//!   may be emitted twice. That is a deliberate trade — dedupe across paths
//!   would require equality-checking arbitrary JSON, which is O(n²) on the
//!   number of object nodes.
//!
//! - **Resilient-by-default field typing.** Every field is wrapped in
//!   `Option<T>` with `#[serde(default)]`. Missing fields in future samples
//!   deserialize to `None` instead of erroring. Authors who want strict
//!   parsing can hand-tighten after generation.
//!
//! - **Case-rename detection.** If the JSON key is not valid snake_case
//!   (contains uppercase or non-ascii word characters), we emit a
//!   `#[serde(rename = "...")]` annotation pointing at the original key and
//!   use a snake_case field identifier in Rust.
//!
//! - **Conservative fuel budget formula.** `compute_max_fuel` turns
//!   declared payload expectations (item count, bytes/item, safety
//!   multiplier) into a wasm fuel budget. Calibrated from observed fuel
//!   consumption during the session 2026-04-11 module rewrites: empty path
//!   ~25K, per-item typed parse ~60K, HTTP tokenization ~2 fuel/byte.
//!
//! ## Security
//!
//! The generator runs entirely host-side on operator-provided JSON input.
//! We enforce:
//! - **Max input size**: 256 KiB. Larger samples are rejected; they're never
//!   representative of production payloads anyway, and tokenizing huge JSON
//!   samples before inference would waste controller CPU.
//! - **Max recursion depth**: 20. JSON with nesting beyond this is almost
//!   certainly adversarial (stack-bomb fingerprint).
//! - **Max generated structs**: 100. Pathologically wide schemas would
//!   otherwise produce hundreds of struct definitions; the cap bounds output
//!   length and protects the operator from accidentally pasting a runaway
//!   sample.
//!
//! None of the generated code is executed here — it is returned as a
//! `String` for the caller to review and pass to `compile_custom_sandbox`.

use std::fmt::Write;

/// Maximum input sample size accepted by the generator.
pub const MAX_INPUT_BYTES: usize = 256 * 1024;
/// Maximum recursion depth during inference.
pub const MAX_DEPTH: usize = 20;
/// Maximum distinct struct definitions the generator may emit.
pub const MAX_STRUCTS: usize = 100;

/// Formula-derived conservative upper-bound for a module's per-execution
/// fuel budget.
///
/// - **50_000** baseline: covers input parsing, typed struct allocation,
///   and output serialization for the always-on control flow.
/// - **60_000 per item** × `item_count`: accounts for parsing a typed JSON
///   object off the HTTP response body with ~6 fields and one nested
///   payload struct (measured from `jira-search-v4` at 58K/issue post-
///   rewrite on 2026-04-11).
/// - **2 fuel per raw byte** × `item_count` × `bytes_per_item`: Wasmtime
///   tokenizes each byte of JSON input, roughly 2 fuel per byte for
///   untagged objects.
///
/// The final value is multiplied by `safety_multiplier` (default 2.0),
/// clamped to `[1_000_000, 50_000_000]`, and returned as `u64`. The upper
/// bound matches the dispatcher's existing 50M cap.
pub fn compute_max_fuel(item_count: u64, bytes_per_item: u64, safety_multiplier: f64) -> u64 {
    compute_max_fuel_with_llm_output(item_count, bytes_per_item, 0, safety_multiplier)
}

/// Structural fuel overhead of the module's language RUNTIME, independent
/// of payload shape. Added ON TOP of the formula budget (and of an
/// explicit `fuel_budget` declaration — the author's payload shape can't
/// know about interpreter boot cost).
///
/// The payload formula above is calibrated for Rust components (~100 KB,
/// near-zero startup). Interpreter-toolchain components embed their whole
/// runtime and burn megafuel BEFORE the first line of user code runs:
///
/// - **JavaScript (jco/StarlingMonkey)**: measured ~2.84–2.91 M fuel for
///   engine boot + source parse on a trivial doubler (functional sweep,
///   2026-07-07). Budget 4 M for headroom on non-trivial sources.
/// - **Python (componentize-py)**: measured ~0.21 M for embedded-CPython
///   startup on the same doubler. Budget 1 M.
/// - **Rust / unknown**: 0 — the formula's 50 K baseline already covers it.
///
/// Without this every JS module compiled with the default budget
/// (~1.38 M) fails in workflows with `fuel exhausted` before user code
/// executes — while confusingly SUCCEEDING under `test_module`, whose
/// dispatch path applies a different limit (the fuel-four-paths trap).
/// The sum is clamped to the dispatcher's 50 M cap by the caller.
pub fn interpreter_fuel_baseline(language: &str) -> u64 {
    match language.to_ascii_lowercase().as_str() {
        "javascript" | "js" | "typescript" | "ts" => 4_000_000,
        "python" | "py" => 1_000_000,
        _ => 0,
    }
}

/// Extended fuel computation that factors in LLM response size.
///
/// LLM-backed modules typically have small input but 2-4 KB of generated
/// output that must be parsed back into a typed struct. Without accounting for
/// this, fuel budgets computed from input shape alone under-provision and the
/// module trips `fuel-exhausted` in production. `llm_output_bytes` expresses
/// the expected LLM response size (in bytes) and is billed at the same fuel
/// rate as input bytes.
///
/// For non-LLM modules pass `llm_output_bytes = 0` — the formula then reduces
/// to [`compute_max_fuel`].
pub fn compute_max_fuel_with_llm_output(
    item_count: u64,
    bytes_per_item: u64,
    llm_output_bytes: u64,
    safety_multiplier: f64,
) -> u64 {
    // Coefficients hoisted to module scope (see the "Fuel-budget coefficients"
    // section below) so the human-translation helpers invert the SAME formula —
    // the forward estimate and the tier/capacity labels shown back to operators
    // can never drift apart.
    let per_item_bytes = item_count
        .saturating_mul(bytes_per_item)
        .saturating_mul(FUEL_PER_BYTE);
    let per_item_parse = item_count.saturating_mul(FUEL_PER_ITEM_TYPED_PARSE);
    // LLM output is parsed once per execution (not per item) so it enters the
    // total directly, not multiplied by item_count.
    let llm_output_fuel = llm_output_bytes.saturating_mul(FUEL_PER_BYTE);
    let subtotal = FUEL_BASELINE
        .saturating_add(per_item_parse)
        .saturating_add(per_item_bytes)
        .saturating_add(llm_output_fuel);

    // Safety multiplier guards against variance (unexpected field explosion,
    // retries, inline LLM calls). Minimum 1.0 (no reduction), maximum 5.0.
    let mult = safety_multiplier.clamp(1.0, 5.0);
    let scaled = (subtotal as f64 * mult) as u64;

    scaled.clamp(FUEL_MIN, FUEL_MAX)
}

// ============================================================================
// Fuel-budget coefficients + human translation
// ============================================================================
//
// A raw `max_fuel` number (a wasmtime instruction-count ceiling) is opaque to
// humans — "8,000,000" says nothing about whether a node will handle its data
// or how close it is to failing. These helpers translate any fuel value into
// the two things an operator actually cares about: "how big a payload does this
// handle?" (capacity / size tier) and "how close to the edge am I?"
// (utilization health). They INVERT the same formula `compute_max_fuel_*` uses,
// with the coefficients living here at module scope so the two directions share
// one source of truth.

/// Fixed per-execution parsing overhead (fuel).
pub(crate) const FUEL_BASELINE: u64 = 50_000;
/// Typed-struct parse cost per input item (fuel).
pub(crate) const FUEL_PER_ITEM_TYPED_PARSE: u64 = 60_000;
/// Wasmtime fuel charged per raw input byte.
pub(crate) const FUEL_PER_BYTE: u64 = 2;
/// Dispatcher clamp floor — the smallest max_fuel any module is given.
pub const FUEL_MIN: u64 = 1_000_000;
/// Dispatcher clamp ceiling — the largest max_fuel any module is given.
pub const FUEL_MAX: u64 = 50_000_000;

/// Reference item size (bytes) used when expressing a fuel budget as a capacity
/// ("handles ~N items of ~2 KB"). Matches the formula's default `bytes_per_item`.
pub(crate) const FUEL_REF_BYTES_PER_ITEM: u64 = 2_000;
/// Reference safety multiplier for the capacity estimate — the formula default.
pub(crate) const FUEL_REF_SAFETY: f64 = 2.0;

/// Coarse, human-facing size label for a fuel budget. Spans the dispatcher's
/// [`FUEL_MIN`, `FUEL_MAX`] range so every real budget maps to exactly one tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FuelTier {
    Light,
    Standard,
    Heavy,
    Max,
}

impl FuelTier {
    pub fn as_str(self) -> &'static str {
        match self {
            FuelTier::Light => "light",
            FuelTier::Standard => "standard",
            FuelTier::Heavy => "heavy",
            FuelTier::Max => "max",
        }
    }
}

/// Map a fuel budget to its size tier. Boundaries are chosen relative to the
/// [1M, 50M] dispatcher range: the ~2.2M default budget lands in `Light`, and
/// only near-ceiling budgets read as `Max`.
pub fn fuel_tier(fuel: u64) -> FuelTier {
    match fuel {
        f if f < 4_000_000 => FuelTier::Light,
        f if f < 12_000_000 => FuelTier::Standard,
        f if f < 30_000_000 => FuelTier::Heavy,
        _ => FuelTier::Max,
    }
}

/// How close a node came to exhausting its budget on a given run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FuelHealth {
    /// Comfortable headroom (< 60% used).
    Comfortable,
    /// Getting close — worth watching (60–85%).
    Tight,
    /// One bad payload from failing (85–100%).
    AtRisk,
    /// Consumed its entire budget — the run hit the ceiling.
    Exhausted,
}

impl FuelHealth {
    pub fn as_str(self) -> &'static str {
        match self {
            FuelHealth::Comfortable => "comfortable",
            FuelHealth::Tight => "tight",
            FuelHealth::AtRisk => "at_risk",
            FuelHealth::Exhausted => "exhausted",
        }
    }
}

/// Classify how close `consumed` came to `limit`. `limit == 0` (unknown ceiling)
/// yields `Comfortable` — risk can't be judged without a ceiling.
pub fn fuel_health(consumed: u64, limit: u64) -> FuelHealth {
    if limit == 0 {
        return FuelHealth::Comfortable;
    }
    let pct = (consumed as f64 / limit as f64) * 100.0;
    if pct >= 100.0 {
        FuelHealth::Exhausted
    } else if pct >= 85.0 {
        FuelHealth::AtRisk
    } else if pct >= 60.0 {
        FuelHealth::Tight
    } else {
        FuelHealth::Comfortable
    }
}

/// Estimate how many reference-sized (~2 KB) items a fuel budget can process, by
/// inverting `compute_max_fuel` at the default safety multiplier. This is the
/// intuitive reading of a budget: "handles ~N items of ~2 KB". Always ≥ 1 (any
/// real budget clears the baseline).
pub fn fuel_capacity_items(fuel: u64) -> u64 {
    // fuel ≈ safety × (BASELINE + items × (PER_ITEM_PARSE + bytes × PER_BYTE))
    // → items ≈ (fuel/safety − BASELINE) / (PER_ITEM_PARSE + bytes × PER_BYTE)
    let per_item = FUEL_PER_ITEM_TYPED_PARSE + FUEL_REF_BYTES_PER_ITEM * FUEL_PER_BYTE;
    let usable = (fuel as f64 / FUEL_REF_SAFETY) - FUEL_BASELINE as f64;
    if usable <= 0.0 {
        return 1;
    }
    ((usable / per_item as f64).floor() as u64).max(1)
}

/// A human-facing description of a fuel budget (and optionally a run's usage).
#[derive(Debug, Clone, serde::Serialize)]
pub struct FuelHuman {
    /// Size tier label (light/standard/heavy/max).
    pub tier: FuelTier,
    /// Approximate payload capacity: reference-sized items this budget handles.
    pub capacity_items: u64,
    /// Plain-English capacity phrase, e.g. "handles ~60 items of ~2 KB".
    pub capacity: String,
    /// Utilization health for a specific run, if `consumed` was provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<FuelHealth>,
    /// One-line summary suitable for a UI chip or log line.
    pub summary: String,
}

/// Translate a fuel budget into human framing. Pass `consumed` from a completed
/// run to include utilization health; pass `None` to describe the budget alone.
pub fn describe_fuel(limit: u64, consumed: Option<u64>) -> FuelHuman {
    let tier = fuel_tier(limit);
    let capacity_items = fuel_capacity_items(limit);
    let capacity = format!(
        "handles ~{} items of ~{} KB",
        capacity_items,
        FUEL_REF_BYTES_PER_ITEM / 1000
    );
    let health = consumed.map(|c| fuel_health(c, limit));
    let summary = match (health, consumed) {
        (Some(h), Some(c)) if limit > 0 => format!(
            "{} budget · used {:.0}% — {}",
            tier.as_str(),
            (c as f64 / limit as f64) * 100.0,
            h.as_str().replace('_', " ")
        ),
        _ => format!("{} budget · {}", tier.as_str(), capacity),
    };
    FuelHuman {
        tier,
        capacity_items,
        capacity,
        health,
        summary,
    }
}

/// Parameters accepted by `generate_module_scaffold`.
#[derive(Debug, Clone)]
pub struct ScaffoldParams<'a> {
    /// Human-readable module name. Used in comments + as a hint for the
    /// root `Input` struct if the caller wants to rename.
    pub name: &'a str,
    /// Capability world (e.g. `"http-node"`). Written into the
    /// `#[talos_module]` attribute.
    pub capability_world: &'a str,
    /// Sample upstream payload — what flows in as `data["input"]` during
    /// workflow execution. `None` emits an empty `Upstream` struct.
    pub upstream_sample: Option<&'a serde_json::Value>,
    /// Sample config block — what flows in as `data["config"]`. `None`
    /// emits an empty `Config` struct. Typical entries here are the
    /// AUTH_HEADER vault path, max-results caps, etc.
    pub config_sample: Option<&'a serde_json::Value>,
    /// Sample output shape — what the `run` body should produce. `None`
    /// emits a placeholder `Output { ok: bool }` struct for the author to
    /// replace.
    pub output_sample: Option<&'a serde_json::Value>,
}

/// Emits a ready-to-compile Rust module skeleton using typed structs
/// inferred from the supplied samples.
///
/// The return value is a `String` of Rust source, NOT a compiled artifact.
/// Authors pass it into `compile_custom_sandbox` after filling in the
/// `run` body.
pub fn generate_module_scaffold(params: ScaffoldParams<'_>) -> Result<String, String> {
    let mut emitted_structs: Vec<String> = Vec::new();
    let mut struct_counter: usize = 0;

    let upstream_type = emit_type_tree(
        "Upstream",
        params.upstream_sample,
        &mut emitted_structs,
        &mut struct_counter,
        0,
    )?;
    let config_type = emit_type_tree(
        "Config",
        params.config_sample,
        &mut emitted_structs,
        &mut struct_counter,
        0,
    )?;
    let output_type = emit_type_tree(
        "Output",
        params.output_sample,
        &mut emitted_structs,
        &mut struct_counter,
        0,
    )?;

    // When the caller omitted a sample, emit_type_tree will have placed an
    // empty-object struct in emitted_structs. That's fine — the author sees
    // an empty shape and fills in the blanks.

    let mut out = String::new();
    out.push_str(
        "// Auto-generated typed scaffold. Review carefully and fill in the `run` body.\n\
         // Generated by the `generate_typed_scaffold` MCP tool from a sample payload.\n\
         // Keep the typed structs — they are 3–10× cheaper in wasmtime fuel than\n\
         // parsing input as `serde_json::Value`.\n\n",
    );
    writeln!(
        out,
        "// Module: {}\n// Capability world: {}\n",
        sanitize_comment(params.name),
        sanitize_comment(params.capability_world)
    )
    .map_err(|e| e.to_string())?;

    for def in &emitted_structs {
        out.push_str(def);
        out.push('\n');
    }

    // Root Input struct ties config + upstream together and mirrors the
    // dispatcher's wrapping format (`data["config"]` + `data["input"]`).
    writeln!(
        out,
        "#[derive(serde::Deserialize)]\n\
         struct Input {{\n\
         \x20   #[serde(default)]\n\
         \x20   config: Option<{}>,\n\
         \x20   #[serde(default)]\n\
         \x20   input: Option<{}>,\n\
         }}\n",
        config_type, upstream_type
    )
    .map_err(|e| e.to_string())?;

    // Body template: typed parse, extract config + upstream, TODO.
    writeln!(
        out,
        "#[talos_sdk_macros::talos_module(world = \"{}\")]\n\
         pub fn run(input: String) -> Result<String, String> {{\n\
         \x20   const MAX_INPUT_BYTES: usize = 256 * 1024;\n\
         \x20   if input.len() > MAX_INPUT_BYTES {{\n\
         \x20       return Err(format!(\"input exceeds {{}} byte limit\", MAX_INPUT_BYTES));\n\
         \x20   }}\n\
         \x20\n\
         \x20   let parsed: Input =\n\
         \x20       serde_json::from_str(&input).map_err(|e| format!(\"invalid input JSON: {{}}\", e))?;\n\
         \x20   let _cfg = parsed.config.unwrap_or_default();\n\
         \x20   let _upstream = parsed.input.unwrap_or_default();\n\
         \x20\n\
         \x20   // TODO: implement the module body here.\n\
         \x20   // Build your typed Output value and serialize it to a String.\n\
         \x20   let out = {} {{\n\
         \x20       ..Default::default()\n\
         \x20   }};\n\
         \x20   serde_json::to_string(&out).map_err(|e| e.to_string())\n\
         }}\n",
        sanitize_comment(params.capability_world),
        output_type
    )
    .map_err(|e| e.to_string())?;

    Ok(out)
}

// ---------------------------------------------------------------------------
// Inference
// ---------------------------------------------------------------------------

/// Emit the type tree rooted at `sample` and return the Rust type name
/// that refers to it.
///
/// - `Object` → new named struct, returns its name.
/// - `Array`  → `Vec<ElementType>`, where `ElementType` is inferred from
///              the first non-null element (or falls back to `serde_json::Value`
///              if the array is empty or heterogeneous).
/// - `String`/`Number`/`Bool` → primitive type names.
/// - `Null`   → `serde_json::Value` (can't know until a real sample arrives).
/// - `None` (no sample supplied) → empty marker struct named after `struct_name`.
fn emit_type_tree(
    struct_name: &str,
    sample: Option<&serde_json::Value>,
    emitted: &mut Vec<String>,
    counter: &mut usize,
    depth: usize,
) -> Result<String, String> {
    if depth > MAX_DEPTH {
        return Err(format!(
            "sample nesting exceeds {} levels — likely pathological input",
            MAX_DEPTH
        ));
    }
    if emitted.len() > MAX_STRUCTS {
        return Err(format!(
            "scaffold would emit more than {} structs — sample is too wide",
            MAX_STRUCTS
        ));
    }

    let value = match sample {
        Some(v) => v,
        // No sample → emit a minimal empty-object struct with Default so the
        // scaffold body still compiles.
        None => {
            emit_empty_struct(struct_name, emitted);
            return Ok(struct_name.to_string());
        }
    };

    match value {
        serde_json::Value::Object(map) => {
            if map.is_empty() {
                emit_empty_struct(struct_name, emitted);
                return Ok(struct_name.to_string());
            }

            // Emit nested structs first so the parent struct (which references
            // them by name) compiles correctly in top-down order.
            let mut fields: Vec<(String, Option<String>, String)> = Vec::with_capacity(map.len());
            for (raw_key, raw_val) in map {
                let field_ident = snake_case(raw_key);
                let serde_rename = if field_ident != *raw_key {
                    Some(raw_key.clone())
                } else {
                    None
                };
                let nested_name = make_struct_name(struct_name, raw_key, counter);
                let field_type =
                    infer_field_type(&nested_name, raw_val, emitted, counter, depth + 1)?;
                fields.push((field_ident, serde_rename, field_type));
            }

            // Now emit the parent struct using the resolved field types.
            let mut def = String::new();
            def.push_str("#[derive(Default, serde::Deserialize, serde::Serialize)]\n");
            def.push_str("#[serde(default)]\n");
            writeln!(def, "struct {} {{", struct_name).map_err(|e| e.to_string())?;
            for (ident, rename, ty) in fields {
                if let Some(orig) = rename {
                    writeln!(
                        def,
                        "    #[serde(rename = \"{}\")]",
                        escape_string_literal(&orig)
                    )
                    .map_err(|e| e.to_string())?;
                }
                writeln!(def, "    {}: Option<{}>,", ident, ty).map_err(|e| e.to_string())?;
            }
            def.push_str("}\n");
            emitted.push(def);
            Ok(struct_name.to_string())
        }
        serde_json::Value::Array(arr) => {
            let elem_name = format!("{}Item", struct_name);
            let element_type = match arr.iter().find(|v| !v.is_null()) {
                Some(first) => infer_field_type(&elem_name, first, emitted, counter, depth + 1)?,
                None => "serde_json::Value".to_string(),
            };
            Ok(format!("Vec<{}>", element_type))
        }
        serde_json::Value::String(_) => Ok("String".to_string()),
        serde_json::Value::Number(n) => Ok(infer_number_type(n).to_string()),
        serde_json::Value::Bool(_) => Ok("bool".to_string()),
        serde_json::Value::Null => Ok("serde_json::Value".to_string()),
    }
}

/// Inference for a single field value. Unlike `emit_type_tree`, this one is
/// allowed to return primitive types directly and only creates a new struct
/// when the value is itself an object.
fn infer_field_type(
    suggested_struct_name: &str,
    value: &serde_json::Value,
    emitted: &mut Vec<String>,
    counter: &mut usize,
    depth: usize,
) -> Result<String, String> {
    if depth > MAX_DEPTH {
        return Err(format!(
            "sample nesting exceeds {} levels — likely pathological input",
            MAX_DEPTH
        ));
    }
    match value {
        serde_json::Value::Object(_) => {
            emit_type_tree(suggested_struct_name, Some(value), emitted, counter, depth)
        }
        serde_json::Value::Array(arr) => {
            let elem_name = format!("{}Item", suggested_struct_name);
            let inner = match arr.iter().find(|v| !v.is_null()) {
                Some(first) => infer_field_type(&elem_name, first, emitted, counter, depth + 1)?,
                None => "serde_json::Value".to_string(),
            };
            Ok(format!("Vec<{}>", inner))
        }
        serde_json::Value::String(_) => Ok("String".to_string()),
        serde_json::Value::Number(n) => Ok(infer_number_type(n).to_string()),
        serde_json::Value::Bool(_) => Ok("bool".to_string()),
        serde_json::Value::Null => Ok("serde_json::Value".to_string()),
    }
}

fn emit_empty_struct(name: &str, emitted: &mut Vec<String>) {
    let mut def = String::new();
    def.push_str("#[derive(Default, serde::Deserialize, serde::Serialize)]\n");
    def.push_str(&format!("struct {} {{}}\n", name));
    emitted.push(def);
}

fn infer_number_type(n: &serde_json::Number) -> &'static str {
    if n.is_f64() {
        "f64"
    } else if n.is_i64() {
        "i64"
    } else {
        "u64"
    }
}

/// Build a unique Pascal-cased struct name from a parent + child field.
/// Increments `counter` if the caller needs a tie-breaking suffix.
fn make_struct_name(parent: &str, field: &str, counter: &mut usize) -> String {
    let mut name = String::new();
    for part in parent.split(|c: char| !c.is_ascii_alphanumeric()) {
        name.push_str(&pascal_case(part));
    }
    for part in field.split(|c: char| !c.is_ascii_alphanumeric()) {
        name.push_str(&pascal_case(part));
    }
    if name.is_empty() {
        *counter += 1;
        name = format!("Struct{}", counter);
    }
    // Drop trailing plural 's' when the parent context suggests the child
    // is an element ("issues" → "Issue"). Only fires when the singular form
    // is at least 3 chars to avoid mangling genuinely short names.
    if name.ends_with('s') && name.len() > 4 && !name.ends_with("ss") {
        let singular = name.trim_end_matches('s').to_string();
        if singular.len() >= 3 {
            name = singular;
        }
    }
    name
}

/// Convert a string to snake_case, stripping non-identifier characters.
///
/// The output always falls through the reserved-keyword and digit-prefix
/// guards so already-lowercase-but-reserved inputs like `"type"` still get
/// the `r#` prefix. The fast path lifts string copy cost off the common
/// `"access_token"`-style case but does NOT skip the guards.
fn snake_case(s: &str) -> String {
    let is_already_snake = !s.is_empty()
        && s.chars()
            .next()
            .map(|c| c.is_ascii_lowercase() || c == '_')
            .unwrap_or(false)
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');

    let trimmed = if is_already_snake {
        s.to_string()
    } else {
        let mut out = String::with_capacity(s.len() + 4);
        let mut prev_is_lower = false;
        for c in s.chars() {
            if c.is_ascii_uppercase() {
                if prev_is_lower {
                    out.push('_');
                }
                out.push(c.to_ascii_lowercase());
                prev_is_lower = false;
            } else if c.is_ascii_alphanumeric() {
                out.push(c);
                prev_is_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
            } else {
                if !out.ends_with('_') {
                    out.push('_');
                }
                prev_is_lower = false;
            }
        }
        // Collapse repeated underscores left over from separator runs.
        let collapsed: String = out
            .chars()
            .fold((String::new(), false), |(mut acc, prev_u), c| {
                let is_u = c == '_';
                if is_u && prev_u {
                    (acc, true)
                } else {
                    acc.push(c);
                    (acc, is_u)
                }
            })
            .0;
        collapsed.trim_matches('_').to_string()
    };

    // Final guards apply to BOTH fast-path and slow-path outputs.
    if trimmed.is_empty()
        || trimmed
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(true)
    {
        format!("field_{}", trimmed)
    } else if RESERVED_KEYWORDS.contains(&trimmed.as_str()) {
        format!("r#{}", trimmed)
    } else {
        trimmed
    }
}

fn pascal_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut capitalize = true;
    for c in s.chars() {
        if !c.is_ascii_alphanumeric() {
            capitalize = true;
            continue;
        }
        if capitalize {
            out.push(c.to_ascii_uppercase());
            capitalize = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// Minimum set of Rust keywords that collide with field names commonly seen
/// in JSON payloads. Extended to match the actually-observed cases from the
/// session 2026-04-11 rewrites; we don't need the full keyword list because
/// most Rust keywords (while, fn, impl, …) never appear as JSON keys.
const RESERVED_KEYWORDS: &[&str] = &[
    "type", "ref", "match", "move", "use", "self", "super", "crate", "mod", "fn", "let", "loop",
    "async", "await", "dyn", "box", "priv", "final", "abstract",
];

/// Escape a string for embedding inside a Rust `"..."` literal. Only
/// handles the subset we actually produce: backslashes and double quotes.
fn escape_string_literal(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Sanitize a free-form string before embedding it in a comment. Strips
/// newline and block-comment terminators so a malicious name can't hide
/// comment-injected Rust code inside the generated output.
fn sanitize_comment(s: &str) -> String {
    s.replace("*/", "*_/").replace(['\n', '\r'], " ")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── fuel formula ───────────────────────────────────────────────────

    #[test]
    fn fuel_formula_empty_is_baseline() {
        // 0 items → BASELINE (50K) × multiplier → clamp to MIN_FUEL (1M)
        assert_eq!(compute_max_fuel(0, 0, 2.0), 1_000_000);
    }

    #[test]
    fn fuel_formula_small_payload() {
        // 15 items × 3000 bytes = 50K + 15*60K + 15*3000*2 = 50K + 900K + 90K = 1.04M
        // × 2.0 mult → 2.08M, clamp to 2.08M (above 1M floor, below 50M cap).
        let f = compute_max_fuel(15, 3000, 2.0);
        assert!((2_000_000..=2_200_000).contains(&f), "got {}", f);
    }

    #[test]
    fn fuel_formula_huge_payload_caps_at_50m() {
        // 1000 items × 100K bytes × 5x safety → saturates far above 50M.
        assert_eq!(compute_max_fuel(1000, 100_000, 5.0), 50_000_000);
    }

    #[test]
    fn interpreter_baseline_covers_measured_boot_cost() {
        // StarlingMonkey boot measured at ~2.91M on a trivial doubler —
        // the JS baseline must clear it with headroom, and the default
        // formula budget (~1.38M) + baseline must exceed it too.
        assert!(interpreter_fuel_baseline("javascript") > 2_910_000);
        assert!(interpreter_fuel_baseline("python") > 210_000);
        // Case-insensitive + alias forms.
        assert_eq!(
            interpreter_fuel_baseline("JavaScript"),
            interpreter_fuel_baseline("js")
        );
        assert_eq!(
            interpreter_fuel_baseline("PYTHON"),
            interpreter_fuel_baseline("py")
        );
        // Rust and unknown languages add nothing.
        assert_eq!(interpreter_fuel_baseline("rust"), 0);
        assert_eq!(interpreter_fuel_baseline(""), 0);
        assert_eq!(interpreter_fuel_baseline("go"), 0);
        // Default formula budget + JS baseline clears the measured boot.
        let default_budget = compute_max_fuel(10, 2000, 2.0);
        assert!(default_budget + interpreter_fuel_baseline("javascript") > 2_910_000);
    }

    #[test]
    fn fuel_formula_negative_multiplier_treated_as_one() {
        // compute_max_fuel clamps multiplier to [1.0, 5.0]. A 0.0 multiplier
        // collapses to 1.0 so the formula never produces less than the raw
        // subtotal.
        let f = compute_max_fuel(10, 1000, 0.0);
        let expected_floor = 50_000 + 10 * 60_000 + 10 * 1000 * 2;
        assert!(f >= expected_floor.max(1_000_000), "got {}", f);
    }

    #[test]
    fn fuel_formula_saturates_on_overflow() {
        // u64::MAX items — should not panic, just clamp to 50M.
        assert_eq!(compute_max_fuel(u64::MAX, u64::MAX, 5.0), 50_000_000);
    }

    // ── snake_case helper ──────────────────────────────────────────────

    #[test]
    fn snake_case_preserves_already_snake() {
        assert_eq!(snake_case("access_token"), "access_token");
        assert_eq!(snake_case("a"), "a");
        assert_eq!(snake_case("item1"), "item1");
    }

    #[test]
    fn snake_case_converts_camel() {
        assert_eq!(snake_case("accessToken"), "access_token");
        assert_eq!(snake_case("threadId"), "thread_id");
        assert_eq!(snake_case("displayName"), "display_name");
    }

    #[test]
    fn snake_case_converts_pascal() {
        assert_eq!(snake_case("AccessToken"), "access_token");
        assert_eq!(snake_case("GmailMessage"), "gmail_message");
    }

    #[test]
    fn snake_case_handles_hyphens_and_dots() {
        assert_eq!(snake_case("Content-Type"), "content_type");
        assert_eq!(snake_case("foo.bar"), "foo_bar");
    }

    #[test]
    fn snake_case_numeric_prefix_gets_field_prefix() {
        assert_eq!(snake_case("2fa_enabled"), "field_2fa_enabled");
    }

    #[test]
    fn snake_case_reserved_keyword_gets_raw_prefix() {
        assert_eq!(snake_case("type"), "r#type");
        assert_eq!(snake_case("ref"), "r#ref");
    }

    #[test]
    fn snake_case_does_not_escape_non_reserved_lookalikes() {
        assert_eq!(snake_case("typed"), "typed");
        assert_eq!(snake_case("reference"), "reference");
    }

    // ── scaffold generation ────────────────────────────────────────────

    #[test]
    fn generate_flat_object() {
        let sample = json!({
            "key": "SECP-1",
            "summary": "Do the thing",
            "priority_score": 7,
            "blocked": true,
        });
        let params = ScaffoldParams {
            name: "jira-fetch",
            capability_world: "http-node",
            upstream_sample: Some(&sample),
            config_sample: None,
            output_sample: None,
        };
        let src = generate_module_scaffold(params).unwrap();
        // Must declare the typed struct with all four fields.
        assert!(src.contains("struct Upstream"));
        assert!(src.contains("key: Option<String>"));
        assert!(src.contains("summary: Option<String>"));
        assert!(src.contains("priority_score: Option<"));
        assert!(src.contains("blocked: Option<bool>"));
        // Must wire up the #[talos_module] attribute.
        assert!(src.contains("#[talos_sdk_macros::talos_module(world = \"http-node\")]"));
        // Must NOT emit `serde_json::Value = serde_json::from_str` — the whole
        // point is to avoid the anti-pattern.
        assert!(!src.contains(": serde_json::Value = serde_json::from_str"));
    }

    #[test]
    fn generate_nested_object_emits_child_struct() {
        let sample = json!({
            "thread": {
                "id": "t1",
                "message_count": 3,
            }
        });
        let params = ScaffoldParams {
            name: "gmail",
            capability_world: "http-node",
            upstream_sample: Some(&sample),
            config_sample: None,
            output_sample: None,
        };
        let src = generate_module_scaffold(params).unwrap();
        // Child struct is named after the parent + field.
        assert!(
            src.contains("struct UpstreamThread"),
            "expected UpstreamThread child struct; got: {}",
            src
        );
        // Parent references the child type.
        assert!(src.contains("thread: Option<UpstreamThread>"));
        // Child's fields are populated.
        assert!(src.contains("id: Option<String>"));
        assert!(src.contains("message_count: Option<"));
    }

    #[test]
    fn generate_array_of_objects_emits_element_struct() {
        let sample = json!({
            "issues": [
                { "key": "SECP-1", "summary": "a" },
                { "key": "SECP-2", "summary": "b" }
            ]
        });
        let params = ScaffoldParams {
            name: "jira",
            capability_world: "http-node",
            upstream_sample: Some(&sample),
            config_sample: None,
            output_sample: None,
        };
        let src = generate_module_scaffold(params).unwrap();
        // Element struct is named singular (Issue, not Issues) with the Item suffix stripped.
        assert!(
            src.contains("Vec<UpstreamIssue") || src.contains("Vec<UpstreamIssues"),
            "expected element struct reference; got: {}",
            src
        );
        // Parent references the Vec<...> type.
        assert!(src.contains("issues: Option<Vec<"));
    }

    #[test]
    fn generate_empty_array_falls_back_to_value() {
        let sample = json!({ "items": [] });
        let params = ScaffoldParams {
            name: "x",
            capability_world: "http-node",
            upstream_sample: Some(&sample),
            config_sample: None,
            output_sample: None,
        };
        let src = generate_module_scaffold(params).unwrap();
        assert!(src.contains("items: Option<Vec<serde_json::Value>>"));
    }

    #[test]
    fn generate_camelcase_key_gets_serde_rename() {
        let sample = json!({ "threadId": "abc", "messageCount": 3 });
        let params = ScaffoldParams {
            name: "x",
            capability_world: "http-node",
            upstream_sample: Some(&sample),
            config_sample: None,
            output_sample: None,
        };
        let src = generate_module_scaffold(params).unwrap();
        assert!(src.contains("#[serde(rename = \"threadId\")]"));
        assert!(src.contains("thread_id: Option<String>"));
        assert!(src.contains("#[serde(rename = \"messageCount\")]"));
        assert!(src.contains("message_count: Option<"));
    }

    #[test]
    fn generate_handles_nullable_field() {
        let sample = json!({ "assignee": null, "key": "SECP-1" });
        let params = ScaffoldParams {
            name: "x",
            capability_world: "http-node",
            upstream_sample: Some(&sample),
            config_sample: None,
            output_sample: None,
        };
        let src = generate_module_scaffold(params).unwrap();
        // Null field gets fallback Value type.
        assert!(src.contains("assignee: Option<serde_json::Value>"));
    }

    #[test]
    fn generate_rejects_excessive_depth() {
        // Hand-build a chain of 25 nested objects; max is 20.
        let mut v = json!({"leaf": 1});
        for _ in 0..25 {
            v = json!({"next": v});
        }
        let params = ScaffoldParams {
            name: "x",
            capability_world: "http-node",
            upstream_sample: Some(&v),
            config_sample: None,
            output_sample: None,
        };
        let err = generate_module_scaffold(params).unwrap_err();
        assert!(err.contains("nesting"), "got: {}", err);
    }

    #[test]
    fn generate_with_no_samples_produces_compilable_skeleton() {
        let params = ScaffoldParams {
            name: "empty",
            capability_world: "minimal-node",
            upstream_sample: None,
            config_sample: None,
            output_sample: None,
        };
        let src = generate_module_scaffold(params).unwrap();
        assert!(src.contains("struct Upstream {}"));
        assert!(src.contains("struct Config {}"));
        assert!(src.contains("struct Output {}"));
        assert!(src.contains("pub fn run(input: String) -> Result<String, String>"));
    }

    #[test]
    fn generate_reserved_keyword_field_uses_raw_ident() {
        let sample = json!({ "type": "task", "match": 1 });
        let params = ScaffoldParams {
            name: "x",
            capability_world: "http-node",
            upstream_sample: Some(&sample),
            config_sample: None,
            output_sample: None,
        };
        let src = generate_module_scaffold(params).unwrap();
        assert!(src.contains("r#type: Option<String>"));
        assert!(src.contains("r#match: Option<"));
    }

    #[test]
    fn generate_sanitizes_comment_injection_attempts() {
        let params = ScaffoldParams {
            name: "bad*/\nuse std::process;\n/*",
            capability_world: "http-node",
            upstream_sample: None,
            config_sample: None,
            output_sample: None,
        };
        let src = generate_module_scaffold(params).unwrap();
        // Must not contain a raw */ that could close the comment block.
        assert!(!src.contains("bad*/"));
        assert!(src.contains("bad*_/"));
    }

    #[test]
    fn fuel_tier_spans_the_dispatcher_range() {
        assert_eq!(fuel_tier(FUEL_MIN), FuelTier::Light); // 1M floor
        assert_eq!(fuel_tier(2_200_000), FuelTier::Light); // ~default budget
        assert_eq!(fuel_tier(3_999_999), FuelTier::Light);
        assert_eq!(fuel_tier(4_000_000), FuelTier::Standard);
        assert_eq!(fuel_tier(8_000_000), FuelTier::Standard);
        assert_eq!(fuel_tier(12_000_000), FuelTier::Heavy);
        assert_eq!(fuel_tier(29_999_999), FuelTier::Heavy);
        assert_eq!(fuel_tier(30_000_000), FuelTier::Max);
        assert_eq!(fuel_tier(FUEL_MAX), FuelTier::Max); // 50M ceiling
    }

    #[test]
    fn fuel_health_maps_utilization_bands() {
        assert_eq!(fuel_health(0, 0), FuelHealth::Comfortable); // unknown ceiling
        assert_eq!(fuel_health(59, 100), FuelHealth::Comfortable);
        assert_eq!(fuel_health(60, 100), FuelHealth::Tight);
        assert_eq!(fuel_health(84, 100), FuelHealth::Tight);
        assert_eq!(fuel_health(85, 100), FuelHealth::AtRisk);
        assert_eq!(fuel_health(99, 100), FuelHealth::AtRisk);
        assert_eq!(fuel_health(100, 100), FuelHealth::Exhausted);
        assert_eq!(fuel_health(140, 100), FuelHealth::Exhausted);
    }

    #[test]
    fn capacity_inverts_the_forward_formula() {
        // For a budget the forward formula produced for N items of the reference
        // size, the capacity estimate must recover ~N (single source of truth).
        for n in [10u64, 30, 60, 120, 200] {
            let fuel = compute_max_fuel(n, FUEL_REF_BYTES_PER_ITEM, FUEL_REF_SAFETY);
            if fuel == FUEL_MIN || fuel == FUEL_MAX {
                continue; // clamped — inverse can't recover N at the rails
            }
            let recovered = fuel_capacity_items(fuel);
            let diff = recovered.abs_diff(n);
            assert!(
                diff <= 1,
                "capacity({fuel}) = {recovered}, expected ~{n} (diff {diff})"
            );
        }
        // Never returns 0, even for a floor budget.
        assert!(fuel_capacity_items(FUEL_MIN) >= 1);
        assert!(fuel_capacity_items(0) >= 1);
    }

    #[test]
    fn describe_fuel_produces_a_human_summary() {
        // The daily-brief example: 8M budget, a run that used 968_107 fuel.
        let h = describe_fuel(8_000_000, Some(968_107));
        assert_eq!(h.tier, FuelTier::Standard);
        assert_eq!(h.health, Some(FuelHealth::Comfortable)); // 12%
        assert!(h.capacity.contains("items of ~2 KB"));
        assert!(h.summary.contains("standard"));
        assert!(h.summary.contains("comfortable"));
        assert!(h.summary.contains("12%"));

        // Budget-only (no run): no health, summary describes capacity.
        let b = describe_fuel(8_000_000, None);
        assert!(b.health.is_none());
        assert!(b.summary.contains("handles"));
    }
}
