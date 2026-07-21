//! Pure argument parsing for `scaffold_actor`: raw MCP args JSON →
//! typed [`talos_actor_scaffold::ScaffoldRequest`].
//!
//! Ported verbatim from `talos-mcp-handlers/src/actor.rs::
//! handle_scaffold_actor` (the MCP-376 / MCP-457 / MCP-280 / MCP-304 /
//! MCP-382 / MCP-1183 / MCP-276 / MCP-1224 / MCP-345 / MCP-350 /
//! MCP-255 / MCP-348 boundary-validation stack). Every rejection
//! message is byte-identical to the pre-extraction handler and locked
//! by the tests below; all rejections map to JSON-RPC `-32602` in the
//! protocol layer.

use serde_json::Value;

use talos_actor_scaffold::{
    BudgetSpec, LlmTier, ScaffoldRequest, SeedMemorySpec, StarterWorkflowSpec,
};

use crate::json_type_name;

/// Parse + validate the `scaffold_actor` argument object. `Err` carries
/// the verbatim -32602 message.
pub fn parse_scaffold_request(args: &Value) -> Result<ScaffoldRequest, String> {
    // MCP-376 (2026-05-11): pre-fix both fields had silent gaps:
    //   - `name`: wrong-type collapsed via `.as_str()` to None →
    //     "Missing required field: name" (diagnostic conflation);
    //     the `s.to_string()` branch returned UNTRIMMED for storage
    //     (whitespace-pollution class).
    //   - `description`: wrong-type silently became None (operator's
    //     typed-wrong description erased); untrimmed Some(s) stored
    //     with padding.
    // MCP-457 (2026-05-11): the canonical single-line control-char rule
    // lives in `talos-validation` (shared with the GraphQL surface).
    // Pre-fix the local trim checks let null bytes and other control
    // characters through — the actor name would land in Postgres
    // unchanged where `\0` surfaces as the opaque "invalid byte
    // sequence" error and other control chars survive into action-log
    // summaries / UI columns.
    let name = match args.get("name") {
        None => return Err("Missing required field: name".to_string()),
        Some(v) => match v.as_str() {
            Some(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Err("name must be a non-empty, non-whitespace string".to_string());
                }
                if let Err(e) = talos_validation::reject_control_chars(
                    "name",
                    trimmed,
                    talos_validation::LineMode::SingleLine,
                ) {
                    return Err(e.message);
                }
                trimmed.to_string()
            }
            None => {
                let kind = json_type_name(v);
                return Err(format!("name must be a string, got {kind}"));
            }
        },
    };
    let description: Option<String> = match args.get("description") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(s) => {
                // Empty string is the documented "clear this field"
                // sentinel — accept and return None (same Option/empty
                // mapping as the canonical MCP validator wrapper).
                if s.is_empty() {
                    None
                } else {
                    match talos_validation::validate_multiline_description(
                        "description",
                        s,
                        5000,
                        "",
                    ) {
                        Ok(trimmed) => Some(trimmed.to_string()),
                        Err(e) => return Err(e.message),
                    }
                }
            }
            None => {
                let kind = json_type_name(v);
                return Err(format!("description must be a string, got {kind}"));
            }
        },
    };
    // MCP-280 (2026-05-10): pre-fix `unwrap_or("agent-node")` collapsed
    // wrong-type into the default — `max_capability_world: 123` (number)
    // → silently "agent-node" (rank 6, high privilege). Distinguish
    // absent (legitimate default) from wrong-type (operator typo).
    // Same direction-class as MCP-187/267.
    let max_capability_world = match args.get("max_capability_world") {
        None | Some(Value::Null) => "agent-node".to_string(),
        Some(v) => match v.as_str() {
            Some(s) => s.to_string(),
            None => {
                let kind = json_type_name(v);
                return Err(format!("max_capability_world must be a string, got {kind}"));
            }
        },
    };

    let llm_tier = match args.get("llm_tier").and_then(|v| v.as_str()) {
        Some(s) => match LlmTier::from_arg(s) {
            Ok(t) => Some(t),
            Err(m) => return Err(m),
        },
        None => None,
    };

    // MCP-304 (2026-05-11): pre-fix `as_object()` collapsed wrong-type
    // into None — `budget: "max_fuel=1M"` (string) silently created
    // the actor with no budget set when the operator clearly intended
    // a budget. Distinguish absent / null (legitimate no-budget) from
    // wrong-type (loud reject). Same MCP-261 / MCP-303 family.
    let budget_obj_opt = match args.get("budget") {
        None | Some(Value::Null) => None,
        Some(Value::Object(o)) => Some(o.clone()),
        Some(v) => {
            let kind = json_type_name(v);
            return Err(format!("budget must be an object, got {kind}"));
        }
    };
    // MCP-382 (2026-05-11): pre-fix `get_i32 = |k| as_i64().map(|n| n as i32)`
    // silently wrapped values > i32::MAX. scaffold_actor with
    // `budget: { max_executions_per_hour: 5_000_000_000 }` got
    // 705_032_704 persisted — the actor hit its rate limit far sooner
    // than declared. Same MCP-299 fix applied to set_actor_budget;
    // missed at scaffold_actor where the closure operates over the
    // inner `o` map instead of `args`. Reject values outside i32 range
    // loudly so the typo is visible at scaffold time, not at runtime.
    let budget = if let Some(o) = budget_obj_opt {
        let get_i32 = |k: &str| -> Result<Option<i32>, String> {
            match o.get(k).and_then(|v| v.as_i64()) {
                Some(n) if (i32::MIN as i64..=i32::MAX as i64).contains(&n) => Ok(Some(n as i32)),
                Some(n) => Err(format!(
                    "budget.{k} value {n} is outside the i32 range (max {})",
                    i32::MAX
                )),
                None => Ok(None),
            }
        };
        let get_i64 = |k: &str| o.get(k).and_then(|v| v.as_i64());

        // MCP-1183 (2026-05-17): scaffold_actor's budget block was a
        // weaker subset of `set_actor_budget`'s validation — it
        // checked i32 RANGE (MCP-382) but missed two gates that
        // `handle_set_actor_budget` enforces:
        //
        //   1. Float-rejection. `Value::as_i64()` returns None for
        //      `100.5` so fractional values were silently dropped
        //      ("None = omitted = no limit"). A caller passing
        //      `max_executions_per_hour: 100.5` ended up with NO
        //      limit on that field, the opposite of the operator's
        //      intent. Sibling to MCP-276 (per-entry ttl_hours
        //      direction class).
        //
        //   2. Positivity check. 0 and negative values were
        //      silently accepted. `max_fuel_per_execution: -1`
        //      depending on enforcement logic either treated as
        //      "unlimited" (bypass) or "limit -1" (every execution
        //      immediately exceeds — self-DoS). `max_workflows_per_
        //      minute: 0` blocks all workflow dispatch for the actor.
        //
        // Mirror the canonical pattern from `handle_set_actor_budget`
        // so the two paths that write to `actor_budget_policies` apply
        // identical gates. Same MCP-internal cross-handler validation
        // drift as MCP-1182's cross-protocol drift fix.
        for field in &[
            "max_executions_per_hour",
            "max_executions_total",
            "max_fuel_per_execution",
            "max_fuel_per_hour",
            "max_outbound_requests_per_hour",
            "max_workflow_count",
            "max_workflows_per_minute",
            "max_compilations_per_hour",
            "max_llm_tokens_per_day",
        ] {
            if let Some(v) = o.get(*field) {
                if v.as_f64().is_some_and(|f| f.fract() != 0.0) {
                    return Err(format!(
                        "budget.{field} must be a positive integer, got {}",
                        v.as_f64().unwrap_or_default()
                    ));
                }
            }
        }

        let max_executions_per_hour = get_i32("max_executions_per_hour")?;
        let max_outbound_requests_per_hour = get_i32("max_outbound_requests_per_hour")?;
        let max_workflow_count = get_i32("max_workflow_count")?;
        let max_workflows_per_minute = get_i32("max_workflows_per_minute")?;
        let max_compilations_per_hour = get_i32("max_compilations_per_hour")?;
        let max_executions_total = get_i64("max_executions_total");
        let max_fuel_per_execution = get_i64("max_fuel_per_execution");
        let max_fuel_per_hour = get_i64("max_fuel_per_hour");
        let max_llm_tokens_per_day = get_i64("max_llm_tokens_per_day");

        // MCP-1183: positivity check on all 8 fields. None = omitted
        // (use default / no limit); 0 or negative is invalid for any
        // budget knob (a zero-fuel budget means no WASM execution
        // can complete; a negative count is semantically meaningless).
        let field_checks: [(&str, Option<i64>); 9] = [
            (
                "max_executions_per_hour",
                max_executions_per_hour.map(i64::from),
            ),
            ("max_llm_tokens_per_day", max_llm_tokens_per_day),
            ("max_executions_total", max_executions_total),
            ("max_fuel_per_execution", max_fuel_per_execution),
            ("max_fuel_per_hour", max_fuel_per_hour),
            (
                "max_outbound_requests_per_hour",
                max_outbound_requests_per_hour.map(i64::from),
            ),
            ("max_workflow_count", max_workflow_count.map(i64::from)),
            (
                "max_workflows_per_minute",
                max_workflows_per_minute.map(i64::from),
            ),
            (
                "max_compilations_per_hour",
                max_compilations_per_hour.map(i64::from),
            ),
        ];
        for (field, val) in &field_checks {
            if let Some(n) = val {
                if *n <= 0 {
                    return Err(format!("budget.{field} must be > 0, got {n}"));
                }
            }
        }

        Some(BudgetSpec {
            max_executions_per_hour,
            max_executions_total,
            max_fuel_per_execution,
            max_fuel_per_hour,
            max_outbound_requests_per_hour,
            max_workflow_count,
            max_workflows_per_minute,
            max_compilations_per_hour,
            max_llm_tokens_per_day,
            on_budget_exceeded: o
                .get("on_budget_exceeded")
                .and_then(|v| v.as_str())
                .map(String::from),
        })
    } else {
        None
    };

    // MCP-276 (2026-05-10): pre-fix per-entry `ttl_hours` was read via
    // bare `.and_then(|v| v.as_f64())` — wrong-type collapsed to None,
    // and downstream `default_expires_at` returns None for NaN/Inf/0/
    // negative. So `seed_memories.foo.ttl_hours = "168"` (string) or
    // -50 quietly persisted the seed as a permanent memory when the
    // operator wanted a 168-hour TTL. Mirror MCP-208 / MCP-256 / MCP-257
    // — distinguish absent / null / wrong-type / NaN-Inf / out-of-range.
    let seed_memories: Vec<SeedMemorySpec> =
        if let Some(map) = args.get("seed_memories").and_then(|v| v.as_object()) {
            let mut out: Vec<SeedMemorySpec> = Vec::with_capacity(map.len());
            for (key, entry) in map {
                // MCP-1224 (2026-05-18): canonical key validation at the
                // boundary. Pre-fix `seed_memories: { "   ": ... }` was
                // accepted, persisted via `persist_memory_with_metadata`'s
                // shallow inline check, and produced a memory row readers
                // (all trim post-MCP-834) couldn't recover. Rejecting at
                // the boundary gives a clearer error message naming the
                // offending JSON key.
                let key = match talos_memory::validate_memory_key(key) {
                    Ok(trimmed) => trimmed.to_string(),
                    Err(e) => {
                        return Err(format!(
                            "seed_memories['{}']: invalid memory key ({})",
                            talos_text_util::bounded_preview(key, 64),
                            e
                        ))
                    }
                };
                let value = match entry.get("value") {
                    Some(v) => v.clone(),
                    None => continue, // legacy: silently skip entries without value
                };
                // MCP-345 (2026-05-11): strict-parse memory_type. Pre-fix
                // `.as_str().unwrap_or("semantic")` collapsed wrong-type
                // into "semantic" silently — but the operator may have
                // intended "episodic" with TTL. Same MCP-341 family
                // applied to scaffold_actor's per-seed parser. Also
                // validate against the canonical type list since the
                // service rejects unknown types but the error message
                // points at "scaffold_actor" rather than the offending
                // seed entry. Same shape for metadata_kind — strict-parse
                // the wrong-type case so a typo doesn't silently store
                // None metadata on what was meant to be a labeled write.
                let memory_type = match entry.get("memory_type") {
                    None | Some(Value::Null) => "semantic".to_string(),
                    Some(v) => match v.as_str() {
                        // MCP-819: canonical memory_type predicate.
                        Some(s) if talos_memory::is_valid_memory_type(s) => s.to_string(),
                        Some(s) => {
                            return Err(format!(
                                "seed_memories['{}'].memory_type must be one of {} — got '{}'",
                                talos_text_util::bounded_preview(&key, 64),
                                talos_memory::memory_types_csv(),
                                talos_text_util::bounded_preview(s, 64)
                            ))
                        }
                        None => {
                            let kind = json_type_name(v);
                            return Err(format!(
                                "seed_memories['{key}'].memory_type must be a string, got {kind}"
                            ));
                        }
                    },
                };
                let metadata_kind = match entry.get("metadata_kind") {
                    None | Some(Value::Null) => None,
                    Some(v) => match v.as_str() {
                        Some(s) => Some(s.to_string()),
                        None => {
                            let kind = json_type_name(v);
                            return Err(format!(
                                "seed_memories['{key}'].metadata_kind must be a string, got {kind}"
                            ));
                        }
                    },
                };
                let ttl_hours: Option<f64> = match entry.get("ttl_hours") {
                    None | Some(Value::Null) => None,
                    Some(v) => match v.as_f64() {
                        Some(h) if !h.is_finite() => {
                            return Err(format!(
                                "seed_memories['{key}'].ttl_hours must be a finite number"
                            ))
                        }
                        Some(h) if !(1.0..=8760.0).contains(&h) => {
                            return Err(format!(
                            "seed_memories['{key}'].ttl_hours must be between 1 and 8760, got {h}"
                        ))
                        }
                        Some(h) => Some(h),
                        None => {
                            let kind = json_type_name(v);
                            return Err(format!(
                                "seed_memories['{key}'].ttl_hours must be a number, got {kind}"
                            ));
                        }
                    },
                };
                out.push(SeedMemorySpec {
                    key: key.clone(),
                    value,
                    memory_type,
                    metadata_kind,
                    ttl_hours,
                });
            }
            out
        } else {
            Vec::new()
        };

    let starter_workflow = match args.get("starter_workflow").and_then(|v| v.as_object()) {
        Some(o) => {
            let wf_name = match o.get("name").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => {
                    return Err(
                        "starter_workflow.name is required when starter_workflow is set"
                            .to_string(),
                    )
                }
            };
            let system_prompt =
                match o.get("system_prompt").and_then(|v| v.as_str()) {
                    Some(s) => s.to_string(),
                    None => return Err(
                        "starter_workflow.system_prompt is required when starter_workflow is set"
                            .to_string(),
                    ),
                };
            // MCP-350 (2026-05-11): pre-fix `filter_map(|v| v.as_str()...)`
            // silently dropped non-string entries from the LLM's required-
            // output-key list. Operator passing
            // `output_schema_keys: ["title", 42, "summary"]` narrowed the
            // schema-validation gate from 3 keys to 2 — the LLM template
            // then accepted outputs missing `42`'s intended key, surfacing
            // as a "looks fine" pass on subsequent runs even though the
            // operator declared a 3-key contract. Same MCP-349 family
            // applied to a nested `starter_workflow` object; open-coded
            // since `o` is `&Map<String, Value>`.
            let output_schema_keys: Vec<String> = match o.get("output_schema_keys") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(arr)) => {
                    let mut out: Vec<String> = Vec::with_capacity(arr.len());
                    for (i, v) in arr.iter().enumerate() {
                        match v.as_str() {
                            Some(s) => out.push(s.to_string()),
                            None => {
                                let kind = json_type_name(v);
                                return Err(format!(
                                    "starter_workflow.output_schema_keys[{i}] must be a string, got {kind}"
                                ));
                            }
                        }
                    }
                    out
                }
                Some(v) => {
                    let kind = json_type_name(v);
                    return Err(format!(
                        "starter_workflow.output_schema_keys must be an array of strings, got {kind}"
                    ));
                }
            };
            // MCP-255 (2026-05-10): pre-fix `as_u64().unwrap_or(2048) as u32`
            // silently substituted the default for any wrong-type value
            // (`max_tokens: "8000"` string, `max_tokens: 1.5` float,
            // `max_tokens: -1`) AND silently truncated values that overflow
            // u32 (`max_tokens: 5_000_000_000` → 705_032_704). Same family
            // as MCP-187. Range cap [1, 16_384] mirrors the downstream
            // `validate_starter_workflow` check so the operator gets one
            // clear error from the boundary instead of a deeper rejection.
            let max_tokens: u32 = match o.get("max_tokens") {
                None | Some(Value::Null) => 2048,
                Some(v) => match v.as_u64() {
                    Some(n) if (1..=16_384).contains(&n) => n as u32,
                    Some(n) => {
                        return Err(format!(
                            "starter_workflow.max_tokens must be in [1, 16384], got {n}"
                        ))
                    }
                    None => {
                        let kind = json_type_name(v);
                        return Err(format!(
                            "starter_workflow.max_tokens must be a non-negative integer, got {kind}"
                        ));
                    }
                },
            };
            // MCP-348 (2026-05-11): pre-fix `as_str().unwrap_or("anthropic")`
            // collapsed wrong-type into "anthropic". Tier-relevant: an
            // operator scaffolding a tier-1 actor who passes
            // `provider: 42` (number) silently gets "anthropic"
            // assigned. The tier ceiling is enforced separately so the
            // job will fail at dispatch with a less obvious error, but
            // the underlying typo is masked by the silent default.
            // Same MCP-346/347 family applied to a nested-object field
            // — open-coded to match the surrounding `max_tokens` shape
            // since the helper takes `&Value` while `o` is `&Map<...>`.
            let provider = match o.get("provider") {
                None | Some(Value::Null) => "anthropic".to_string(),
                Some(v) => match v.as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        let kind = json_type_name(v);
                        return Err(format!(
                            "starter_workflow.provider must be a string, got {kind}"
                        ));
                    }
                },
            };
            let model = o.get("model").and_then(|v| v.as_str()).map(String::from);
            let description = o
                .get("description")
                .and_then(|v| v.as_str())
                .map(String::from);
            Some(StarterWorkflowSpec {
                name: wf_name,
                description,
                system_prompt,
                output_schema_keys,
                max_tokens,
                provider,
                model,
            })
        }
        None => None,
    };

    Ok(ScaffoldRequest {
        name,
        description,
        max_capability_world,
        llm_tier,
        budget,
        seed_memories,
        starter_workflow,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn err_of(args: serde_json::Value) -> String {
        parse_scaffold_request(&args).expect_err("expected parse rejection")
    }

    // ── Error strings locked verbatim (r304 discipline) ────────────────────

    #[test]
    fn name_errors_locked() {
        assert_eq!(err_of(json!({})), "Missing required field: name");
        assert_eq!(
            err_of(json!({"name": "   "})),
            "name must be a non-empty, non-whitespace string"
        );
        assert_eq!(
            err_of(json!({"name": 42})),
            "name must be a string, got number"
        );
    }

    #[test]
    fn description_errors_locked() {
        assert_eq!(
            err_of(json!({"name": "a", "description": ["x"]})),
            "description must be a string, got array"
        );
        // Absent / null / empty-string all mean "no description".
        let req = parse_scaffold_request(&json!({"name": "a", "description": ""})).unwrap();
        assert_eq!(req.description, None);
        let req = parse_scaffold_request(&json!({"name": "a", "description": null})).unwrap();
        assert_eq!(req.description, None);
        // Trimmed on the happy path.
        let req = parse_scaffold_request(&json!({"name": "a", "description": "  hi  "})).unwrap();
        assert_eq!(req.description.as_deref(), Some("hi"));
    }

    #[test]
    fn capability_world_and_tier_errors_locked() {
        assert_eq!(
            err_of(json!({"name": "a", "max_capability_world": 123})),
            "max_capability_world must be a string, got number"
        );
        assert_eq!(
            err_of(json!({"name": "a", "llm_tier": "tier3"})),
            "llm_tier must be 'tier1' or 'tier2' (got 'tier3')"
        );
        // Default world when absent.
        let req = parse_scaffold_request(&json!({"name": "a"})).unwrap();
        assert_eq!(req.max_capability_world, "agent-node");
        assert!(req.llm_tier.is_none());
    }

    #[test]
    fn budget_errors_locked() {
        assert_eq!(
            err_of(json!({"name": "a", "budget": "max_fuel=1M"})),
            "budget must be an object, got string"
        );
        assert_eq!(
            err_of(json!({"name": "a", "budget": {"max_executions_per_hour": 5_000_000_000i64}})),
            format!(
                "budget.max_executions_per_hour value 5000000000 is outside the i32 range (max {})",
                i32::MAX
            )
        );
        assert_eq!(
            err_of(json!({"name": "a", "budget": {"max_executions_per_hour": 100.5}})),
            "budget.max_executions_per_hour must be a positive integer, got 100.5"
        );
        assert_eq!(
            err_of(json!({"name": "a", "budget": {"max_fuel_per_execution": -1}})),
            "budget.max_fuel_per_execution must be > 0, got -1"
        );
        assert_eq!(
            err_of(json!({"name": "a", "budget": {"max_workflows_per_minute": 0}})),
            "budget.max_workflows_per_minute must be > 0, got 0"
        );
    }

    #[test]
    fn budget_happy_path_maps_all_fields() {
        let req = parse_scaffold_request(&json!({
            "name": "a",
            "budget": {
                "max_executions_per_hour": 10,
                "max_executions_total": 100,
                "max_fuel_per_execution": 1_000_000,
                "max_fuel_per_hour": 10_000_000,
                "max_outbound_requests_per_hour": 50,
                "max_workflow_count": 5,
                "max_workflows_per_minute": 2,
                "max_compilations_per_hour": 3,
                "on_budget_exceeded": "suspend"
            }
        }))
        .unwrap();
        let b = req.budget.expect("budget parsed");
        assert_eq!(b.max_executions_per_hour, Some(10));
        assert_eq!(b.max_executions_total, Some(100));
        assert_eq!(b.max_fuel_per_execution, Some(1_000_000));
        assert_eq!(b.max_fuel_per_hour, Some(10_000_000));
        assert_eq!(b.max_outbound_requests_per_hour, Some(50));
        assert_eq!(b.max_workflow_count, Some(5));
        assert_eq!(b.max_workflows_per_minute, Some(2));
        assert_eq!(b.max_compilations_per_hour, Some(3));
        assert_eq!(b.on_budget_exceeded.as_deref(), Some("suspend"));
    }

    #[test]
    fn seed_memory_errors_locked() {
        assert_eq!(
            err_of(json!({"name": "a", "seed_memories": {"k": {"value": 1, "memory_type": 42}}})),
            "seed_memories['k'].memory_type must be a string, got number"
        );
        assert_eq!(
            err_of(json!({"name": "a", "seed_memories": {"k": {"value": 1, "metadata_kind": 42}}})),
            "seed_memories['k'].metadata_kind must be a string, got number"
        );
        assert_eq!(
            err_of(json!({"name": "a", "seed_memories": {"k": {"value": 1, "ttl_hours": "168"}}})),
            "seed_memories['k'].ttl_hours must be a number, got string"
        );
        assert_eq!(
            err_of(json!({"name": "a", "seed_memories": {"k": {"value": 1, "ttl_hours": -50}}})),
            "seed_memories['k'].ttl_hours must be between 1 and 8760, got -50"
        );
    }

    #[test]
    fn seed_memory_entry_without_value_is_skipped() {
        // Legacy contract: entries without `value` are silently skipped.
        let req = parse_scaffold_request(&json!({
            "name": "a",
            "seed_memories": {
                "no-value": {"memory_type": "semantic"},
                "with-value": {"value": {"x": 1}}
            }
        }))
        .unwrap();
        assert_eq!(req.seed_memories.len(), 1);
        assert_eq!(req.seed_memories[0].key, "with-value");
        assert_eq!(req.seed_memories[0].memory_type, "semantic");
    }

    #[test]
    fn starter_workflow_errors_locked() {
        assert_eq!(
            err_of(json!({"name": "a", "starter_workflow": {}})),
            "starter_workflow.name is required when starter_workflow is set"
        );
        assert_eq!(
            err_of(json!({"name": "a", "starter_workflow": {"name": "w"}})),
            "starter_workflow.system_prompt is required when starter_workflow is set"
        );
        assert_eq!(
            err_of(json!({"name": "a", "starter_workflow": {
                "name": "w", "system_prompt": "p", "output_schema_keys": ["title", 42]
            }})),
            "starter_workflow.output_schema_keys[1] must be a string, got number"
        );
        assert_eq!(
            err_of(json!({"name": "a", "starter_workflow": {
                "name": "w", "system_prompt": "p", "output_schema_keys": "title"
            }})),
            "starter_workflow.output_schema_keys must be an array of strings, got string"
        );
        assert_eq!(
            err_of(json!({"name": "a", "starter_workflow": {
                "name": "w", "system_prompt": "p", "max_tokens": 50_000
            }})),
            "starter_workflow.max_tokens must be in [1, 16384], got 50000"
        );
        assert_eq!(
            err_of(json!({"name": "a", "starter_workflow": {
                "name": "w", "system_prompt": "p", "max_tokens": "8000"
            }})),
            "starter_workflow.max_tokens must be a non-negative integer, got string"
        );
        assert_eq!(
            err_of(json!({"name": "a", "starter_workflow": {
                "name": "w", "system_prompt": "p", "provider": 42
            }})),
            "starter_workflow.provider must be a string, got number"
        );
    }

    #[test]
    fn starter_workflow_defaults_preserved() {
        let req = parse_scaffold_request(&json!({
            "name": "a",
            "starter_workflow": {"name": "w", "system_prompt": "p"}
        }))
        .unwrap();
        let wf = req.starter_workflow.expect("starter workflow parsed");
        assert_eq!(wf.max_tokens, 2048);
        assert_eq!(wf.provider, "anthropic");
        assert!(wf.output_schema_keys.is_empty());
        assert!(wf.model.is_none());
    }

    #[test]
    fn name_is_trimmed_for_storage() {
        let req = parse_scaffold_request(&json!({"name": "  spaced  "})).unwrap();
        assert_eq!(req.name, "spaced");
    }
}
