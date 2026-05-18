use talos_sdk_macros::talos_module;

#[talos_module(world = "automation-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value =
        serde_json::from_str(&input).map_err(|e| format!("Invalid JSON input: {}", e))?;
    let config = input_json
        .get("config")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    // ── Extract config ───────────────────────────────────────────────────
    let routing_table_str = config
        .get("ROUTING_TABLE")
        .and_then(|v| v.as_str())
        .ok_or("Missing required config: ROUTING_TABLE")?;

    let routing_table: serde_json::Value = serde_json::from_str(routing_table_str).map_err(|e| {
        format!(
            "ROUTING_TABLE must be a valid JSON object mapping capability names to workflow IDs: {}",
            e
        )
    })?;

    let routing_map = routing_table
        .as_object()
        .ok_or("ROUTING_TABLE must be a JSON object, not an array or scalar")?;

    if routing_map.is_empty() {
        return Err("ROUTING_TABLE is empty -- add at least one capability-to-workflow mapping".to_string());
    }

    let default_workflow_id = config
        .get("DEFAULT_WORKFLOW_ID")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let match_threshold = config
        .get("MATCH_THRESHOLD")
        .and_then(|v| v.as_u64())
        .unwrap_or(1)
        .max(1) as usize;

    let pass_through = config
        .get("PASS_THROUGH_INPUT")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    // ── Extract the task description from input ──────────────────────────
    let data = input_json
        .get("input")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    let task_description = data
        .get("task")
        .and_then(|v| v.as_str())
        .or_else(|| data.as_str())
        .ok_or(
            "Missing 'task' in input. Expected {\"task\": \"description of work to be done\"}",
        )?
        .to_string();

    if task_description.is_empty() {
        return Err("Task description must not be empty".to_string());
    }

    let task_summary: String = task_description.chars().take(200).collect();

    // ── Tokenize and score capabilities ──────────────────────────────────
    // Tokenize: lowercase, split on whitespace + hyphens + underscores
    fn tokenize(text: &str) -> Vec<String> {
        text.to_lowercase()
            .split(|c: char| c.is_whitespace() || c == '-' || c == '_' || c == '/')
            .filter(|t| !t.is_empty() && t.len() > 1)
            .map(|t| t.to_string())
            .collect()
    }

    let task_tokens = tokenize(&task_description);

    let mut best_capability: Option<String> = None;
    let mut best_workflow_id: Option<String> = None;
    let mut best_score: usize = 0;
    let mut all_scores = serde_json::Map::new();

    for (capability, workflow_id_val) in routing_map {
        let workflow_id = workflow_id_val
            .as_str()
            .ok_or_else(|| {
                format!(
                    "ROUTING_TABLE value for '{}' must be a string (workflow_id UUID), got: {}",
                    capability, workflow_id_val
                )
            })?;

        let cap_tokens = tokenize(capability);

        // Count how many capability tokens appear in the task description
        let score = cap_tokens
            .iter()
            .filter(|ct| task_tokens.iter().any(|tt| tt.contains(ct.as_str()) || ct.contains(tt.as_str())))
            .count();

        all_scores.insert(capability.clone(), serde_json::json!(score));

        if score > best_score {
            best_score = score;
            best_capability = Some(capability.clone());
            best_workflow_id = Some(workflow_id.to_string());
        }
    }

    // ── Apply threshold and fallback ─────────────────────────────────────
    let (matched_capability, selected_workflow_id) = if best_score >= match_threshold {
        (best_capability, best_workflow_id)
    } else {
        // No match above threshold -- try default
        (None, None)
    };

    let final_workflow_id = selected_workflow_id
        .or_else(|| default_workflow_id.clone())
        .ok_or_else(|| {
            format!(
                "No capability matched with threshold {} (best score: {}). Scores: {:?}. \
                 Set DEFAULT_WORKFLOW_ID to handle unmatched tasks.",
                match_threshold,
                best_score,
                all_scores
            )
        })?;

    // ── Build dispatch output ────────────────────────────────────────────
    // The output includes __dispatch__ metadata that the Talos parallel
    // executor uses to trigger the sub-workflow.
    let dispatch_input = if pass_through {
        data.clone()
    } else {
        serde_json::json!({
            "routed_from": "multi-agent-router",
            "matched_capability": matched_capability,
            "task_summary": task_summary,
        })
    };

    let result = serde_json::json!({
        "routed": true,
        "matched_capability": matched_capability,
        "match_score": best_score,
        "workflow_id": final_workflow_id,
        "task_summary": task_summary,
        "all_scores": all_scores,
        "__dispatch__": {
            "workflow_id": final_workflow_id,
            "input": dispatch_input,
        },
    });

    serde_json::to_string(&result).map_err(|e| format!("Failed to serialize output: {}", e))
}
