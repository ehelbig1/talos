use anyhow::{bail, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};
use talos_registry::NodeTemplate;

/// Returns all module templates discovered in the `module-templates` directory.
/// This is a synchronous version used primarily for testing and discovery.
pub fn all_templates() -> Vec<NodeTemplate> {
    let base_path = if Path::new("/app/module-templates").exists() {
        PathBuf::from("/app/module-templates")
    } else {
        // Fallback for development - assuming we're in controller/ or project root
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        if p.ends_with("controller") {
            p.pop();
        }
        p.push("module-templates");
        p
    };

    let mut templates = Vec::new();
    if let Ok(entries) = std::fs::read_dir(base_path) {
        for entry in entries.flatten() {
            if let Some(t) = load_template(&entry.path()) {
                templates.push(t);
            }
        }
    }

    // Sort for stability
    templates.sort_by(|a, b| a.name.cmp(&b.name));
    templates
}

/// Retrieves a specific module template by its name.
pub fn get_template(name: &str) -> Option<NodeTemplate> {
    all_templates().into_iter().find(|t| t.name == name)
}

/// Validates that a configuration object is safe for use with a template.
pub fn validate_config(_template: &NodeTemplate, config: &Value) -> Result<(), String> {
    validate_internal(config).map_err(|e| e.to_string())
}

fn load_template(path: &Path) -> Option<NodeTemplate> {
    if !path.is_dir() {
        return None;
    }
    let talos_json = path.join("talos.json");
    let template_rs = path.join("template.rs");

    if !talos_json.exists() || !template_rs.exists() {
        return None;
    }

    let meta_str = std::fs::read_to_string(talos_json).ok()?;
    let meta: Value = serde_json::from_str(&meta_str).ok()?;
    let code = std::fs::read_to_string(template_rs).ok()?;

    let name = meta.get("name")?.as_str()?.to_string();
    let category = meta
        .get("category")
        .and_then(|v| v.as_str())
        .unwrap_or("Uncategorized")
        .to_string();
    let description = meta
        .get("description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let config_schema = meta
        .get("config_schema")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let world = meta
        .get("capability_world")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| extract_world_from_source(&code))
        .unwrap_or_else(|| "minimal-node".to_string());

    let allowed_hosts = meta
        .get("allowed_hosts")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_else(|| default_allowed_hosts_for_world(&world));

    Some(NodeTemplate {
        id: uuid::Uuid::new_v4(),
        name,
        description,
        category,
        config_schema,
        code_template: code,
        precompiled_wasm: None,
        icon: meta
            .get("icon")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        oci_url: meta
            .get("oci_url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        allowed_hosts,
        allowed_methods: meta
            .get("allowed_methods")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default(),
        allowed_secrets: meta
            .get("allowed_secrets")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default(),
        requires_approval_for: meta
            .get("requires_approval_for")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default(),
        max_retries: meta
            .get("max_retries")
            .and_then(|v| v.as_i64())
            .unwrap_or(3) as i32,
        retry_backoff_ms: meta
            .get("retry_backoff_ms")
            .and_then(|v| v.as_i64())
            .unwrap_or(1000),
        capability_world: world,
        dependencies: None, // catalog templates use only the standard crate set
    })
}

fn extract_world_from_source(source: &str) -> Option<String> {
    let marker = r#"talos_module(world = ""#;
    source.find(marker).and_then(|start| {
        let rest = &source[start + marker.len()..];
        rest.find('"').map(|end| rest[..end].to_string())
    })
}

fn default_allowed_hosts_for_world(world: &str) -> Vec<String> {
    let needs_hosts = world.contains("network")
        || world.contains("http")
        || world.contains("automation")
        || world.contains("secrets")
        || world.contains("database");
    if needs_hosts {
        vec!["*".to_string()]
    } else {
        vec![]
    }
}

fn validate_internal(config: &Value) -> Result<()> {
    match config {
        Value::Object(map) => {
            for (key, value) in map {
                validate_internal(value)?;
                if key.contains("{{") || key.contains("}}") || key.contains("${") {
                    bail!(
                        "Config key '{}' contains potentially unsafe characters",
                        key
                    );
                }
            }
        }
        Value::String(s) if (s.contains("{{") || s.contains("}}") || s.contains("${")) => {
            bail!("Config value contains potentially unsafe characters");
        }
        Value::Array(arr) => {
            for v in arr {
                validate_internal(v)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
#[path = "module_templates_tests.rs"]
mod tests;
