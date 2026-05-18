use anyhow::bail;

fn parse_deps() {
    let dependencies: Option<&serde_json::Value> = None;
    let mut custom_deps = String::new();
    if let Some(serde_json::Value::Object(deps)) = dependencies {
        for (crate_name, version_val) in deps {
            if !crate_name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
                bail!("Invalid crate name: {}", crate_name);
            }
            let version = match version_val {
                serde_json::Value::String(s) => s,
                _ => bail!("Invalid dependency version format for crate {}", crate_name),
            };
            if version.contains("git") || version.contains("path") || version.contains('{') || version.contains('}') {
                bail!("Invalid dependency format for {}: only version strings allowed to prevent LFI", crate_name);
            }
            custom_deps.push_str(&format!("{} = \"{}\"\n", crate_name, version));
        }
    }
}
