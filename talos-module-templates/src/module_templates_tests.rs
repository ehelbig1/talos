#[cfg(test)]
mod tests {
    use crate::{default_allowed_hosts_for_world, extract_world_from_source, validate_internal};

    #[test]
    fn test_extract_world_from_source_finds_marker() {
        let source = r#"#[talos_module(world = "http-node")]"#;
        assert_eq!(
            extract_world_from_source(source),
            Some("http-node".to_string())
        );
    }

    #[test]
    fn test_extract_world_from_source_not_found() {
        let source = r#"#[talos_node]"#;
        assert_eq!(extract_world_from_source(source), None);
    }

    #[test]
    fn test_default_allowed_hosts_for_world_http() {
        let hosts = default_allowed_hosts_for_world("http-node");
        assert_eq!(hosts, vec!["*".to_string()]);
    }

    #[test]
    fn test_default_allowed_hosts_for_world_network() {
        let hosts = default_allowed_hosts_for_world("network-node");
        assert_eq!(hosts, vec!["*".to_string()]);
    }

    #[test]
    fn test_default_allowed_hosts_for_world_minimal() {
        let hosts = default_allowed_hosts_for_world("minimal-node");
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_validate_internal_accepts_simple_config() {
        let config = serde_json::json!({
            "key": "value",
            "number": 42
        });
        assert!(validate_internal(&config).is_ok());
    }

    #[test]
    fn test_validate_internal_rejects_unsafe_key() {
        let config = serde_json::json!({
            "key{{}}": "value"
        });
        assert!(validate_internal(&config).is_err());
    }

    #[test]
    fn test_validate_internal_rejects_unsafe_value() {
        let config = serde_json::json!({
            "key": "value${ENV}"
        });
        assert!(validate_internal(&config).is_err());
    }

    #[test]
    fn test_validate_internal_accepts_nested_config() {
        let config = serde_json::json!({
            "outer": {
                "inner": ["value1", "value2"]
            }
        });
        assert!(validate_internal(&config).is_ok());
    }

    #[test]
    fn test_validate_internal_rejects_nested_unsafe() {
        let config = serde_json::json!({
            "outer": {
                "inner": "{{unsafe}}"
            }
        });
        assert!(validate_internal(&config).is_err());
    }
}
