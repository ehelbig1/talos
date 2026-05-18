//! Integration tests for the module template system.
//!
//! Validates built-in templates: schema validity, config validation,
//! code generation, and template retrieval.

use controller::module_templates::{all_templates, get_template, validate_config};
use controller::templates::TemplateGenerator;
use serde_json::json;

// ---------------------------------------------------------------------------
// Template retrieval
// ---------------------------------------------------------------------------

#[test]
fn all_core_templates_can_be_retrieved_by_id() {
    let expected_ids = [
        "http-request",
        "database-query",
        "send-slack-message",
        "send-gmail",
        "json-transform",
        "mock-responder",
        "redis-cache",
        "file-transform",
    ];

    for id in &expected_ids {
        let template = get_template(id);
        assert!(
            template.is_some(),
            "template '{}' should be retrievable by ID",
            id
        );
    }
}

#[test]
fn all_templates_count_is_sufficient() {
    let count = all_templates().len();
    assert!(
        count >= 8,
        "there should be at least 8 built-in templates (found {})",
        count
    );
}

#[test]
fn get_template_returns_none_for_unknown_id() {
    assert!(get_template("nonexistent-template").is_none());
    assert!(get_template("").is_none());
}

// ---------------------------------------------------------------------------
// Config schema validity
// ---------------------------------------------------------------------------

#[test]
fn config_schema_is_valid_object_for_each_template() {
    for t in all_templates() {
        let schema = t.config_schema;
        assert!(
            schema.is_object(),
            "Template '{}' config_schema should be a JSON object",
            t.name
        );
        assert_eq!(
            schema["type"], "object",
            "Template '{}' config_schema should have type: object",
            t.name
        );
    }
}

// ---------------------------------------------------------------------------
// validate_config — valid configs
// ---------------------------------------------------------------------------

#[test]
fn validate_config_accepts_valid_http_request() {
    let t = get_template("http-request").unwrap();
    let config = json!({
        "URL": "https://api.example.com/data",
        "METHOD": "POST",
        "BODY": "{\"test\": true}"
    });
    assert!(validate_config(&t, &config).is_ok());
}

#[test]
fn validate_config_accepts_valid_database_query() {
    let t = get_template("database-query").unwrap();
    let config = json!({
        "query": "SELECT id, name FROM users WHERE active = true",
        "params": ["true"]
    });
    assert!(validate_config(&t, &config).is_ok());
}

#[test]
fn validate_config_accepts_valid_slack_message() {
    let t = get_template("send-slack-message").unwrap();
    let config = json!({
        "CHANNEL": "#alerts",
        "TEXT": "Alert: testing",
        "BOT_TOKEN": "slack_token"
    });
    assert!(validate_config(&t, &config).is_ok());
}

#[test]
fn validate_config_accepts_valid_email_send() {
    let t = get_template("send-gmail").unwrap();
    let config = json!({
        "TO": "user@example.com",
        "SUBJECT": "Test Subject",
        "BODY": "Hello world",
        "OAUTH_TOKEN": "token_path"
    });
    assert!(validate_config(&t, &config).is_ok());
}

#[test]
fn validate_config_accepts_valid_json_transform() {
    let t = get_template("json-transform").unwrap();
    let config = json!({
        "SELECTOR": "data.items",
        "TRANSFORM": "flatten"
    });
    assert!(validate_config(&t, &config).is_ok());
}

#[test]
fn validate_config_accepts_valid_mock_responder() {
    let t = get_template("mock-responder").unwrap();
    let config = json!({"RESPONSE": "{\"status\": \"ok\"}"});
    assert!(validate_config(&t, &config).is_ok());
}

#[test]
fn validate_config_accepts_valid_redis_cache() {
    let t = get_template("redis-cache").unwrap();
    let config = json!({
        "operation": "get",
        "key": "user:123"
    });
    assert!(validate_config(&t, &config).is_ok());
}

#[test]
fn validate_config_accepts_valid_file_transform() {
    let t = get_template("file-transform").unwrap();
    let config = json!({
        "input_file": "/data/input.csv",
        "output_file": "/data/output.json"
    });
    assert!(validate_config(&t, &config).is_ok());
}

// ---------------------------------------------------------------------------
// validate_config — injection protection
// ---------------------------------------------------------------------------

#[test]
fn validate_config_rejects_injection_in_keys() {
    let t = get_template("http-request").unwrap();
    let config = json!({
        "URL": "https://example.com",
        "{{evil}}": "bad"
    });
    assert!(validate_config(&t, &config).is_err());
}

#[test]
fn validate_config_rejects_injection_in_values() {
    let t = get_template("http-request").unwrap();
    let config = json!({
        "URL": "https://example.com",
        "METHOD": "{{malicious_script}}"
    });
    assert!(validate_config(&t, &config).is_err());
}

// ---------------------------------------------------------------------------
// generate_code — produces valid Rust source for each template
// ---------------------------------------------------------------------------

#[test]
fn generate_code_http_request_contains_key_markers() {
    let t = get_template("http-request").unwrap();
    let config = json!({"URL": "https://api.test.com", "METHOD": "POST"});
    let generator = TemplateGenerator::new();
    let code = generator.generate_code(&t.code_template, &config).unwrap();

    assert!(
        code.contains("talos_module"),
        "should contain talos_module attribute"
    );
    assert!(
        code.contains("network-node"),
        "should target network-node world"
    );
    assert!(code.contains("fn run("), "should contain a run function");
}

#[test]
fn generate_code_database_query_contains_key_markers() {
    let t = get_template("database-query").unwrap();
    let config = json!({"query": "SELECT * FROM users"});
    let generator = TemplateGenerator::new();
    let code = generator.generate_code(&t.code_template, &config).unwrap();

    assert!(code.contains("database-node") || code.contains("minimal-node"));
    assert!(code.contains("SELECT * FROM users") || code.contains("query"));
}

#[test]
fn generate_code_all_templates_produce_nonempty_rust() {
    let generator = TemplateGenerator::new();
    let ids = [
        "http-request",
        "database-query",
        "send-slack-message",
        "send-gmail",
    ];

    for id in &ids {
        let t = get_template(id).unwrap();
        let config = json!({});
        let code = generator.generate_code(&t.code_template, &config).unwrap();
        assert!(!code.is_empty(), "template '{}' generated empty code", id);
        assert!(
            code.contains("fn run("),
            "template '{}' should contain a run function",
            id
        );
    }
}
