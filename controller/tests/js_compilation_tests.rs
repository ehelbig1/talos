//! Integration tests for JS/TS compilation support.
//!
//! Tests language detection, JS world extraction, and template availability.
//! These are pure-logic tests that do not require a database or external tools.

use controller::compilation::js_templates;
use controller::compilation::{detect_language, ModuleLanguage};

// ---------------------------------------------------------------------------
// ModuleLanguage::from_str_loose
// ---------------------------------------------------------------------------

#[test]
fn from_str_loose_rust_variants() {
    assert_eq!(ModuleLanguage::from_str_loose("rust"), ModuleLanguage::Rust);
    assert_eq!(ModuleLanguage::from_str_loose("Rust"), ModuleLanguage::Rust);
    assert_eq!(ModuleLanguage::from_str_loose("RUST"), ModuleLanguage::Rust);
}

#[test]
fn from_str_loose_javascript_variants() {
    assert_eq!(
        ModuleLanguage::from_str_loose("javascript"),
        ModuleLanguage::JavaScript
    );
    assert_eq!(
        ModuleLanguage::from_str_loose("js"),
        ModuleLanguage::JavaScript
    );
    assert_eq!(
        ModuleLanguage::from_str_loose("JavaScript"),
        ModuleLanguage::JavaScript
    );
    assert_eq!(
        ModuleLanguage::from_str_loose("JS"),
        ModuleLanguage::JavaScript
    );
}

#[test]
fn from_str_loose_typescript_variants() {
    assert_eq!(
        ModuleLanguage::from_str_loose("typescript"),
        ModuleLanguage::TypeScript
    );
    assert_eq!(
        ModuleLanguage::from_str_loose("ts"),
        ModuleLanguage::TypeScript
    );
    assert_eq!(
        ModuleLanguage::from_str_loose("TypeScript"),
        ModuleLanguage::TypeScript
    );
    assert_eq!(
        ModuleLanguage::from_str_loose("TS"),
        ModuleLanguage::TypeScript
    );
}

#[test]
fn from_str_loose_unknown_defaults_to_rust() {
    assert_eq!(
        ModuleLanguage::from_str_loose("unknown"),
        ModuleLanguage::Rust
    );
    // Python and Go are now supported languages
    assert_eq!(
        ModuleLanguage::from_str_loose("python"),
        ModuleLanguage::Python
    );
    assert_eq!(ModuleLanguage::from_str_loose("go"), ModuleLanguage::Go);
    assert_eq!(ModuleLanguage::from_str_loose(""), ModuleLanguage::Rust);
}

// ---------------------------------------------------------------------------
// detect_language
// ---------------------------------------------------------------------------

#[test]
fn detect_language_identifies_rust_from_wit_bindgen() {
    let code = r#"
wit_bindgen::generate!({
    world: "automation-node",
    path: "../wit/talos.wit",
});
struct MyNode;
impl Guest for MyNode {
    fn run(input: String) -> Result<String, String> { Ok(input) }
}
export!(MyNode);
"#;
    assert_eq!(detect_language(code), ModuleLanguage::Rust);
}

#[test]
fn detect_language_identifies_rust_from_talos_node_macro() {
    let code = r#"
use talos_sdk_macros::talos_node;
#[talos_node(world = "http-node")]
pub fn run(input: String) -> Result<String, String> { Ok("hi".into()) }
"#;
    assert_eq!(detect_language(code), ModuleLanguage::Rust);
}

#[test]
fn detect_language_identifies_rust_from_impl_block() {
    let code = r#"
use serde_json::Value;
pub fn run(input: String) -> Result<String, String> {
    let val: Value = serde_json::from_str(&input).unwrap();
    Ok(val.to_string())
}
"#;
    assert_eq!(detect_language(code), ModuleLanguage::Rust);
}

#[test]
fn detect_language_identifies_javascript() {
    let code = r#"
export function run(input) {
    const data = JSON.parse(input);
    return JSON.stringify({ result: "ok" });
}
"#;
    assert_eq!(detect_language(code), ModuleLanguage::JavaScript);
}

#[test]
fn detect_language_identifies_javascript_with_async() {
    let code = r#"
export async function run(input) {
    const response = await fetch("https://example.com");
    return JSON.stringify({ status: response.status });
}
"#;
    assert_eq!(detect_language(code), ModuleLanguage::JavaScript);
}

#[test]
fn detect_language_identifies_typescript_with_type_annotations() {
    let code = r#"
interface InputData { message: string; }
export function run(input: string): string {
    const data: InputData = JSON.parse(input);
    return JSON.stringify({ result: "ok" });
}
"#;
    assert_eq!(detect_language(code), ModuleLanguage::TypeScript);
}

#[test]
fn detect_language_identifies_typescript_with_promise() {
    let code = r#"
export async function run(input: string): Promise<string> {
    const data = JSON.parse(input);
    return JSON.stringify(data);
}
"#;
    assert_eq!(detect_language(code), ModuleLanguage::TypeScript);
}

// ---------------------------------------------------------------------------
// extract_js_wit_world (tested via js_templates module functions)
// ---------------------------------------------------------------------------

// Note: extract_js_wit_world is a private function in compilation/mod.rs.
// We test its behavior indirectly through the existing unit tests in that module.
// Here we test the template retrieval functions from js_templates.

// ---------------------------------------------------------------------------
// JS templates exist for each supported world
// ---------------------------------------------------------------------------

#[test]
fn js_template_exists_for_minimal_world() {
    let template = js_templates::js_template_for_world("minimal-node");
    assert!(!template.is_empty());
    assert!(template.contains("export function run"));
}

#[test]
fn js_template_exists_for_http_world() {
    let template = js_templates::js_template_for_world("http-node");
    assert!(!template.is_empty());
    assert!(template.contains("fetch"));
}

#[test]
fn js_template_exists_for_network_world() {
    let template = js_templates::js_template_for_world("network-node");
    assert!(!template.is_empty());
    assert!(
        template.contains("fetch"),
        "network-node should map to HTTP template"
    );
}

#[test]
fn js_template_exists_for_database_world() {
    let template = js_templates::js_template_for_world("database-node");
    assert!(!template.is_empty());
    assert!(template.contains("query") || template.contains("database"));
}

#[test]
fn js_template_exists_for_messaging_world() {
    let template = js_templates::js_template_for_world("messaging-node");
    assert!(!template.is_empty());
    assert!(template.contains("topic") || template.contains("publish"));
}

#[test]
fn js_template_exists_for_secrets_world() {
    let template = js_templates::js_template_for_world("secrets-node");
    assert!(!template.is_empty());
    assert!(template.contains("secret") || template.contains("Secret"));
}

#[test]
fn js_template_falls_back_to_minimal_for_unknown() {
    let template = js_templates::js_template_for_world("unknown-world");
    let minimal = js_templates::js_template_for_world("minimal-node");
    assert_eq!(
        template, minimal,
        "unknown world should fall back to minimal"
    );
}

// ---------------------------------------------------------------------------
// TS templates exist for each supported world
// ---------------------------------------------------------------------------

#[test]
fn ts_template_exists_for_minimal_world() {
    let template = js_templates::ts_template_for_world("minimal-node");
    assert!(!template.is_empty());
    assert!(
        template.contains("interface") || template.contains(": string"),
        "TS minimal template should have type annotations"
    );
}

#[test]
fn ts_template_exists_for_http_world() {
    let template = js_templates::ts_template_for_world("http-node");
    assert!(!template.is_empty());
    assert!(template.contains("fetch") || template.contains("Promise"));
}

#[test]
fn ts_template_exists_for_database_world() {
    let template = js_templates::ts_template_for_world("database-node");
    assert!(!template.is_empty());
}

#[test]
fn ts_template_exists_for_messaging_world() {
    let template = js_templates::ts_template_for_world("messaging-node");
    assert!(!template.is_empty());
}

#[test]
fn ts_template_exists_for_secrets_world() {
    let template = js_templates::ts_template_for_world("secrets-node");
    assert!(!template.is_empty());
}

#[test]
fn ts_template_falls_back_to_minimal_for_unknown() {
    let template = js_templates::ts_template_for_world("unknown-world");
    let minimal = js_templates::ts_template_for_world("minimal-node");
    assert_eq!(
        template, minimal,
        "unknown world should fall back to TS minimal"
    );
}

// ---------------------------------------------------------------------------
// ModuleLanguage display and as_str
// ---------------------------------------------------------------------------

#[test]
fn module_language_as_str() {
    assert_eq!(ModuleLanguage::Rust.to_string(), "rust");
    assert_eq!(ModuleLanguage::JavaScript.to_string(), "javascript");
    assert_eq!(ModuleLanguage::TypeScript.to_string(), "typescript");
}

#[test]
fn module_language_display() {
    assert_eq!(format!("{}", ModuleLanguage::Rust), "rust");
    assert_eq!(format!("{}", ModuleLanguage::JavaScript), "javascript");
    assert_eq!(format!("{}", ModuleLanguage::TypeScript), "typescript");
}
