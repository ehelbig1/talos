//! The manifest shape a registry catalog row is read in, and the order the
//! registry catalog is listed in. One shape for both sources, so the
//! install's grant logic and the listing's renderer cannot tell which one
//! an entry came from — except by the `source` field that says so.

use crate::modules::{catalog_surfaces, registry_catalog_items, registry_entry_manifest};
use talos_module_repository::SharedRegistryEntry;

fn entry(slug: &str, name: &str, category: Option<&str>) -> SharedRegistryEntry {
    SharedRegistryEntry {
        id: uuid::Uuid::new_v4(),
        name: name.to_string(),
        catalog_slug: Some(slug.to_string()),
        category: category.map(str::to_string),
        description: Some("Reads one thing.".to_string()),
        config_schema: serde_json::json!({"type": "object", "properties": {"URL": {}}}),
        capability_world: "http-node".to_string(),
        allowed_hosts: vec!["api.example.test".to_string()],
        allowed_methods: vec!["GET".to_string()],
        allowed_secrets: vec!["example/api_key".to_string()],
        requires_approval_for: vec![],
        max_fuel: 6_450_000,
        oci_url: format!("registry.example.test/talos-tools/{slug}:v1.0.0"),
    }
}

#[test]
fn a_registry_row_reads_in_the_shape_a_template_manifest_has() {
    let item = registry_entry_manifest(&entry(
        "json-api-reader",
        "JSON API Reader",
        Some("Network"),
    ));
    assert_eq!(item["name"], "json-api-reader");
    assert_eq!(item["display_name"], "JSON API Reader");
    assert_eq!(item["category"], "Network");
    assert_eq!(item["capability_world"], "http-node");
    assert_eq!(
        item["allowed_hosts"],
        serde_json::json!(["api.example.test"])
    );
    assert_eq!(item["allowed_methods"], serde_json::json!(["GET"]));
    assert_eq!(
        item["allowed_secrets"],
        serde_json::json!(["example/api_key"])
    );
    assert_eq!(item["requires_secrets"], item["allowed_secrets"]);
    assert_eq!(
        item["config_schema"]["properties"]["URL"],
        serde_json::json!({})
    );
    assert_eq!(item["source"], "registry");
    // Nothing a template manifest carries for COMPILING is invented.
    assert!(item.get("dependencies").is_none());
    assert!(item.get("recommended_fuel").is_none());
}

#[test]
fn a_row_with_no_slug_or_category_still_has_a_name_and_a_category() {
    let mut bare = entry("x", "Unslugged", None);
    bare.catalog_slug = None;
    let item = registry_entry_manifest(&bare);
    assert_eq!(item["name"], "Unslugged");
    assert_eq!(item["category"], "catalog");
}

#[test]
fn the_registry_catalog_is_ordered_by_category_then_slug() {
    let items = registry_catalog_items(&[
        entry("zeta", "Zeta", Some("Network")),
        entry("alpha", "Alpha", Some("Network")),
        entry("mid", "Mid", Some("Data")),
    ]);
    let order: Vec<&str> = items.iter().map(|i| i["name"].as_str().unwrap()).collect();
    assert_eq!(order, ["mid", "alpha", "zeta"]);
}

#[test]
fn the_status_report_names_what_each_surface_reads_in_each_mode() {
    let disk = catalog_surfaces(false);
    let registry = catalog_surfaces(true);
    assert!(disk["install_module_from_catalog"]
        .as_str()
        .unwrap()
        .contains("compiles"));
    assert!(registry["install_module_from_catalog"]
        .as_str()
        .unwrap()
        .contains("nothing is compiled"));
    assert!(registry["list_module_catalog"]
        .as_str()
        .unwrap()
        .contains("registry"));
    assert_eq!(disk["list_templates"], registry["list_templates"]);
}
