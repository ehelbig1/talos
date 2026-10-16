//! Finds every catalog template that carries tests and prepares it to compile
//! natively (see `talos_module_testkit::build`).
//!
//! Discovery is by content, not by a list: a template gains or loses its
//! place here by gaining or losing a `#[cfg(test)]` module.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use talos_module_testkit::build::{generate, Module};

/// Crates every module gets without declaring them.
const BUNDLED: &[&str] = &["serde", "serde_json"];

/// The crates this crate links, read from its own manifest.
fn linked_crates(manifest: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut in_deps = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_deps = t == "[dependencies]";
            continue;
        }
        if in_deps && !t.starts_with('#') {
            if let Some((name, _)) = t.split_once('=') {
                out.insert(name.trim().trim_end_matches(".workspace").to_string());
            }
        }
    }
    out
}

/// The crates a template declares, through the one reader of a template's
/// manifest (the same one every compile path uses).
fn declared_crates(dir: &Path) -> Vec<String> {
    let template = talos_compilation::CatalogTemplate::load(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    template
        .dependencies()
        .and_then(serde_json::Value::as_object)
        .map(|deps| deps.keys().cloned().collect())
        .unwrap_or_default()
}

fn main() {
    let here = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    // allow-undocumented-env: OUT_DIR — set by cargo for a build script; not Talos configuration
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let templates = here.join("../module-templates");
    // The skeletons `make new-template` copies are templates too, held to the
    // same tests and gates, so a new template starts from one that passes.
    let skeletons = here.join("skeletons");
    println!("cargo:rerun-if-changed={}", templates.display());
    println!("cargo:rerun-if-changed={}", skeletons.display());
    println!("cargo:rerun-if-changed=Cargo.toml");

    let linked =
        linked_crates(&std::fs::read_to_string(here.join("Cargo.toml")).expect("own manifest"));
    let mut dirs: Vec<PathBuf> = [&templates, &skeletons]
        .into_iter()
        .flat_map(|root| {
            std::fs::read_dir(root)
                .unwrap_or_else(|e| panic!("{}: {e}", root.display()))
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.is_dir())
                .collect::<Vec<_>>()
        })
        .collect();
    dirs.sort();

    let mut modules = Vec::new();
    // The security checks among them: a check hands over its catalogue of
    // rules when asked (`CATALOGUE_ONLY`), which is how the planted-fault
    // gate finds it. Found by content, like everything here.
    let mut checks = Vec::new();
    for dir in dirs {
        let source = dir.join("template.rs");
        let Ok(text) = std::fs::read_to_string(&source) else {
            continue;
        };
        if !text.contains("#[cfg(test)]") {
            continue;
        }
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .expect("template directory name")
            .to_string();
        for krate in declared_crates(&dir) {
            let known = BUNDLED.contains(&krate.as_str())
                || linked.contains(&krate)
                || linked.contains(&krate.replace('-', "_"));
            assert!(
                known,
                "template '{name}' declares the crate '{krate}' in talos.json; add it to talos-catalog-tests/Cargo.toml so its tests can run"
            );
        }
        if text.contains("\"CATALOGUE_ONLY\"") {
            checks.push(name.clone());
        }
        modules.push(Module::new(&name, source));
    }

    generate(&modules, &out_dir).expect("prepare template sources");
    let mut discovered = String::from(
        "/// The templates whose tests this crate runs.\npub const DISCOVERED: &[&str] = &[\n",
    );
    for m in &modules {
        let _ = writeln!(discovered, "    {:?},", m.name);
    }
    discovered.push_str("];\n");
    discovered.push_str(
        "/// The security checks among them (each answers `CATALOGUE_ONLY`), with their entry points.\n\
         pub const SECURITY_CHECKS: &[(&str, fn(String) -> Result<String, String>)] = &[\n",
    );
    for name in &checks {
        let _ = writeln!(
            discovered,
            "    ({name:?}, crate::{}::run),",
            name.replace('-', "_")
        );
    }
    discovered.push_str("];\n");
    std::fs::write(out_dir.join("discovered.rs"), discovered).expect("write discovered.rs");
}
