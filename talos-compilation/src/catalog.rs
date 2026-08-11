//! The single reader of a catalog template directory's **compile inputs**.
//!
//! # Why this type exists
//!
//! Every catalog template (`module-templates/<slug>/`) declares its extra
//! crate dependencies in `talos.json`'s `dependencies` field. Before this
//! module there were **five** places that compiled a catalog template and
//! only ONE of them forwarded that field:
//!
//! | site | forwarded deps? |
//! |---|---|
//! | `controller::bootstrap::services::seed_templates` (disk seeding, every boot) | **no** |
//! | `controller::cli` `publish-templates` (the OCI publish path) | **no** |
//! | `talos_mcp_handlers::modules::handle_restore_pinned_modules` | **no** |
//! | `talos_mcp_handlers::modules::handle_install_module_from_catalog` | yes |
//! | `talos_mcp_handlers::sandbox::handle_compile_template` (reads `modules.dependencies`) | column never written for catalog rows ⇒ **no** |
//!
//! The result, observed live on 2026-08-11: three catalog templates
//! (`briefing-html-generator`, `google-calendar-list-events`,
//! `create-calendar-event`) failed to compile at **every** controller boot
//! with `use of unresolved module or unlinked crate`, their `wasm_bytes`
//! stayed `NULL` forever, and CI's `make check-catalog` was green the whole
//! time because it scaffolds from `talos.json` — i.e. two compile paths for
//! the same artifact honouring different dependency sources.
//!
//! [`CatalogTemplate`] closes that by construction: it is the only way to
//! obtain a catalog template's source, and it always carries the declared
//! dependencies alongside it. [`crate::CompilationService::compile_catalog_template`]
//! takes one and forwards `dependencies()`, so a catalog compile cannot
//! silently lose them. The old dependency-less
//! `CompilationService::compile_to_wasm` convenience was **deleted** rather
//! than left as a footgun.
//!
//! # Supply-chain bound (this widens NOTHING)
//!
//! `dependencies()` is fed to the same
//! [`crate::dependency_allowlist::validate_dependencies`] gate that
//! `create_workspace` enforces unconditionally for *every* caller.
//!
//! The NET bound on a `talos.json` is: only crates on
//! `DEFAULT_ALLOWED_DEPENDENCIES` (16 today — `serde`, `serde_json`,
//! `chrono`, `uuid`, `base64`, `url`, `urlencoding`, `percent-encoding`,
//! `regex`, `tokio`, `anyhow`, `thiserror`, `rand`, `sha2`, `hmac`, `http`),
//! at a version string that is neither `*` nor empty and that contains no
//! `git`/`path`/quote/brace/newline characters. Path deps, git deps and
//! registry overrides remain impossible — the generated manifest is a fixed
//! `format!` template and the only interpolated dependency lines are
//! `name = "version"`.
//!
//! **That bound is enforced by TWO separate gates, not one, and the
//! distinction is operationally load-bearing.**
//! `validate_dependencies` enforces the allowlist and the `*`/empty-version
//! rule *only*; the crate-name charset check and the `git`/`path`/quote/
//! brace rejection live in a separate block inside `create_workspace`. So
//! [`CatalogTemplate::validate_dependencies`] — the pre-flight below — sees
//! the allowlist half and nothing else. A manifest naming an allowlisted
//! crate at a *malformed version* passes the pre-flight and is refused later,
//! by `create_workspace`, which is the correct outcome but not an early one.
//! Do not describe the pre-flight as covering the whole bound.
//!
//! The allowlist is also not a constant: `MCP_ALLOWED_CRATE_DEPENDENCIES`
//! replaces it wholesale and `MCP_ALLOWED_CRATE_DEPENDENCIES_EXTRA` extends
//! it, both read from the controller's environment
//! (`dependency_allowlist::get_allowed_dependencies`). "16 crates" is the
//! default, not a ceiling — an operator can widen it, and this path inherits
//! whatever they set.
//!
//! An attacker who controls a `talos.json` (i.e. who can already write to the
//! image's `module-templates/`, or to the signed OCI artifact) gains exactly
//! one new capability: causing an allowlisted crate at an allowlisted version
//! to be linked into that template's WASM. They cannot add an arbitrary crate,
//! cannot point at a path/git source, and cannot escape the TOML string
//! literal. That is strictly weaker than what such an attacker already has —
//! they control `template.rs`, i.e. the module's entire source.

use std::path::{Path, PathBuf};

/// Failure modes of [`CatalogTemplate::load`], kept distinct so callers can
/// preserve their own operator-recognisable error strings.
#[derive(Debug)]
pub enum CatalogTemplateError {
    /// `talos.json` missing or unreadable.
    ReadManifest(std::io::Error),
    /// `talos.json` present but not valid JSON.
    ParseManifest(serde_json::Error),
    /// Neither `template.rs` nor `src/lib.rs` could be read.
    ReadSource(std::io::Error),
}

impl std::fmt::Display for CatalogTemplateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadManifest(e) => write!(f, "{e}"),
            Self::ParseManifest(e) => write!(f, "{e}"),
            Self::ReadSource(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CatalogTemplateError {}

/// A catalog template directory's compile inputs, read as one unit.
///
/// Construct only via [`load`](Self::load) — there is deliberately no way to
/// build one from a bare source string, because that is exactly how the
/// declared dependencies got dropped at four of five call sites.
#[derive(Debug, Clone)]
pub struct CatalogTemplate {
    dir: PathBuf,
    manifest: serde_json::Value,
    source: String,
}

impl CatalogTemplate {
    /// Read `talos.json` plus the module source from a catalog template dir.
    ///
    /// Source precedence is `template.rs` then `src/lib.rs` — byte-identical
    /// to what `seed_templates` did inline, so switching it to this type
    /// cannot change which file production compiles.
    pub fn load(dir: &Path) -> Result<Self, CatalogTemplateError> {
        let manifest_bytes =
            std::fs::read(dir.join("talos.json")).map_err(CatalogTemplateError::ReadManifest)?;
        let manifest: serde_json::Value =
            serde_json::from_slice(&manifest_bytes).map_err(CatalogTemplateError::ParseManifest)?;
        let source = std::fs::read_to_string(dir.join("template.rs"))
            .or_else(|_| std::fs::read_to_string(dir.join("src/lib.rs")))
            .map_err(CatalogTemplateError::ReadSource)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            manifest,
            source,
        })
    }

    /// The parsed `talos.json`.
    pub fn manifest(&self) -> &serde_json::Value {
        &self.manifest
    }

    /// The Rust source the compiler will build.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The template directory this was loaded from.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The stable template identity — the on-disk directory name.
    pub fn slug(&self) -> Option<&str> {
        self.dir.file_name().and_then(|f| f.to_str())
    }

    /// The template's declared extra crate dependencies.
    ///
    /// **This is the only place in the workspace that reads a catalog
    /// manifest's `dependencies` key for compilation** (structural lint check
    /// 68 keeps it that way). Returns `None` when absent or `null`, which the
    /// compiler treats as "no extra crates" — identical to `{}`.
    ///
    /// The value is NOT trusted: `create_workspace` runs it through
    /// `validate_dependencies` before it reaches a Cargo.toml. See the module
    /// docs for the exact bound.
    ///
    /// An EMPTY object normalises to `None` too. The three spellings
    /// (absent / `null` / `{}`) are identical to the compiler, and collapsing
    /// them here keeps them identical to `modules.dependencies` — otherwise
    /// `{}` would persist as a non-NULL value that differs from the NULL an
    /// absent field writes, and the `deps_changed` arm of `needs_recompile`
    /// would rebuild the template on every boot forever.
    pub fn dependencies(&self) -> Option<&serde_json::Value> {
        match self.manifest.get("dependencies") {
            Some(serde_json::Value::Object(m)) if m.is_empty() => None,
            Some(serde_json::Value::Null) | None => None,
            Some(v) => Some(v),
        }
    }

    /// Reject a manifest whose declared dependencies are outside the
    /// compiler's crate allowlist, with a message naming the crate.
    ///
    /// Purely a diagnostic convenience — `create_workspace` calls the very
    /// same function unconditionally, so skipping this cannot widen anything,
    /// and calling it saves no meaningful work either (`create_workspace`
    /// bails before `cargo generate-lockfile` / `cargo audit` /
    /// `cargo component build`, so a rejected manifest costs a compilation
    /// permit for microseconds, not a compile).
    ///
    /// **It is NOT the whole gate.** This covers the allowlist and the
    /// `*`/empty-version rule. The crate-name charset check and the
    /// `git`/`path`/quote/brace/newline version rejection are a separate
    /// block inside `create_workspace`, so an allowlisted crate at a
    /// malformed version passes here and is refused there. A caller that
    /// treats `Ok(())` as "this will build" is wrong.
    pub fn validate_dependencies(&self) -> Result<(), String> {
        crate::dependency_allowlist::validate_dependencies(self.dependencies())
    }
}

#[cfg(test)]
mod catalog_template_tests {
    use super::*;

    fn write(dir: &Path, rel: &str, body: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, body).unwrap();
    }

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// The regression this whole module exists for: a template declaring
    /// `dependencies` in talos.json must surface them, so the compile path
    /// physically cannot pass `None`.
    #[test]
    fn declared_dependencies_are_surfaced() {
        let td = tmpdir();
        let d = td.path();
        write(
            d,
            "talos.json",
            r#"{"name":"x","dependencies":{"chrono":"0.4"}}"#,
        );
        write(d, "template.rs", "fn main() {}");
        let t = CatalogTemplate::load(d).unwrap();
        let deps = t.dependencies().expect("chrono must be surfaced");
        assert_eq!(deps.get("chrono").and_then(|v| v.as_str()), Some("0.4"));
        assert!(t.validate_dependencies().is_ok());
    }

    #[test]
    fn absent_and_null_dependencies_are_none() {
        let td = tmpdir();
        let d = td.path();
        write(d, "talos.json", r#"{"name":"x"}"#);
        write(d, "template.rs", "fn main() {}");
        let t = CatalogTemplate::load(d).unwrap();
        assert!(t.dependencies().is_none());
        std::fs::write(d.join("talos.json"), r#"{"name":"x","dependencies":null}"#).unwrap();
        let t = CatalogTemplate::load(d).unwrap();
        assert!(t.dependencies().is_none());
        assert!(t.validate_dependencies().is_ok());
        // `{}` must normalise to None too, or it persists as a non-NULL
        // `modules.dependencies` that differs from the NULL an absent field
        // writes — rebuilding the template on every boot forever.
        std::fs::write(d.join("talos.json"), r#"{"name":"x","dependencies":{}}"#).unwrap();
        let t = CatalogTemplate::load(d).unwrap();
        assert!(t.dependencies().is_none());
    }

    /// A manifest naming a crate outside the allowlist must be refused —
    /// forwarding `talos.json` must NOT widen the supply-chain boundary.
    #[test]
    fn non_allowlisted_dependency_is_refused() {
        let td = tmpdir();
        let d = td.path();
        write(
            d,
            "talos.json",
            r#"{"name":"x","dependencies":{"reqwest":"0.11"}}"#,
        );
        write(d, "template.rs", "fn main() {}");
        let t = CatalogTemplate::load(d).unwrap();
        let err = t.validate_dependencies().unwrap_err();
        assert!(err.contains("Disallowed"), "got: {err}");
        assert!(err.contains("reqwest"), "got: {err}");
    }

    /// Source precedence must match what `seed_templates` did inline, or the
    /// refactor silently changes which file production compiles.
    #[test]
    fn template_rs_wins_over_src_lib_rs() {
        let td = tmpdir();
        let d = td.path();
        write(d, "talos.json", "{}");
        write(d, "template.rs", "// from template.rs");
        write(d, "src/lib.rs", "// from src/lib.rs");
        assert_eq!(
            CatalogTemplate::load(d).unwrap().source(),
            "// from template.rs"
        );
        std::fs::remove_file(d.join("template.rs")).unwrap();
        assert_eq!(
            CatalogTemplate::load(d).unwrap().source(),
            "// from src/lib.rs"
        );
    }

    #[test]
    fn missing_manifest_and_bad_json_are_distinguishable() {
        let td = tmpdir();
        let d = td.path();
        write(d, "template.rs", "fn main() {}");
        assert!(matches!(
            CatalogTemplate::load(d),
            Err(CatalogTemplateError::ReadManifest(_))
        ));
        write(d, "talos.json", "{not json");
        assert!(matches!(
            CatalogTemplate::load(d),
            Err(CatalogTemplateError::ParseManifest(_))
        ));
        write(d, "talos.json", "{}");
        std::fs::remove_file(d.join("template.rs")).unwrap();
        assert!(matches!(
            CatalogTemplate::load(d),
            Err(CatalogTemplateError::ReadSource(_))
        ));
    }

    /// `seed_templates` behaviour change #1, pinned at its precondition: a
    /// template dir with a manifest but NO source used to be seeded with an
    /// EMPTY `source_code` (and then failed to compile on every boot,
    /// permanently, producing a row that was advertised and could not run).
    /// The seeder can no longer do that because there is no way to obtain a
    /// `CatalogTemplate` for such a dir — `load` fails, and the only thing a
    /// caller can do with the failure is skip.
    ///
    /// Scope, stated: this pins the PRECONDITION, not the seeder's control
    /// flow. Exercising `seed_templates` itself needs a Postgres pool and a
    /// `ModuleRegistry`; what is testable without them is that the type makes
    /// the empty-source row unconstructible, which is the load-bearing half.
    #[test]
    fn manifest_without_source_cannot_produce_a_template() {
        let td = tmpdir();
        let d = td.path();
        write(d, "talos.json", r#"{"name":"x","display_name":"X"}"#);
        let err = CatalogTemplate::load(d).expect_err("a source-less dir must not load");
        assert!(matches!(err, CatalogTemplateError::ReadSource(_)));
    }

    /// `seed_templates` behaviour change #2, pinned at its precondition: a
    /// manifest declaring a non-allowlisted crate must still LOAD, and must
    /// still surface its metadata and dependencies, so the seeder can upsert
    /// the row and let the compile fail loudly.
    ///
    /// An earlier revision `continue`d before the upsert on this condition.
    /// That looked like fail-fast and was actually silent staleness: a
    /// template seeded under an OLDER manifest kept its previously compiled
    /// `wasm_bytes`, stayed in `list_templates`, and was invisible to
    /// `never_compiled` (it HAS bytes), to
    /// `talos_catalog_templates_missing_wasm`, and to `on_disk_not_in_db`
    /// (the row exists). It also could not save a compile: `create_workspace`
    /// runs this same `validate_dependencies` and bails BEFORE
    /// `cargo generate-lockfile` / `cargo audit` / `cargo component build`.
    #[test]
    fn disallowed_dependency_template_still_loads_and_reports_its_metadata() {
        let td = tmpdir();
        let d = td.path();
        write(
            d,
            "talos.json",
            r#"{"name":"x","display_name":"X","dependencies":{"reqwest":"0.11"}}"#,
        );
        write(d, "template.rs", "fn main() {}");
        let t = CatalogTemplate::load(d).expect("a bad dependency must not block loading");
        assert_eq!(
            t.manifest().get("display_name").and_then(|v| v.as_str()),
            Some("X"),
            "the seeder needs the metadata to upsert the row"
        );
        assert!(
            t.dependencies().is_some(),
            "the seeder writes modules.dependencies verbatim so the failure is \
             diagnosable from the row, not only from a log line"
        );
        assert!(t.validate_dependencies().is_err());
    }

    /// Every shipped catalog template must declare, in `talos.json`, every
    /// extra crate its own `Cargo.toml` declares. `talos.json` is the ONLY
    /// declaration production reads; a `Cargo.toml`-only dep compiles green
    /// in dev and in `make check-catalog`'s old per-crate mode and then fails
    /// at runtime — exactly how `create-calendar-event` shipped a
    /// `urlencoding` dependency that production never got.
    ///
    /// This is the in-Rust twin of `scripts/check-catalog.sh` leg 2; the
    /// script is the gate that runs in CI, this is the gate that runs in
    /// `cargo test`.
    #[test]
    fn shipped_templates_declare_cargo_toml_deps_in_talos_json() {
        const PRE_BUNDLED: &[&str] = &[
            "serde",
            "serde_json",
            "wit-bindgen",
            "wit-bindgen-rt",
            "talos_sdk_macros",
            "talos-sdk-macros",
        ];
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../module-templates");
        if !root.is_dir() {
            // Layout moved — fail loudly rather than silently pass over zero
            // templates (a green check over zero assertions is worse than an
            // honest failure).
            panic!(
                "module-templates not found at {} — update this test",
                root.display()
            );
        }
        let mut offenders: Vec<String> = Vec::new();
        let mut checked = 0usize;
        for entry in std::fs::read_dir(&root).unwrap().flatten() {
            let dir = entry.path();
            if !dir.is_dir() || !dir.join("talos.json").exists() {
                continue;
            }
            let cargo_toml = dir.join("Cargo.toml");
            if !cargo_toml.exists() {
                continue;
            }
            let Ok(t) = CatalogTemplate::load(&dir) else {
                continue;
            };
            checked += 1;
            let declared: std::collections::HashSet<String> = t
                .dependencies()
                .and_then(|v| v.as_object())
                .map(|m| m.keys().map(|k| k.to_lowercase()).collect())
                .unwrap_or_default();
            let toml_body = std::fs::read_to_string(&cargo_toml).unwrap_or_default();
            let mut in_deps = false;
            for line in toml_body.lines() {
                let l = line.trim();
                if l.starts_with('[') {
                    in_deps = l == "[dependencies]";
                    continue;
                }
                if !in_deps || l.is_empty() || l.starts_with('#') {
                    continue;
                }
                let Some(name) = l.split('=').next().map(|s| s.trim()) else {
                    continue;
                };
                if name.is_empty() || PRE_BUNDLED.contains(&name) {
                    continue;
                }
                if !declared.contains(&name.to_lowercase()) {
                    offenders.push(format!(
                        "{}: Cargo.toml declares `{}` but talos.json `dependencies` does not",
                        dir.file_name().and_then(|f| f.to_str()).unwrap_or("?"),
                        name
                    ));
                }
            }
        }
        assert!(
            checked > 0,
            "no Cargo.toml-carrying templates were examined"
        );
        assert!(
            offenders.is_empty(),
            "talos.json is the only dependency declaration production reads:\n  {}",
            offenders.join("\n  ")
        );
    }
}
