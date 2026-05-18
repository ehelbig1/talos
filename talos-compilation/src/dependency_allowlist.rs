//! Allowlist gate for `compile_custom_sandbox` Cargo.toml dependencies.
//!
//! Enforces a closed set of crates that user-supplied module sources may
//! depend on, plus version-string sanitisation (no `*` / empty pinning).
//! Lifted from `controller/src/mcp/utils.rs` so the compilation pipeline
//! owns its own allowlist instead of reaching back into MCP.

// ============================================================================
// SECURITY: Dependency allowlist for compile_custom_sandbox
// ============================================================================

/// Default set of approved crate dependencies for WASM sandboxes.
/// Can be overridden via the `MCP_ALLOWED_CRATE_DEPENDENCIES` env var (comma-separated).
static DEFAULT_ALLOWED_DEPENDENCIES: &[&str] = &[
    // serde and serde_json are pre-bundled in every module's base Cargo.toml template
    // and are always available without any explicit declaration. Listing them here keeps
    // them in the "allowed" set so validate_dependencies doesn't produce a confusing
    // "Disallowed: serde" error when a user includes them. The dep injector in
    // compilation/mod.rs silently skips pre-bundled crates to prevent duplicate-key errors.
    "serde",
    "serde_json",
    // NOTE: reqwest is intentionally NOT on this list.
    // reqwest's default feature set links against wasm-bindgen browser JS bindings
    // (__wbg_fetch_*, __wbindgen_* exports) which target wasm32-unknown-unknown
    // (browser WASM), not wasm32-wasip2 (WASI component model). It will fail to
    // link with a missing import error at wasmtime instantiation time.
    // HTTP in WASM modules must be performed through the WIT host interface
    // (talos::core::http / fetch / webhook / graphql), not via reqwest directly.
    "chrono",
    "uuid",
    "base64",
    "url",
    "urlencoding",
    "percent-encoding",
    "regex",
    "tokio",
    "anyhow",
    "thiserror",
    "rand",
    "sha2",
    "hmac",
    "http",
];

/// Returns the set of allowed crate dependencies.
///
/// Consults two env vars in this order:
///
/// 1. `MCP_ALLOWED_CRATE_DEPENDENCIES_EXTRA` — comma-separated crate names
///    *added* to the default allowlist. Use this for the common case
///    (operator wants to permit one extra crate without risking the
///    accidental loss of the curated defaults — `chrono`, `uuid`,
///    `base64`, etc. — that the comments at the top of this file
///    deliberately include).
/// 2. `MCP_ALLOWED_CRATE_DEPENDENCIES` — comma-separated crate names
///    that *replace* the entire default allowlist. Use this only when
///    the operator deliberately wants to lock down to a smaller set
///    than the defaults.
///
/// If both are set, REPLACE wins and EXTRA is appended on top, so an
/// operator who sets both gets `REPLACE ∪ EXTRA`. This combination is
/// unusual but defined; the common cases (set neither / set EXTRA only /
/// set REPLACE only) all behave intuitively.
pub fn get_allowed_dependencies() -> std::collections::HashSet<String> {
    // MCP-621 (2026-05-12): treat empty `MCP_ALLOWED_CRATE_DEPENDENCIES`
    // as unset so the default allowlist applies. Pre-fix, `Ok("")`
    // matched the `if let Ok(...)` branch, split-and-filter produced
    // an empty HashSet (no defaults), and every dependency rejected
    // — module compilation universally failed with "crate not in
    // allowlist." Helm `values.yaml` placeholders
    // `mcpAllowedCrateDependencies: ""` hit this routinely.
    //
    // Fail-closed direction (operator sees loud failures rather than
    // silent privilege escalation), but operationally broken AND
    // inconsistent with every other empty-env-var fix in the codebase
    // (MCP-590/591/592/597/598/599/611/615/620).
    //
    // The EXTRA variant on line 81 below correctly treats empty as
    // "add nothing" — that path doesn't need a fix because empty
    // ≡ unset semantically aligns there.
    let replace = std::env::var("MCP_ALLOWED_CRATE_DEPENDENCIES")
        .ok()
        .filter(|v| !v.is_empty());
    let mut set: std::collections::HashSet<String> = if let Some(env_val) = replace {
        env_val
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        DEFAULT_ALLOWED_DEPENDENCIES
            .iter()
            .map(|s| s.to_string())
            .collect()
    };

    if let Ok(extra) = std::env::var("MCP_ALLOWED_CRATE_DEPENDENCIES_EXTRA") {
        set.extend(
            extra
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty()),
        );
    }

    set
}

/// Validates that all requested dependencies are in the allowlist and have valid version ranges.
/// Returns Ok(()) or Err with a description of disallowed/invalid dependencies.
pub fn validate_dependencies(deps: Option<&serde_json::Value>) -> Result<(), String> {
    // MCP-307 (2026-05-11): pre-fix `_ => return Ok(())` silently
    // accepted any non-Object input — wrong-type was treated as
    // "no dependencies", so `dependencies: "serde=1.0,url=2"` (string
    // attempt instead of object) compiled WITHOUT the operator's
    // requested deps. The compile would fail at link time with
    // "crate not found", obscuring the real cause (operator typed
    // wrong shape). Distinguish absent / null / empty-object (Ok)
    // from non-Object wrong-type (Err).
    let deps_obj = match deps {
        None | Some(serde_json::Value::Null) => return Ok(()),
        Some(serde_json::Value::Object(m)) if m.is_empty() => return Ok(()),
        Some(serde_json::Value::Object(m)) => m,
        Some(other) => {
            let kind = match other {
                serde_json::Value::Array(_) => "array",
                serde_json::Value::Bool(_) => "boolean",
                serde_json::Value::Number(_) => "number",
                serde_json::Value::String(_) => "string",
                _ => "other",
            };
            return Err(format!(
                "dependencies must be an object mapping crate-name → version-string, got {kind}"
            ));
        }
    };

    let allowed = get_allowed_dependencies();
    let mut disallowed = Vec::new();
    let mut invalid_versions = Vec::new();

    for (crate_name, version_val) in deps_obj {
        let name_lower = crate_name.trim().to_lowercase();
        if !allowed.contains(&name_lower) {
            disallowed.push(crate_name.clone());
        }

        // Reject wildcard versions ("*") which could pull in any version
        if let Some(version_str) = version_val.as_str() {
            let trimmed = version_str.trim();
            if trimmed == "*" || trimmed.is_empty() {
                invalid_versions.push(format!("{} = \"{}\"", crate_name, trimmed));
            }
        }
    }

    if !disallowed.is_empty() || !invalid_versions.is_empty() {
        let mut msg = String::new();
        if !disallowed.is_empty() {
            msg.push_str(&format!(
                "Disallowed crate dependencies: [{}]. Allowed crates: [{}]",
                disallowed.join(", "),
                allowed.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
        if !invalid_versions.is_empty() {
            if !msg.is_empty() {
                msg.push_str(". ");
            }
            msg.push_str(&format!(
                "Invalid version specifiers (wildcard '*' or empty versions are not allowed): [{}]",
                invalid_versions.join(", ")
            ));
        }
        return Err(msg);
    }

    Ok(())
}

#[cfg(test)]
mod validate_dependencies_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn absent_and_null_and_empty_object_are_ok() {
        assert!(validate_dependencies(None).is_ok());
        assert!(validate_dependencies(Some(&serde_json::Value::Null)).is_ok());
        assert!(validate_dependencies(Some(&json!({}))).is_ok());
    }

    #[test]
    fn allowed_object_passes() {
        let v = json!({"serde": "1.0", "url": "2.5"});
        assert!(validate_dependencies(Some(&v)).is_ok());
    }

    #[test]
    fn disallowed_crate_errors() {
        let v = json!({"reqwest": "0.11"});
        let err = validate_dependencies(Some(&v)).unwrap_err();
        assert!(err.contains("Disallowed"), "got: {err}");
        assert!(err.contains("reqwest"), "got: {err}");
    }

    #[test]
    fn wildcard_version_rejected() {
        let v = json!({"serde": "*"});
        let err = validate_dependencies(Some(&v)).unwrap_err();
        assert!(err.contains("Invalid version specifiers"), "got: {err}");
    }

    #[test]
    fn empty_version_rejected() {
        let v = json!({"serde": ""});
        let err = validate_dependencies(Some(&v)).unwrap_err();
        assert!(err.contains("Invalid version specifiers"), "got: {err}");
    }

    // MCP-307: pre-fix, any non-Object value was silently treated as "no deps"
    // and compilation continued without the operator's requested crates.
    #[test]
    fn string_wrong_type_is_rejected() {
        let v = json!("serde=1.0,url=2");
        let err = validate_dependencies(Some(&v)).unwrap_err();
        assert!(err.contains("must be an object"), "got: {err}");
        assert!(err.contains("string"), "got: {err}");
    }

    #[test]
    fn array_wrong_type_is_rejected() {
        let v = json!(["serde", "url"]);
        let err = validate_dependencies(Some(&v)).unwrap_err();
        assert!(err.contains("must be an object"), "got: {err}");
        assert!(err.contains("array"), "got: {err}");
    }

    #[test]
    fn number_wrong_type_is_rejected() {
        let v = json!(42);
        let err = validate_dependencies(Some(&v)).unwrap_err();
        assert!(err.contains("must be an object"), "got: {err}");
        assert!(err.contains("number"), "got: {err}");
    }

    #[test]
    fn bool_wrong_type_is_rejected() {
        let v = json!(true);
        let err = validate_dependencies(Some(&v)).unwrap_err();
        assert!(err.contains("must be an object"), "got: {err}");
        assert!(err.contains("boolean"), "got: {err}");
    }

    // MCP-621 (2026-05-12): empty `MCP_ALLOWED_CRATE_DEPENDENCIES`
    // env value must fall through to DEFAULT_ALLOWED_DEPENDENCIES,
    // not strip all deps. Pre-fix `Ok("")` matched the if-let-Ok
    // branch and produced an empty HashSet, causing every
    // compilation to fail with "crate not in allowlist". Probe var
    // is the real env name — Cargo runs each test binary in a
    // separate process, but within this binary we must serialize
    // this test against any other test that touches the same env
    // variable. None do today; flagged via name.
    //
    // SAFETY: per Rust's `std::env::set_var` docs, env mutation is
    // unsound in the presence of concurrent threads reading env.
    // Tests in this binary do not run concurrent env reads — the
    // function under test is the only reader, called serially here.
    #[test]
    fn empty_replace_env_falls_through_to_default() {
        // First, snapshot any pre-existing value so we restore on exit.
        let prev = std::env::var("MCP_ALLOWED_CRATE_DEPENDENCIES").ok();
        std::env::set_var("MCP_ALLOWED_CRATE_DEPENDENCIES", "");
        let set = get_allowed_dependencies();
        // Default contains serde — proves we DIDN'T get the empty-set
        // pre-fix behaviour. Use serde because it's been in the default
        // list since the crate was extracted; an unrelated future change
        // dropping serde would surface here AND in every other test
        // above that constructs `json!({"serde": ...})`.
        assert!(
            set.contains("serde"),
            "empty REPLACE env must fall through to DEFAULT_ALLOWED_DEPENDENCIES (MCP-621); got {set:?}"
        );
        // Restore.
        match prev {
            Some(v) => std::env::set_var("MCP_ALLOWED_CRATE_DEPENDENCIES", v),
            None => std::env::remove_var("MCP_ALLOWED_CRATE_DEPENDENCIES"),
        }
    }
}
