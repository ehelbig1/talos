//! Every host function names itself for the fuel profile.
//!
//! `fuel_profile` charges a run's fuel to the host call each stretch of guest
//! code followed, and it learns which call that was from the call itself: the
//! first statement of every host function is `self.host_call("<iface>::<fn>")`.
//! A function that does not is not wrong and nothing fails — its transition
//! is treated like the runtime's own (ends no stretch, has no row), so the
//! fuel after it is silently reported under the call before it. That is why
//! this is pinned: the omission produces a plausible report, not an error.
//!
//! The population is DERIVED, not listed: every production module `mod.rs`
//! declares must be in the table below (a new host file fails the pin until
//! it is added), and every function of every `impl …::Host for TalosContext`
//! block in those files is checked. TEXTUAL, and it says so: it proves the
//! statement is there and names the function it sits in, not that the label
//! reaches the profile — `worker/tests/fuel_profile_tests.rs` drives that
//! end to end for one call.

/// Every production module of `host/`, by the name `mod.rs` declares it.
const HOST_FILES: &[(&str, &str)] = &[
    ("cache", include_str!("cache.rs")),
    ("crypto", include_str!("crypto.rs")),
    ("data", include_str!("data.rs")),
    ("database", include_str!("database.rs")),
    ("egress", include_str!("egress.rs")),
    ("egress_admission", include_str!("egress_admission.rs")),
    ("email", include_str!("email.rs")),
    ("files", include_str!("files.rs")),
    ("governance", include_str!("governance.rs")),
    ("graphql", include_str!("graphql.rs")),
    ("http", include_str!("http.rs")),
    ("http_stream", include_str!("http_stream.rs")),
    ("integration_state", include_str!("integration_state.rs")),
    ("limits", include_str!("limits.rs")),
    ("line_reader", include_str!("line_reader.rs")),
    ("llm", include_str!("llm.rs")),
    ("llm_gate", include_str!("llm_gate.rs")),
    ("llm_local_stream", include_str!("llm_local_stream.rs")),
    ("llm_streaming", include_str!("llm_streaming.rs")),
    ("llm_tools", include_str!("llm_tools.rs")),
    ("logging", include_str!("logging.rs")),
    ("memory", include_str!("memory.rs")),
    ("messaging", include_str!("messaging.rs")),
    ("model", include_str!("model.rs")),
    ("object_storage", include_str!("object_storage.rs")),
    ("orchestration", include_str!("orchestration.rs")),
    ("secrets", include_str!("secrets.rs")),
    ("state", include_str!("state.rs")),
    ("vault", include_str!("vault.rs")),
    ("wasi_http", include_str!("wasi_http.rs")),
    ("webhook", include_str!("webhook.rs")),
];

/// Modules that are directories. Their files are not scanned: a host trait
/// implemented inside one would not be seen (none is today).
const DIRECTORY_MODULES: &[&str] = &["llm_providers"];

/// The production modules `mod.rs` declares: every `mod x;` not under a
/// `#[cfg(test)]`.
fn declared_production_modules() -> Vec<String> {
    let mut out = Vec::new();
    let mut test_only = false;
    for line in include_str!("mod.rs").lines() {
        let line = line.trim();
        if line.starts_with("#[cfg(test)]") {
            test_only = true;
            continue;
        }
        let name = ["pub(crate) mod ", "pub mod ", "mod "]
            .iter()
            .find_map(|prefix| line.strip_prefix(prefix))
            .and_then(|rest| rest.strip_suffix(';'));
        if let Some(name) = name {
            if !test_only {
                out.push(name.to_string());
            }
        }
        // An attribute applies to the next item only; comments and other
        // attributes between it and the item do not end it.
        if !(line.is_empty() || line.starts_with("//") || line.starts_with("#[")) {
            test_only = false;
        }
    }
    out
}

/// `(file, interface, function, first statement)` for every function of
/// every `impl …::Host for TalosContext` block.
fn host_functions() -> Vec<(&'static str, String, String, String)> {
    let mut out = Vec::new();
    for (file, src) in HOST_FILES {
        let lines: Vec<&str> = src.lines().collect();
        let mut interface: Option<String> = None;
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            if let Some(path) = line
                .strip_prefix("impl ")
                .and_then(|rest| rest.strip_suffix("::Host for TalosContext {"))
            {
                let module = path.rsplit("::").next().unwrap_or(path);
                interface = Some(module.trim_start_matches("wit_").replace('_', "-"));
            } else if line == "}" {
                interface = None;
            } else if let Some(iface) = &interface {
                let signature = line
                    .strip_prefix("    async fn ")
                    .or_else(|| line.strip_prefix("    fn "));
                if let Some(signature) = signature {
                    let name: String = signature
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    // The body opens on the first line of the signature that
                    // ends with `{`; the statement after it is the first.
                    while !lines[i].trim_end().ends_with('{') {
                        i += 1;
                    }
                    let first = lines[i + 1..]
                        .iter()
                        .map(|l| l.trim())
                        .find(|l| !l.is_empty())
                        .unwrap_or_default();
                    out.push((*file, iface.clone(), name, first.to_string()));
                }
            }
            i += 1;
        }
    }
    out
}

#[test]
fn every_host_file_is_in_the_table() {
    let mut declared = declared_production_modules();
    declared.retain(|m| !DIRECTORY_MODULES.contains(&m.as_str()));
    declared.sort();
    let mut listed: Vec<String> = HOST_FILES.iter().map(|(n, _)| (*n).to_string()).collect();
    listed.sort();
    assert_eq!(
        listed, declared,
        "host/mod.rs and HOST_FILES disagree: add a new host module to HOST_FILES so its \
         functions are checked"
    );
    for directory in DIRECTORY_MODULES {
        assert!(
            declared_production_modules().iter().any(|m| m == directory),
            "{directory} is no longer a module; drop it from DIRECTORY_MODULES"
        );
    }
}

#[test]
fn every_host_function_names_itself_first() {
    let functions = host_functions();
    // A scan that stops matching must fail, not pass over nothing.
    assert!(
        functions.len() >= 110,
        "only {} host functions found; the scan no longer sees them",
        functions.len()
    );
    let mut labels = std::collections::BTreeSet::new();
    for (file, interface, name, first) in &functions {
        let label = format!("{interface}::{}", name.replace('_', "-"));
        let call = ["self.host_", "call(\""].concat();
        assert_eq!(
            first,
            &format!("{call}{label}\");"),
            "{file}.rs: `{name}` must begin by naming itself, or the fuel burned after it \
             is reported under the call before it"
        );
        assert!(
            labels.insert(label.clone()),
            "two host functions share the label {label}"
        );
        assert_ne!(label, crate::fuel_profile::UNNAMED);
    }
}

/// The raw `wasi:http` handler is not a `Host` trait function, so the scan
/// above does not reach it; JavaScript and Python modules make every HTTP
/// call through it.
#[test]
fn the_raw_wasi_http_handler_names_itself_first() {
    let src = include_str!("wasi_http.rs");
    let at = src
        .find("pub(crate) fn gated_handle(")
        .expect("gated_handle is defined");
    let body = &src[at..];
    let open = body.find("{\n").expect("gated_handle has a body");
    let first = body[open + 2..]
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or_default();
    let want = ["ctx.host_", "call(\"wasi-http::handle\");"].concat();
    assert_eq!(first, want);
}
