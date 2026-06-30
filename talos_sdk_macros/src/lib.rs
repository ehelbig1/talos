use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, FnArg, ItemFn, PatType};

/// Extract a named attribute value from an attribute string like
/// `provider = "anthropic", model = "claude-sonnet-4-20250514"`.
///
/// Returns `None` if the key is not present.
fn extract_attr(attr_str: &str, key: &str) -> Option<String> {
    let pattern = format!("{} = \"", key);
    if let Some(start) = attr_str.find(&pattern) {
        let rest = &attr_str[start + pattern.len()..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    // Also try without spaces around `=`
    let pattern_no_space = format!("{}=\"", key);
    if let Some(start) = attr_str.find(&pattern_no_space) {
        let rest = &attr_str[start + pattern_no_space.len()..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    None
}

/// Entry-point macro for a Talos WASM module whose `run` takes typed config
/// fields (one fn argument per `config` key, auto-deserialized).
///
/// # The `world` attribute selects your capabilities — and it is the ONLY thing
/// that does.
///
/// ```ignore
/// #[talos_node(world = "secrets-node")]   // ← this drives everything
/// fn run(repo: String, token_secret: String) -> Result<String, String> { ... }
/// ```
///
/// The `world` string picks the WIT *capability world* the module is compiled
/// against. The compilation scaffold reads it straight out of this attribute
/// (`talos-compilation`'s `extract_wit_world`) to generate `bindings.rs`, so it
/// decides which `talos::core::*` interfaces exist. It is **NOT** read from
/// `talos.json` — `capability_world` there is metadata for the catalog UI and
/// MUST be kept identical to this attribute (enforced by `lint-structural.sh`
/// check 48). If they disagree, the macro wins and you get a confusing
/// `unresolved import talos::core::http` instead of a clear error.
///
/// **Omitting `world` defaults to `minimal-node`** (least privilege: `logging`,
/// `json`, `datetime`, `crypto`, `env` only — JSON in/out, no `http`/`secrets`).
/// Always declare it explicitly; a bare `#[talos_node]` that imports
/// `talos::core::http` will fail to compile because `minimal-node` has no `http`.
///
/// # Available worlds (least → most privileged)
/// | world | adds on top of minimal |
/// |---|---|
/// | `minimal-node` | — (logging, json, datetime, crypto, env) |
/// | `http-node` | `http`, `webhook` |
/// | `secrets-node` | `http`, `secrets` (GitHub/OpenAI tokens via `get_secret`) |
/// | `network-node` | `http`, `graphql`, `email`, `state`, `http-stream`, … |
/// | `database-node` | `database` (sandbox SQL) |
/// | `llm-node` | `llm` host functions |
/// | `cache-node`, `messaging-node`, `filesystem-node`, `governance-node`, `agent-node`, `automation-node` | see `wit/talos.wit` |
///
/// Pick the *smallest* world that satisfies your imports. The exact interface
/// set per world is the source of truth in `wit/talos.wit`.
///
/// # Example
/// ```ignore
/// use talos::core::http::{fetch, Method, Request};
/// use talos::core::secrets::get_secret;
///
/// #[talos_node(world = "secrets-node")]
/// fn run(repo: String, token_secret: String) -> Result<String, String> {
///     let token = get_secret(&token_secret)?;
///     // ... fetch + return JSON string ...
///     Ok("{}".into())
/// }
/// ```
///
/// See also [`talos_module`] (free-form `run(input: String)` signature) and
/// [`talos_agent`] (LLM agent scaffold).
#[proc_macro_attribute]
pub fn talos_node(attr: TokenStream, item: TokenStream) -> TokenStream {
    let parsed_fn = parse_macro_input!(item as ItemFn);

    // Parse the world from #[talos_node(world = "xxx")]
    // Default to minimal-node (least privilege) if not provided
    let world_str = if attr.is_empty() {
        "minimal-node".to_string()
    } else {
        let attr_str = attr.to_string();
        extract_attr(&attr_str, "world").unwrap_or_else(|| "minimal-node".to_string())
    };

    let world_marker = format!("__talos_world_{}__", world_str);
    let world_marker_bytes =
        syn::LitByteStr::new(world_marker.as_bytes(), proc_macro2::Span::call_site());

    let fn_name = &parsed_fn.sig.ident;
    let inputs = &parsed_fn.sig.inputs;

    let mut deserializers = Vec::new();
    let mut call_args = Vec::new();

    for input in inputs {
        if let FnArg::Typed(PatType { pat, ty, .. }) = input {
            if let syn::Pat::Ident(pat_ident) = &**pat {
                let arg_name = &pat_ident.ident;
                let arg_name_str = arg_name.to_string();

                deserializers.push(quote! {
                    let #arg_name: #ty = match serde_json::from_value(config.get(#arg_name_str).cloned().unwrap_or(serde_json::Value::Null)) {
                        Ok(v) => v,
                        Err(e) => return Err(format!("Invalid '{}' parameter: {}", #arg_name_str, e)),
                    };
                });

                call_args.push(quote! { #arg_name });
            }
        }
    }

    let expanded = quote! {
        // cargo-component 0.21+ auto-generates src/bindings.rs from the WIT file.
        // include!() with CARGO_MANIFEST_DIR finds it regardless of whether the
        // crate root is src/lib.rs or template.rs (both resolve to package_root/src/).
        #[allow(warnings)]
        mod bindings {
            include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bindings.rs"));
        }

        // Expose crate::bindings::talos at the top-level `talos` path so template
        // code can use the idiomatic `use talos::core::cache` / `talos::core::secrets`
        // syntax.  All WIT worlds live in the `talos:core` package, so this alias
        // is always valid regardless of which capability world is selected.
        #[allow(unused_imports)]
        use crate::bindings::talos as talos;

        struct TalosGuest;

        impl bindings::Guest for TalosGuest {
            fn run(input_str: String) -> Result<String, String> {
                // catch_unwind is present for future compatibility but is currently
                // unreachable on wasm32-wasip2 component targets: the WASM component
                // model adapter assumes panic = "abort" ABI conventions, so enabling
                // software unwinding breaks the WIT boundary entirely.  Panics are
                // recovered at the host level via WASI stderr capture and
                // extract_panic_message_from_stderr() in worker/src/runtime.rs, which
                // produces the same clean Err("PANIC: ...") presentation.
                match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| {
                    let payload: serde_json::Value = match serde_json::from_str(&input_str) {
                        Ok(p) => p,
                        Err(e) => return Err(format!("Failed to parse workflow input: {}", e)),
                    };

                    let config = payload.get("config").unwrap_or(&serde_json::Value::Null);

                    #(#deserializers)*

                    match #fn_name(#(#call_args),*) {
                        Ok(res) => Ok(res),
                        Err(err) => Err(err),
                    }
                })) {
                    Ok(r) => r,
                    Err(p) => {
                        let msg = p.downcast_ref::<&str>()
                            .map(|s| s.to_string())
                            .or_else(|| p.downcast_ref::<::std::string::String>().cloned())
                            .unwrap_or_else(|| "panic (non-string payload)".to_string());
                        Err(::std::format!("PANIC: {}", msg))
                    }
                }
            }
        }

        bindings::export!(TalosGuest with_types_in bindings);

        #[used]
        #[no_mangle]
        pub static __TALOS_WORLD: &[u8] = #world_marker_bytes;

        #[export_name = "wizer.initialize"]
        pub extern "C" fn init() {
            let _prime = Vec::<u8>::with_capacity(1024 * 1024);
        }

        #parsed_fn
    };

    TokenStream::from(expanded)
}

/// Entry-point macro for a Talos WASM module whose `run` takes the raw envelope
/// `String` (you parse `{config, input, ...}` yourself). Use [`talos_node`]
/// instead if you want typed config arguments.
///
/// # The `world` attribute selects your capabilities
///
/// Identical contract to [`talos_node`]: the `world = "..."` string picks the
/// WIT capability world the module compiles against (read by the compilation
/// scaffold's `extract_wit_world`), which determines the available
/// `talos::core::*` interfaces. It is **NOT** taken from `talos.json` — keep
/// `talos.json`'s `capability_world` identical to this attribute
/// (`lint-structural.sh` check 48 enforces the match). Omitting `world` defaults
/// to `minimal-node` (no `http`/`secrets`), so a bare `#[talos_module]` that
/// imports `talos::core::http` fails to compile.
///
/// See [`talos_node`] for the full world table and a worked example.
///
/// # Example
/// ```ignore
/// #[talos_module(world = "http-node")]
/// fn run(input: String) -> Result<String, String> {
///     use talos::core::http::{Method, Request};
///     // ... parse `input`, fetch, return JSON string ...
///     Ok("{}".into())
/// }
/// ```
#[proc_macro_attribute]
pub fn talos_module(attr: TokenStream, item: TokenStream) -> TokenStream {
    let parsed_fn = parse_macro_input!(item as ItemFn);

    let world_str = if attr.is_empty() {
        "minimal-node".to_string()
    } else {
        let attr_str = attr.to_string();
        extract_attr(&attr_str, "world").unwrap_or_else(|| "minimal-node".to_string())
    };

    let world_marker = format!("__talos_world_{}__", world_str);
    let world_marker_bytes =
        syn::LitByteStr::new(world_marker.as_bytes(), proc_macro2::Span::call_site());

    let fn_name = &parsed_fn.sig.ident;

    let expanded = quote! {
        // cargo-component 0.21+ auto-generates src/bindings.rs from the WIT file.
        // include!() with CARGO_MANIFEST_DIR finds it regardless of whether the
        // crate root is src/lib.rs or template.rs (both resolve to package_root/src/).
        #[allow(warnings)]
        mod bindings {
            include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bindings.rs"));
        }

        // Expose crate::bindings::talos at the top-level `talos` path so template
        // code can use the idiomatic `use talos::core::cache` / `talos::core::secrets`
        // syntax.  All WIT worlds live in the `talos:core` package, so this alias
        // is always valid regardless of which capability world is selected.
        #[allow(unused_imports)]
        use crate::bindings::talos as talos;

        struct TalosGuest;

        impl bindings::Guest for TalosGuest {
            fn run(input_str: String) -> Result<String, String> {
                // catch_unwind is present for future compatibility but is currently
                // unreachable on wasm32-wasip2 component targets: the WASM component
                // model adapter assumes panic = "abort" ABI conventions, so enabling
                // software unwinding breaks the WIT boundary entirely.  Panics are
                // recovered at the host level via WASI stderr capture and
                // extract_panic_message_from_stderr() in worker/src/runtime.rs, which
                // produces the same clean Err("PANIC: ...") presentation.
                match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| {
                    #fn_name(input_str)
                })) {
                    Ok(r) => r,
                    Err(p) => {
                        let msg = p.downcast_ref::<&str>()
                            .map(|s| s.to_string())
                            .or_else(|| p.downcast_ref::<::std::string::String>().cloned())
                            .unwrap_or_else(|| "panic (non-string payload)".to_string());
                        Err(::std::format!("PANIC: {}", msg))
                    }
                }
            }
        }

        bindings::export!(TalosGuest with_types_in bindings);

        #[used]
        #[no_mangle]
        pub static __TALOS_WORLD: &[u8] = #world_marker_bytes;

        #[export_name = "wizer.initialize"]
        pub extern "C" fn init() {
            let _prime = Vec::<u8>::with_capacity(1024 * 1024);
        }

        #parsed_fn
    };

    TokenStream::from(expanded)
}

/// Macro for building LLM-powered agent modules.
///
/// Defaults to the `secrets-node` world which includes LLM, secrets, and HTTP access.
/// Generates boilerplate for deserializing agent input (messages, tools, system prompt)
/// and serializing agent output.
///
/// The annotated function receives an `AgentInput` struct (auto-generated) with fields:
/// - `prompt` — the user's prompt or message
/// - `messages` — conversation history as JSON values
/// - `tools` — tool definitions available to the agent
/// - `system_prompt` — system prompt for the LLM
/// - `config` — module configuration from the workflow
/// - `input` — input data from parent nodes
///
/// and must return `Result<AgentOutput, String>` where `AgentOutput` has:
/// - `response` — the agent's response text
/// - `data` — optional structured data (`Option<serde_json::Value>`)
/// - `tool_calls` — tool calls made during execution (`Vec<serde_json::Value>`)
///
/// # Attributes
/// - `world = "..."` — Override the capability world (default: `secrets-node`)
/// - `provider = "..."` — Default LLM provider hint (default: `anthropic`)
/// - `model = "..."` — Default model hint (default: `claude-sonnet-4-20250514`)
///
/// # Example
/// ```ignore
/// #[talos_agent(provider = "anthropic", model = "claude-sonnet-4-20250514")]
/// fn run(input: AgentInput) -> Result<AgentOutput, String> {
///     Ok(AgentOutput {
///         response: format!("Processed: {}", input.prompt),
///         data: None,
///         tool_calls: vec![],
///     })
/// }
/// ```
///
/// # Required dependencies in the agent crate
/// The generated code references `serde` and `serde_json` (pre-bundled).
/// `wit-bindgen-rt` is also pre-bundled automatically. No additional deps needed.
#[proc_macro_attribute]
pub fn talos_agent(attr: TokenStream, item: TokenStream) -> TokenStream {
    let parsed_fn = parse_macro_input!(item as ItemFn);

    let attr_str = attr.to_string();

    // Extract world (default: secrets-node — agents need LLM + secrets access)
    let world_str = extract_attr(&attr_str, "world").unwrap_or_else(|| "secrets-node".to_string());

    // Extract provider and model hints for metadata markers
    let provider = extract_attr(&attr_str, "provider").unwrap_or_else(|| "anthropic".to_string());
    let model =
        extract_attr(&attr_str, "model").unwrap_or_else(|| "claude-sonnet-4-20250514".to_string());

    // Build world marker (same scheme as talos_node / talos_module)
    let world_marker = format!("__talos_world_{}__", world_str);
    let world_marker_bytes =
        syn::LitByteStr::new(world_marker.as_bytes(), proc_macro2::Span::call_site());

    // Agent metadata markers for binary inspection
    let provider_marker = format!("__talos_agent_provider_{}__", provider);
    let provider_marker_bytes =
        syn::LitByteStr::new(provider_marker.as_bytes(), proc_macro2::Span::call_site());

    let model_marker = format!("__talos_agent_model_{}__", model);
    let model_marker_bytes =
        syn::LitByteStr::new(model_marker.as_bytes(), proc_macro2::Span::call_site());

    let fn_name = &parsed_fn.sig.ident;

    let expanded = quote! {
        /// Agent input deserialized from the workflow engine.
        #[derive(serde::Deserialize, Debug)]
        pub struct AgentInput {
            /// The user's prompt or message.
            #[serde(default)]
            pub prompt: String,
            /// Conversation history (JSON array of messages).
            #[serde(default)]
            pub messages: Vec<serde_json::Value>,
            /// Tool definitions available to the agent (JSON array).
            #[serde(default)]
            pub tools: Vec<serde_json::Value>,
            /// System prompt for the LLM.
            #[serde(default)]
            pub system_prompt: String,
            /// Module configuration from the workflow.
            #[serde(default)]
            pub config: serde_json::Value,
            /// Input data from parent nodes.
            #[serde(default)]
            pub input: serde_json::Value,
        }

        /// Agent output serialized back to the workflow engine.
        #[derive(serde::Serialize, Debug)]
        pub struct AgentOutput {
            /// The agent's response text.
            pub response: String,
            /// Optional structured data.
            #[serde(skip_serializing_if = "Option::is_none")]
            pub data: Option<serde_json::Value>,
            /// Tool calls made during execution (for logging/audit).
            #[serde(skip_serializing_if = "Vec::is_empty")]
            pub tool_calls: Vec<serde_json::Value>,
        }

        // cargo-component 0.21+ auto-generates src/bindings.rs from the WIT file.
        // include!() with CARGO_MANIFEST_DIR finds it regardless of whether the
        // crate root is src/lib.rs or template.rs (both resolve to package_root/src/).
        #[allow(warnings)]
        mod bindings {
            include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bindings.rs"));
        }

        // Expose crate::bindings::talos at the top-level `talos` path so template
        // code can use the idiomatic `use talos::core::cache` / `talos::core::secrets`
        // syntax.  All WIT worlds live in the `talos:core` package, so this alias
        // is always valid regardless of which capability world is selected.
        #[allow(unused_imports)]
        use crate::bindings::talos as talos;

        struct TalosAgentGuest;

        impl bindings::Guest for TalosAgentGuest {
            fn run(raw_input: String) -> Result<String, String> {
                // catch_unwind is present for future compatibility but is currently
                // unreachable on wasm32-wasip2 component targets: the WASM component
                // model adapter assumes panic = "abort" ABI conventions, so enabling
                // software unwinding breaks the WIT boundary entirely.  Panics are
                // recovered at the host level via WASI stderr capture and
                // extract_panic_message_from_stderr() in worker/src/runtime.rs, which
                // produces the same clean Err("PANIC: ...") presentation.
                match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| {
                    // Parse agent input from JSON
                    let agent_input: AgentInput = serde_json::from_str(&raw_input)
                        .map_err(|e| format!("Failed to parse agent input: {}", e))?;

                    // Call user's agent function
                    let output = #fn_name(agent_input)?;

                    // Serialize output
                    serde_json::to_string(&output)
                        .map_err(|e| format!("Failed to serialize agent output: {}", e))
                })) {
                    Ok(r) => r,
                    Err(p) => {
                        let msg = p.downcast_ref::<&str>()
                            .map(|s| s.to_string())
                            .or_else(|| p.downcast_ref::<::std::string::String>().cloned())
                            .unwrap_or_else(|| "panic (non-string payload)".to_string());
                        Err(::std::format!("PANIC: {}", msg))
                    }
                }
            }
        }

        bindings::export!(TalosAgentGuest with_types_in bindings);

        // World marker — same scheme as talos_node / talos_module
        #[used]
        #[no_mangle]
        pub static __TALOS_WORLD: &[u8] = #world_marker_bytes;

        // Agent metadata markers for tooling / binary inspection
        #[used]
        #[no_mangle]
        pub static __TALOS_AGENT_PROVIDER: &[u8] = #provider_marker_bytes;

        #[used]
        #[no_mangle]
        pub static __TALOS_AGENT_MODEL: &[u8] = #model_marker_bytes;

        // Wizer pre-allocation (same pattern as other macros)
        #[export_name = "wizer.initialize"]
        pub extern "C" fn init() {
            let _prime = Vec::<u8>::with_capacity(1024 * 1024);
        }

        #parsed_fn
    };

    TokenStream::from(expanded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_attr_with_spaces() {
        let attr_str = r#"world = "secrets-node", provider = "anthropic""#;
        assert_eq!(
            extract_attr(attr_str, "world"),
            Some("secrets-node".to_string())
        );
        assert_eq!(
            extract_attr(attr_str, "provider"),
            Some("anthropic".to_string())
        );
    }

    #[test]
    fn test_extract_attr_without_spaces() {
        let attr_str = r#"world="minimal-node",provider="openai""#;
        assert_eq!(
            extract_attr(attr_str, "world"),
            Some("minimal-node".to_string())
        );
        assert_eq!(
            extract_attr(attr_str, "provider"),
            Some("openai".to_string())
        );
    }

    #[test]
    fn test_extract_attr_missing() {
        let attr_str = r#"world = "minimal-node""#;
        assert_eq!(extract_attr(attr_str, "model"), None);
        assert_eq!(extract_attr(attr_str, "unknown"), None);
    }

    #[test]
    fn test_extract_attr_empty_string() {
        let attr_str = "";
        assert_eq!(extract_attr(attr_str, "world"), None);
    }

    #[test]
    fn test_extract_attr_partial_match() {
        // Should not match "worlds" when looking for "world"
        let attr_str = r#"worlds = "test", world = "correct""#;
        assert_eq!(extract_attr(attr_str, "world"), Some("correct".to_string()));
    }

    #[test]
    fn test_extract_attr_only_key() {
        // Missing value
        let attr_str = r#"world ="#;
        assert_eq!(extract_attr(attr_str, "world"), None);
    }

    #[test]
    fn test_extract_attr_unclosed_quote() {
        // Unclosed quote returns None - no closing quote found
        let attr_str = r#"world = "secrets-node"#;
        assert_eq!(extract_attr(attr_str, "world"), None);
    }

    #[test]
    fn test_extract_attr_single_quotes_not_supported() {
        // Single quotes should not be recognized
        let attr_str = r#"world = 'secrets-node'"#;
        assert_eq!(extract_attr(attr_str, "world"), None);
    }
}
