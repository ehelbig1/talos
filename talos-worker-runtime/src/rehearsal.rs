//! The two pure pieces of a REHEARSAL — one module run answered from
//! recorded HTTP responses instead of the network (see [`crate::http_replay`]).
//!
//! They live here, beside the runtime that executes the run, because more
//! than one caller rehearses a module and each must hand it the same thing:
//! the `test_module` tool, and the catalog's recorded-run fuel gate
//! (`talos-catalog-tests/tests/fuel_fixtures.rs`), which measures what a
//! template costs before it is published. A second copy of either function
//! would let the gate measure a payload the platform never sends.

use crate::http_replay::HttpFixture;

/// The payload a rehearsed module receives, shaped as the engine shapes a
/// node's input: config and input keys merged at the root, the two objects
/// also under `config` / `input`, and — when the caller supplies it — earlier
/// nodes' outputs under `__accumulated__`.
///
/// `__accumulated__` is set LAST and only from the dedicated argument, so a
/// same-named key inside `config` or `input` cannot stand in for it.
pub fn node_payload(
    config: &serde_json::Value,
    input: &serde_json::Value,
    accumulated: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut merged = serde_json::Map::new();
    if let Some(obj) = config.as_object() {
        for (k, v) in obj {
            merged.insert(k.clone(), v.clone());
        }
    }
    if let Some(obj) = input.as_object() {
        for (k, v) in obj {
            merged.insert(k.clone(), v.clone());
        }
    }
    if !config.is_null() && *config != serde_json::json!({}) {
        merged.insert("config".to_string(), config.clone());
    }
    if !input.is_null() && *input != serde_json::json!({}) {
        merged.insert("input".to_string(), input.clone());
    }
    match accumulated {
        Some(acc) => {
            merged.insert("__accumulated__".to_string(), acc.clone());
        }
        None => {
            merged.remove("__accumulated__");
        }
    }
    serde_json::Value::Object(merged)
}

/// One recorded HTTP response as a caller writes it. Unknown fields are
/// refused: a misspelled `url_contains` would otherwise be a fixture that
/// matches anything.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpFixtureArg {
    method: Option<String>,
    url_contains: Option<String>,
    status: Option<u16>,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    body: serde_json::Value,
}

/// Recorded responses from their JSON form — an array of
/// `{method?, url_contains?, status?, headers?, body?}`. A string body is
/// sent as written; any other JSON value is sent as compact JSON; absent is
/// empty. `status` defaults to 200.
///
/// The caps on count and size are [`crate::http_replay::HttpReplay`]'s and
/// are applied when the fixtures are handed to it.
pub fn parse_http_fixtures(raw: &serde_json::Value) -> Result<Vec<HttpFixture>, String> {
    let args: Vec<HttpFixtureArg> = serde_json::from_value(raw.clone()).map_err(|e| {
        format!(
            "http_fixtures must be an array of recorded responses \
             ({{method?, url_contains?, status?, headers?, body?}}): {e}"
        )
    })?;
    Ok(args
        .into_iter()
        .map(|a| HttpFixture {
            method: a.method.map(|m| m.trim().to_ascii_uppercase()),
            url_contains: a.url_contains,
            status: a.status.unwrap_or(200),
            headers: a.headers.into_iter().collect(),
            body: match a.body {
                serde_json::Value::Null => Vec::new(),
                serde_json::Value::String(text) => text.into_bytes(),
                other => other.to_string().into_bytes(),
            },
        })
        .collect())
}
