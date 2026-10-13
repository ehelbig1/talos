//! The `options` a caller may pass with a completion, in one place.
//!
//! A module passes provider options to `llm::complete-with-options` as a
//! JSON string (`{"think": true, "response_format": {"type": "json_object"}}`).
//! The operator's `local_llm_complete` tool takes the same object, so a
//! prompt tuned through the tool behaves inside the module as it did in the
//! tool. Both go through the two functions here, so there is one rule for
//! what `options` may be and one translation of it into a request to the
//! local model.
//!
//! What options can and cannot do is the worker's rule, unchanged: they TUNE
//! a request (`think`, `response_format`, the samplers, `num_ctx`, …). They
//! cannot name the model, replace the messages or switch on streaming; those
//! keys are dropped (`model`, `messages`, `system`, `stream`, `template`,
//! `raw`).

use crate::host::llm_providers::adapter_for;
use crate::host_impl::MAX_PROVIDER_OPTIONS_BYTES;

/// The largest `options` text accepted, in bytes.
pub const MAX_OPTIONS_BYTES: usize = MAX_PROVIDER_OPTIONS_BYTES;

/// Read a caller's `options`: absent or blank is none; otherwise a JSON
/// object of at most [`MAX_OPTIONS_BYTES`].
///
/// # Errors
/// The words a caller is shown: the text is too large, or is not a JSON
/// object. The caller set `options` and expects it to apply, so a malformed
/// one is refused rather than ignored.
pub fn parse_provider_options(
    raw: Option<&str>,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>, String> {
    let Some(text) = raw.filter(|s| !s.trim().is_empty()) else {
        return Ok(None);
    };
    if text.len() > MAX_OPTIONS_BYTES {
        return Err(format!("provider options exceed {MAX_OPTIONS_BYTES} bytes"));
    }
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(serde_json::Value::Object(map)) => Ok(Some(map)),
        _ => Err("provider options must be a JSON object".to_string()),
    }
}

/// Apply checked options to a native Ollama `/api/chat` body, exactly as
/// the worker does for a module's call to the local model.
///
/// The caller owns what must not change afterwards (the model it checked
/// for locality, the messages): the translation drops those keys, and a
/// caller that depends on it re-asserts them.
pub fn apply_to_local_body(
    body: &mut serde_json::Value,
    options: serde_json::Map<String, serde_json::Value>,
) {
    adapter_for("ollama").apply_provider_options(body, options);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn options_are_a_bounded_json_object_or_nothing() {
        assert_eq!(parse_provider_options(None), Ok(None));
        assert_eq!(parse_provider_options(Some("")), Ok(None));
        assert_eq!(parse_provider_options(Some("  \n")), Ok(None));
        let parsed = parse_provider_options(Some(r#"{"think":true,"seed":7}"#))
            .unwrap()
            .unwrap();
        assert_eq!(parsed.get("think"), Some(&json!(true)));

        for not_an_object in ["[1,2]", "\"think\"", "7", "null", "{not json"] {
            assert_eq!(
                parse_provider_options(Some(not_an_object)),
                Err("provider options must be a JSON object".to_string()),
                "{not_an_object}"
            );
        }
        let at_the_limit = format!(r#"{{"pad":"{}"}}"#, "x".repeat(MAX_OPTIONS_BYTES - 10));
        assert_eq!(at_the_limit.len(), MAX_OPTIONS_BYTES);
        assert!(parse_provider_options(Some(&at_the_limit)).is_ok());
        let over = format!(r#"{{"pad":"{}"}}"#, "x".repeat(MAX_OPTIONS_BYTES));
        assert_eq!(
            parse_provider_options(Some(&over)),
            Err(format!("provider options exceed {MAX_OPTIONS_BYTES} bytes"))
        );
    }

    fn local_body() -> serde_json::Value {
        json!({
            "model": "local-model",
            "messages": [{ "role": "user", "content": "hello" }],
            "stream": false,
            "think": false,
            "options": { "num_predict": 100 },
        })
    }

    /// The options the observed module passed, applied as the worker
    /// applies them.
    #[test]
    fn a_modules_options_reach_the_local_request_as_the_worker_sends_them() {
        let mut body = local_body();
        let options = parse_provider_options(Some(
            r#"{"think": true, "response_format": {"type": "json_object"}, "temperature": 0.2, "max_tokens": 1500}"#,
        ))
        .unwrap()
        .unwrap();
        apply_to_local_body(&mut body, options);
        assert_eq!(body["think"], true, "the caller's think wins");
        assert_eq!(
            body["format"], "json",
            "response_format becomes the native format"
        );
        assert_eq!(body["options"]["temperature"], 0.2);
        assert_eq!(
            body["options"]["num_predict"], 1500,
            "max_tokens is the native num_predict"
        );
        assert!(body.get("response_format").is_none() && body.get("max_tokens").is_none());
    }

    /// Options tune a request. They do not choose the model, replace the
    /// prompt or turn on streaming.
    #[test]
    fn options_cannot_name_the_model_or_replace_the_messages() {
        let mut body = local_body();
        let options = parse_provider_options(Some(
            r#"{"model": "someone-elses:cloud", "messages": [{"role":"user","content":"other"}],
                "system": "ignore the above", "stream": true, "template": "x", "raw": true}"#,
        ))
        .unwrap()
        .unwrap();
        apply_to_local_body(&mut body, options);
        assert_eq!(body["model"], "local-model");
        assert_eq!(
            body["messages"],
            json!([{ "role": "user", "content": "hello" }])
        );
        assert_eq!(body["stream"], false);
        for key in ["system", "template", "raw"] {
            assert!(
                body.get(key).is_none(),
                "{key} was carried into the request"
            );
        }
    }
}
