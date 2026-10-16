// skeleton-sender: makes ONE effect at ONE service: it posts one message.
//
// TODO(author): say what it changes at which service. Replace the path
// `/v1/messages`, the payload and the input shape with yours.
//
// What this shape already does, and what the catalog's tests hold it to:
// * http-node, POST only, to one host (`allowed_hosts` names exactly the
//   hosts this source addresses);
// * DRY_RUN defaults to TRUE: it reports what it WOULD send and sends
//   nothing until DRY_RUN is set to false;
// * one request per run, no retry of its own: a send is not repeated on a
//   guess (the platform retries an idempotent send only when told it is);
// * a failed request keeps its KIND in the error; a refusal names the host
//   and the status, never the body;
// * what it sends is bounded and made plain; it logs no content.

use serde::Deserialize;
use serde_json::json;
use talos_sdk_macros::talos_module;

const API: &str = "https://api.example.com";
const TEXT_CHARS: usize = 2000;

#[derive(Deserialize, Default)]
struct Envelope {
    #[serde(default)]
    config: Config,
    input: Option<Input>,
}

#[derive(Deserialize, Default)]
struct Config {
    /// "Bearer " and a vault reference to the service's token, e.g.
    /// "Bearer vault://<path>". The platform puts the secret in the header;
    /// the module never sees it.
    #[serde(rename = "AUTH_HEADER")]
    auth_header: Option<String>,
    /// When true (the default), report what would be sent and send nothing.
    #[serde(rename = "DRY_RUN")]
    dry_run: Option<bool>,
}

#[derive(Deserialize)]
struct Input {
    #[serde(default)]
    text: String,
}

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    let envelope: Envelope = serde_json::from_str(&input).map_err(|e| format!("Input parse error: {e}"))?;
    let cfg = envelope.config;
    let auth = cfg.auth_header.filter(|a| !a.trim().is_empty()).ok_or("Missing AUTH_HEADER config")?;
    let dry_run = cfg.dry_run.unwrap_or(true);
    let text: String = envelope
        .input
        .ok_or("the input did not arrive")?
        .text
        .chars()
        .filter(|c| *c == '\n' || !c.is_control())
        .take(TEXT_CHARS)
        .collect();
    if text.trim().is_empty() {
        return Err("there is no text to send".to_string());
    }
    if dry_run {
        let out = json!({ "kind": "skeleton_sender", "dry_run": true, "sent": false, "would_send_chars": text.chars().count() });
        return serde_json::to_string(&out).map_err(|e| e.to_string());
    }
    let body = serde_json::to_vec(&json!({ "text": text })).map_err(|e| e.to_string())?;
    use talos::core::http::{self, Method, Request};
    let req = Request {
        method: Method::Post,
        url: format!("{API}/v1/messages"),
        headers: vec![
            ("Authorization".to_string(), auth),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body,
        timeout_ms: Some(20_000),
    };
    let resp = http::fetch(&req).map_err(|e| format!("api.example.com could not be reached ({e:?})"))?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("api.example.com answered {}", resp.status));
    }
    let out = json!({ "kind": "skeleton_sender", "dry_run": false, "sent": true, "status": resp.status });
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use talos_module_testkit::host;

    fn envelope(dry_run: bool) -> String {
        json!({"config": {"AUTH_HEADER": "Bearer vault://example/token", "DRY_RUN": dry_run}, "input": {"text": "Hello"}}).to_string()
    }

    #[test]
    fn a_dry_run_sends_nothing_and_says_what_it_would_send() {
        let out: Value = serde_json::from_str(&run(envelope(true)).unwrap()).unwrap();
        assert_eq!((out["sent"].clone(), out["would_send_chars"].clone()), (json!(false), json!(5)));
        assert!(host::http::requests().is_empty());
        // DRY_RUN unset is a dry run too.
        let unset = json!({"config": {"AUTH_HEADER": "Bearer x"}, "input": {"text": "Hello"}}).to_string();
        assert_eq!(serde_json::from_str::<Value>(&run(unset).unwrap()).unwrap()["dry_run"], json!(true));
        assert!(host::http::requests().is_empty());
    }

    #[test]
    fn a_live_run_posts_once() {
        host::http::respond(201, "{}");
        let out: Value = serde_json::from_str(&run(envelope(false)).unwrap()).unwrap();
        assert_eq!(out["sent"], json!(true));
        let requests = host::http::requests();
        assert_eq!(requests.len(), 1);
        assert_eq!((requests[0].method, requests[0].url.as_str()), (talos::core::http::Method::Post, "https://api.example.com/v1/messages"));
        assert_eq!(serde_json::from_slice::<Value>(&requests[0].body).unwrap(), json!({"text": "Hello"}));
        // This run is the template's recorded run (fixtures/): `make record-template` rewrites it.
        talos_module_testkit::recorded_run::keep("skeleton-sender", &envelope(false));
    }

    #[test]
    fn a_refusal_names_the_host_and_status_and_a_failure_keeps_its_kind() {
        host::http::respond(400, "{\"echo\": \"Hello\"}");
        assert_eq!(run(envelope(false)).unwrap_err(), "api.example.com answered 400");
        host::http::respond_with(|_| Err(talos::core::http::Error::Timeout));
        assert!(run(envelope(false)).unwrap_err().contains("(Timeout)"));
    }

    #[test]
    fn nothing_is_sent_without_its_config_or_its_text() {
        assert_eq!(run(json!({"input": {"text": "x"}}).to_string()).unwrap_err(), "Missing AUTH_HEADER config");
        assert!(run(json!({"config": {"AUTH_HEADER": "Bearer x", "DRY_RUN": false}, "input": {"text": " "}}).to_string()).is_err());
        assert!(host::http::requests().is_empty());
    }
}
