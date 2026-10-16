// skeleton-reader: reads one service and changes nothing there. It hands on
// the service's items reduced to typed fields, never the raw body.
//
// TODO(author): say what it reads, from which service, and what it hands on.
// Replace `Item` with the fields you need (unread fields cost nothing), and
// the path `/v1/items` with the service's.
//
// What this shape already does, and what the catalog's tests hold it to:
// * GET only, to one host (`allowed_hosts` in talos.json names exactly the
//   hosts this source addresses);
// * bounded: at most MAX_PAGES requests and MAX_ITEMS items, and it says when
//   it stopped short (`truncated`);
// * a failed request keeps its KIND in the error (`({e:?})`), so the platform
//   retries a timeout and not a refusal; a refusal names the host and the
//   status, never the body;
// * the config is checked before any request.
//
// Network: api.example.com only.

use serde::Deserialize;
use serde_json::json;
use talos_sdk_macros::talos_module;

const API: &str = "https://api.example.com";
/// The most items one run hands on, and the most pages it reads.
const MAX_ITEMS: usize = 100;
const MAX_PAGES: usize = 5;
/// The longest text kept from one field.
const FIELD_CHARS: usize = 200;

#[derive(Deserialize, Default)]
struct Envelope {
    #[serde(default)]
    config: Config,
}

#[derive(Deserialize, Default)]
struct Config {
    /// "Bearer " and a vault reference to the service's token, e.g.
    /// "Bearer vault://<path>". The platform puts the secret in the header;
    /// the module never sees it.
    #[serde(rename = "AUTH_HEADER")]
    auth_header: Option<String>,
    /// The most items to hand on, 1 to 100 (default 100).
    #[serde(rename = "MAX_ITEMS")]
    max_items: Option<usize>,
}

/// One page of the service's answer. Only the fields read are parsed.
#[derive(Deserialize)]
struct Page {
    #[serde(default)]
    items: Vec<Item>,
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize)]
struct Item {
    id: String,
    #[serde(default)]
    name: String,
}

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    let envelope: Envelope = serde_json::from_str(&input).map_err(|e| format!("Input parse error: {e}"))?;
    let cfg = envelope.config;
    let auth = cfg.auth_header.filter(|a| !a.trim().is_empty()).ok_or("Missing AUTH_HEADER config")?;
    let cap = cfg.max_items.unwrap_or(MAX_ITEMS);
    if !(1..=MAX_ITEMS).contains(&cap) {
        return Err(format!("MAX_ITEMS must be 1 to {MAX_ITEMS}"));
    }

    let mut items = Vec::new();
    let mut next: Option<String> = None;
    let mut truncated = false;
    for page_number in 0..MAX_PAGES {
        let url = match &next {
            None => format!("{API}/v1/items"),
            Some(token) => format!("{API}/v1/items?page={token}"),
        };
        let page = get(&auth, &url)?;
        for item in page.items {
            if items.len() == cap {
                truncated = true;
                break;
            }
            items.push(json!({ "id": plain(&item.id), "name": plain(&item.name) }));
        }
        match page.next {
            None => break,
            // Full: a further page would only be cut.
            Some(_) if truncated || items.len() == cap => {
                truncated = true;
                break;
            }
            // A token goes back into a URL: only a plain one is sent back.
            Some(token) if token_ok(&token) => {
                if page_number + 1 == MAX_PAGES {
                    truncated = true;
                }
                next = Some(token);
            }
            Some(_) => return Err("api.example.com answered with a next-page token that cannot be sent back".to_string()),
        }
    }
    let out = json!({ "kind": "skeleton_reader", "count": items.len(), "truncated": truncated, "items": items });
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

/// One GET, its answer typed. A failure names the host and the status.
fn get(auth: &str, url: &str) -> Result<Page, String> {
    use talos::core::http::{self, Method, Request};
    let req = Request {
        method: Method::Get,
        url: url.to_string(),
        headers: vec![
            ("Authorization".to_string(), auth.to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: Vec::new(),
        timeout_ms: Some(20_000),
    };
    let resp = http::fetch(&req).map_err(|e| format!("api.example.com could not be reached ({e:?})"))?;
    if resp.status != 200 {
        return Err(format!("api.example.com answered {}", resp.status));
    }
    serde_json::from_slice(&resp.body).map_err(|_| "api.example.com answered with something that could not be read".to_string())
}

/// A page token as one may be sent back in a query: letters, digits, `-` and `_`.
fn token_ok(token: &str) -> bool {
    (1..=200).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Text as it may be handed on: no control characters, cut to a length.
fn plain(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(FIELD_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use talos_module_testkit::host;

    /// The envelope every test runs the module with.
    fn envelope() -> String {
        json!({"config": {"AUTH_HEADER": "Bearer vault://example/token", "MAX_ITEMS": 3}}).to_string()
    }

    fn pages() {
        host::http::respond_with(|req| {
            let body = if req.url.contains("page=p2") {
                json!({"items": [{"id": "c", "name": "Third"}, {"id": "d", "name": "Fourth"}]})
            } else {
                json!({"items": [{"id": "a", "name": "First"}, {"id": "b", "name": "Second"}], "next": "p2"})
            };
            Ok(host::http::response(200, body.to_string()))
        });
    }

    #[test]
    fn it_reads_page_by_page_with_gets_only_and_stops_at_its_cap() {
        pages();
        let out: Value = serde_json::from_str(&run(envelope()).unwrap()).unwrap();
        assert_eq!(out["items"], json!([{"id": "a", "name": "First"}, {"id": "b", "name": "Second"}, {"id": "c", "name": "Third"}]));
        assert_eq!((out["count"].clone(), out["truncated"].clone()), (json!(3), json!(true)));
        let requests = host::http::requests();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|r| r.method == talos::core::http::Method::Get && r.url.starts_with(API)));
        // This run is the template's recorded run (fixtures/): `make record-template` rewrites it.
        talos_module_testkit::recorded_run::keep("skeleton-reader", &envelope());
    }

    #[test]
    fn a_refusal_names_the_host_and_status_and_never_the_body() {
        host::http::respond(403, "{\"secret\": \"do not repeat me\"}");
        let err = run(envelope()).unwrap_err();
        assert_eq!(err, "api.example.com answered 403");
    }

    #[test]
    fn a_failed_request_keeps_its_kind() {
        host::http::respond_with(|_| Err(talos::core::http::Error::Timeout));
        assert!(run(envelope()).unwrap_err().contains("(Timeout)"));
    }

    #[test]
    fn the_config_is_checked_before_any_request() {
        assert_eq!(run(json!({"config": {}}).to_string()).unwrap_err(), "Missing AUTH_HEADER config");
        assert!(run(json!({"config": {"AUTH_HEADER": "Bearer x", "MAX_ITEMS": 0}}).to_string()).is_err());
        assert!(host::http::requests().is_empty());
    }

    #[test]
    fn a_next_page_token_that_cannot_be_sent_back_is_refused() {
        host::http::respond(200, json!({"items": [], "next": "../../etc"}).to_string());
        assert!(run(envelope()).unwrap_err().contains("cannot be sent back"));
    }
}
