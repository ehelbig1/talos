//! A template's recorded run, kept from one of its own tests.
//!
//! The fuel check (`make check-catalog-fuel`) runs a template in the worker
//! runtime against `fixtures/http.json` (and `config.json`, `input.json`). A
//! recording made by hand drifts from the module and invites a real capture
//! into a public repository; one made from a test is the test's own made-up
//! data, and stays what the module does. So a template's test ends with
//!
//! ```text
//! let envelope = json!({"config": config}).to_string();
//! let out = run(envelope.clone()).unwrap();
//! // …assertions on `out`…
//! talos_module_testkit::recorded_run::keep("my-template", &envelope);
//! ```
//!
//! and `keep` holds the template's `fixtures/` to what that test served:
//!
//! * normally it COMPARES, and panics when the files differ from the test
//!   (or are missing), naming the command that rewrites them;
//! * with `TALOS_RECORD_RUNS=1` (`make record-template TEMPLATE=<slug>`) it
//!   WRITES them: `http.json` (each answered request, in order), and
//!   `config.json` / `input.json` from the envelope when they are not empty.
//!
//! A module that makes no request (a decider) is recorded as `http.json` =
//! `[]` with the input it was given; the fuel check measures it on that.
//!
//! Two layouts are known. A catalog template is `module-templates/<slug>/`
//! (or `talos-catalog-tests/skeletons/<slug>/`) with a `talos.json`; an
//! authoring lane's module is `modules/<name>/` under the crate running the
//! tests, with a `module.json`. The lane's `scripts/rehearse.py` runs a module
//! on the platform against the same `fixtures/` files, so one recording
//! serves both. `TALOS_TEMPLATES_DIR` names another root outright.

use crate::host;
use crate::talos::core::http::Method;
use serde_json::{json, Map, Value};
use std::path::PathBuf;

/// The environment variable that turns comparing into writing.
pub const RECORD_ENV: &str = "TALOS_RECORD_RUNS";
/// Where templates live, when not the workspace's own `module-templates/`.
pub const TEMPLATES_ENV: &str = "TALOS_TEMPLATES_DIR";
/// The manifests that make a directory a module's: the catalog's and an
/// authoring lane's.
const MANIFESTS: &[&str] = &["talos.json", "module.json"];
/// The longest `url_contains` the replay accepts.
const MAX_MATCH_CHARS: usize = 512;
/// The most responses one recording may hold (the replay's own limit).
const MAX_RESPONSES: usize = 64;

fn method_name(m: Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
        Method::Patch => "PATCH",
    }
}

/// What the replay matches a request on: its host and path. The query is
/// left out (a page token changes, the order does not), and the scheme too.
fn url_contains(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let path = rest.split(['?', '#']).next().unwrap_or(rest);
    path.chars().take(MAX_MATCH_CHARS).collect()
}

/// The recording of what this thread's test served, as `http.json` holds it.
#[must_use]
pub fn http_fixtures() -> Value {
    let served = host::http::served();
    assert!(
        served.len() <= MAX_RESPONSES,
        "the test answered {} requests; a recorded run holds at most {MAX_RESPONSES}",
        served.len()
    );
    Value::Array(
        served
            .iter()
            .map(|(req, resp)| {
                let body = String::from_utf8(resp.body.clone()).unwrap_or_else(|_| {
                    panic!(
                        "the answer to {} is not UTF-8; a recorded run holds text",
                        req.url
                    )
                });
                let headers: Map<String, Value> = resp
                    .headers
                    .iter()
                    .map(|(k, v)| (k.to_ascii_lowercase(), Value::String(v.clone())))
                    .collect();
                let mut fixture = json!({
                    "method": method_name(req.method),
                    "url_contains": url_contains(&req.url),
                    "status": resp.status,
                    "body": body,
                });
                if !headers.is_empty() {
                    fixture["headers"] = Value::Object(headers);
                }
                fixture
            })
            .collect(),
    )
}

/// A slug is a template directory's name: lower-case letters, digits and
/// single hyphens. Nothing else can name a path.
fn slug_ok(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 64
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !slug.starts_with('-')
        && !slug.ends_with('-')
        && !slug.contains("--")
}

/// The roots a slug is looked for under, in order: the one named by
/// `TALOS_TEMPLATES_DIR`, else the running crate's own `modules/` (an
/// authoring lane), the skeletons `make new-template` copies (a `skeleton-`
/// slug) and the catalog's `module-templates/`.
fn roots(slug: &str) -> Vec<PathBuf> {
    if let Some(named) = std::env::var_os(TEMPLATES_ENV) {
        return vec![PathBuf::from(named)];
    }
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut out = Vec::new();
    // Set by cargo for the test binary it runs: the crate whose tests these
    // are, which in an authoring lane is where `modules/` lives.
    if let Some(running) = std::env::var_os("CARGO_MANIFEST_DIR") {
        out.push(PathBuf::from(running).join("modules"));
    }
    if slug.starts_with("skeleton-") {
        out.push(workspace.join("talos-catalog-tests/skeletons"));
    }
    out.push(workspace.join("module-templates"));
    out
}

/// The module's directory: the first root under which `<slug>/` holds a
/// manifest.
fn module_dir(slug: &str) -> PathBuf {
    assert!(slug_ok(slug), "{slug:?} is not a module's name");
    let roots = roots(slug);
    roots
        .iter()
        .map(|root| root.join(slug))
        .find(|dir| MANIFESTS.iter().any(|m| dir.join(m).is_file()))
        .unwrap_or_else(|| {
            panic!(
                "{slug} is not a module under {} (no talos.json or module.json)",
                roots
                    .iter()
                    .map(|r| r.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

fn fixtures_dir(slug: &str) -> PathBuf {
    module_dir(slug).join("fixtures")
}

/// The files a recorded run consists of, for this test: name → contents.
fn files(envelope: &str) -> Vec<(&'static str, Value)> {
    let envelope: Value =
        serde_json::from_str(envelope).unwrap_or_else(|e| panic!("the envelope is not JSON: {e}"));
    let mut out = vec![("http.json", http_fixtures())];
    for (key, file) in [("config", "config.json"), ("input", "input.json")] {
        match envelope.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::Object(o)) if o.is_empty() => {}
            Some(v @ Value::Object(_)) => out.push((file, v.clone())),
            Some(_) => panic!(
                "the envelope's {key} is not an object, so it cannot be a recorded run's {file}"
            ),
        }
    }
    out
}

fn text(value: &Value) -> String {
    let mut s = serde_json::to_string_pretty(value).expect("JSON serialises");
    s.push('\n');
    s
}

/// Hold the module's `fixtures/` to the run this test just made with
/// `envelope` (the JSON it passed to `run`). See the module docs.
pub fn keep(slug: &str, envelope: &str) {
    let dir = fixtures_dir(slug);
    let wanted = files(envelope);
    let recording = std::env::var(RECORD_ENV).is_ok_and(|v| v == "1");
    if recording {
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        for (name, value) in &wanted {
            let path = dir.join(name);
            std::fs::write(&path, text(value))
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        }
        return;
    }
    // The catalog has a target for it; a lane sets the variable on its test.
    let again = format!(
        "make record-template TEMPLATE={slug}` in the Talos workspace, or `{RECORD_ENV}=1 cargo test {}",
        slug.replace('-', "_")
    );
    for (name, value) in &wanted {
        let path = dir.join(name);
        let Ok(kept) = std::fs::read_to_string(&path) else {
            panic!(
                "{} is missing: write it from this test with `{again}`",
                path.display()
            );
        };
        let kept: Value = serde_json::from_str(&kept)
            .unwrap_or_else(|e| panic!("{}: not JSON ({e})", path.display()));
        assert!(
            &kept == value,
            "{} is not what this test serves any more: the module or the test changed. Rewrite it with `{again}` and read the diff",
            path.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::talos::core::http::{self as wit_http, Request};

    fn get(url: &str) -> Request {
        Request {
            method: Method::Get,
            url: url.to_string(),
            headers: vec![],
            body: vec![],
            timeout_ms: None,
        }
    }

    #[test]
    fn what_a_test_served_is_recorded_in_order_by_host_and_path() {
        host::http::respond_with(|req| {
            let mut r = host::http::response(200, format!("{{\"for\":\"{}\"}}", req.url));
            r.headers
                .push(("Content-Type".to_string(), "application/json".to_string()));
            Ok(r)
        });
        wit_http::fetch(&get("https://api.example.com/v1/items?page=2")).unwrap();
        wit_http::fetch(&Request {
            method: Method::Post,
            ..get("http://api.example.com/v1/search#x")
        })
        .unwrap();
        assert_eq!(
            http_fixtures(),
            json!([
                {"method": "GET", "url_contains": "api.example.com/v1/items", "status": 200,
                 "headers": {"content-type": "application/json"}, "body": "{\"for\":\"https://api.example.com/v1/items?page=2\"}"},
                {"method": "POST", "url_contains": "api.example.com/v1/search", "status": 200,
                 "headers": {"content-type": "application/json"}, "body": "{\"for\":\"http://api.example.com/v1/search#x\"}"},
            ])
        );
    }

    #[test]
    fn a_request_that_was_not_answered_is_not_in_the_recording() {
        host::http::respond_with(|_| Err(wit_http::Error::Timeout));
        assert!(wit_http::fetch(&get("https://api.example.com/x")).is_err());
        assert_eq!(http_fixtures(), json!([]));
    }

    #[test]
    fn the_envelope_gives_the_config_and_input_files_only_when_they_hold_something() {
        let names = |e: &str| files(e).into_iter().map(|(n, _)| n).collect::<Vec<_>>();
        assert_eq!(
            names(r#"{"config": {"A": 1}}"#),
            ["http.json", "config.json"]
        );
        assert_eq!(
            names(r#"{"config": {}, "input": {"x": [1]}}"#),
            ["http.json", "input.json"]
        );
        assert_eq!(names(r#"{"input": null}"#), ["http.json"]);
        assert!(std::panic::catch_unwind(|| files(r#"{"input": [1]}"#)).is_err());
    }

    #[test]
    fn a_module_is_found_by_either_manifest_and_a_lane_root_comes_first() {
        // Both layouts resolve from the roots; the running crate's own
        // `modules/` is tried before the catalog's.
        let r = roots("x");
        assert!(r.len() >= 2 && r[0].ends_with("modules"), "{r:?}");
        assert!(r.last().is_some_and(|p| p.ends_with("module-templates")));
        assert!(roots("skeleton-x").iter().any(|p| p.ends_with("skeletons")));
        // A catalog template is found by its talos.json.
        assert!(module_dir("http-request").join("talos.json").is_file());
        assert!(fixtures_dir("http-request").ends_with("http-request/fixtures"));
        // Neither manifest: not a module.
        assert!(std::panic::catch_unwind(|| module_dir("no-such-module-here")).is_err());
    }

    #[test]
    fn only_a_template_name_can_name_the_directory() {
        for bad in ["", "../etc", "a/b", "A", "a--b", "-a", "a-", "a.b", "a b"] {
            assert!(!slug_ok(bad), "{bad:?}");
        }
        assert!(slug_ok("gcp-alerting-evidence") && slug_ok("a1"));
    }

    #[test]
    fn a_long_url_is_cut_to_what_the_replay_matches() {
        let long = format!("https://api.example.com/{}", "a".repeat(600));
        assert_eq!(url_contains(&long).chars().count(), MAX_MATCH_CHARS);
    }
}
