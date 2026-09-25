//! `vault://` in a request BODY must be resolved — or refused — on EVERY
//! guest-composed egress surface, not just `http::fetch`.
//!
//! Measured on 2026-09-24: all four guest-composed body-carrying surfaces
//! resolved a `vault://` marker in HEADERS, and exactly ONE (`http::fetch`)
//! resolved it in the BODY. On `http::fetch_all` — the batch sibling in the
//! SAME FILE — `webhook::send` and `graphql::execute` a marker in the body was
//! neither substituted nor refused: it was transmitted VERBATIM, so the vault
//! PATH (which names the provider and, for gmail, the account address) reached
//! the destination. That is exactly the harm the unaddressable-pointer REFUSAL
//! exists to prevent, and three of four surfaces had no such rule.
//!
//! These tests drive the PRODUCTION host functions, not the pure planner: the
//! refusal is observable as the latched `reason_class`, and a site that does
//! not call `resolve_vault_json_body` cannot latch `secret-lookup` — so this
//! is a wiring guard, which a source pin can only approximate.
//!
//! Every refusal case is paired with a CONTROL, so none of them can pass
//! because the surface refuses unconditionally.

use std::collections::HashMap;

use talos_workflow_job_protocol::LlmTier;

use super::{wit_graphql, wit_http, wit_webhook, TalosContext};
use crate::reason_class;
use crate::wit_inspector::CapabilityWorld;

/// An IP literal, so the DNS-rebinding pre-check does not deny before the body
/// is ever looked at. Not routable, so nothing leaves the test host.
const HOST: &str = "1.0.0.9";
const JSON: &str = "application/json";
/// Granted AND present in the provider.
const GRANTED_PATH: &str = "test/token";
const PLAINTEXT: &str = "s3cr3t-plaintext-value";
/// Syntactically fine, deliberately NOT granted — the resolver must refuse.
const UNGRANTED_MARKER: &str = "vault://denied/token";

fn ctx(secrets: HashMap<String, String>, allowed_secrets: &[&str]) -> TalosContext {
    let mut c = TalosContext::new(
        CapabilityWorld::Http,
        vec![HOST.to_string()],
        vec!["POST".to_string(), "GET".to_string()],
        128,
        secrets,
        None,
        None,
        false,
        None,
        std::sync::Arc::new(crate::expose_fallback::ExposeFallback::new()),
        LlmTier::Tier2,
        None,
    )
    .expect("test context");
    c.allowed_secrets = allowed_secrets.iter().map(|s| (*s).to_string()).collect();
    c
}

/// Nothing granted, nothing stored: every marker is unaddressable.
fn bare() -> TalosContext {
    ctx(HashMap::new(), &[])
}

fn granted() -> TalosContext {
    let mut m = HashMap::new();
    m.insert(GRANTED_PATH.to_string(), PLAINTEXT.to_string());
    ctx(m, &[GRANTED_PATH])
}

fn latched(c: &TalosContext) -> Option<&'static str> {
    c.network_reason_handle().lock().unwrap().map(|r| r.class)
}

fn json_body(marker: &str) -> Vec<u8> {
    format!(r#"{{"client_id":"public","secret":"{marker}"}}"#).into_bytes()
}

fn post_req(body: Vec<u8>, content_type: Option<&str>) -> wit_http::Request {
    wit_http::Request {
        method: wit_http::Method::Post,
        url: format!("https://{HOST}/r"),
        headers: content_type
            .map(|ct| vec![("content-type".to_string(), ct.to_string())])
            .unwrap_or_default(),
        body,
        // 1 ms, so a control that legitimately reaches the network fails there
        // immediately instead of holding the test open.
        timeout_ms: Some(1),
    }
}

// ── the resolver itself, with a LIVE provider ────────────────────────────────
// EE recorded that `resolve_vault_json_body` "needs a live secret provider and
// cannot be driven from a unit test". It can: `TalosContext::new` takes the
// secrets map. So the substitution is asserted directly rather than only
// through the pure planner.

#[tokio::test]
async fn a_granted_marker_is_substituted_and_the_marker_never_survives() {
    let mut c = granted();
    let body = json_body(&format!("vault://{GRANTED_PATH}"));
    let out = c
        .resolve_vault_json_body(
            crate::context::SecretUseSurface::HttpJsonBody,
            HOST,
            &body,
            Some(JSON),
        )
        .await
        .expect("granted path resolves");
    let out = String::from_utf8(out.expect("a marker was present, so bytes changed")).unwrap();
    assert!(
        out.contains(PLAINTEXT),
        "plaintext must reach the wire: {out}"
    );
    assert!(
        !out.contains("vault://"),
        "the marker must not survive into the sent bytes: {out}"
    );
    // The sibling field is untouched — substitution is per string VALUE.
    assert!(out.contains("\"client_id\":\"public\""), "{out}");
}

#[tokio::test]
async fn a_body_with_no_marker_is_left_byte_identical() {
    // The control that keeps the feature free for every send that does not use
    // it: no marker ⇒ `None` ⇒ the caller sends the guest's own bytes.
    let mut c = granted();
    let out = c
        .resolve_vault_json_body(
            crate::context::SecretUseSurface::HttpJsonBody,
            HOST,
            br#"{"a":"b"}"#,
            Some(JSON),
        )
        .await
        .expect("no marker is not an error");
    assert!(
        out.is_none(),
        "unchanged bodies must report no substitution"
    );
}

// ── http::fetch — the one surface that already resolved ──────────────────────

#[tokio::test]
async fn fetch_refuses_an_ungranted_marker_in_a_json_body() {
    let mut c = bare();
    let r = <TalosContext as wit_http::Host>::fetch(
        &mut c,
        post_req(json_body(UNGRANTED_MARKER), Some(JSON)),
    )
    .await;
    assert!(r.is_err(), "{r:?}");
    assert_eq!(latched(&c), Some(reason_class::SECRET_LOOKUP));
}

#[tokio::test]
async fn fetch_without_a_marker_is_not_refused_for_a_secret_lookup() {
    let mut c = bare();
    let _ = <TalosContext as wit_http::Host>::fetch(
        &mut c,
        post_req(br#"{"a":"b"}"#.to_vec(), Some(JSON)),
    )
    .await;
    assert_ne!(latched(&c), Some(reason_class::SECRET_LOOKUP));
}

// ── http::fetch_all — the batch sibling, same file, no body resolve ──────────

#[tokio::test]
async fn fetch_all_refuses_an_ungranted_marker_and_only_that_entry() {
    // `fetch_all` resolves in its up-front validation pass, which already ran
    // the HEADER resolve under dry-run too — so dry-run is a faithful (and
    // fast) rehearsal here, unlike `fetch`/`webhook`, which return earlier.
    let mut c = bare();
    c.dry_run = true;
    let out = <TalosContext as wit_http::Host>::fetch_all(
        &mut c,
        vec![
            post_req(json_body(UNGRANTED_MARKER), Some(JSON)),
            post_req(br#"{"a":"b"}"#.to_vec(), Some(JSON)),
        ],
    )
    .await;
    assert_eq!(out.len(), 2, "{out:?}");
    assert!(
        out[0].is_err(),
        "the marker entry must be refused: {:?}",
        out[0]
    );
    assert!(
        out[1].is_ok(),
        "a clean sibling entry must still be sent — MCP-783's per-entry rule: {:?}",
        out[1]
    );
    assert_eq!(latched(&c), Some(reason_class::SECRET_LOOKUP));
}

#[tokio::test]
async fn fetch_all_without_a_marker_is_not_refused_for_a_secret_lookup() {
    let mut c = bare();
    c.dry_run = true;
    let _ = <TalosContext as wit_http::Host>::fetch_all(
        &mut c,
        vec![post_req(br#"{"a":"b"}"#.to_vec(), Some(JSON))],
    )
    .await;
    assert_ne!(latched(&c), Some(reason_class::SECRET_LOOKUP));
}

// ── webhook::send ────────────────────────────────────────────────────────────

fn hook(body: &str, content_type: Option<&str>) -> wit_webhook::WebhookRequest {
    wit_webhook::WebhookRequest {
        url: format!("https://{HOST}/hook"),
        headers: content_type
            .map(|ct| vec![("content-type".to_string(), ct.to_string())])
            .unwrap_or_default(),
        body: body.to_string(),
        max_retries: Some(0),
        retry_delay_ms: Some(1),
    }
}

#[tokio::test]
async fn webhook_refuses_an_ungranted_marker_in_a_json_body() {
    // Fast with no network by construction: the resolve sits BEFORE the retry
    // loop and before the circuit-breaker permit, so a refusal returns without
    // opening a connection.
    let mut c = bare();
    let r = <TalosContext as wit_webhook::Host>::send(
        &mut c,
        hook(
            &String::from_utf8(json_body(UNGRANTED_MARKER)).unwrap(),
            Some(JSON),
        ),
    )
    .await;
    assert!(matches!(r, Err(wit_webhook::Error::Sendfailed)), "{r:?}");
    assert_eq!(latched(&c), Some(reason_class::SECRET_LOOKUP));
}

#[tokio::test]
async fn webhook_refuses_a_marker_when_the_guest_declares_no_json_content_type() {
    // `send` sets no content type of its own, so the JSON declaration has to
    // come from the guest. A marker in a body that is not declared JSON is
    // REFUSED, never rewritten — the rule `http::fetch` already applied.
    let mut c = bare();
    let r = <TalosContext as wit_webhook::Host>::send(
        &mut c,
        hook(
            &String::from_utf8(json_body(UNGRANTED_MARKER)).unwrap(),
            None,
        ),
    )
    .await;
    assert!(matches!(r, Err(wit_webhook::Error::Sendfailed)), "{r:?}");
    assert_eq!(latched(&c), Some(reason_class::SECRET_LOOKUP));
}

#[tokio::test]
async fn webhook_refuses_a_grantable_marker_when_no_json_content_type_is_declared() {
    // The DISCRIMINATING form of the test above. That one uses an ungranted
    // path, so it would still refuse even if the content type were assumed
    // rather than read — measured: assuming `application/json` at the call site
    // survived it. Here the path IS granted and present, so the only thing left
    // that can refuse is the absent JSON declaration, and a surface that
    // assumes the content type substitutes instead and reaches the network.
    let mut c = granted();
    let r = <TalosContext as wit_webhook::Host>::send(
        &mut c,
        hook(
            &String::from_utf8(json_body(&format!("vault://{GRANTED_PATH}"))).unwrap(),
            None,
        ),
    )
    .await;
    assert!(matches!(r, Err(wit_webhook::Error::Sendfailed)), "{r:?}");
    assert_eq!(
        latched(&c),
        Some(reason_class::SECRET_LOOKUP),
        "a marker in a body that is not declared JSON must be REFUSED, never rewritten"
    );
}

#[tokio::test]
async fn webhook_dry_run_does_not_resolve_the_body() {
    // The CONTROL for the two refusals above — it proves they come from the
    // resolve and not from something this surface refuses unconditionally —
    // and it pins the decision: dry-run returns before the resolve, so a
    // rehearsal performs no vault read and writes no ledger entry for a send
    // that never happens. Safe because dry-run does not egress.
    let mut c = bare();
    c.dry_run = true;
    let r = <TalosContext as wit_webhook::Host>::send(
        &mut c,
        hook(
            &String::from_utf8(json_body(UNGRANTED_MARKER)).unwrap(),
            Some(JSON),
        ),
    )
    .await;
    assert!(r.is_ok(), "dry-run must not attempt the resolve: {r:?}");
    assert_ne!(latched(&c), Some(reason_class::SECRET_LOOKUP));
}

// ── graphql::execute ────────────────────────────────────────────────────────

fn gql(variables: Option<&str>) -> wit_graphql::Request {
    wit_graphql::Request {
        url: format!("https://{HOST}/graphql"),
        query: "{ ok }".to_string(),
        variables: variables.map(str::to_string),
        headers: None,
        timeout_ms: Some(1),
    }
}

#[tokio::test]
async fn graphql_refuses_an_ungranted_marker_in_a_variable() {
    let mut c = bare();
    let r = <TalosContext as wit_graphql::Host>::execute(
        &mut c,
        gql(Some(&format!(r#"{{"token":"{UNGRANTED_MARKER}"}}"#))),
    )
    .await;
    assert!(r.is_err(), "{r:?}");
    assert_eq!(latched(&c), Some(reason_class::SECRET_LOOKUP));
}

#[tokio::test]
async fn graphql_without_a_marker_is_not_refused_for_a_secret_lookup() {
    let mut c = bare();
    let _ = <TalosContext as wit_graphql::Host>::execute(&mut c, gql(Some(r#"{"a":"b"}"#))).await;
    assert_ne!(latched(&c), Some(reason_class::SECRET_LOOKUP));
}

// ── the wiring properties no in-process test can observe ────────────────────
// The tests above prove each site REFUSES an unaddressable marker, which is
// what a missing resolver call cannot fake. They cannot see which BYTES reqwest
// was handed, because the only observable for that is the socket. These pins
// cover that half.
//
// This module deliberately lives in a file it does not `include_str!`: the pin
// it supersedes sat inside `http.rs`, so reverting `http.rs` to reproduce the
// defect deleted the pin too.
mod wiring_pins {
    /// Assembled at runtime so a pin cannot match its own source.
    fn needle(parts: &[&str]) -> String {
        parts.concat()
    }

    /// Drop `#[cfg(test)]` regions so a pin cannot be satisfied by test code.
    ///
    /// Deliberately NOT `split_once("#[cfg(test)]")`, which is how the pin this
    /// supersedes was written: `graphql.rs` carries a test module at line 375
    /// while its resolver call is at 1153, so that split truncated 778 lines
    /// ABOVE the code being pinned and could never see it. Conservative in the
    /// safe direction, as check 58's strip is — a region whose end is missed
    /// leaves test code in the haystack (a false PASS is impossible; only a
    /// false finding), and an indented attribute is not stripped at all.
    fn production(src: &str) -> String {
        let mut out = String::with_capacity(src.len());
        let mut skipping = false;
        for line in src.lines() {
            if !skipping && line.starts_with("#[cfg(test)]") {
                skipping = true;
                continue;
            }
            if skipping {
                if line == "}" {
                    skipping = false;
                }
                continue;
            }
            // Comment lines are dropped too. Without this, a pin is satisfied —
            // or, for a negative assertion, BROKEN — by the prose that explains
            // it: the comment above graphql's scoped envelope names the very
            // `.json(&body)` form this module asserts is absent. Checks 73, 87,
            // 97 and EG's check 4 each hit that trap; it is the reason a rule
            // must never be enforced against the sentence describing it.
            if line.trim_start().starts_with("//") {
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    const HTTP: &str = include_str!("http.rs");
    const WEBHOOK: &str = include_str!("webhook.rs");
    const GRAPHQL: &str = include_str!("graphql.rs");

    #[test]
    fn every_guest_composed_body_surface_calls_the_one_resolver() {
        let call = needle(&["resolve_vault_json_body", "("]);
        // `fetch` and `fetch_all` — the batch sibling that carried the body
        // through verbatim until 2026-09-24.
        assert_eq!(
            production(HTTP).matches(&call).count(),
            2,
            "http.rs must resolve the body in BOTH fetch and fetch_all"
        );
        assert_eq!(
            production(WEBHOOK).matches(&call).count(),
            1,
            "webhook::send must resolve its body"
        );
        assert_eq!(
            production(GRAPHQL).matches(&call).count(),
            1,
            "graphql::execute must resolve its body"
        );
    }

    #[test]
    fn a_body_resolution_refusal_exits_and_never_falls_through_to_a_send() {
        // One refusal spelling per surface, each returning rather than
        // continuing with the unresolved placeholder. `fetch_all` is the
        // exception by design: its refusal is per ENTRY, so it pushes an `Err`
        // and continues with the REST of the batch.
        assert!(production(HTTP).contains(&needle(&[
            "Err(_) => return Err(deny_forbidden(self, ",
            "reason_class::SECRET_LOOKUP))"
        ])));
        assert!(production(HTTP).contains(&needle(&[
            "validated.push(Err(deny_forbidden(self, ",
            "reason_class::SECRET_LOOKUP)));"
        ])));
        assert!(production(WEBHOOK).contains(&needle(&[
            "Err(_) => return Err(webhook_deny(self, ",
            "reason_class::SECRET_LOOKUP))"
        ])));
        assert!(production(GRAPHQL).contains(&needle(&[
            "Err(_) => return Err(gql_deny(self, ",
            "reason_class::SECRET_LOOKUP))"
        ])));
    }

    #[test]
    fn the_resolved_bytes_are_the_bytes_sent() {
        // `fetch` SHADOWS the guest's body with the resolved bytes, so the
        // original is not reachable under that name at the send.
        assert!(
            production(HTTP).contains(&needle(&["let body = resolved_body", ".unwrap_or(body);"])),
            "fetch must shadow the guest's body with the resolved bytes"
        );
        // GraphQL's composed envelope is scoped to its serialization block, so
        // the `Value` does not survive to the send — which is what makes the
        // one-token revert a COMPILE error rather than a silent wire change.
        assert!(
            !production(GRAPHQL).contains(&needle(&[".json(&", "body)"])),
            "graphql must not serialize the pre-substitution envelope at the send"
        );
        assert!(
            production(GRAPHQL).contains(&needle(&[".body(body_bytes", ".clone())"])),
            "graphql must send the resolved bytes"
        );
        // `fetch_all` cannot shadow: it iterates `&reqs`, so the guest's
        // `req.body` stays reachable by construction. The validated tuple must
        // therefore be asserted to carry the RESOLVED bytes — without this, a
        // one-token revert of the push leaves the resolve running (so every
        // refusal test still passes) while the placeholder goes on the wire.
        assert!(
            production(HTTP).contains(&needle(&["                resolved_body", ","])),
            "fetch_all must carry the resolved body into the validated entry"
        );
        // The `Some` arm must RETURN the substituted bytes. Without this a site
        // can resolve correctly and then discard the result — measured as a
        // survivor: `Ok(Some(_)) => body_bytes` keeps every other assertion in
        // this module green while the placeholder goes on the wire.
        let some_arm = needle(&["Ok(Some(substituted)) =>", " substituted,"]);
        assert!(
            production(GRAPHQL).contains(&some_arm),
            "graphql's Some arm must return the substituted bytes"
        );
        assert!(
            production(WEBHOOK).contains(&some_arm),
            "webhook's Some arm must return the substituted bytes"
        );
    }

    #[test]
    fn the_declared_content_type_comes_from_the_request_itself() {
        // The JSON-only rule is decided by what the request declares, never
        // assumed — for `fetch`/`fetch_all`/`webhook` that is the guest's own
        // header; for GraphQL the envelope is host-composed, so the host's own
        // `application/json` is the honest answer.
        let from_headers = needle(&["eq_ignore_ascii_case(", "\"content-type\")"]);
        assert_eq!(
            production(HTTP).matches(&from_headers).count(),
            2,
            "both http surfaces must read the declared content type"
        );
        assert!(production(WEBHOOK).contains(&from_headers));
        assert!(production(GRAPHQL).contains(&needle(&["Some(", "\"application/json\")"])));
    }
}
