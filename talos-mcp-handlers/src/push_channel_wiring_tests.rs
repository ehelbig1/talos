//! `create_router` must hand its `push_channels` to BOTH consumers.
//!
//! # Why a source pin rather than a behavioural test
//!
//! Measured 2026-09-08 (mutation M9b): passing `None` at either consumer in
//! `create_router` leaves every test in this workspace green while the hygiene
//! report silently stops saying anything about push channels and
//! `list_push_channels` renders `not_measured` forever. Making
//! `HygieneService::new` take the value as a REQUIRED parameter closed the
//! forgotten-builder half — the compiler now asks — but it cannot stop a caller
//! from answering `None`, which is the call-site class checks 74b and 79b both
//! state as their own limit.
//!
//! A behavioural guard would have to drive the real `create_router`, i.e. a
//! full controller boot with NATS, Redis, a runtime and a compiler. This is the
//! `task_supervision_wiring_tests` shape instead: pin the wiring in the source,
//! which costs nothing and fails loudly on the exact revert.
//!
//! Stated limit: this proves the IDENTIFIER reaches both consumers, never that
//! the value behind it is a non-empty set. The set's construction is in
//! `controller/src/bootstrap/services.rs` and is guarded by nothing but review.

const CREATE_ROUTER_SRC: &str = include_str!("lib.rs");

/// The body of `create_router`, from its signature to the `McpState` literal's
/// close. Anchored on text that must exist; a rename fails LOUDLY rather than
/// silently scanning nothing (checks 64 / 65).
fn create_router_body() -> &'static str {
    let start = CREATE_ROUTER_SRC
        .find("pub fn create_router(")
        .expect("create_router moved or was renamed; this pin must move with it");
    let rest = &CREATE_ROUTER_SRC[start..];
    let end = rest
        .find("    // Authenticated routes (Bearer token required)")
        .expect("the McpState literal's landmark moved; this pin must move with it");
    &rest[..end]
}

#[test]
fn create_router_threads_push_channels_to_both_consumers() {
    let body = create_router_body();

    // (1) The parameter exists at all.
    assert!(
        body.contains("push_channels: Option<std::sync::Arc<talos_push_channel_inventory::PushChannelInventorySet>>"),
        "create_router lost its push_channels parameter"
    );
    // (2) It reaches the hygiene service, which renders `dangling_push_channels`.
    assert!(
        body.contains("push_channels.clone(),"),
        "HygieneService::new is no longer handed create_router's push_channels; \
         the hygiene report will silently stop naming a dangling channel"
    );
    // (3) …and the MCP state, which backs `list_push_channels`.
    assert!(
        body.contains("        push_channels,\n"),
        "McpState no longer receives create_router's push_channels; \
         list_push_channels will render not_measured on every call"
    );
    // (4) …and neither consumer is passed a literal `None`, which is the exact
    // revert (M9b) that survives every behavioural test in this workspace.
    assert!(
        !body.contains("module_repo.clone(),\n        None,"),
        "HygieneService::new is being passed a literal None"
    );
}

/// The tripwire the pin needs: if the shape it scans for ever vanishes, the
/// assertions above would all be over an empty region and pass vacuously.
#[test]
fn the_pinned_region_is_not_empty() {
    let body = create_router_body();
    assert!(body.len() > 500, "create_router body scan returned nothing");
    assert!(body.contains("let hygiene_service"));
    assert!(body.contains("McpState {"));
}
