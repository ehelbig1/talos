#[test]
fn aot_version_header_is_correct() {
    // Tracks the latest AOT blob version bump. Update whenever the
    // wasmtime engine config OR the HMAC-input domain changes.
    //   TALOSV3 → TALOSV4: HMAC input now binds CapabilityWorld
    //                       (aot_hmac_input).
    //   TALOSV4 → TALOSV5: L-2 (2026-05-22 wasm-security review) —
    //                       HMAC input now binds engine-config
    //                       fingerprint hash so Config:: knob changes
    //                       automatically invalidate cached blobs.
    assert_eq!(crate::runtime::AOT_VERSION_HDR, b"TALOSV5");
}

