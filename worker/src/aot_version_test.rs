#[test]
fn aot_version_header_is_correct() {
    // Tracks the latest AOT blob version bump. Update whenever the
    // wasmtime engine config OR the HMAC-input domain changes.
    //   TALOSV3 → TALOSV4: HMAC input now binds CapabilityWorld
    //                       (aot_hmac_input).
    assert_eq!(crate::runtime::AOT_VERSION_HDR, b"TALOSV4");
}

