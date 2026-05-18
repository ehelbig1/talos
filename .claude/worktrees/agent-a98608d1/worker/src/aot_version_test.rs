#[test]
fn aot_version_header_is_correct() {
    assert_eq!(crate::runtime::AOT_VERSION_HDR, b"TALOSV1");
}

