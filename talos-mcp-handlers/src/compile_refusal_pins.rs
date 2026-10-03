//! The compile switch (`TALOS_MODULE_COMPILATION=false`) reaches the caller
//! as the operator's stated policy, not as "see server logs".
//!
//! The compile service refuses with a typed error; what the caller READS is
//! decided where each handler turns an `Err` into a response. Every one of
//! those used to hold its own copy of the generic sentence, which would
//! have answered a deliberate refusal with a pointer to a log the caller
//! cannot read.

use talos_compilation::{
    caller_facing_service_error, CompilationDisabled, COMPILATION_DISABLED_MESSAGE,
    COMPILATION_SERVICE_ERROR_MESSAGE,
};

/// No handler holds the generic compile-error sentence itself: it has one
/// home, beside the function that knows when NOT to say it.
#[test]
fn no_handler_spells_the_generic_compile_error_itself() {
    for (file, source) in [
        ("advanced.rs", include_str!("advanced.rs")),
        ("modules.rs", include_str!("modules.rs")),
        ("sandbox.rs", include_str!("sandbox.rs")),
        ("workflows.rs", include_str!("workflows.rs")),
        ("platform.rs", include_str!("platform.rs")),
    ] {
        assert!(
            !source.contains(COMPILATION_SERVICE_ERROR_MESSAGE),
            "{file} spells the generic compile-error sentence; call \
             talos_compilation::caller_facing_service_error(&e) so a deployment with \
             compilation off is told so"
        );
    }
}

#[test]
fn the_two_typed_services_say_the_policy_verbatim() {
    let inline = talos_inline_compile_service::InlineCompileError::CompilationDisabled;
    assert_eq!(inline.user_facing_message(), COMPILATION_DISABLED_MESSAGE);
    assert_eq!(inline.jsonrpc_code(), -32000);

    let hot = talos_hot_update_service::HotUpdateError::CompilationDisabled;
    assert_eq!(hot.to_string(), COMPILATION_DISABLED_MESSAGE);

    let refused = anyhow::Error::new(CompilationDisabled);
    assert_eq!(
        caller_facing_service_error(&refused),
        COMPILATION_DISABLED_MESSAGE
    );
}

#[test]
fn both_status_reports_state_the_switch() {
    let on = crate::modules::module_compilation_report(true);
    let off = crate::modules::module_compilation_report(false);
    assert_eq!(on["enabled"], true);
    assert_eq!(off["enabled"], false);
    assert!(off["note"]
        .as_str()
        .unwrap()
        .contains("TALOS_MODULE_COMPILATION=false"));
    for (file, source) in [
        ("modules.rs", include_str!("modules.rs")),
        ("platform.rs", include_str!("platform.rs")),
    ] {
        assert!(
            source.contains("module_compilation_report("),
            "{file} no longer reports the compile switch"
        );
    }
}
