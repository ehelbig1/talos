//! The catalog templates' own tests, run natively.
//!
//! A template (`module-templates/<name>/template.rs`) is built for the
//! sandbox by the controller, and until this crate existed the tests inside
//! it ran only when their author built a scratch project by hand. `build.rs`
//! finds every template with a `#[cfg(test)]` module and includes it here
//! against `talos-module-testkit`'s stand-in for the host bindings, so
//! `cargo test --workspace` runs them.
//!
//! What this does not do: build a template for the sandbox. That is
//! `scripts/check-catalog.sh`, against the real bindings.

// The templates are held to their own gate (`make check-catalog`), not to the
// workspace's lint levels: they are module sources, compiled elsewhere with
// other settings, and included here only to run their tests.
#![allow(warnings, clippy::all, clippy::pedantic)]

pub use talos_module_testkit::talos;

include!(concat!(env!("OUT_DIR"), "/modules.rs"));
include!(concat!(env!("OUT_DIR"), "/discovered.rs"));

#[cfg(test)]
mod discovery {
    /// Discovery is by content. A scan that stopped matching would leave a
    /// crate with no tests, which passes; this is the floor under it.
    #[test]
    fn the_templates_with_tests_were_found() {
        assert!(
            super::DISCOVERED.len() >= 7,
            "found only {:?}",
            super::DISCOVERED
        );
        for known in ["google_health_daily", "jwt_validator", "llm_inference"] {
            assert!(
                super::DISCOVERED.contains(&known),
                "{known} is missing from {:?}",
                super::DISCOVERED
            );
        }
    }
}
