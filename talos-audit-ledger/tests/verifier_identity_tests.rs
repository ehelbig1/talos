//! The verifier must NEVER borrow the writer's identity.
//!
//! # Why this is its own binary
//!
//! The rule is about which ENVIRONMENT VARIABLES are read, and the only honest
//! way to pin it is to set the writer's `AWS_*` in a process where the
//! verifier's own variables are unset and watch the builder refuse. Env
//! mutation is `unsafe` in edition 2024 precisely because it races sibling
//! threads, so this test owns its process: one `#[test]`, one binary, nothing
//! else in it.
//!
//! # What it would have caught
//!
//! Everything in this file fails on `origin/main` @ 3fb8c921 by not compiling
//! — `build_audit_verifier_client_from_env` did not exist there, because the
//! sweep and the on-demand admin path both called `build_audit_s3_client`,
//! which resolves credentials through `aws_config::load_defaults`, i.e. the
//! `AWS_*` chain, i.e. the WRITE-ONLY writer. Measured on the dev stack
//! 2026-09-06: `mc ls` with those credentials answers `Access Denied`, and the
//! controller had logged 37 unverifiable executions in an hour and zero
//! verified chains in its entire history.

use talos_audit_ledger::VerifierClient;

#[test]
fn the_writers_aws_credentials_are_not_a_fallback_for_the_verifier() {
    // SAFETY: single-test binary; no other thread exists to observe the write.
    unsafe {
        std::env::set_var("MINIO_ENDPOINT", "http://127.0.0.1:9000");
        // The WRITER's identity, exactly as docker-compose.yml wires it.
        std::env::set_var("AWS_ACCESS_KEY_ID", "the-write-only-writer");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "the-write-only-writer-secret");
        std::env::remove_var("AUDIT_VERIFIER_ACCESS_KEY_ID");
        std::env::remove_var("AUDIT_VERIFIER_SECRET_ACCESS_KEY");
    }

    // An endpoint IS configured, so the ledger is being written. The verifier
    // identity is not, so NO client may be built — and the answer must be
    // `NoCredentials`, not `NoEndpoint`: "there is no WORM store here" and
    // "there is one and nothing can read it" are different findings and
    // `security_audit` grades them differently.
    assert!(
        matches!(
            talos_audit_ledger::build_audit_verifier_client_from_env(),
            VerifierClient::NoCredentials
        ),
        "the verifier must refuse to build a client from the writer's AWS_* credentials"
    );

    // EMPTY IS UNSET (lint check 73). A Helm placeholder renders "", and a
    // half-configured pair that reached MinIO would come back as an anonymous
    // AccessDenied — the same misdiagnosis this whole change removes.
    unsafe {
        std::env::set_var("AUDIT_VERIFIER_ACCESS_KEY_ID", "");
        std::env::set_var("AUDIT_VERIFIER_SECRET_ACCESS_KEY", "");
    }
    assert!(
        matches!(
            talos_audit_ledger::build_audit_verifier_client_from_env(),
            VerifierClient::NoCredentials
        ),
        "an empty verifier credential pair must read as UNSET, not as a principal"
    );

    // One half without the other is not a usable identity either.
    unsafe {
        std::env::set_var("AUDIT_VERIFIER_ACCESS_KEY_ID", "verifier");
        std::env::remove_var("AUDIT_VERIFIER_SECRET_ACCESS_KEY");
    }
    assert!(matches!(
        talos_audit_ledger::build_audit_verifier_client_from_env(),
        VerifierClient::NoCredentials
    ));

    // With BOTH halves present a client is built — so the refusals above are
    // about the credentials being absent and not about the builder being inert
    // (a negative assertion that passes for the wrong reason is the shape a
    // positive control exists to catch).
    unsafe {
        std::env::set_var("AUDIT_VERIFIER_SECRET_ACCESS_KEY", "verifier-secret");
    }
    assert!(matches!(
        talos_audit_ledger::build_audit_verifier_client_from_env(),
        VerifierClient::Ready(_)
    ));

    // And with no endpoint at all the answer is `NoEndpoint` — a deployment
    // with no WORM store has nothing to verify and must not be reported as a
    // broken control.
    unsafe {
        std::env::remove_var("MINIO_ENDPOINT");
        std::env::remove_var("AWS_ENDPOINT_URL");
    }
    assert!(matches!(
        talos_audit_ledger::build_audit_verifier_client_from_env(),
        VerifierClient::NoEndpoint
    ));
}
