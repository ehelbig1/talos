//! `aws` CLI argv construction — pure, so the security-critical command
//! shape is unit-tested without a bucket, a credential or a network.
//!
//! This is the `cosign_verify_argv` pattern (`talos-worker-runtime`) applied
//! to object storage. Backblaze B2 is addressed through its S3-compatible
//! API, so the provider is a `--endpoint-url` and nothing else: swapping to
//! S3, R2 or MinIO changes one string, not a code path.
//!
//! # Credentials are STRUCTURALLY absent from argv
//!
//! [`S3Target`] has no field for a secret, so no function here can put one on
//! a command line even by accident. `aws` reads `AWS_ACCESS_KEY_ID` /
//! `AWS_SECRET_ACCESS_KEY` from the environment, which `ps` does not show to
//! other users on macOS or on modern Linux. The key **id** may be logged; the
//! secret may not, and the only way to log it would be to write new code that
//! reads it, which is a visible act rather than an accident.

/// Where the archives go. Everything here is non-secret configuration that
/// is safe to print in a log line or an error message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Target {
    /// e.g. `https://s3.us-west-004.backblazeb2.com`
    pub endpoint_url: String,
    pub bucket: String,
    /// B2 requires the region that matches the endpoint; the AWS CLI refuses
    /// to sign without one and its error ("You must specify a region") is
    /// classified as [`crate::FailureReason::Config`], not `Auth`.
    pub region: String,
}

/// Flags every invocation carries.
///
/// `--no-cli-pager` is not cosmetic: without it the AWS CLI v2 pipes output
/// through `$PAGER` when stdout is a terminal, which turns an interactive
/// `probe-append-only` run into a hang. `--output json` keeps parsing stable
/// against a user's `~/.aws/config` setting `output = table`.
fn common(t: &S3Target) -> Vec<String> {
    vec![
        "--endpoint-url".to_string(),
        t.endpoint_url.clone(),
        "--region".to_string(),
        t.region.clone(),
        "--output".to_string(),
        "json".to_string(),
        "--no-cli-pager".to_string(),
    ]
}

/// Upload one already-encrypted file to one key.
///
/// **This does not, and cannot, make the write append-only.** `PutObject`
/// with `s3:PutObject` permission overwrites an existing key silently — same
/// name, new bytes, history gone. What keeps that from happening is, in
/// order of strength: the operator's application key having no
/// `deleteFiles`, the bucket's lifecycle/versioning rule set with the MASTER
/// key, the derived-and-therefore-unique object key, and finally the
/// caller's `head-object` pre-flight. Only the first two are controls.
#[must_use]
pub fn put_object_argv(t: &S3Target, key: &str, body_path: &str) -> Vec<String> {
    let mut a = vec!["s3api".to_string(), "put-object".to_string()];
    a.extend(common(t));
    a.extend([
        "--bucket".to_string(),
        t.bucket.clone(),
        "--key".to_string(),
        key.to_string(),
        "--body".to_string(),
        body_path.to_string(),
    ]);
    a
}

/// Does this key already exist?
///
/// **TOCTOU, deliberately unclosed.** Between this answering "no" and the
/// PUT landing, anything holding the credential can create the key; the PUT
/// then overwrites it. Closing that needs a conditional write
/// (`If-None-Match: *`), which the S3 API supports but which is not
/// documented as supported by B2's S3 compatibility layer — shipping a
/// dependency on an unverified provider behaviour would be a claim, not a
/// control. So this is a GUARD against the ordinary case (a re-run finding
/// its own earlier upload), not a defence against a hostile writer. The
/// defence against a hostile writer is the bucket's retention rule.
#[must_use]
pub fn head_object_argv(t: &S3Target, key: &str) -> Vec<String> {
    let mut a = vec!["s3api".to_string(), "head-object".to_string()];
    a.extend(common(t));
    a.extend([
        "--bucket".to_string(),
        t.bucket.clone(),
        "--key".to_string(),
        key.to_string(),
    ]);
    a
}

/// Download one key to a local path.
#[must_use]
pub fn get_object_argv(t: &S3Target, key: &str, dest_path: &str) -> Vec<String> {
    let mut a = vec!["s3api".to_string(), "get-object".to_string()];
    a.extend(common(t));
    a.extend([
        "--bucket".to_string(),
        t.bucket.clone(),
        "--key".to_string(),
        key.to_string(),
        // The destination is a POSITIONAL argument to `get-object`, and it
        // must be last. Passing it as `--outfile` is not a thing.
        dest_path.to_string(),
    ]);
    a
}

/// List keys under a prefix. `continuation` carries S3's pagination token;
/// a listing that stops at the first 1000 keys would make "the newest object
/// in the bucket" wrong the moment the bucket has three years of dailies in
/// it — the unbounded-pagination class, inverted.
#[must_use]
pub fn list_objects_argv(t: &S3Target, prefix: &str, continuation: Option<&str>) -> Vec<String> {
    let mut a = vec!["s3api".to_string(), "list-objects-v2".to_string()];
    a.extend(common(t));
    a.extend([
        "--bucket".to_string(),
        t.bucket.clone(),
        "--prefix".to_string(),
        prefix.to_string(),
    ]);
    if let Some(token) = continuation {
        a.extend(["--continuation-token".to_string(), token.to_string()]);
    }
    a
}

/// Attempt a delete. **Only ever called by `probe-append-only`, and it is
/// expected to FAIL.** A capability you have not tried to violate is a
/// claim, not a control — this is how the claim gets tested. If it ever
/// succeeds against the upload credential, the credential is wrong and the
/// probe says so loudly.
#[must_use]
pub fn delete_object_argv(t: &S3Target, key: &str) -> Vec<String> {
    let mut a = vec!["s3api".to_string(), "delete-object".to_string()];
    a.extend(common(t));
    a.extend([
        "--bucket".to_string(),
        t.bucket.clone(),
        "--key".to_string(),
        key.to_string(),
    ]);
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> S3Target {
        S3Target {
            endpoint_url: "https://s3.us-west-004.backblazeb2.com".into(),
            bucket: "talos-offhost".into(),
            region: "us-west-004".into(),
        }
    }

    fn assert_flag(argv: &[String], flag: &str, value: &str) {
        let pos = argv
            .iter()
            .position(|a| a == flag)
            .unwrap_or_else(|| panic!("{flag} missing from {argv:?}"));
        assert_eq!(argv[pos + 1], value, "{flag} carried the wrong value");
    }

    #[test]
    fn every_verb_pins_endpoint_region_and_bucket() {
        // The endpoint is what makes this provider-agnostic. Dropping it
        // silently retargets every call at real AWS S3 — a different
        // provider, a different account, and a bucket that does not exist.
        let t = target();
        for argv in [
            put_object_argv(&t, "k", "/tmp/f"),
            head_object_argv(&t, "k"),
            get_object_argv(&t, "k", "/tmp/f"),
            list_objects_argv(&t, "p", None),
            delete_object_argv(&t, "k"),
        ] {
            assert_eq!(argv[0], "s3api");
            assert_flag(&argv, "--endpoint-url", &t.endpoint_url);
            assert_flag(&argv, "--region", &t.region);
            assert_flag(&argv, "--bucket", &t.bucket);
            assert!(argv.iter().any(|a| a == "--no-cli-pager"));
            assert_flag(&argv, "--output", "json");
        }
    }

    #[test]
    fn no_argv_can_carry_a_credential() {
        // Structural, not textual: S3Target has no secret field, so this
        // asserts the shape rather than a redaction. If someone adds a
        // `secret` field and threads it through, this test is what breaks.
        let t = target();
        let all: Vec<String> = [
            put_object_argv(&t, "k", "/tmp/f"),
            head_object_argv(&t, "k"),
            get_object_argv(&t, "k", "/tmp/f"),
            list_objects_argv(&t, "p", Some("tok")),
            delete_object_argv(&t, "k"),
        ]
        .concat();
        for a in &all {
            let lower = a.to_ascii_lowercase();
            for forbidden in ["secret", "passphrase", "password", "access-key", "token="] {
                assert!(
                    !lower.contains(forbidden),
                    "argv element '{a}' looks credential-bearing"
                );
            }
        }
    }

    #[test]
    fn get_object_destination_is_the_last_positional() {
        // `aws s3api get-object … <outfile>` — the destination is positional
        // and must be last. Anywhere else and the CLI treats it as the value
        // of the preceding flag, writing nothing and exiting 0.
        let argv = get_object_argv(&target(), "talos/v1/postgres/x.age", "/tmp/out.age");
        assert_eq!(argv.last().unwrap(), "/tmp/out.age");
        assert!(!argv.iter().any(|a| a == "--outfile"));
    }

    #[test]
    fn list_pagination_token_is_only_present_when_supplied() {
        let t = target();
        let first = list_objects_argv(&t, "talos/v1/", None);
        assert!(!first.iter().any(|a| a == "--continuation-token"));
        let next = list_objects_argv(&t, "talos/v1/", Some("abc123"));
        assert_flag(&next, "--continuation-token", "abc123");
    }

    #[test]
    fn put_body_is_a_path_not_a_stream() {
        let argv = put_object_argv(&target(), "talos/v1/postgres/x.age", "/var/tmp/x.age");
        assert_flag(&argv, "--body", "/var/tmp/x.age");
        assert_flag(&argv, "--key", "talos/v1/postgres/x.age");
    }

    #[test]
    fn values_are_propagated_verbatim() {
        // No mangling. A key with a `+` or a `=` in it must reach the API
        // exactly as constructed, or the pre-flight checks one key and the
        // PUT writes another.
        let t = target();
        let odd = "talos/v1/postgres/2026/08/20260817T101757Z-postgres.age";
        assert_flag(&put_object_argv(&t, odd, "/f"), "--key", odd);
        assert_flag(&head_object_argv(&t, odd), "--key", odd);
        assert_flag(&delete_object_argv(&t, odd), "--key", odd);
    }
}
