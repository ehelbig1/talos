//! Failure classification.
//!
//! # Why this is a CLOSED set and not a free-text label
//!
//! The reason ends up as a Prometheus label. A label whose values come from
//! provider error text is an unbounded-cardinality DoS surface, and — worse
//! for this change — an unbounded label set cannot be PRE-SEEDED, so
//! `increase(talos_offhost_backup_failures_total[6h]) > 0` would be
//! undefined until the first failure of each flavour. Absent is not zero:
//! the alert would be silenced by exactly the condition it detects, right up
//! until it had already fired once.
//!
//! Seven values, fixed at compile time, all emitted at 0 on every run.

/// Why an upload (or a fetch) failed. Closed set; see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FailureReason {
    /// The operator has not finished wiring this up: no bucket configured,
    /// no credentials in the environment, no region. Actionable by reading
    /// `docs/offhost-backup.md`, not by paging anyone.
    Config,
    /// `aws` or another required binary is not installed / not on PATH.
    MissingTool,
    /// Credentials present but rejected, or the key lacks the capability.
    /// **This is the one that means the off-host copy has silently stopped**
    /// — a rotated or revoked application key looks exactly like this.
    Auth,
    /// Could not reach the endpoint at all. The benign case (a closed
    /// laptop, a hotel network) and the malicious case (egress blocked)
    /// are indistinguishable from here, which is why the alert is on
    /// PERSISTENT failure rather than on any single one.
    Network,
    /// The object asked for is not in the bucket. Only ever a failure on the
    /// FETCH path — on the upload path a missing key is the happy case.
    NotFound,
    /// `age` encryption or decryption failed. On the drill's fetch path this
    /// is the wrong-passphrase case, and it must be fatal: a drill that
    /// "passed" without decrypting proves nothing.
    Encrypt,
    /// Anything unrecognised. Not a catch-all to be comfortable with — if
    /// this fires repeatedly, the classifier needs a new arm, because
    /// `reason="other"` tells an operator nothing.
    Other,
}

impl FailureReason {
    /// Every reason, in a stable order. The metric renderer pre-seeds one
    /// series per entry so `increase(...)` is well-defined from the first
    /// scrape.
    pub const ALL: [FailureReason; 7] = [
        FailureReason::Config,
        FailureReason::MissingTool,
        FailureReason::Auth,
        FailureReason::Network,
        FailureReason::NotFound,
        FailureReason::Encrypt,
        FailureReason::Other,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            FailureReason::Config => "config",
            FailureReason::MissingTool => "missing_tool",
            FailureReason::Auth => "auth",
            FailureReason::Network => "network",
            FailureReason::NotFound => "not_found",
            FailureReason::Encrypt => "encrypt",
            FailureReason::Other => "other",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

/// Classify a failed `aws` invocation.
///
/// **Order is load-bearing and is asserted by the tests below.** The AWS CLI
/// mentions several of these words in one message — "Unable to locate
/// credentials" contains "credentials" and nothing else useful, while a 403
/// body can mention both `AccessDenied` and the endpoint host. Getting the
/// order wrong files a revoked key under `network` and the alert then reads
/// as "the laptop was closed" for as long as it takes someone to look.
///
/// `exit_code` is `None` when the process was killed by a signal.
#[must_use]
pub fn classify_aws_failure(exit_code: Option<i32>, stderr: &str) -> FailureReason {
    let s = stderr.to_ascii_lowercase();

    // 1. The tool itself. Checked first because every other arm assumes the
    //    text came FROM aws; if aws never ran, the text is the shell's.
    if exit_code == Some(127)
        || s.contains("command not found")
        || s.contains("no such file or directory: aws")
        || s.contains("executable file not found")
    {
        return FailureReason::MissingTool;
    }

    // 2. Operator has not finished configuring. Distinguished from `auth`
    //    on purpose: "you never set this up" and "your key was revoked" want
    //    completely different responses, and merging them makes the more
    //    urgent one look routine.
    if s.contains("unable to locate credentials")
        || s.contains("you must specify a region")
        || s.contains("nosuchbucket")
        || s.contains("the specified bucket does not exist")
        || s.contains("invalidbucketname")
        || s.contains("could not connect to the endpoint url: \"\"")
    {
        return FailureReason::Config;
    }

    // 3. Credentials rejected. Before the network arm: a 403 response is
    //    proof the endpoint WAS reachable.
    if s.contains("invalidaccesskeyid")
        || s.contains("signaturedoesnotmatch")
        || s.contains("accessdenied")
        || s.contains("access denied")
        || s.contains("unauthorized")
        || s.contains("expiredtoken")
        || s.contains("(403)")
        || s.contains("status code: 403")
    {
        return FailureReason::Auth;
    }

    // 4. Object genuinely absent. Also after auth: B2, like S3, may answer
    //    403 rather than 404 for a key you may not read, and calling that
    //    "not found" would hide a permissions regression.
    if s.contains("nosuchkey")
        || s.contains("(404)")
        || s.contains("status code: 404")
        || s.contains("not found")
    {
        return FailureReason::NotFound;
    }

    // 5. Never got an answer.
    if s.contains("could not connect to the endpoint")
        || s.contains("endpointconnectionerror")
        || s.contains("connecttimeouterror")
        || s.contains("readtimeouterror")
        || s.contains("connection was closed")
        || s.contains("network is unreachable")
        || s.contains("temporary failure in name resolution")
        || s.contains("nodename nor servname")
        || s.contains("name or service not known")
        || s.contains("ssl")
    {
        return FailureReason::Network;
    }

    FailureReason::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_values_are_stable_and_unique() {
        // These strings are Prometheus label VALUES. Renaming one silently
        // splits a counter in two and orphans every dashboard on the old
        // name, so they are pinned here rather than derived.
        let want = [
            "config",
            "missing_tool",
            "auth",
            "network",
            "not_found",
            "encrypt",
            "other",
        ];
        let got: Vec<&str> = FailureReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(got, want);
        let mut sorted = got.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), want.len(), "label values must be unique");
    }

    #[test]
    fn every_reason_round_trips_through_its_label() {
        for r in FailureReason::ALL {
            assert_eq!(FailureReason::parse(r.as_str()), Some(r));
        }
        assert_eq!(FailureReason::parse("nonsense"), None);
    }

    #[test]
    fn revoked_key_is_auth_not_network() {
        // THE case this classifier exists for. A rotated B2 application key
        // is how a working off-host backup silently stops, and filing it as
        // `network` makes it read like a closed laptop.
        assert_eq!(
            classify_aws_failure(
                Some(255),
                "An error occurred (InvalidAccessKeyId) when calling the PutObject operation: \
                 Malformed Access Key Id"
            ),
            FailureReason::Auth
        );
        assert_eq!(
            classify_aws_failure(
                Some(1),
                "An error occurred (AccessDenied) when calling the PutObject operation \
                 (Status Code: 403): Access Denied"
            ),
            FailureReason::Auth
        );
    }

    #[test]
    fn a_403_is_auth_even_though_it_names_the_endpoint_host() {
        // Order check: this text contains both an auth marker and the
        // endpoint hostname. Reaching the network arm first would misfile it.
        let msg = "An error occurred (AccessDenied) when calling the PutObject operation \
                   on https://s3.us-west-004.backblazeb2.com: Access Denied";
        assert_eq!(classify_aws_failure(Some(1), msg), FailureReason::Auth);
    }

    #[test]
    fn unconfigured_is_config_not_auth() {
        assert_eq!(
            classify_aws_failure(Some(253), "Unable to locate credentials"),
            FailureReason::Config
        );
        assert_eq!(
            classify_aws_failure(Some(252), "You must specify a region."),
            FailureReason::Config
        );
    }

    #[test]
    fn unreachable_endpoint_is_network() {
        for msg in [
            "Could not connect to the endpoint URL: \"https://s3.us-west-004.backblazeb2.com/b\"",
            "EndpointConnectionError: Could not connect",
            "ConnectTimeoutError: Connect timeout on endpoint URL",
            "botocore.exceptions.EndpointConnectionError: nodename nor servname provided",
        ] {
            assert_eq!(
                classify_aws_failure(Some(255), msg),
                FailureReason::Network,
                "{msg}"
            );
        }
    }

    #[test]
    fn missing_binary_is_missing_tool_even_with_empty_stderr() {
        assert_eq!(
            classify_aws_failure(Some(127), ""),
            FailureReason::MissingTool
        );
        assert_eq!(
            classify_aws_failure(None, "aws: command not found"),
            FailureReason::MissingTool
        );
    }

    #[test]
    fn missing_key_is_not_found_but_a_forbidden_key_is_auth() {
        assert_eq!(
            classify_aws_failure(
                Some(254),
                "An error occurred (NoSuchKey) when calling the GetObject operation: \
                 The specified key does not exist."
            ),
            FailureReason::NotFound
        );
        // B2/S3 may answer 403 for a key you are not allowed to see. Calling
        // that "not found" would hide a permissions regression behind a
        // benign-looking reason.
        assert_eq!(
            classify_aws_failure(
                Some(254),
                "An error occurred (403) when calling the HeadObject operation: Forbidden"
            ),
            FailureReason::Auth
        );
    }

    #[test]
    fn unrecognised_text_falls_through_to_other() {
        assert_eq!(
            classify_aws_failure(Some(1), "something nobody has seen before"),
            FailureReason::Other
        );
        // A signal kill with no stderr is not "fine".
        assert_eq!(classify_aws_failure(None, ""), FailureReason::Other);
    }

    #[test]
    fn classification_is_case_insensitive() {
        assert_eq!(
            classify_aws_failure(Some(1), "ACCESSDENIED"),
            FailureReason::Auth
        );
        assert_eq!(
            classify_aws_failure(Some(1), "NoSuchBucket"),
            FailureReason::Config
        );
    }
}
