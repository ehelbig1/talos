//! Derive `module_executions.error_type` from the failure text the row is
//! about to store.
//!
//! # The gap this closes
//!
//! `module_executions.error_type` has always been WRITABLE — `fail_execution`
//! takes it, `timeout_execution` hardcodes `'timeout'`, the stuck sweep writes
//! `'stuck'`/`'ledger_unfinalized'`, and four integration dispatch paths pass
//! `signing_error` / `nats_publish` / `dlq_replay_dispatch`. What none of them
//! covers is the COMMON case: a module that actually ran and failed. That path
//! is [`ModuleExecutionStore::record_completed`], whose trait signature has no
//! `error_type` slot at all, so every engine-recorded failure stored NULL.
//! Measured on the live dev ledger: 55 of 55 failed rows over 30 days, 59 of 59
//! all-time. The column reaches an operator through GraphQL's
//! `ModuleExecution.errorType` (`moduleExecutionHistory`), so what they saw was
//! a field that is null for exactly the status where a cause matters — with
//! nothing distinguishing "unclassifiable" from "nobody ever wrote this".
//!
//! Note the shape of the null, because it is not uniform: `timeout` rows DO
//! carry a value (20 971 `ledger_unfinalized` + 903 `stuck`). The column was
//! never dead — it was blind on one status.
//!
//! # Vocabulary — reused, not minted
//!
//! Three failure vocabularies already exist in this workspace, and a fourth
//! would be worse than the null:
//!
//! * [`talos_retry_intelligence::classify_error`] — RETRY DISPOSITION
//!   (`network_transient`, `fuel_exhaustion`, `auth_failure`). Answers "will a
//!   retry help", not "what went wrong".
//! * [`talos_reason_class::Family`] — the worker's host-stamped
//!   `[reason_class=<token>]` marker. Authoritative, but it deliberately
//!   declines to name buckets, and its own doc names "an `error_type` in an MCP
//!   report" as one of the per-surface vocabularies it refuses to collapse.
//! * `talos_failure_analysis_service::classify_error` — returns
//!   `(error_type, description)`. The first element is LITERALLY called
//!   `error_type`, and it is what the `analyze_execution_failure` MCP tool
//!   already shows an operator for the very same message.
//!
//! So this module consumes the third. That is not a preference: it is the only
//! one under which the stored column and the report an operator opens next
//! cannot give two names to one cause on one screen. It also gets the marker
//! for free — `classify_error` hoists `token_family` ahead of every prose gate,
//! so a host-stamped failure is classified from the authoritative token rather
//! than from a substring guess.
//!
//! # NULL is a real answer here
//!
//! A stored label is DURABLE and, once written, indistinguishable from a
//! correct one. So this module refuses to store the classifier's FALL-THROUGH
//! bucket — the arm that means "none of the gates matched" — and writes NULL
//! instead. Two consequences, both accepted deliberately:
//!
//! * It UNDER-reports. Measured on the live corpus, 14 of 59 rows classified to
//!   the fall-through and stayed NULL, including six `circuit open for host …`
//!   messages whose cause IS a known family ([`Family::CircuitOpen`]) but which
//!   carried no marker and matched no prose gate. Losing those was the cost of
//!   not inventing a second prose classifier beside the one that exists — and
//!   it was the RIGHT cost to pay rather than the right outcome: the sibling
//!   change added that unmarked breaker arm IN the classifier, so those six now
//!   store `circuit_open`. The remaining NULLs are messages no classifier
//!   currently recognises, which is what NULL is for.
//! * It cannot be defeated by RENAMING the fall-through. The bucket is
//!   discovered at runtime by probing the classifier with a string that matches
//!   no gate, so a future rename of `runtime_error` cannot silently turn the
//!   fall-through into a stored label. [`fallthrough_is_still_runtime_error`]
//!   additionally pins the token, so a SEMANTIC change is visible too.
//!
//! [`ModuleExecutionStore::record_completed`]:
//!     talos_workflow_engine_core::ModuleExecutionStore::record_completed
//! [`Family::CircuitOpen`]: talos_reason_class::Family::CircuitOpen

use std::sync::OnceLock;

/// The dispatcher's diagnostic appendix separator.
///
/// `talos-workflow-engine-nats`'s retry-exhausted arm appends
/// `" | diag: {…}"` — a JSON dump of the job's SIGNED FIELD VALUES — so an
/// operator can spot the diverged field without pod-shell access (MCP-1212).
const DIAG_SEPARATOR: &str = " | diag: ";

/// Everything below the classifier is a SUBSTRING guess over prose, which
/// makes a key/value configuration dump adversarial input by construction.
/// This is not hypothetical: the live ledger holds
/// `"… signature verification failed | diag: {…,\"timeout_ms\":120000,…}"`,
/// where the appendix's own `timeout_ms` key trips the classifier's `timeout`
/// gate. Stored, that is a specific and actionable claim — "bump timeout_secs
/// or split the work" — about a job whose signature did not verify.
///
/// Stripping the appendix is input hygiene, not a second classifier: the text
/// removed is machine-composed metadata that sits AFTER the cause clause and
/// never carries the cause itself.
fn strip_diag_appendix(msg: &str) -> &str {
    match msg.find(DIAG_SEPARATOR) {
        Some(at) => &msg[..at],
        None => msg,
    }
}

/// The bucket `classify_error` answers with when NO gate matched.
///
/// Derived by PROBE rather than by naming the literal, so that a rename in the
/// classifier crate cannot silently convert "nothing matched" into a stored
/// label. The probe is a string that contains no substring any gate looks for;
/// whatever the classifier answers for it IS, by construction, its fall-through.
fn fallthrough_bucket() -> &'static str {
    static PROBE: OnceLock<&'static str> = OnceLock::new();
    PROBE.get_or_init(|| talos_failure_analysis_service::classify_error("zzzz").0)
}

/// Classify the failure text a `module_executions` row is about to store into
/// the surface's `error_type` vocabulary, or `None` when it cannot be
/// classified.
///
/// `None` for a non-failure status, for an absent message, and — the point of
/// this function — for a message the classifier does not recognise.
///
/// Pass the SAME string that will be persisted in `error_message`. Deriving
/// from the stored text rather than from an earlier form is what makes the two
/// columns unable to disagree: a reader comparing the label against the message
/// is comparing the label against the text it was computed from.
#[must_use]
pub fn derive_error_type(status: &str, error_message: Option<&str>) -> Option<&'static str> {
    // `record_completed` is called with "completed" on the success path. A
    // success has no cause, and the guard is on the STATUS rather than on the
    // message being absent so that a future caller passing an informational
    // message alongside "completed" cannot label a successful row.
    if status == "completed" {
        return None;
    }
    let msg = error_message?;
    let (bucket, _description) =
        talos_failure_analysis_service::classify_error(strip_diag_appendix(msg));
    if bucket == fallthrough_bucket() {
        return None;
    }
    Some(bucket)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fall-through's IDENTITY is probed, but its VALUE is pinned here so
    /// that a semantic change — the classifier growing a real bucket distinct
    /// from its fall-through, say — fails loudly instead of quietly making
    /// every unrecognised message store that bucket.
    ///
    /// Updated for the sibling change that renamed the fall-through
    /// `runtime_error` -> `unclassified`. That rename is exactly what this pin
    /// is for: it fired, and the confirmation it asked for is that the new
    /// value is still "nothing matched" rather than a real cause. It is —
    /// `unclassified` is defined as "matched no known cause, and in particular
    /// NOT established to be the module", so it maps to NULL here for the same
    /// reason the old value did.
    #[test]
    fn fallthrough_is_not_a_real_bucket() {
        assert_eq!(
            fallthrough_bucket(),
            "unclassified",
            "the classifier's fall-through bucket changed. derive_error_type \
             maps the fall-through to NULL by probe, so this test failing does \
             NOT mean the mapping broke — it means someone should confirm the \
             new fall-through is still 'nothing matched' and not a real bucket."
        );
    }

    #[test]
    fn a_completed_row_is_never_labelled() {
        assert_eq!(derive_error_type("completed", None), None);
        assert_eq!(
            derive_error_type("completed", Some("execution timed out after 30 seconds")),
            None
        );
    }

    #[test]
    fn an_absent_message_yields_no_label() {
        assert_eq!(derive_error_type("failed", None), None);
    }

    /// THE MEASURED HAZARD. Verbatim from the live ledger. Without the diag
    /// strip this stores `timeout` for a signature-verification failure.
    #[test]
    fn a_diag_appendix_cannot_manufacture_a_cause() {
        let observed = "Job failed after 1 attempts: signature verification failed | diag: \
            {\"actor_id\":\"4f14999a-2de3-412f-b0f2-a37859e77268\",\
            \"allow_tier2_exposure\":false,\"allowed_hosts\":[],\"allowed_methods\":[],\
            \"expected_wasm_hash\":null,\"signature_byte_len\":64,\"timeout_ms\":120000,\
            \"verify_error\":\"job_nonce is too old (902 s, max 300)\"}";
        assert_eq!(
            talos_failure_analysis_service::classify_error(observed).0,
            "timeout",
            "premise check: the UNSTRIPPED message really does trip the timeout \
             gate. If this stops holding the strip may no longer be earning its keep."
        );
        assert_eq!(
            derive_error_type("failed", Some(observed)),
            None,
            "a signature-verification failure must not be stored as 'timeout' \
             because a diagnostic dump of signed fields happened to contain the \
             key 'timeout_ms'"
        );
    }

    /// The live 30-day failure corpus, verbatim, with the label each message
    /// must produce. This is the measurement, kept as the pin: a change to the
    /// classifier that silently re-labels stored history shows up here.
    ///
    /// `None` entries are the deliberate under-reports. Two are worth naming:
    /// the `circuit open for host …` message names a cause the platform HAS a
    /// family for and still classifies to nothing (no marker, no matching prose
    /// gate), and `result_nonce is too old` is a controller/worker clock
    /// problem that the fall-through would have described as "an unexpected
    /// runtime error occurred inside the module" — false, and about the wrong
    /// component.
    #[test]
    fn the_live_failure_corpus_classifies_as_measured() {
        let corpus: &[(&str, Option<&str>)] = &[
            (
                "Job failed after 1 attempts: execution timed out after 30 seconds",
                Some("timeout"),
            ),
            (
                "Job failed after 1 attempts: execution timed out after 120 seconds \
                 (enforced limit from job timeout_ms: node timeout_secs, else controller default)",
                Some("timeout"),
            ),
            (
                "Job failed after 3 attempts: execution failure: Component returned error: \
                 list fetch: Error { code: 2, name: \"networkerror\", message: \"\" } \
                 [reason_class=dns]",
                Some("network_error"),
            ),
            (
                "Job failed after 1 attempts: execution failure: Component returned error: \
                 HTTP request failed: Error { code: 2, name: \"networkerror\", message: \"\" } \
                 [reason_class=tier1-egress]",
                Some("egress_tier_denied"),
            ),
            (
                "Job failed after 1 attempts: execution failure: Component returned error: \
                 HTTP request failed: Error { code: 0, name: \"invalidurl\", message: \"\" } \
                 [reason_class=insecure-scheme]",
                Some("insecure_scheme"),
            ),
            (
                "Execution failed: {\"error\":\"execution failure: Component returned error: \
                 Missing AUTH_HEADER config\"}",
                Some("config_error"),
            ),
            (
                "Job failed (retry_condition not met): execution failure: Component returned \
                 error: Gmail 401: access_token invalid or expired. Call refresh_oauth_token \
                 to force a refresh.",
                Some("http_401"),
            ),
            (
                "Job failed (non-transient: fuel_exhaustion): execution failure: WASM fuel \
                 exhausted: the module consumed 1000000 instructions of a 1000000-instruction \
                 budget and did not finish",
                Some("fuel_exhausted"),
            ),
            (
                "Job failed after 1 attempts: execution failure: Component returned error: \
                 LLM provider 'ollama' returned an API error: Network error: error sending \
                 request for url (http://host.docker.internal:11434/api/chat)",
                Some("network_error"),
            ),
            // ── deliberate under-reports ─────────────────────────────────
            // Measured as NULL; now `circuit_open`. The sibling change added
            // the UNMARKED breaker arm this crate could not add itself, so the
            // disclosed compromise — "six live rows store NULL despite
            // Family::CircuitOpen existing" — is closed. This corpus test is
            // what DETECTED the improvement rather than silently absorbing it.
            (
                "Job failed (retry_condition not met): execution failure: circuit open for \
                 host gmail.googleapis.com: cooling down after repeated failures — skipping \
                 retries until the host recovers",
                Some("circuit_open"),
            ),
            (
                "Job result signature verification failed: result_nonce is too old \
                 (715 s, max 300)",
                None,
            ),
            (
                "Failed to parse job result: EOF while parsing a value at line 1 column 0",
                None,
            ),
            (
                "Job failed (non-transient: unknown): execution failure: Component returned \
                 error: ordinary module failure",
                None,
            ),
            (
                "Job failed after 1 attempts: execution failure: Component returned error: \
                 HTTP request failed: Error { code: 0, name: \"invalidurl\", message: \"\" }",
                None,
            ),
            ("Pipeline aborted before this step", None),
        ];

        for (msg, expected) in corpus {
            assert_eq!(
                derive_error_type("failed", Some(msg)),
                *expected,
                "corpus message classified differently than measured: {msg}"
            );
        }
    }

    /// A host-stamped marker must beat the prose around it. `[reason_class=dns]`
    /// sits in a message that ALSO contains the word "networkerror", so this
    /// only proves the ordering when the two would disagree — hence a token
    /// whose family no prose gate can reach.
    #[test]
    fn the_host_stamped_marker_outranks_the_prose() {
        assert_eq!(
            derive_error_type(
                "failed",
                Some("Component returned error: request refused [reason_class=write-ceiling]")
            ),
            Some("write_ceiling_denied")
        );
    }
}
