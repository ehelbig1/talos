//! What a dry run stubbed.
//!
//! Under `dry_run` the host answers some outbound calls itself instead of
//! making them: a non-GET HTTP request, a webhook send, a messaging publish,
//! an agent invoke or send. The module is handed a success, so its output
//! says `sent: true`, and until 2026-10-12 nothing on the node's output said
//! the call had been answered by a stub. It was impossible to tell from the
//! output whether a test had just messaged someone.
//!
//! [`DryRunLedger`] counts the stubbed calls of one execution by host
//! surface, and [`stamp_output`] writes the count onto the module's output
//! under [`DRY_RUN_REPORT_KEY`].
//!
//! # What a dry run does NOT stub
//!
//! `database`, `object_storage`, `files` and `http_stream` have no dry-run
//! branch (`email::send` and a `graphql::execute` that may be a mutation are
//! stubbed since 2026-10-14, security review G-27); memory
//! writes and LLM calls are real too. A node that used one of those under a
//! dry run reports `stubbed_calls: 0`, which is the truth: nothing of its was
//! stubbed.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

pub use talos_workflow_job_protocol::DRY_RUN_REPORT_KEY;

/// A host surface that has a dry-run stub. A closed set: the value is a key
/// in the stamped report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StubbedSurface {
    /// `talos:core/http` `fetch` / `fetch-all`, a non-GET request.
    Http,
    /// `wasi:http`, a mutating request.
    WasiHttp,
    /// `webhook::send`.
    Webhook,
    /// `messaging` publish.
    Messaging,
    /// `agent-orchestration` invoke / send.
    AgentOrchestration,
    /// `email::send` (2026-10-14, security review G-27).
    Email,
    /// `graphql::execute` of a document that may be a mutation (2026-10-14,
    /// G-27).
    Graphql,
}

impl StubbedSurface {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::WasiHttp => "wasi_http",
            Self::Webhook => "webhook",
            Self::Messaging => "messaging",
            Self::AgentOrchestration => "agent_orchestration",
            Self::Email => "email",
            Self::Graphql => "graphql",
        }
    }
}

/// One execution's stubbed calls, by surface. Cloned into the futures that
/// have no `self` (the `fetch-all` entries) and kept by the runtime after the
/// context moves into the wasmtime store.
#[derive(Debug, Clone, Default)]
pub struct DryRunLedger(Arc<Mutex<BTreeMap<StubbedSurface, u32>>>);

impl DryRunLedger {
    /// Count one call that was answered by a stub.
    pub fn record(&self, surface: StubbedSurface) {
        let mut counts = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = counts.entry(surface).or_insert(0);
        *count = count.saturating_add(1);
    }

    /// The counts so far, by surface.
    pub fn snapshot(&self) -> BTreeMap<StubbedSurface, u32> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

/// Write (or remove) the dry-run report on a module's output.
///
/// Set-or-REMOVE, like every key the platform authors. On a dry run the
/// report is written whatever the module returned under the key, including
/// when nothing was stubbed (`stubbed_calls: 0`): a module cannot fabricate a
/// report or hide one. On an ordinary run the key is removed, so a module
/// cannot make a real run read as a rehearsal.
///
/// A module that passes a stubbed response through as its own output returns
/// the stub's `"__dry_run__": true`; that is replaced by the report here.
///
/// An output that is not a JSON object has nowhere to carry the key and is
/// left alone.
pub fn stamp_output(output: &mut serde_json::Value, dry_run: bool, ledger: &DryRunLedger) {
    let Some(object) = output.as_object_mut() else {
        return;
    };
    if !dry_run {
        object.remove(DRY_RUN_REPORT_KEY);
        return;
    }
    let counts = ledger.snapshot();
    object.insert(
        DRY_RUN_REPORT_KEY.to_string(),
        talos_workflow_job_protocol::dry_run_report(
            counts
                .iter()
                .map(|(surface, count)| (surface.as_str(), *count)),
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_dry_runs_output_says_how_many_calls_were_stubbed_and_where() {
        let ledger = DryRunLedger::default();
        ledger.record(StubbedSurface::Http);
        ledger.record(StubbedSurface::Http);
        ledger.record(StubbedSurface::Webhook);
        // The observed output: a send node that reports success.
        let mut output = json!({ "sent": true, "message_id": "" });
        stamp_output(&mut output, true, &ledger);
        assert_eq!(
            output,
            json!({
                "sent": true,
                "message_id": "",
                "__dry_run__": { "stubbed_calls": 3, "by_surface": { "http": 2, "webhook": 1 } },
            })
        );
    }

    #[test]
    fn a_dry_run_that_stubbed_nothing_says_zero() {
        // A node whose calls are GETs, or go through a surface with no stub.
        let mut output = json!({ "rows": 3 });
        stamp_output(&mut output, true, &DryRunLedger::default());
        assert_eq!(
            output["__dry_run__"],
            json!({ "stubbed_calls": 0, "by_surface": {} })
        );
    }

    #[test]
    fn a_module_cannot_author_the_report_either_way() {
        // On a dry run its own value is replaced, including the stub
        // response's `true` passed straight through.
        let ledger = DryRunLedger::default();
        ledger.record(StubbedSurface::Messaging);
        for forged in [json!(true), json!({ "stubbed_calls": 99 })] {
            let mut output = json!({ "__dry_run__": forged });
            stamp_output(&mut output, true, &ledger);
            assert_eq!(output["__dry_run__"]["stubbed_calls"], 1);
        }
        // On a real run the key is removed: a real send cannot be made to
        // read as a rehearsal.
        let mut output = json!({ "sent": true, "__dry_run__": { "stubbed_calls": 1 } });
        stamp_output(&mut output, false, &ledger);
        assert_eq!(output, json!({ "sent": true }));
    }

    #[test]
    fn an_ordinary_runs_output_is_untouched_and_a_non_object_is_left_alone() {
        let mut output = json!({ "sent": true, "message_id": "m1" });
        stamp_output(&mut output, false, &DryRunLedger::default());
        assert_eq!(output, json!({ "sent": true, "message_id": "m1" }));

        for mut not_an_object in [json!("text"), json!([1, 2]), json!(null)] {
            let before = not_an_object.clone();
            stamp_output(&mut not_an_object, true, &DryRunLedger::default());
            assert_eq!(not_an_object, before);
        }
    }

    #[test]
    fn clones_share_one_count() {
        let ledger = DryRunLedger::default();
        let for_an_entry_future = ledger.clone();
        for_an_entry_future.record(StubbedSurface::Http);
        assert_eq!(ledger.snapshot().get(&StubbedSurface::Http), Some(&1));
    }
}

/// Whether a GraphQL document may carry a mutation (or subscription), so a
/// dry run must not send it: the word `mutation` or `subscription` anywhere in
/// it. Errs toward stubbing — a query that merely names a field `mutation…` is
/// stubbed too, which costs a rehearsal an answer, never a side effect.
#[must_use]
pub fn graphql_may_mutate(document: &str) -> bool {
    document.contains("mutation") || document.contains("subscription")
}

#[cfg(test)]
mod graphql_dry_run_tests {
    use super::graphql_may_mutate;

    #[test]
    fn a_mutation_is_stubbed_and_a_plain_query_is_not() {
        assert!(graphql_may_mutate(
            "mutation { createIssue(input: {}) { id } }"
        ));
        assert!(graphql_may_mutate("  mutation Named($x: ID!) { a(x: $x) }"));
        assert!(!graphql_may_mutate("query { viewer { login } }"));
        assert!(!graphql_may_mutate("{ viewer { login } }"));
    }
}
