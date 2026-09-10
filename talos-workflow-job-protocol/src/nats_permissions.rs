//! Broker-level permission sets for the WORKER's NATS user.
//!
//! Until 2026-09-10 every process on the bus authenticated as ONE NATS user
//! with no `permissions` block, so a worker was indistinguishable from the
//! controller at the broker: it could subscribe to `_INBOX.>` (every reply
//! the controller ever awaits — job results, sealed-secret claim responses,
//! webhook replies), to `talos.results.*` (every other worker's module
//! output), to `wasm.log.*`, to the heartbeat stream, and it could publish
//! forged jobs on `talos.jobs`, forged cancels on `talos.workers.cmd.cancel`
//! and forged approvals on `talos.approvals.wait.<exec>`. Signing stops the
//! forgeries from being ACTED on; nothing stopped the eavesdropping, and a
//! dropped forgery still costs the controller a verify.
//!
//! This module is the ONE home for the sets a worker credential is granted.
//! Two rendered copies exist because Helm's `.Files.Get` cannot read outside
//! the chart and compose cannot read inside it —
//! `deploy/nats/worker-permissions.conf` (compose) and
//! `deploy/helm/talos/files/nats-worker-permissions.conf` (chart) — and
//! [`render_worker_permissions_conf`] is what both must be byte-equal to,
//! pinned by `rendered_conf_files_match_the_code`. Edit the arrays here, run
//! that test, copy its output; never edit the `.conf` files by hand.
//!
//! # Shape of the sets, and why they differ
//!
//! * **Subscribe is an ALLOW-list.** The worker's subscribe footprint is a
//!   closed set the code enumerates: the two job queues (and their per-user
//!   edge-routing children), the fleet-wide cancel command, the per-execution
//!   approval-wait reply subject, and its own request inboxes. Everything
//!   else the broker carries — controller inboxes, other workers' results,
//!   logs, heartbeats, token streams, the audit ledger — is refused at the
//!   broker, which is the property signing cannot give.
//! * **Publish is a DENY-list.** The worker's publish footprint is NOT closed:
//!   the `messaging` WIT lets guest modules publish to any subject outside the
//!   runtime's reserved prefixes (`RESERVED_PUBLISH_PREFIXES`), and the
//!   catalog's `message-publisher` template takes its topic from module
//!   config. A publish permission violation is an ASYNCHRONOUS `-ERR` on the
//!   connection, not an error returned to the publisher, so an allow-list
//!   would have made every guest publish to an unlisted subject a silent drop
//!   that `messaging::publish` reported as success. What IS closed is the set
//!   of subjects the worker must never author — the controller-consumed ones
//!   it does not legitimately publish — and those are denied.
//!
//! # The inbox prefix
//!
//! async-nats derives every request inbox from one connection-level prefix
//! (`_INBOX` by default). Giving the worker its own, [`WORKER_INBOX_PREFIX`],
//! is what lets the subscribe allow-list admit the worker's own replies
//! without admitting the controller's: `_WINBOX.>` is allowed, `_INBOX.>` is
//! not. The controller replies to a worker RPC by publishing to the request's
//! reply subject, so a controller credential that is ever given a permissions
//! block MUST allow publish on `_WINBOX.>`.
//!
//! # Stated limits
//!
//! * The prefix is per PROCESS KIND, not per worker: every worker shares
//!   `_WINBOX.>`, so a compromised worker can still read a SIBLING worker's
//!   RPC replies (decrypted memory values in flight). Per-worker isolation
//!   needs per-worker credentials (NATS accounts / auth callout), which a
//!   static config cannot mint. Recorded, not fixed.
//! * `talos.jobs` itself is visible to every worker BY DESIGN (it is the
//!   queue), so a worker can read every `JobRequest`, including the
//!   `encrypted_secrets` envelope, which is sealed under the fleet-shared
//!   `WORKER_SHARED_KEY`. Permissions cannot change that; per-execution
//!   envelope sealing (`TALOS_ENVELOPE_SEALING=required`) is the control.
//! * The sets are enforced by the BROKER's configuration, not by this crate.
//!   This module makes the sets sayable and pins the rendered files to them;
//!   `talos-workflow-engine-nats/tests/nats_worker_permissions.rs` drives the
//!   rendered config on a live `nats-server` and checks that the broker's
//!   answer matches [`worker_may_publish`] / [`worker_may_subscribe`] on
//!   every subject in the table.

/// Inbox prefix for the WORKER's NATS connection (`ConnectOptions::
/// custom_inbox_prefix`). Distinct from async-nats' default `_INBOX`, which the
/// controller keeps, so the worker's subscribe permission can admit its own
/// request/reply traffic and nothing else's.
pub const WORKER_INBOX_PREFIX: &str = "_WINBOX";

/// The controller's inbox prefix — async-nats' default. Named here so the
/// deny-list and the tests spell it once.
pub const CONTROLLER_INBOX_PREFIX: &str = "_INBOX";

/// Subjects the worker credential may SUBSCRIBE to. Closed set; every entry
/// maps to a `subscribe`/`queue_subscribe` call in `worker/` or
/// `talos-worker-runtime/`, listed in the order the worker takes them at boot.
pub const WORKER_SUBSCRIBE_ALLOW: &[&str] = &[
    // worker/src/main.rs — the single-job queue (`NATS_JOB_TOPIC` default) and
    // its per-user edge-routing children `talos.jobs.<user_id>`. An operator
    // who overrides `NATS_JOB_TOPIC` outside this prefix must widen the set.
    "talos.jobs",
    "talos.jobs.>",
    // worker/src/main.rs — the pipeline (chain) queue and its children.
    "talos.pipeline.jobs",
    "talos.pipeline.jobs.>",
    // worker/src/main.rs `run_cancel_listener` — plain (non-queue) subscribe,
    // fleet-wide, signed body. `talos.workers.cmd.shutdown` is deliberately
    // NOT here: it has zero publishers and zero subscribers
    // (`docs/inert-mechanisms.md`), and an inert subject earns no permission.
    "talos.workers.cmd.cancel",
    // talos-worker-runtime/src/host/governance.rs — the approve/reject reply
    // for a suspended governance node, keyed on the node's exec id.
    "talos.approvals.wait.>",
    // Every `Client::request` the worker issues (the seven signed RPCs, the
    // secret claim, agent orchestration, guest `messaging::request`).
    "_WINBOX.>",
];

/// Subjects the worker credential may NOT PUBLISH to. Everything not listed
/// is permitted (see the module docs for why this is a deny-list). Every
/// entry is a subject the controller authors or the broker owns, and that no
/// line in `worker/` or `talos-worker-runtime/` publishes to.
pub const WORKER_PUBLISH_DENY: &[&str] = &[
    // Job dispatch is the controller's alone. A forged JobRequest fails its
    // signature check on the receiving worker, but the broker refusing it is
    // cheaper than every worker verifying it.
    "talos.jobs",
    "talos.jobs.>",
    "talos.pipeline.jobs",
    "talos.pipeline.jobs.>",
    // Fleet commands (cancel today; shutdown is inert) are controller → worker.
    "talos.workers.cmd.>",
    // Execution-failure alerts are authored by the controller's result
    // collector and carry NO signature — the one consumer-trusted subject a
    // worker could have written into.
    "talos.alerts.>",
    // The approve/reject reply is published by the controller's webhook
    // handler from a Redis-routed reply subject; a worker publishing here
    // could approve a SIBLING worker's suspended node.
    "talos.approvals.wait.>",
    // Token stream relayed to GraphQL subscribers. No worker publisher exists
    // today (measured 2026-09-10: zero `llm_stream_for` call sites outside the
    // registry and the GraphQL relay); a future worker producer must remove
    // this entry, and `worker_publish_set_is_pinned` will say so.
    "talos.llm.stream.>",
    // Other workers' request inboxes — the worker only ever RECEIVES here.
    "_WINBOX.>",
    // NATS system and JetStream API namespaces. The worker uses no JetStream
    // (zero `jetstream` references in `worker/` and `talos-worker-runtime/`).
    "$SYS.>",
    "$JS.>",
    "$KV.>",
    "$O.>",
];

/// NATS subject matching: tokens are `.`-separated; `*` matches exactly one
/// token, `>` matches one or more trailing tokens. Mirrors the server's own
/// rules so the tests here predict what the broker will do.
#[must_use]
pub fn subject_matches(pattern: &str, subject: &str) -> bool {
    let mut pat = pattern.split('.');
    let mut sub = subject.split('.').peekable();
    loop {
        match (pat.next(), sub.peek()) {
            // Both exhausted together, or `>` with at least one token left.
            (None, None) | (Some(">"), Some(_)) => return true,
            // One side ran out before the other (`>` needs ≥1 token).
            (None, Some(_)) | (Some(_), None) => return false,
            (Some("*"), Some(_)) => {
                sub.next();
            }
            (Some(p), Some(&s)) => {
                if p != s {
                    return false;
                }
                sub.next();
            }
        }
    }
}

/// Would the broker admit a worker SUBSCRIBE on `subject`?
#[must_use]
pub fn worker_may_subscribe(subject: &str) -> bool {
    WORKER_SUBSCRIBE_ALLOW
        .iter()
        .any(|p| subject_matches(p, subject))
}

/// Would the broker admit a worker PUBLISH to `subject`?
#[must_use]
pub fn worker_may_publish(subject: &str) -> bool {
    !WORKER_PUBLISH_DENY
        .iter()
        .any(|p| subject_matches(p, subject))
}

/// The nats-server configuration fragment defining `WORKER_PERMISSIONS`, for
/// `include` from a `nats.conf` whose `authorization { users = [...] }` binds
/// it to the worker credential. Both checked-in copies must equal this
/// byte-for-byte (`rendered_conf_files_match_the_code`).
#[must_use]
pub fn render_worker_permissions_conf() -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    out.push_str(
        "# GENERATED — do not edit. Source: talos-workflow-job-protocol/src/nats_permissions.rs\n\
         # (`render_worker_permissions_conf`). `cargo test -p talos-workflow-job-protocol \\\n\
         #   nats_permissions` fails when this file and the Rust sets disagree; regenerate with\n\
         # `TALOS_NATS_PERMISSIONS_WRITE=1` set on that same test run.\n\
         #\n\
         # Permission set for the WORKER's NATS user. Subscribe is an allow-list (the\n\
         # worker's subscribe footprint is closed); publish is a deny-list (guest modules\n\
         # may publish to any non-reserved subject, and a publish permission violation is\n\
         # an async -ERR the publisher never sees, so an allow-list would silently drop\n\
         # guest messages). The controller's credential carries no permissions block; if\n\
         # it ever does, it must allow publish on `_WINBOX.>` — that is where it replies\n\
         # to worker RPCs.\n\
         WORKER_PERMISSIONS = {\n  subscribe: {\n    allow: [\n",
    );
    for s in WORKER_SUBSCRIBE_ALLOW {
        let _ = writeln!(out, "      \"{s}\",");
    }
    out.push_str("    ]\n  }\n  publish: {\n    deny: [\n");
    for s in WORKER_PUBLISH_DENY {
        let _ = writeln!(out, "      \"{s}\",");
    }
    out.push_str("    ]\n  }\n}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subjects;

    /// The seven signed data-RPC subjects. Their canonical consts live in
    /// `talos-memory` (`SUBJECT_*`), a crate ABOVE this one, so they are
    /// spelled here as literals and cross-pinned from that crate's own tests
    /// (`talos_memory::rpc_auth::nats_permission_pins`).
    const RPC_SUBJECTS: &[&str] = &[
        "talos.memory.op",
        "talos.graph.search",
        "talos.database.query",
        "talos.state.write",
        "talos.integration_state.op",
        "talos.ml.predict",
        "talos.ml.fewshot",
    ];

    #[test]
    fn matcher_follows_nats_token_rules() {
        assert!(subject_matches("talos.jobs", "talos.jobs"));
        assert!(!subject_matches("talos.jobs", "talos.jobs.u1"));
        assert!(subject_matches("talos.jobs.>", "talos.jobs.u1"));
        assert!(subject_matches("talos.jobs.>", "talos.jobs.u1.priority"));
        assert!(!subject_matches("talos.jobs.>", "talos.jobs"));
        assert!(subject_matches("talos.results.*", "talos.results.j1"));
        assert!(!subject_matches("talos.results.*", "talos.results.j1.x"));
        assert!(!subject_matches("talos.results.*", "talos.results"));
        assert!(subject_matches("$JS.>", "$JS.API.INFO"));
        assert!(!subject_matches("$JS.>", "$JSX.API"));
        assert!(!subject_matches("_INBOX.>", "_WINBOX.a.1"));
    }

    #[test]
    fn inbox_prefixes_are_distinct_single_tokens() {
        assert_ne!(WORKER_INBOX_PREFIX, CONTROLLER_INBOX_PREFIX);
        for p in [WORKER_INBOX_PREFIX, CONTROLLER_INBOX_PREFIX] {
            assert!(p.starts_with('_'), "{p} should be underscore-prefixed");
            assert!(!p.contains('.'), "{p} must be a single token");
            assert!(!p.contains('*') && !p.contains('>'));
        }
        assert!(WORKER_SUBSCRIBE_ALLOW.contains(&"_WINBOX.>"));
        assert_eq!(format!("{WORKER_INBOX_PREFIX}.>"), "_WINBOX.>");
    }

    /// Every subject the worker SUBSCRIBES to (one entry per call site).
    #[test]
    fn every_worker_subscribe_site_is_allowed() {
        let sites = [
            subjects::JOBS.to_string(),
            subjects::jobs_for("user-1"),
            subjects::PIPELINE_JOBS.to_string(),
            format!("{}.user-1", subjects::PIPELINE_JOBS),
            subjects::WORKERS_CMD_CANCEL.to_string(),
            subjects::approvals_wait_for("exec-1"),
            format!("{WORKER_INBOX_PREFIX}.abcdef.1"),
        ];
        for s in sites {
            assert!(
                worker_may_subscribe(&s),
                "worker must be able to subscribe to {s}"
            );
        }
    }

    /// Subjects the worker has NO business reading. The allow-list is what
    /// makes these refusals; this test is the record of what it refuses.
    #[test]
    fn eavesdropping_subjects_are_refused_on_subscribe() {
        let refused = [
            format!("{CONTROLLER_INBOX_PREFIX}.abcdef.1"),
            subjects::results_for("job-1"),
            subjects::pipeline_results_for("job-1"),
            "wasm.log.exec-1".to_string(),
            subjects::worker_heartbeat_for("w-1"),
            subjects::AUDIT_LEDGER.to_string(),
            subjects::APPROVALS_PENDING.to_string(),
            subjects::llm_stream_for("exec-1"),
            subjects::agent_invoke_for("t"),
            subjects::workflow_event_for("e", "done"),
            subjects::ALERTS_EXECUTION_FAILED.to_string(),
            subjects::WORKERS_CMD_SHUTDOWN.to_string(),
            "$SYS.REQ.SERVER.PING".to_string(),
            "$JS.API.INFO".to_string(),
        ];
        for s in refused.iter().chain(
            RPC_SUBJECTS
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .iter(),
        ) {
            assert!(
                !worker_may_subscribe(s),
                "worker must NOT be able to subscribe to {s}"
            );
        }
    }

    /// Every subject the worker PUBLISHES to (one entry per call site), plus
    /// two guest-shaped topics the `messaging` host would forward.
    #[test]
    fn every_worker_publish_site_is_permitted() {
        let mut sites = vec![
            subjects::results_for("job-1"),
            subjects::pipeline_results_for("job-1"),
            format!("{CONTROLLER_INBOX_PREFIX}.abcdef.1"), // reply_topic + claim_inbox
            subjects::AUDIT_LEDGER.to_string(),
            subjects::APPROVALS_PENDING.to_string(),
            subjects::worker_heartbeat_for("w-1"),
            "wasm.log.exec-1".to_string(),
            subjects::agent_invoke_for("target"),
            subjects::agent_message_for("target"),
            subjects::workflow_event_for("exec-1", "node_done"),
            "orders.created".to_string(),
            "acme.team.notifications".to_string(),
        ];
        sites.extend(RPC_SUBJECTS.iter().map(|s| s.to_string()));
        for s in sites {
            assert!(
                worker_may_publish(&s),
                "worker must be able to publish to {s}"
            );
        }
    }

    /// Controller-authored and broker-owned subjects the worker must never
    /// write into. Adding a worker publisher for one of these means removing
    /// it from `WORKER_PUBLISH_DENY` here, in a reviewed commit.
    #[test]
    fn worker_publish_set_is_pinned() {
        let denied = [
            subjects::JOBS.to_string(),
            subjects::jobs_for("user-1"),
            format!("{}.priority", subjects::JOBS),
            subjects::PIPELINE_JOBS.to_string(),
            format!("{}.user-1", subjects::PIPELINE_JOBS),
            subjects::WORKERS_CMD_CANCEL.to_string(),
            subjects::WORKERS_CMD_SHUTDOWN.to_string(),
            subjects::ALERTS_EXECUTION_FAILED.to_string(),
            subjects::approvals_wait_for("exec-1"),
            subjects::llm_stream_for("exec-1"),
            format!("{WORKER_INBOX_PREFIX}.abcdef.1"),
            "$SYS.REQ.SERVER.PING".to_string(),
            "$JS.API.STREAM.INFO.x".to_string(),
            "$KV.bucket.key".to_string(),
            "$O.bucket.x".to_string(),
        ];
        for s in denied {
            assert!(
                !worker_may_publish(&s),
                "worker must NOT be able to publish to {s}"
            );
        }
    }

    /// The allow-list never admits a controller inbox and the deny-list never
    /// covers the worker's own — the two prefixes must not be confusable by a
    /// wildcard.
    #[test]
    fn inbox_isolation_is_asymmetric() {
        assert!(worker_may_subscribe("_WINBOX.x.1"));
        assert!(!worker_may_subscribe("_INBOX.x.1"));
        assert!(worker_may_publish("_INBOX.x.1"));
        assert!(!worker_may_publish("_WINBOX.x.1"));
    }

    #[test]
    fn no_pattern_is_malformed() {
        for p in WORKER_SUBSCRIBE_ALLOW
            .iter()
            .chain(WORKER_PUBLISH_DENY.iter())
        {
            assert!(!p.is_empty());
            assert!(!p.contains(' '), "{p} contains whitespace");
            assert!(
                !p.starts_with('.') && !p.ends_with('.'),
                "{p} has an empty token"
            );
            if let Some(i) = p.find('>') {
                assert_eq!(i, p.len() - 1, "{p}: `>` must be the last token");
            }
        }
    }

    /// The two checked-in fragments are DERIVED from this module. A drift
    /// fails here with the regenerated text, so the fix is copy-paste — or
    /// run once with `TALOS_NATS_PERMISSIONS_WRITE=1`, which rewrites both
    /// files from the render before asserting (the snapshot-update idiom).
    #[test]
    fn rendered_conf_files_match_the_code() {
        let rendered = render_worker_permissions_conf();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let write = std::env::var("TALOS_NATS_PERMISSIONS_WRITE")
            .ok()
            .filter(|v| !v.is_empty())
            .is_some();
        for rel in [
            "deploy/nats/worker-permissions.conf",
            "deploy/helm/talos/files/nats-worker-permissions.conf",
        ] {
            let path = root.join(rel);
            if write {
                std::fs::write(&path, &rendered).expect("write rendered fragment");
            }
            let on_disk = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!(
                    "{}: {e}\n--- expected content ---\n{rendered}",
                    path.display()
                )
            });
            assert!(
                on_disk == rendered,
                "{rel} is out of date. Replace its contents with:\n--- 8< ---\n{rendered}--- >8 ---"
            );
        }
    }

    #[test]
    fn rendered_conf_names_every_entry_once() {
        let rendered = render_worker_permissions_conf();
        for s in WORKER_SUBSCRIBE_ALLOW
            .iter()
            .chain(WORKER_PUBLISH_DENY.iter())
        {
            let needle = format!("\"{s}\"");
            let n = rendered.matches(&needle).count();
            // `talos.jobs` etc. appear in BOTH lists by design.
            assert!(n >= 1, "{s} missing from the rendered fragment");
        }
        assert!(rendered.contains("WORKER_PERMISSIONS = {"));
        assert!(rendered.contains("subscribe: {\n    allow: ["));
        assert!(rendered.contains("publish: {\n    deny: ["));
    }
}
