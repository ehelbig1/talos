//! Call-site pin: the worker's NATS job path excludes local-inference queueing
//! from the job's deadlines and tells the dispatcher (RFC 0014 P2).
//!
//! The mechanism is tested where it lives — the ledger and the pausable
//! deadline in `talos-worker-runtime`, the gate's reporting on its own
//! semaphore and through both LLM call sites, the dispatcher's pause in
//! `talos-workflow-engine-nats`. What none of those can see is whether
//! `execute_job` WIRES it: a ledger built and never passed, an outer deadline
//! left as a plain `tokio::time::timeout`, or a notifier aimed at the unsigned
//! wire reply header would each compile and pass every other test. So this
//! reads `main.rs` itself, from its own file for the reason
//! `retry_policy_pin.rs` gives.

fn production_source() -> String {
    let src = include_str!("main.rs");
    let mut out = String::new();
    let mut lines = src.lines().peekable();
    while let Some(line) = lines.next() {
        if line == "#[cfg(test)]"
            && lines
                .peek()
                .is_some_and(|next| next.starts_with("mod ") && next.ends_with('{'))
        {
            for inner in lines.by_ref() {
                if inner == "}" {
                    break;
                }
            }
            continue;
        }
        if line.trim_start().starts_with("//") {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// The body of `async fn execute_job(` up to the next top-level `fn`.
fn execute_job_body(prod: &str) -> &str {
    let start = prod
        .find("async fn execute_job(")
        .expect("vacuity guard: execute_job not found in main.rs");
    let rest = &prod[start..];
    let end = rest[1..]
        .find("\nasync fn ")
        .or_else(|| rest[1..].find("\nfn "))
        .map_or(rest.len(), |i| i + 1);
    &rest[..end]
}

#[test]
fn the_nats_job_path_pauses_its_deadlines_for_local_inference_queueing() {
    let prod = production_source();
    let body = execute_job_body(&prod);
    assert!(
        body.contains("worker::inference_wait::with_pausable_deadline("),
        "the outer job deadline must be the pausable one"
    );
    assert!(
        !body.contains("tokio::time::timeout(\n        job_timeout"),
        "the outer job deadline reverted to a plain tokio::time::timeout"
    );
    assert!(
        body.contains("Some(inference_wait.clone()),"),
        "execute_job must hand the job's ledger to the runtime (the inner timeout, \
         the epoch bound and the LLM gate all read it from there)"
    );
    assert!(
        body.contains("req.reply_topic.as_deref().map(|inbox|")
            && body.contains("subjects::job_progress_for(inbox)"),
        "the progress notifier must be aimed at the job's SIGNED reply inbox"
    );
    assert!(
        !body.contains("msg.reply"),
        "execute_job must not read the unsigned wire reply header"
    );
}
