//! Drives the RENDERED worker permission config on a LIVE nats-server and
//! checks that the broker's answer on every subject matches the Rust model
//! in `talos_workflow_job_protocol::nats_permissions`.
//!
//! The unit tests in that module prove the sets are internally consistent and
//! that the two checked-in `.conf` fragments equal the render; nothing there
//! proves nats-server READS the fragment the way the model predicts. This
//! binary does: `scripts/test-integration.sh` starts
//! `nats:2.10-alpine -c deploy/nats/nats.conf` (the compose config, worker
//! fragment included) with two credentials and exports the five
//! `TALOS_TEST_NATS_PERM_*` variables below. Without them every test here
//! returns early and says so — the harness is what makes it real coverage
//! rather than a green skip (check 64).
//!
//! How a refusal is observed: a permission violation is an ASYNC `-ERR` on the
//! offending connection — `publish()` still returns `Ok`, `subscribe()` still
//! returns a `Subscriber` that never delivers. So each probe has a CONTROL: the
//! same subject exercised by the unrestricted controller credential, which must
//! deliver, proving the wire carried the message the worker did not get (or
//! did not send). The `-ERR` text itself is captured through the worker
//! connection's event callback and checked to name the refused subject.

use futures::StreamExt;
use std::time::Duration;
use talos_workflow_job_protocol::nats_permissions::{
    worker_may_publish, worker_may_subscribe, CONTROLLER_INBOX_PREFIX, WORKER_INBOX_PREFIX,
};
use talos_workflow_job_protocol::subjects;

struct PermEnv {
    url: String,
    ctl_user: String,
    ctl_pass: String,
    wrk_user: String,
    wrk_pass: String,
}

fn perm_env() -> Option<PermEnv> {
    let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    Some(PermEnv {
        url: get("TALOS_TEST_NATS_PERM_URL")?,
        ctl_user: get("TALOS_TEST_NATS_PERM_CONTROLLER_USER")?,
        ctl_pass: get("TALOS_TEST_NATS_PERM_CONTROLLER_PASSWORD")?,
        wrk_user: get("TALOS_TEST_NATS_PERM_WORKER_USER")?,
        wrk_pass: get("TALOS_TEST_NATS_PERM_WORKER_PASSWORD")?,
    })
}

/// Long enough for a same-host broker round trip many times over; short
/// enough that the ~30 negative probes below finish in seconds.
const DELIVERY_WAIT: Duration = Duration::from_millis(500);

/// The three tests share ONE broker and, by construction, the SAME subjects
/// (`talos.jobs` is `talos.jobs`), so run concurrently they consume each
/// other's messages — the first run of this binary failed exactly that way:
/// the job-request test's queue subscriber swallowed the probe test's control
/// publish on `talos.jobs` and the probe test read the request as a
/// non-delivery. An async mutex serializes them across await points
/// (`--test-threads=1` would too, but the lock survives a runner that forgets).
static BROKER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn connect_controller(env: &PermEnv) -> async_nats::Client {
    async_nats::ConnectOptions::with_user_and_password(env.ctl_user.clone(), env.ctl_pass.clone())
        .connect(&env.url)
        .await
        .expect("controller credential connects")
}

/// The worker connection, built the way `worker/src/main.rs` builds it: the
/// worker inbox prefix, and an event callback that captures every server
/// `-ERR` so a refusal is observable.
async fn connect_worker(
    env: &PermEnv,
) -> (
    async_nats::Client,
    tokio::sync::mpsc::UnboundedReceiver<String>,
) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let client = async_nats::ConnectOptions::with_user_and_password(
        env.wrk_user.clone(),
        env.wrk_pass.clone(),
    )
    .custom_inbox_prefix(WORKER_INBOX_PREFIX)
    .event_callback(move |event| {
        let tx = tx.clone();
        async move {
            if let async_nats::Event::ServerError(err) = event {
                let _ = tx.send(err.to_string());
            }
        }
    })
    .connect(&env.url)
    .await
    .expect("worker credential connects");
    (client, rx)
}

async fn next_within(sub: &mut async_nats::Subscriber, d: Duration) -> Option<async_nats::Message> {
    tokio::time::timeout(d, sub.next()).await.ok().flatten()
}

/// Subject the controller echoes on, so any connection can prove the server
/// has PROCESSED everything it sent before. `Client::flush()` is not that: it
/// drains the client's write buffer and returns, without a server round trip,
/// so "subscribe, flush, have the OTHER connection publish" raced on the first
/// runs of this binary (the server trace showed the worker's `SUB` arriving
/// before the controller's `PUB` and the fan-out still missing it). NATS
/// processes one connection's commands in order, so a request/reply on the
/// subscribing connection AFTER its `SUB` is a real barrier.
const BARRIER_SUBJECT: &str = "sync.barrier";

/// The responder's `SUB` is issued HERE, on the caller's task, before the
/// handle is returned: a subscribe inside the spawned task raced the first
/// `barrier(&ctl)` (same connection, but the request was sent first) and the
/// server answered it with "no responders". Same connection, `SUB` first, is
/// exactly the ordering the barrier relies on.
async fn spawn_barrier_responder(ctl: &async_nats::Client) -> tokio::task::JoinHandle<()> {
    let mut sub = ctl
        .subscribe(BARRIER_SUBJECT.to_string())
        .await
        .expect("barrier responder subscribes");
    let ctl_task = ctl.clone();
    let handle = tokio::spawn(async move {
        while let Some(msg) = sub.next().await {
            if let Some(reply) = msg.reply {
                let _ = ctl_task.publish(reply, "ok".into()).await;
            }
        }
    });
    // Prove the responder's SUB is installed before ANY other connection may
    // rely on it: this request is on the SAME connection as the SUB, so the
    // server processed the SUB first. Without it, a worker-side barrier
    // issued straight after this call raced the SUB and got "no responders"
    // (1 in 8 runs).
    barrier(ctl).await;
    handle
}

async fn barrier(client: &async_nats::Client) {
    tokio::time::timeout(
        Duration::from_secs(5),
        client.request(BARRIER_SUBJECT.to_string(), "".into()),
    )
    .await
    .expect("barrier round trip within 5 s")
    .expect("barrier reply");
}

/// One row of the probe table: a CONCRETE subject and the model's verdicts.
struct Probe {
    subject: String,
    publish: bool,
    subscribe: bool,
}

fn probe(subject: impl Into<String>) -> Probe {
    let subject = subject.into();
    Probe {
        publish: worker_may_publish(&subject),
        subscribe: worker_may_subscribe(&subject),
        subject,
    }
}

/// Every subject family the worker or the controller touches, as concrete
/// subjects, PLUS the verdict the Rust model gives for each. The live probes
/// below assert the broker agrees with every verdict. The expected verdicts are
/// ALSO asserted literally for the load-bearing rows, so a model change that
/// flipped one of them cannot pass by agreeing with itself.
fn probe_table() -> Vec<Probe> {
    let rows = vec![
        // worker subscribes / controller publishes
        probe(subjects::JOBS),
        probe(subjects::jobs_for("user-1")),
        probe(subjects::PIPELINE_JOBS),
        probe(format!("{}.user-1", subjects::PIPELINE_JOBS)),
        probe(subjects::WORKERS_CMD_CANCEL),
        probe(subjects::approvals_wait_for("exec-1")),
        probe(format!("{WORKER_INBOX_PREFIX}.probe.1")),
        // worker publishes / controller subscribes
        probe(subjects::results_for("job-1")),
        probe(subjects::pipeline_results_for("job-1")),
        probe(subjects::AUDIT_LEDGER),
        probe(subjects::APPROVALS_PENDING),
        probe(subjects::worker_heartbeat_for("w-1")),
        probe("wasm.log.exec-1"),
        probe("talos.memory.op"),
        probe("talos.graph.search"),
        probe("talos.database.query"),
        probe("talos.state.write"),
        probe("talos.integration_state.op"),
        probe("talos.ml.predict"),
        probe("talos.ml.fewshot"),
        probe(subjects::agent_invoke_for("target")),
        probe(subjects::workflow_event_for("exec-1", "node_done")),
        probe("orders.created"), // a guest `messaging::publish` topic
        probe(format!("{CONTROLLER_INBOX_PREFIX}.probe.1")),
        // neither direction is legitimate from the worker
        probe(subjects::ALERTS_EXECUTION_FAILED),
        probe(subjects::llm_stream_for("exec-1")),
        probe(subjects::WORKERS_CMD_SHUTDOWN),
        probe("$SYS.talos.probe"),
        probe("$JS.talos.probe"),
    ];
    let find = |s: &str| rows.iter().find(|p| p.subject == s).expect("row present");
    // Literal pins on the rows whose direction is the whole point.
    assert!(find(subjects::JOBS).subscribe && !find(subjects::JOBS).publish);
    assert!(
        find(subjects::WORKERS_CMD_CANCEL).subscribe && !find(subjects::WORKERS_CMD_CANCEL).publish
    );
    let winbox = format!("{WORKER_INBOX_PREFIX}.probe.1");
    assert!(find(&winbox).subscribe && !find(&winbox).publish);
    let inbox = format!("{CONTROLLER_INBOX_PREFIX}.probe.1");
    assert!(!find(&inbox).subscribe && find(&inbox).publish);
    let results = subjects::results_for("job-1");
    assert!(!find(&results).subscribe && find(&results).publish);
    assert!(!find("talos.memory.op").subscribe && find("talos.memory.op").publish);
    assert!(!find("wasm.log.exec-1").subscribe && find("wasm.log.exec-1").publish);
    assert!(find("orders.created").publish && !find("orders.created").subscribe);
    assert!(!find(subjects::ALERTS_EXECUTION_FAILED).publish);
    assert!(!find(subjects::ALERTS_EXECUTION_FAILED).subscribe);
    rows
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broker_agrees_with_the_rust_model_on_every_subject() {
    let Some(env) = perm_env() else {
        eprintln!("skipping: set TALOS_TEST_NATS_PERM_* to run (scripts/test-integration.sh does)");
        return;
    };
    let _serial = BROKER_LOCK.lock().await;
    let ctl = connect_controller(&env).await;
    let (wrk, mut wrk_errors) = connect_worker(&env).await;
    let responder = spawn_barrier_responder(&ctl).await;
    assert!(worker_may_publish(BARRIER_SUBJECT) && !worker_may_subscribe(BARRIER_SUBJECT));

    let mut disagreements = Vec::new();
    let mut refused_subjects: Vec<(String, &'static str)> = Vec::new();

    for p in probe_table() {
        // ---- PUBLISH probe: worker publishes, controller listens. -------------
        // Control: the controller's own publish on the same subject must land,
        // so a missing worker message is a refusal and not a broken wire.
        {
            let mut ctl_sub = ctl
                .subscribe(p.subject.clone())
                .await
                .expect("ctl subscribe");
            ctl.flush().await.expect("ctl flush");
            ctl.publish(p.subject.clone(), "control".into())
                .await
                .expect("ctl publish");
            ctl.flush().await.expect("ctl flush");
            let control = next_within(&mut ctl_sub, DELIVERY_WAIT).await;
            assert!(
                control.is_some_and(|m| m.payload.as_ref() == b"control"),
                "{}: the CONTROL publish did not arrive — the wire itself is broken",
                p.subject
            );
            wrk.publish(p.subject.clone(), "from-worker".into())
                .await
                .expect("wrk publish enqueues");
            wrk.flush().await.expect("wrk flush");
            let got = next_within(&mut ctl_sub, DELIVERY_WAIT)
                .await
                .is_some_and(|m| m.payload.as_ref() == b"from-worker");
            if got != p.publish {
                disagreements.push(format!(
                    "PUBLISH {}: model says {}, broker delivered={got}",
                    p.subject,
                    if p.publish { "allowed" } else { "denied" }
                ));
            }
            if !p.publish {
                refused_subjects.push((p.subject.clone(), "Publish"));
            }
        }

        // ---- SUBSCRIBE probe: worker listens, controller publishes. -----------
        // Control: a controller subscription on the same subject receives.
        {
            let mut wrk_sub = wrk
                .subscribe(p.subject.clone())
                .await
                .expect("wrk subscribe returns");
            let mut ctl_sub = ctl
                .subscribe(p.subject.clone())
                .await
                .expect("ctl subscribe");
            // Both SUBs must be INSTALLED server-side before the publish: the
            // controller's is ordered with its own PUB by the connection; the
            // worker's needs the round trip.
            barrier(&wrk).await;
            ctl.publish(p.subject.clone(), "to-worker".into())
                .await
                .expect("ctl publish");
            ctl.flush().await.expect("ctl flush");
            let control = next_within(&mut ctl_sub, DELIVERY_WAIT).await;
            assert!(
                control.is_some_and(|m| m.payload.as_ref() == b"to-worker"),
                "{}: the CONTROL subscription did not receive — the wire itself is broken",
                p.subject
            );
            let got = next_within(&mut wrk_sub, DELIVERY_WAIT)
                .await
                .is_some_and(|m| m.payload.as_ref() == b"to-worker");
            if got != p.subscribe {
                disagreements.push(format!(
                    "SUBSCRIBE {}: model says {}, broker delivered={got}",
                    p.subject,
                    if p.subscribe { "allowed" } else { "denied" }
                ));
            }
            if !p.subscribe {
                refused_subjects.push((p.subject.clone(), "Subscription"));
            }
        }
    }

    assert!(
        disagreements.is_empty(),
        "the broker disagrees with nats_permissions on {} subject(s):\n  {}",
        disagreements.len(),
        disagreements.join("\n  ")
    );

    // Every refusal must have been REPORTED on the worker connection as a
    // `-ERR Permissions Violation …` naming the subject and the operation —
    // that async line is the only signal the worker's event callback can
    // turn into a WARN, so its shape is part of the contract.
    wrk.flush().await.expect("wrk flush");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut errors = Vec::new();
    while let Ok(e) = wrk_errors.try_recv() {
        errors.push(e);
    }
    assert!(
        !refused_subjects.is_empty(),
        "the probe table has no refused row — the model has stopped refusing anything"
    );
    for (subject, op) in &refused_subjects {
        let needle_op = format!("Permissions Violation for {op}");
        assert!(
            errors
                .iter()
                .any(|e| e.contains(&needle_op) && e.contains(subject.as_str())),
            "no `{needle_op} … {subject}` was reported on the worker connection; got {} error line(s):\n  {}",
            errors.len(),
            errors.join("\n  ")
        );
    }
    responder.abort();
}

/// The dispatch shape end to end: the controller REQUESTS on `talos.jobs` with
/// its default `_INBOX` reply subject, the worker answers by publishing to
/// that reply subject (a `_INBOX.>` publish the deny-list must leave alone).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_replies_to_a_controller_job_request() {
    let Some(env) = perm_env() else {
        eprintln!("skipping: set TALOS_TEST_NATS_PERM_* to run (scripts/test-integration.sh does)");
        return;
    };
    let _serial = BROKER_LOCK.lock().await;
    let ctl = connect_controller(&env).await;
    let (wrk, _errs) = connect_worker(&env).await;

    let barrier_responder = spawn_barrier_responder(&ctl).await;
    let mut jobs = wrk
        .queue_subscribe(subjects::JOBS.to_string(), subjects::JOBS.to_string())
        .await
        .expect("worker queue_subscribe");
    // The worker's SUB must be installed before the controller's request, or
    // the server answers the request with "no responders" (seen once in six
    // runs with only a `flush()` here).
    barrier(&wrk).await;
    let responder = {
        let wrk = wrk.clone();
        tokio::spawn(async move {
            let msg = jobs.next().await.expect("a job arrives");
            let reply = msg.reply.clone().expect("request carries a reply subject");
            assert!(
                reply.starts_with(&format!("{CONTROLLER_INBOX_PREFIX}.")),
                "controller reply inbox should use the default prefix, got {reply}"
            );
            wrk.publish(reply, "job-result".into())
                .await
                .expect("worker publishes the result");
            wrk.flush().await.expect("flush");
        })
    };
    let reply = tokio::time::timeout(
        Duration::from_secs(5),
        ctl.request(subjects::JOBS.to_string(), "job-request".into()),
    )
    .await
    .expect("request completes within 5 s")
    .expect("request succeeds");
    assert_eq!(reply.payload.as_ref(), b"job-result");
    responder.await.expect("responder task");
    barrier_responder.abort();
}

/// The RPC shape end to end: the worker REQUESTS on `talos.memory.op` — its
/// reply inbox must be under `_WINBOX.` (the only inbox prefix the worker can
/// subscribe to) and the controller's reply into it must arrive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_answers_a_worker_rpc_on_the_worker_inbox() {
    let Some(env) = perm_env() else {
        eprintln!("skipping: set TALOS_TEST_NATS_PERM_* to run (scripts/test-integration.sh does)");
        return;
    };
    let _serial = BROKER_LOCK.lock().await;
    let ctl = connect_controller(&env).await;
    let (wrk, _errs) = connect_worker(&env).await;

    let barrier_responder = spawn_barrier_responder(&ctl).await;
    let mut rpc = ctl
        .subscribe("talos.memory.op".to_string())
        .await
        .expect("ctl subscribe");
    barrier(&ctl).await; // controller's SUB installed before the worker's request
    let responder = {
        let ctl = ctl.clone();
        tokio::spawn(async move {
            let msg = rpc.next().await.expect("an rpc arrives");
            let reply = msg.reply.clone().expect("request carries a reply subject");
            assert!(
                reply.starts_with(&format!("{WORKER_INBOX_PREFIX}.")),
                "worker reply inbox must use the worker prefix, got {reply}"
            );
            assert!(
                worker_may_subscribe(&reply),
                "the model must admit the worker's own inbox {reply}"
            );
            ctl.publish(reply, "rpc-reply".into())
                .await
                .expect("controller replies");
            ctl.flush().await.expect("flush");
        })
    };
    let reply = tokio::time::timeout(
        Duration::from_secs(5),
        wrk.request("talos.memory.op".to_string(), "rpc-request".into()),
    )
    .await
    .expect("request completes within 5 s")
    .expect("request succeeds");
    assert_eq!(reply.payload.as_ref(), b"rpc-reply");
    responder.await.expect("responder task");
    barrier_responder.abort();
}
