//! The signed-RPC data plane must be COUNTED, not only logged.
//!
//! # What this pins, and why a unit test could not
//!
//! `talos_rpc_subscribers::kernel::record_rpc_metric`'s NAME asserted a metric
//! and its body was two `tracing` calls. Measured live 2026-09-09:
//! `curl /metrics/prometheus | grep '^talos_rpc'` returned exactly six series,
//! all of them #760's `talos_rpc_write_ceiling_refusals_total`, all at 0 —
//! nothing counted a call, an outcome or a latency on any of the seven
//! subjects, while 1317 module executions in 24 h drove them. The SUCCESS arm
//! logged at `debug!`, which this deployment does not enable for the
//! `talos_rpc` target, so "how many memory RPCs did we serve, and how fast"
//! was unanswerable in every channel at once.
//!
//! Check 58's own stated limit is why the guard has to be here rather than in
//! `talos-metrics`: it proves an increment SITE EXISTS and says nothing about
//! whether anything reaches it. A test of `record_rpc_call_on` in isolation
//! would stay green with every call site deleted — the shape #783 closed for
//! three scheduler publish sites, and the shape the brief for this change
//! names explicitly.
//!
//! So this drives the PRODUCTION entry point: the real
//! `spawn_memory_rpc_subscriber`, over a real NATS connection, with real
//! signed `MemoryRpcRequest`s, against a real Postgres — and asserts on the
//! SERIES the controller would export, with a control pair that must NOT move
//! in the same run.
//!
//! # The `set_global` hazard, and how this binary avoids it
//!
//! `talos_metrics::set_global` is a process-wide `OnceLock`. CLAUDE.md records
//! the flake that follows when two tests in one binary each install their own
//! registry: whichever wins installs ITS collectors while the loser asserts
//! against an `Arc` no production site writes to. The fix recorded there is
//! ONE ACCESSOR, not one installer — [`installed_test_metrics`] below returns
//! the installed global and installs only if there is none.
//!
//! Runs in CI via `scripts/test-integration.sh` (**CTRL_TESTS**, per sub-leg
//! 64b — it is a `mod common` binary, so it needs `DATABASE_URL` pointed at a
//! migrated template database, which CTRL_TESTS supplies and TC_TESTS does
//! not), plus `TALOS_TEST_NATS_URL`.

mod common;

use std::sync::Arc;

use serde_json::json;
use talos_memory::memory_rpc::{MemoryOp, MemoryRpcReply, MemoryRpcRequest, SUBJECT_MEMORY_OP};
use talos_metrics::{RpcOutcome, RpcSubject, TalosMetrics};
use uuid::Uuid;

/// The ONE accessor. Returns the installed process-global registry, installing
/// one only if nothing has yet. Never a second installer — see the module
/// docs.
fn installed_test_metrics() -> Arc<TalosMetrics> {
    if let Some(m) = talos_metrics::global() {
        return m.clone();
    }
    let m = TalosMetrics::new().expect("build metrics");
    talos_metrics::set_global(m);
    talos_metrics::global()
        .expect("a registry is installed after set_global")
        .clone()
}

/// The live value of one `(subject, outcome)` series, read from the collector
/// the production path writes to.
fn counter(m: &TalosMetrics, subject: RpcSubject, outcome: RpcOutcome) -> f64 {
    m.rpc_calls_total
        .with_label_values(&[subject.as_str(), outcome.as_str(), outcome.class().as_str()])
        .get()
}

fn prepare_env() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    // Keep the write path hermetic: an unconfigured embedding provider makes
    // `generate_embedding` return `None` and the row still lands, which is all
    // this test needs. A half-configured one would add an HTTP timeout to
    // every phase.
    std::env::remove_var("EMBEDDING_API_URL");
    // The ceiling is not what is under test here; leave it at its default-off
    // so a permitted write is permitted for the ordinary reason.
    std::env::remove_var("TALOS_WRITE_CEILING_ENFORCED");
}

async fn seed_actor(pool: &sqlx::Pool<sqlx::Postgres>) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("rpcinst-{user}@talos.test"))
    .execute(pool)
    .await
    .expect("seed user");
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) \
         VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("rpcinstorg-{tag}"))
    .bind(format!("rpcinstorg-{tag}"))
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("seed org");
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, org_id) VALUES ($1, $2, $3, $4)")
        .bind(actor)
        .bind(user)
        .bind(format!("rpcinst-actor-{tag}"))
        .bind(org)
        .execute(pool)
        .await
        .expect("seed actor");
    actor
}

async fn register_crypto(pool: &sqlx::Pool<sqlx::Postgres>) {
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    talos_memory::register_memory_crypto_hook(Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(sm.clone()),
    ));
}

/// Sign → NATS → admission gate → handler → reply. The whole production path.
async fn call_rpc(nats: &async_nats::Client, actor: Uuid, op: MemoryOp) -> MemoryRpcReply {
    let req = MemoryRpcRequest::new_signed(actor, op).expect("sign (HMAC key registered)");
    request_bytes(nats, serde_json::to_vec(&req).expect("serialize")).await
}

/// The same path with the signature corrupted, so admission refuses it.
///
/// The byte is flipped on the STRUCT rather than in the serialized JSON, so
/// the wire shape is exactly what a real sender produces and only the MAC is
/// wrong — which is the state a half-rotated `WORKER_SHARED_KEY` or an
/// unauthorized sender puts the subject in.
async fn call_rpc_with_bad_signature(
    nats: &async_nats::Client,
    actor: Uuid,
    op: MemoryOp,
) -> MemoryRpcReply {
    let mut req = MemoryRpcRequest::new_signed(actor, op).expect("sign");
    assert!(
        !req.signature.is_empty(),
        "a signed request must carry a MAC, or this phase proves nothing"
    );
    req.signature[0] ^= 0xff;
    request_bytes(nats, serde_json::to_vec(&req).expect("serialize")).await
}

async fn request_bytes(nats: &async_nats::Client, payload: Vec<u8>) -> MemoryRpcReply {
    let msg = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        nats.request(SUBJECT_MEMORY_OP, payload.into()),
    )
    .await
    .expect("subscriber replied within 10s")
    .expect("NATS request succeeded");
    serde_json::from_slice(&msg.payload).expect("decode reply")
}

/// ONE test, four phases, ONE database — the same reason
/// `rpc_write_ceiling_tests` gives: `register_memory_crypto_hook` is a
/// process-wide `OnceLock` (first registration wins), so parallel tests on
/// separate isolated databases would all encrypt through whichever pool
/// registered first.
///
/// # Phase 1 — a served call moves `(memory.op, ok, served)` by exactly one
///
/// The pair is PRE-SEEDED, so the assertion is a DELTA of exactly 1 from a
/// known 0, not "greater than zero" — which would also pass if some other
/// phase double-counted.
///
/// # Phase 2 — a designed decline is counted, and is NOT the same series
///
/// `Get` on a key that was never written is `KeyNotFound` -> `not_found` ->
/// `Declined`. Before this change it was a `warn!` and nothing else; this is
/// the class that made 53% of the controller's WARN volume one designed state.
///
/// # Phase 3 — a refused call is counted too
///
/// A corrupted signature is refused at admission, above the handler. That path
/// records `unauthorized`, class `finding`. Counting it is the point: on a
/// FLEET-SHARED-key transport a burst of these is a real security signal, and
/// until now it existed only as a log line.
///
/// # Phase 4 — the control, and the cardinality invariant
///
/// A subject nothing was sent to must still read 0 — otherwise phases 1-3
/// would pass on an instrument that increments everything. And the rendered
/// exposition must contain the actor's uuid NOWHERE: `actor_id` is a LOG
/// FIELD and must never become a label, because it is caller-supplied and
/// unbounded.
#[tokio::test]
async fn the_production_rpc_path_moves_the_instrument() {
    prepare_env();
    let metrics = installed_test_metrics();

    talos_memory::rpc_auth::register_hmac_key(Arc::new(b"rpc-instrument-test-key".to_vec()));

    let (pool, _db) = common::isolated_db_pool().await;
    register_crypto(&pool).await;

    let nats_url = std::env::var("TALOS_TEST_NATS_URL")
        .unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let nats = async_nats::connect(&nats_url)
        .await
        .unwrap_or_else(|e| panic!("connect to NATS at {nats_url}: {e}"));

    let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    talos_rpc_subscribers::spawn_memory_rpc_subscriber(
        Arc::new(nats.clone()),
        pool.clone(),
        shutdown_rx,
    );
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let actor = seed_actor(&pool).await;

    // Baselines. Every one of these is a PRE-SEEDED pair, so it is readable
    // before anything has happened — which is the whole argument for seeding:
    // an absent series matches no `increase(...) > 0`.
    let base_ok = counter(&metrics, RpcSubject::MemoryOp, RpcOutcome::Ok);
    let base_nf = counter(&metrics, RpcSubject::MemoryOp, RpcOutcome::NotFound);
    let base_unauth = counter(&metrics, RpcSubject::MemoryOp, RpcOutcome::Unauthorized);
    let base_graph = counter(&metrics, RpcSubject::GraphSearch, RpcOutcome::Ok);
    assert_eq!(
        (base_ok, base_nf, base_unauth, base_graph),
        (0.0, 0.0, 0.0, 0.0),
        "every pair the table declares must be present at 0 on a cold registry"
    );
    assert!(
        !metrics
            .render_prometheus()
            .expect("render")
            .contains("talos_rpc_duration_seconds{"),
        "the histogram is deliberately unseeded; a series before the first call \
         means someone seeded it"
    );

    // ── Phase 1: a served Set ────────────────────────────────────────────
    let key = format!("rpcinst/{}", Uuid::new_v4());
    let reply = call_rpc(
        &nats,
        actor,
        MemoryOp::Set {
            key: key.clone(),
            value: json!({"note": "served"}),
            memory_type: "episodic".into(),
            ttl_hours: Some(1.0),
            metadata: None,
        },
    )
    .await;
    assert!(
        reply.result.is_ok(),
        "control write must succeed: {reply:?}"
    );
    assert_eq!(
        counter(&metrics, RpcSubject::MemoryOp, RpcOutcome::Ok) - base_ok,
        1.0,
        "a served memory RPC must move talos_rpc_calls_total exactly once — \
         delete the increment at the call site and this is the assertion that fails"
    );
    let rendered = metrics.render_prometheus().expect("render");
    assert!(
        rendered.contains(
            r#"talos_rpc_duration_seconds_count{class="served",outcome="ok",subject="talos.memory.op"}"#
        ),
        "the latency histogram must observe the same call the counter counted"
    );

    // ── Phase 2: a designed decline ──────────────────────────────────────
    let reply = call_rpc(
        &nats,
        actor,
        MemoryOp::Get {
            key: format!("rpcinst/absent/{}", Uuid::new_v4()),
        },
    )
    .await;
    assert!(
        reply.result.is_err(),
        "a Get on an absent key is KeyNotFound: {reply:?}"
    );
    assert_eq!(
        counter(&metrics, RpcSubject::MemoryOp, RpcOutcome::NotFound) - base_nf,
        1.0,
        "a declined call must be counted under its OWN outcome, not folded into ok"
    );
    assert_eq!(
        counter(&metrics, RpcSubject::MemoryOp, RpcOutcome::Ok) - base_ok,
        1.0,
        "the decline must not have moved the served series"
    );
    assert_eq!(
        RpcOutcome::NotFound.class().as_str(),
        "declined",
        "not_found is the designed-decline class; if this moves, the log level \
         and the alert selector move with it"
    );

    // ── Phase 3: a refusal at admission ──────────────────────────────────
    let reply = call_rpc_with_bad_signature(
        &nats,
        actor,
        MemoryOp::Get {
            key: "rpcinst/forged".into(),
        },
    )
    .await;
    assert!(
        reply.result.is_err(),
        "a corrupted signature must be refused: {reply:?}"
    );
    assert_eq!(
        counter(&metrics, RpcSubject::MemoryOp, RpcOutcome::Unauthorized) - base_unauth,
        1.0,
        "a refusal at admission must reach the instrument — it is above the \
         handler, so a metric wired only at the handler would miss it entirely"
    );

    // ── Phase 4: the control, and the cardinality invariant ──────────────
    assert_eq!(
        counter(&metrics, RpcSubject::GraphSearch, RpcOutcome::Ok),
        base_graph,
        "a subject nothing was sent to must not move; without this the three \
         assertions above would pass on an instrument that increments everything"
    );
    let rendered = metrics.render_prometheus().expect("render");
    assert!(
        !rendered.contains(&actor.to_string()),
        "the actor id must appear NOWHERE in the exposition — it is a log field, \
         and a caller-supplied label value is an unbounded-cardinality DoS surface"
    );
    assert!(
        !rendered.contains(&key),
        "no memory key may reach the exposition"
    );
    // The label set is exactly the three declared names, in every series.
    for line in rendered
        .lines()
        .filter(|l| l.starts_with("talos_rpc_calls_total{"))
    {
        let labels = line
            .split_once('{')
            .and_then(|(_, r)| r.split_once('}'))
            .map(|(l, _)| l)
            .expect("a labelled series");
        let mut names: Vec<&str> = labels
            .split(',')
            .filter_map(|kv| kv.split('=').next())
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec!["class", "outcome", "subject"],
            "unexpected label set on {line}"
        );
    }
}
