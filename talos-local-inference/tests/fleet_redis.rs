// ci-store: redis — scripts/test-integration.sh runs this with that store (scripts/ci_test_targets.py)
//! The fleet-wide local-inference queue (RFC 0014 P3b) against a real Redis.
//!
//! Each `FleetAdmission` here owns its own Redis connection and its own
//! process semaphore, i.e. it stands in for one process (the controller or a
//! worker replica). Every test names its own backend, so its queue is its own.
//!
//! Skipped (green) unless `TALOS_TEST_REDIS_URL` is set. Locally, against a
//! disposable Redis rather than the stack's:
//!
//! ```bash
//! docker run -d --rm -p 16399:6379 redis:7-alpine
//! TALOS_TEST_REDIS_URL=redis://127.0.0.1:16399 \
//!   cargo nextest run -p talos-local-inference --test fleet_redis
//! ```

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use talos_local_inference::fleet::{
    FleetAcquire, FleetAdmission, FleetEvent, FleetOutcome, FleetTiming,
};
use talos_local_inference::gate::{
    admit, LocalLlmSlot, NoWaitObserver, QueueWaitObserver, Ungated,
};
use tokio::sync::Semaphore;
use tokio::time::Instant;

const TIMING: FleetTiming = FleetTiming {
    lease: Duration::from_millis(600),
    renew_every: Duration::from_millis(150),
    alive: Duration::from_millis(1500),
    poll: Duration::from_millis(20),
    redis_call: Duration::from_millis(400),
};

fn redis_url() -> Option<String> {
    std::env::var("TALOS_TEST_REDIS_URL").ok()
}

macro_rules! url_or_skip {
    () => {
        match redis_url() {
            Some(u) => u,
            None => {
                eprintln!("skipping: TALOS_TEST_REDIS_URL is not set");
                return;
            }
        }
    };
}

fn backend() -> String {
    format!("http://itest-{}:11434", uuid::Uuid::new_v4())
}

type Seen = Arc<Mutex<Vec<FleetOutcome>>>;
type Events = Arc<Mutex<Vec<FleetEvent>>>;

/// One "process": its own connection, its own gate, a sink recording outcomes
/// (`seen`) and every event (`events`).
struct Process {
    fleet: FleetAdmission,
    gate: Arc<Semaphore>,
    seen: Seen,
    events: Events,
}

async fn process(url: &str, backend: &str, cap: usize, timing: FleetTiming) -> Process {
    let seen: Seen = Arc::default();
    let events: Events = Arc::default();
    let (s, e) = (seen.clone(), events.clone());
    let fleet = FleetAdmission::connect(
        redis::Client::open(url).unwrap(),
        backend,
        cap,
        timing,
        Some(Arc::new(move |ev| {
            if let FleetEvent::Outcome(o) = ev {
                s.lock().unwrap().push(o);
            }
            e.lock().unwrap().push(ev);
        })),
    )
    .await
    .expect("connect to the test Redis");
    Process {
        fleet,
        gate: Arc::new(Semaphore::new(cap)),
        seen,
        events,
    }
}

impl Process {
    async fn admit(&self, wait_cap: Duration) -> (LocalLlmSlot, Duration) {
        self.admit_for(wait_cap, "model-a").await
    }

    async fn admit_for(&self, wait_cap: Duration, model: &str) -> (LocalLlmSlot, Duration) {
        admit::<NoWaitObserver>(Some(&self.gate), Some(&self.fleet), wait_cap, None, model).await
    }

    fn switches(&self) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| **e == FleetEvent::ModelSwitch)
            .count()
    }

    fn arrivals(&self) -> Vec<u64> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                FleetEvent::Arrival { ahead } => Some(*ahead),
                _ => None,
            })
            .collect()
    }
}

/// Run `n` calls on each of the given processes at once, each holding its
/// slot for `hold`, and return the peak number held at the same time.
async fn peak_of(processes: &[Arc<Process>], n: usize, hold: Duration) -> usize {
    let in_flight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for p in processes {
        for _ in 0..n {
            let (p, in_flight, peak) = (p.clone(), in_flight.clone(), peak.clone());
            tasks.push(tokio::spawn(async move {
                let (slot, _) = p.admit(Duration::from_secs(20)).await;
                assert!(
                    matches!(slot, LocalLlmSlot::Held(_)),
                    "every call is admitted"
                );
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(hold).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
                drop(slot);
            }));
        }
    }
    for t in tasks {
        t.await.unwrap();
    }
    peak.load(Ordering::SeqCst)
}

/// The defect P3b closes, and its fix: two processes with a gate each let two
/// calls reach one backend; with the fleet queue, one.
#[tokio::test]
async fn two_processes_share_one_slot() {
    let url = url_or_skip!();
    let b = backend();
    let a = Arc::new(process(&url, &b, 1, TIMING).await);
    let c = Arc::new(process(&url, &b, 1, TIMING).await);
    let peak = peak_of(&[a.clone(), c.clone()], 3, Duration::from_millis(80)).await;
    assert_eq!(peak, 1, "the fleet queue admitted two at once");
    assert_eq!(
        a.seen.lock().unwrap().len() + c.seen.lock().unwrap().len(),
        6,
        "every call recorded one outcome"
    );
    assert!(a
        .seen
        .lock()
        .unwrap()
        .iter()
        .chain(c.seen.lock().unwrap().iter())
        .all(|o| *o == FleetOutcome::Leased));
}

/// Control: the same two processes WITHOUT the fleet queue overlap, so the
/// peak of 1 above is the queue's doing.
#[tokio::test]
async fn control_two_process_gates_alone_overlap() {
    let in_flight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let gate = Arc::new(Semaphore::new(1));
        let (in_flight, peak) = (in_flight.clone(), peak.clone());
        tasks.push(tokio::spawn(async move {
            let (slot, _) =
                admit::<NoWaitObserver>(Some(&gate), None, Duration::from_secs(5), None, "m").await;
            let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(150)).await;
            in_flight.fetch_sub(1, Ordering::SeqCst);
            drop(slot);
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(peak.load(Ordering::SeqCst), 2);
}

/// A cap of 2 admits two across the fleet, never three.
#[tokio::test]
async fn a_cap_of_two_admits_two_across_the_fleet() {
    let url = url_or_skip!();
    let b = backend();
    let ps: Vec<_> = futures_join(
        (0..3)
            .map(|_| process(&url, &b, 2, TIMING))
            .collect::<Vec<_>>(),
    )
    .await
    .into_iter()
    .map(Arc::new)
    .collect();
    let peak = peak_of(&ps, 2, Duration::from_millis(120)).await;
    assert_eq!(peak, 2);
}

async fn futures_join<F: std::future::Future>(fs: Vec<F>) -> Vec<F::Output> {
    let mut out = Vec::with_capacity(fs.len());
    for f in fs {
        out.push(f.await);
    }
    out
}

/// FIFO across processes: callers are admitted in the order they queued.
#[tokio::test]
async fn waiters_are_admitted_in_the_order_they_queued() {
    let url = url_or_skip!();
    let b = backend();
    let holder = process(&url, &b, 1, TIMING).await;
    let (first, _) = holder.admit(Duration::from_secs(5)).await;
    assert!(matches!(first, LocalLlmSlot::Held(_)));

    let order = Arc::new(Mutex::new(Vec::new()));
    let mut tasks = Vec::new();
    for i in 0..4 {
        let p = process(&url, &b, 1, TIMING).await;
        let order = order.clone();
        tasks.push(tokio::spawn(async move {
            let (slot, _) = p.admit(Duration::from_secs(10)).await;
            assert!(matches!(slot, LocalLlmSlot::Held(_)));
            order.lock().unwrap().push(i);
            tokio::time::sleep(Duration::from_millis(30)).await;
            drop(slot);
        }));
        // Let each waiter take its ticket before the next arrives.
        tokio::time::sleep(Duration::from_millis(60)).await;
    }
    drop(first);
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(*order.lock().unwrap(), vec![0, 1, 2, 3]);
}

/// A holder that dies (stops renewing, never releases) holds the slot for at
/// most one lease; then the next caller is admitted.
#[tokio::test]
async fn a_dead_holders_slot_frees_after_its_lease() {
    let url = url_or_skip!();
    let b = backend();
    let dead = process(&url, &b, 1, TIMING).await;
    let FleetAcquire::Leased(lease) = dead
        .fleet
        .acquire(
            Instant::now() + Duration::from_secs(2),
            "model-a",
            || async {},
        )
        .await
    else {
        panic!("the first caller is admitted");
    };
    lease.abandon();

    let next = process(&url, &b, 1, TIMING).await;
    let (slot, waited) = next.admit(Duration::from_secs(5)).await;
    assert!(matches!(slot, LocalLlmSlot::Held(_)));
    assert!(
        waited >= TIMING.lease / 2,
        "admitted after {waited:?}: the dead holder's lease was ignored"
    );
    assert!(
        waited < TIMING.lease * 3,
        "admitted after {waited:?}: longer than one lease"
    );
}

/// A live holder renews: a call longer than one lease keeps its slot, and a
/// second caller whose wait is shorter than that call is not admitted.
#[tokio::test]
async fn a_live_holder_keeps_its_slot_past_one_lease() {
    let url = url_or_skip!();
    let b = backend();
    let holder = process(&url, &b, 1, TIMING).await;
    let (slot, _) = holder.admit(Duration::from_secs(2)).await;
    assert!(matches!(slot, LocalLlmSlot::Held(_)));

    let other = process(&url, &b, 1, TIMING).await;
    let (late, waited) = other.admit(TIMING.lease * 3).await;
    assert!(
        matches!(late, LocalLlmSlot::Ungated(Ungated::WaitExpired)),
        "a second caller was admitted while the first still held a renewed lease"
    );
    assert!(waited >= TIMING.lease * 3);
    assert_eq!(*other.seen.lock().unwrap(), vec![FleetOutcome::WaitExpired]);
    drop(slot);
}

/// A waiter that gives up leaves the queue at once, so it does not stand
/// ahead of the next caller for its liveness window.
#[tokio::test]
async fn a_waiter_that_gives_up_leaves_the_queue() {
    let url = url_or_skip!();
    let b = backend();
    let holder = process(&url, &b, 1, TIMING).await;
    let (slot, _) = holder.admit(Duration::from_secs(2)).await;

    let quitter = process(&url, &b, 1, TIMING).await;
    let (gave_up, _) = quitter.admit(Duration::from_millis(100)).await;
    assert!(matches!(
        gave_up,
        LocalLlmSlot::Ungated(Ungated::WaitExpired)
    ));
    // Its release runs in the background; give it a moment.
    tokio::time::sleep(Duration::from_millis(100)).await;

    drop(slot);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let next = process(&url, &b, 1, TIMING).await;
    let (admitted, waited) = next.admit(Duration::from_secs(5)).await;
    assert!(matches!(admitted, LocalLlmSlot::Held(_)));
    assert!(
        waited < TIMING.alive / 2,
        "waited {waited:?}: the departed waiter still stood in the queue"
    );
}

/// A TCP proxy to the test Redis that can be FROZEN: once frozen it forwards
/// nothing in either direction. Stalls one connection without touching the
/// shared Redis (a `CLIENT PAUSE` would stall every test running beside this
/// one).
async fn freezable_proxy(url: &str) -> (String, Arc<std::sync::atomic::AtomicBool>) {
    use std::sync::atomic::AtomicBool;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let upstream = url
        .trim_start_matches("redis://")
        .split('/')
        .next()
        .unwrap()
        .to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let frozen = Arc::new(AtomicBool::new(false));
    let f = frozen.clone();
    tokio::spawn(async move {
        loop {
            let (client, _) = listener.accept().await.unwrap();
            let server = tokio::net::TcpStream::connect(&upstream).await.unwrap();
            let (cr, cw) = client.into_split();
            let (sr, sw) = server.into_split();
            for (mut from, mut to, frozen) in [
                (
                    Box::new(cr) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
                    Box::new(sw) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
                    f.clone(),
                ),
                (Box::new(sr) as _, Box::new(cw) as _, f.clone()),
            ] {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = match from.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        while frozen.load(Ordering::SeqCst) {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        if to.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        }
    });
    (format!("redis://{addr}"), frozen)
}

/// Redis that stops answering mid-call: the call proceeds on its process
/// gate after one bounded Redis call, never refused and never hung.
#[tokio::test]
async fn a_stalled_redis_falls_back_to_the_process_gate() {
    let url = url_or_skip!();
    let (proxied, frozen) = freezable_proxy(&url).await;
    let p = process(&proxied, &backend(), 1, TIMING).await;
    frozen.store(true, Ordering::SeqCst);

    // Bounded from outside: a missing Redis timeout would otherwise hang here
    // rather than fail.
    let (slot, waited) =
        tokio::time::timeout(Duration::from_secs(5), p.admit(Duration::from_secs(10)))
            .await
            .expect("a stalled Redis hung the call");
    let LocalLlmSlot::Held(admitted) = slot else {
        panic!("a stalled Redis must not refuse or expire the call");
    };
    assert!(!admitted.holds_fleet_lease());
    assert!(
        waited >= TIMING.redis_call && waited < TIMING.redis_call * 3,
        "waited {waited:?}"
    );
    assert_eq!(*p.seen.lock().unwrap(), vec![FleetOutcome::Unavailable]);
}

#[derive(Default)]
struct Counting {
    begun: AtomicUsize,
    ended: AtomicUsize,
}

impl QueueWaitObserver for Counting {
    async fn begin_wait(&self) {
        self.begun.fetch_add(1, Ordering::SeqCst);
    }
    async fn end_wait(&self) {
        self.ended.fetch_add(1, Ordering::SeqCst);
    }
}

/// A call that queues in the FLEET (its own process gate was free) reports
/// the wait, so a worker's job deadlines stand still for it (P2a).
#[tokio::test]
async fn a_fleet_wait_is_reported_once() {
    let url = url_or_skip!();
    let b = backend();
    let holder = process(&url, &b, 1, TIMING).await;
    let (slot, _) = holder.admit(Duration::from_secs(2)).await;

    let p = process(&url, &b, 1, TIMING).await;
    let seen = Counting::default();
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(slot);
    });
    let (admitted, waited) = admit(
        Some(&p.gate),
        Some(&p.fleet),
        Duration::from_secs(5),
        Some(&seen),
        "model-a",
    )
    .await;
    release.await.unwrap();
    assert!(matches!(admitted, LocalLlmSlot::Held(_)));
    assert!(waited >= Duration::from_millis(250));
    assert_eq!(seen.begun.load(Ordering::SeqCst), 1);
    assert_eq!(seen.ended.load(Ordering::SeqCst), 1);
}

/// A free fleet reports nothing.
#[tokio::test]
async fn a_free_fleet_reports_nothing() {
    let url = url_or_skip!();
    let p = process(&url, &backend(), 1, TIMING).await;
    let seen = Counting::default();
    let (slot, _) = admit(
        Some(&p.gate),
        Some(&p.fleet),
        Duration::from_secs(5),
        Some(&seen),
        "model-a",
    )
    .await;
    assert!(matches!(slot, LocalLlmSlot::Held(_)));
    assert_eq!(seen.begun.load(Ordering::SeqCst), 0);
    assert_eq!(seen.ended.load(Ordering::SeqCst), 0);
}

/// RFC 0014 P4b: a switch is counted when a call is admitted for a different
/// model than the PREVIOUS admission to the backend — by any process — and
/// only then. The first admission has nothing to switch from.
#[tokio::test]
async fn model_switches_are_counted_across_processes() {
    let url = url_or_skip!();
    let b = backend();
    let a = process(&url, &b, 1, TIMING).await;
    let c = process(&url, &b, 1, TIMING).await;
    for (p, model) in [
        (&a, "qwen3.6"),       // first: nothing to switch from
        (&a, "qwen3.6"),       // same model
        (&c, "qwen2.5-coder"), // a switch, by the other process
        (&c, "qwen2.5-coder"), // same
        (&a, "qwen3.6"),       // a switch back
        (&c, ""),              // unknown model: not compared
    ] {
        let (slot, _) = p.admit_for(Duration::from_secs(5), model).await;
        assert!(matches!(slot, LocalLlmSlot::Held(_)));
        drop(slot);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(a.switches(), 1, "a's switch back");
    assert_eq!(c.switches(), 1, "c's switch");
}

/// RFC 0014 P4b: every call reports, once, how many calls were ahead of it
/// when it joined — 0 when admitted at once — so a herd is visible however
/// briefly it lasts.
#[tokio::test]
async fn each_call_reports_how_many_were_ahead_on_arrival() {
    let url = url_or_skip!();
    let b = backend();
    let holder = process(&url, &b, 1, TIMING).await;
    let (slot, _) = holder.admit(Duration::from_secs(2)).await;
    assert_eq!(holder.arrivals(), vec![0]);

    let second = process(&url, &b, 1, TIMING).await;
    let third = process(&url, &b, 1, TIMING).await;
    let t2 = tokio::spawn(async move {
        let (s, _) = second.admit(Duration::from_secs(5)).await;
        drop(s);
        second
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let t3 = tokio::spawn(async move {
        let (s, _) = third.admit(Duration::from_secs(5)).await;
        drop(s);
        third
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(slot);
    let second = t2.await.unwrap();
    let third = t3.await.unwrap();
    assert_eq!(second.arrivals(), vec![1], "one holder ahead");
    assert_eq!(third.arrivals(), vec![2], "a holder and a waiter ahead");
}
