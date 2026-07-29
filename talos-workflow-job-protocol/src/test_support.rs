//! Shared wire-invariant property harness — the generator and counterexamples
//! that found the 2026-07-27 signing outage, exposed so every crate signing
//! JSON tests against the SAME adversary.
//!
//! # Why this is a module and not a copy
//!
//! The 2026-07-27 dispatch-signature outage was found by SEARCH, not by
//! deduction: six reasoned hypotheses were wrong, and a property test that
//! simply asked "is the round trip ever unstable?" found the cause in seconds.
//! Every hand-written sign/verify test in the fleet used `json!({})` payloads,
//! which is structurally incapable of catching a payload-DEPENDENT fault.
//!
//! When the memory-RPC twin (#598) needed the same harness it COPIED the
//! generator, because the original was `#[cfg(test)]`-private to this crate.
//! The copy immediately drifted: `talos-memory`'s property coverage never
//! grew the size-independence sweep, the text-vs-meaning assertion, or the
//! transcode trap, so the second signed-wire surface was tested strictly more
//! weakly than the first — silently, since both suites were green. One home
//! for the adversary means an assertion class added for one surface is
//! available to the other by construction.
//!
//! # Feature gate
//!
//! Compiled only under `cfg(test)` (this crate's own suites) or the
//! non-default `test-support` feature (downstream dev-dependencies). It is
//! invisible to production builds: nothing in the default feature set
//! references it, so `cargo build`/`cargo check` of any dependent crate does
//! not compile a line of it.
//!
//! # What the generator deliberately produces
//!
//! The shapes that actually broke us: floats built from raw bit patterns
//! (the real failure), computed ratios (~10% of which are round-trip
//! unstable), deep nesting, mixed arrays, non-ASCII keys, and integers at
//! JSON's typing boundaries. Any suite using it should also assert the
//! generator is not vacuous — see [`round_trip_unstable_count`].

/// A float with **no round-trip fixed point** under `serde_json`: writing it,
/// re-parsing, and writing again yields text that differs from the first
/// write, forever.
///
/// ```text
///   5.455171886890906e-115
///     -> 5.455171886890905e-115
///     -> 5.4551718868909045e-115
///     -> 5.455171886890905e-115   <- a permanent 2-cycle
/// ```
///
/// This is the value that makes "normalise to the fixed point" (the #595
/// first attempt) provably insufficient and forces raw-bytes signing. Any
/// signed-wire suite should carry at least one payload containing it.
pub const POISON_2CYCLE: f64 = 5.455171886890906e-115;

/// The exact bit pattern the #597 search surfaced as round-trip unstable;
/// kept as a second, independently-sourced sample so a single `serde_json`
/// version bump cannot silently make a whole suite vacuous. Use via
/// `f64::from_bits(POISON_BITS)`.
pub const POISON_BITS: u64 = 0x2284_3773_1ab4_9c0f;

/// Pseudo-random structured JSON.
///
/// Seeded (never `thread_rng`) so a property failure is REPRODUCIBLE from the
/// printed seed — a flaky property test that cannot be replayed is worse than
/// none. `depth` bounds recursion; 3–4 is the range the existing suites use.
pub fn arbitrary_json(seed: &mut u64, depth: u32) -> serde_json::Value {
    // xorshift64 — tiny, deterministic, no dev-dependency.
    let mut next = || {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    };
    let pick = next() % if depth == 0 { 6 } else { 8 };
    match pick {
        0 => serde_json::Value::Null,
        1 => serde_json::Value::Bool(next() % 2 == 0),
        // Floats from RAW BITS: this is the class that actually broke signing
        // (parse(write(x)) landing one ULP away).
        2 => {
            let f = f64::from_bits(next());
            serde_json::Number::from_f64(f)
                .map_or(serde_json::Value::Null, serde_json::Value::Number)
        }
        // Integers at the boundaries where JSON number typing is subtle.
        3 => serde_json::json!(next() as i64),
        4 => serde_json::json!(next()),
        // Computed ratios — the digest's actual content, and what agent/LLM
        // nodes persist; ~10% of them are round-trip unstable.
        5 => {
            let (a, b) = (next() % 1000 + 1, next() % 1000 + 1);
            serde_json::json!(a as f64 / b as f64)
        }
        6 => {
            let n = (next() % 4) as usize;
            serde_json::Value::Array((0..n).map(|_| arbitrary_json(seed, depth - 1)).collect())
        }
        _ => {
            let n = (next() % 4) as usize;
            let mut m = serde_json::Map::new();
            for i in 0..n {
                // Non-ASCII keys and values: escaping differences would
                // change byte length without changing meaning.
                m.insert(
                    format!("k{i}\u{2014}\u{1f600}"),
                    arbitrary_json(seed, depth - 1),
                );
            }
            serde_json::Value::Object(m)
        }
    }
}

/// Anti-vacuousness measurement: how many of `iters` generated values change
/// their JSON TEXT when written, re-parsed, and written again.
///
/// A suite whose generator returns 0 here is passing for reasons unrelated to
/// floats — assert this is `> 0` alongside the property tests themselves.
pub fn round_trip_unstable_count(seed: &mut u64, iters: usize, depth: u32) -> usize {
    let mut unstable = 0;
    for _ in 0..iters {
        let v = arbitrary_json(seed, depth);
        let once = v.to_string();
        if let Ok(p) = serde_json::from_str::<serde_json::Value>(&once) {
            if p.to_string() != once {
                unstable += 1;
            }
        }
    }
    unstable
}

/// The wire hop production actually performs: `to_vec` on the signed struct,
/// `from_slice` on the received bytes.
///
/// Byte-preserving, so a correctly-implemented signed message must still
/// verify afterwards. Faithful to both surfaces: the dispatcher publishes and
/// consumes NATS payloads as bytes, and the worker/controller memory-RPC path
/// does the same (`talos-worker-runtime/src/host/memory.rs` →
/// `talos-rpc-subscribers/src/admission.rs`). No intermediate `Value` hop
/// exists on either side.
///
/// # Panics
/// If the value fails to serialise or the bytes fail to deserialise — both
/// are harness bugs, not protocol findings.
pub fn wire_hop<T: serde::Serialize + serde::de::DeserializeOwned>(value: &T) -> T {
    let bytes = serde_json::to_vec(value).expect("harness: serialise");
    serde_json::from_slice(&bytes).expect("harness: deserialise")
}

/// The trap hop: `to_value` → `from_value`, which RE-DERIVES the payload text
/// and therefore silently breaks the signature of any message carrying a
/// round-trip-unstable float.
///
/// Exists so suites can assert the breakage explicitly rather than discovering
/// it in production. Rule for callers of signed types: move them over the wire
/// as bytes or a string, NEVER via `serde_json::Value`.
///
/// # Panics
/// If the value fails to convert in either direction — a harness bug.
pub fn value_transcode_hop<T: serde::Serialize + serde::de::DeserializeOwned>(value: &T) -> T {
    let as_value = serde_json::to_value(value).expect("harness: to_value");
    serde_json::from_value(as_value).expect("harness: from_value")
}
