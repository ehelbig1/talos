//! Build-identity cache + the one diagnostic sentence it exists to produce.
//!
//! ## Why this lives on the RPC rejection path
//!
//! Signed wire formats are version-coupled. When the memory-RPC signed-body
//! formula moved (#598, then again in #600), a mixed fleet failed EVERY
//! memory / integration-state RPC closed — correctly, fail-safe, and with an
//! operator-visible signal indistinguishable from a clock-drift or a
//! misconfigured shared key. The controller now KNOWS what build each worker
//! reported (#601's registration handshake), so at the exact moment a
//! signature fails to check out it can say whether the two sides were built
//! from the same commit. That single sentence is the difference between
//! "roll controller+worker together" and twelve hypotheses.
//!
//! ## Shape
//!
//! * A process-global `worker_id → Option<build_version>` map, replaced
//!   WHOLESALE by [`set_worker_build_cache`] from the same registry load that
//!   installs the verifying-key overlay. Wholesale replacement is why there
//!   is no sweep to write: the map is exactly the active fleet, never a
//!   monotonically growing keyed cache (the keyed-DashMap-sweep rule).
//! * A `OnceLock` for the controller's own build, stamped once at startup.
//! * Reads happen ONLY on the rejection path, and only for the one failure
//!   class where build skew is a plausible explanation. Steady-state cost is
//!   zero: a successful RPC never touches either.
//!
//! `std::sync::RwLock<Arc<HashMap>>` rather than `ArcSwap`: this crate does
//! not depend on `arc-swap` today, the read is off the hot path, and the
//! `Arc` clone under a short read guard gives readers a snapshot that a
//! concurrent wholesale replace cannot tear.
//!
//! ## Honesty rule
//!
//! Unverifiable NEVER reads as "match" (#578's lesson, restated in #601's
//! `log_build_identity`). A worker absent from the cache, or either side
//! reporting a placeholder sha, produces the "cannot rule skew in or out"
//! wording — never the reassuring one.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

use talos_worker_identity_repository::{build_is_verifiable, build_suffix, builds_match};

/// `worker_id → build_version` for the ACTIVE fleet. `None` = the worker has
/// a registry row but never reported a build (a pre-handshake image).
type BuildMap = HashMap<String, Option<String>>;

fn worker_builds() -> &'static RwLock<Arc<BuildMap>> {
    static SLOT: OnceLock<RwLock<Arc<BuildMap>>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(Arc::new(HashMap::new())))
}

static CONTROLLER_BUILD: OnceLock<String> = OnceLock::new();

/// Longest build string this cache will hold. Matches the registration
/// endpoint's own `MAX_BUILD_VERSION_BYTES`; duplicated as a number rather
/// than imported because the direction of the dependency forbids reaching
/// into the controller bin from here, and the value is a log-hygiene bound,
/// not a protocol constant that must agree byte-for-byte.
const MAX_BUILD_STRING_BYTES: usize = 128;

/// Make a build string safe for the ONE sink this module has: an operator's
/// log line.
///
/// **Why here and not only at ingest.** The worker-reported build string is
/// unsigned and attacker-controllable (the migration says so in capitals),
/// and today every writer — the `/internal/worker-key` handler — sanitizes it
/// before the DB write, while the operator CLI writes `None`. This filter is
/// deliberately REDUNDANT with that. It exists because the value now travels
/// registration → DB → registry load → process-global cache → a `tracing`
/// field, and the guarantee it depends on lives four hops away in another
/// crate. A single future writer that forgets — an admin tool, a backfill, a
/// second registration path — would hand a registrant `\n` and `\x1b` in the
/// operator's own diagnostic channel, which is the trusted channel this whole
/// change exists to enrich. Sanitizing where the string is FORMATTED makes
/// that impossible to regress from a distance.
///
/// Same rules as the ingest filter: ASCII-graphic only (no whitespace — SPACE
/// is `tracing`'s field separator and would let a value forge a second field —
/// no control characters, no non-ASCII), capped, and an empty result collapses
/// to `None` so "reported only garbage" reads as unverifiable rather than as a
/// build.
fn sanitize_build_string(raw: String) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(char::is_ascii_graphic)
        .take(MAX_BUILD_STRING_BYTES)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// Replace the whole worker→build map. Called from the controller's
/// worker-identity registry load (boot, the periodic refresh, and the eager
/// refresh after a successful self-registration), so the cache is exactly as
/// fresh as the verifying-key overlay it ships alongside.
///
/// Wholesale replace, never per-key insert: bounded by fleet size by
/// construction, so a churning worker_id cannot inflate it and there is
/// nothing to sweep.
///
/// Values are re-sanitized on the way in (see [`sanitize_build_string`]) —
/// the caller reads them out of a DB column no signature covers.
///
/// **Repeated `worker_id`s collapse to "unknown", not to "last one wins".**
/// The registry is keyed on `(worker_id, public_key)`, so one worker
/// legitimately contributes SEVERAL rows during a key rotation overlap — and
/// those rows can carry different builds, because each was stamped by the
/// registration that installed that key. Picking one arbitrarily (whatever
/// the row order happened to be) would let the hint state a confident
/// `build-skew: worker=<sha>` naming a sha the worker has since moved off.
/// Disagreement is exactly the state we cannot resolve from here, so it
/// resolves to `None` and the wording says "cannot rule build skew in or
/// out". Same rule as everywhere else in this module: never render
/// uncertainty as a verdict.
pub fn set_worker_build_cache(entries: impl IntoIterator<Item = (String, Option<String>)>) {
    use std::collections::hash_map::Entry;
    let mut map: BuildMap = HashMap::new();
    for (worker_id, build) in entries {
        let build = build.and_then(sanitize_build_string);
        match map.entry(worker_id) {
            Entry::Vacant(slot) => {
                slot.insert(build);
            }
            Entry::Occupied(mut slot) => {
                if *slot.get() != build {
                    slot.insert(None);
                }
            }
        }
    }
    // Poisoned lock: a panic while holding the write guard would leave the
    // map's contents intact (the panic can only come from allocation), and a
    // stale hint is strictly better than poisoning the RPC rejection path —
    // recover rather than propagate.
    let mut guard = worker_builds()
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = Arc::new(map);
}

/// Stamp the controller's own build string. Idempotent (`OnceLock`);
/// first call wins, matching the `rpc_auth` key-registration convention.
///
/// Sanitized like the worker half: the controller's build string is normally
/// composed from `build.rs` constants, but `TALOS_VERSION` overrides it
/// verbatim from the environment, and a chart value carrying a newline should
/// not be able to split a log line either. An all-garbage override leaves the
/// slot unset, which the wording renders as "unverifiable" — never as a match.
pub fn set_controller_build(version: String) {
    if let Some(clean) = sanitize_build_string(version) {
        let _ = CONTROLLER_BUILD.set(clean);
    }
}

/// The controller build, if it was stamped. `None` in unit tests and in any
/// embedding that never calls [`set_controller_build`] — which the hint
/// wording must treat as unverifiable, not as agreement.
fn controller_build() -> Option<&'static str> {
    CONTROLLER_BUILD.get().map(String::as_str)
}

/// This worker's reported build. Outer `None` = not in the cache at all
/// (static-ring worker that never self-registered, a worker registered since
/// the last refresh, a fleet past `MAX_FLEET_BUILD_ROWS`, or an unknown/forged
/// id); inner `None` = in the registry but with no usable build — pre-handshake,
/// all-garbage after sanitizing, or rows that disagreed with each other. Every
/// one of those is unverifiable, and the wording says so.
fn worker_build(worker_id: &str) -> Option<String> {
    let snapshot = {
        let guard = worker_builds()
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(&guard)
    };
    snapshot.get(worker_id).cloned().flatten()
}

/// The three wordings, deliberately kept apart.
///
/// The `unverifiable` arm must never be mistaken for agreement — it is the
/// arm a pre-handshake worker, a static-ring worker, an `unknown` sha, or an
/// unstamped controller all land in, and none of those are evidence the two
/// binaries came from one tree.
pub(crate) const HINT_MATCH: &str =
    "builds match — divergence is NOT explained by build skew; look at the shared key, \
     the signed-body formula, or the clock";
pub(crate) const HINT_UNVERIFIABLE: &str =
    "build identity unverifiable (worker not in the identity registry — static-ring or \
     pre-handshake — or a side reports no usable commit sha); cannot rule build skew in or out";

/// Pure core of the hint, split out so all three wordings are unit-testable
/// without the process-global caches.
pub(crate) fn skew_hint_for(controller: Option<&str>, worker: Option<&str>) -> String {
    match (controller, worker) {
        (Some(cb), Some(wb)) if builds_match(cb, wb) => HINT_MATCH.to_string(),
        // Both sides carry a real commit sha and they differ. "-dirty" on one
        // side only lands here too: same commit, but a dirty tree corresponds
        // to no commit at all, so the binaries were built from different bytes.
        (Some(cb), Some(wb)) if build_is_verifiable(cb) && build_is_verifiable(wb) => format!(
            "build-skew: worker={} controller={} — signed wire formats are version-coupled; \
             roll controller+worker together",
            build_suffix(wb).unwrap_or("none"),
            build_suffix(cb).unwrap_or("none")
        ),
        _ => HINT_UNVERIFIABLE.to_string(),
    }
}

/// The hint for one rejected request, resolved against the process-global
/// caches. Two lock-free-ish reads (one `OnceLock`, one short read guard) on
/// the FAILURE path only.
///
/// Call this ONLY for `bad_signature`. Stale, oversized, non-finite, unknown
/// signer, and replay are not skew symptoms, and attaching a skew sentence to
/// them would manufacture exactly the false lead this work removes.
pub(crate) fn skew_hint(worker_id: &str) -> String {
    skew_hint_for(controller_build(), worker_build(worker_id).as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises the tests that MUTATE the process-global cache. Without it
    /// they race each other: `cache_replaces_wholesale_and_stays_bounded`
    /// asserts on entries a concurrently-running `set_worker_build_cache`
    /// would have already replaced, which fails intermittently and reads like
    /// a cache bug rather than a harness one. The pure `skew_hint_for` tests
    /// touch no global and stay lock-free.
    static CACHE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_cache() -> std::sync::MutexGuard<'static, ()> {
        CACHE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn matching_commit_suffixes_report_match() {
        // The package halves legitimately differ per crate (controller
        // `1.0.0-rN` vs worker `0.1.0`); only the sha is compared.
        assert_eq!(
            skew_hint_for(Some("1.0.0-r304+ab85eb2"), Some("0.1.0+ab85eb2")),
            HINT_MATCH
        );
    }

    #[test]
    fn differing_commit_suffixes_report_skew_with_both_shas() {
        let hint = skew_hint_for(Some("1.0.0-r304+ab85eb2"), Some("0.1.0+f099158"));
        assert!(
            hint.starts_with("build-skew: worker=f099158 controller=ab85eb2"),
            "{hint}"
        );
        assert!(hint.contains("roll controller+worker together"), "{hint}");
    }

    #[test]
    fn dirty_on_one_side_only_is_skew_not_match() {
        let hint = skew_hint_for(Some("1.0.0+ab85eb2"), Some("0.1.0+ab85eb2-dirty"));
        assert!(hint.starts_with("build-skew:"), "{hint}");
    }

    /// The honesty rule: absence of evidence is never reported as agreement.
    #[test]
    fn unverifiable_never_reads_as_match() {
        for (c, w) in [
            (None, None),
            (None, Some("0.1.0+ab85eb2")),
            (Some("1.0.0+ab85eb2"), None),
            // Placeholder shas (`build.rs` outside a git checkout) on either
            // side, including BOTH — two `unknown`s are not agreement.
            (Some("1.0.0+unknown"), Some("0.1.0+ab85eb2")),
            (Some("1.0.0+ab85eb2"), Some("0.1.0+unknown")),
            (Some("1.0.0+unknown"), Some("0.1.0+unknown")),
            (Some("1.0.0+unknown-dirty"), Some("0.1.0+unknown-dirty")),
            // No `+sha` half at all (a bare TALOS_VERSION override).
            (Some("1.2.3"), Some("1.2.3")),
        ] {
            let hint = skew_hint_for(c, w);
            assert_eq!(
                hint, HINT_UNVERIFIABLE,
                "controller={c:?} worker={w:?} must be unverifiable, got: {hint}"
            );
            assert!(!hint.contains("builds match"), "{hint}");
        }
    }

    /// The cache is a wholesale replacement, so it tracks the fleet exactly:
    /// a worker that leaves the registry leaves the map, and the map never
    /// accumulates. (The bound is what makes a sweep unnecessary.)
    #[test]
    fn cache_replaces_wholesale_and_stays_bounded() {
        let _guard = lock_cache();
        set_worker_build_cache([
            ("w-a".to_string(), Some("0.1.0+aaaaaaa".to_string())),
            ("w-b".to_string(), None),
        ]);
        assert_eq!(worker_build("w-a").as_deref(), Some("0.1.0+aaaaaaa"));
        // Registered but pre-handshake: unverifiable, same as absent.
        assert_eq!(worker_build("w-b"), None);
        assert_eq!(worker_build("w-never-seen"), None);

        set_worker_build_cache([("w-c".to_string(), Some("0.1.0+ccccccc".to_string()))]);
        assert_eq!(worker_build("w-c").as_deref(), Some("0.1.0+ccccccc"));
        assert_eq!(
            worker_build("w-a"),
            None,
            "a wholesale replace must DROP the previous generation, not merge it"
        );

        set_worker_build_cache(std::iter::empty());
        assert_eq!(worker_build("w-c"), None);
    }

    /// An unknown worker_id resolves through the real caches to the
    /// unverifiable wording — the path the rejection log actually takes.
    #[test]
    fn live_lookup_of_an_unknown_worker_is_unverifiable() {
        let _guard = lock_cache();
        set_worker_build_cache(std::iter::empty());
        assert_eq!(skew_hint("no-such-worker"), HINT_UNVERIFIABLE);
    }

    /// A build string reaching the cache is UNSIGNED, worker-reported, and
    /// arrives via a DB column — four hops from the endpoint that sanitizes
    /// it. Re-filter at the point of formatting so a writer that forgets
    /// cannot forge lines in the operator's own diagnostic channel.
    ///
    /// Both primitives are covered: `\n` (forge a whole line) and SPACE
    /// (`tracing`'s field separator — a value can otherwise emit a second,
    /// forged `controller_build=` field beside the real one).
    #[test]
    fn hostile_build_strings_are_defanged_at_the_cache_boundary() {
        let _guard = lock_cache();
        set_worker_build_cache([(
            "w-hostile".to_string(),
            Some(
                "0.1.0+aaaaaaa\n2026-07-28 WARN talos_rpc: all clear skew_hint=builds match"
                    .to_string(),
            ),
        )]);
        let stored = worker_build("w-hostile").expect("kept, minus the injection");
        assert!(
            !stored.contains('\n') && !stored.contains(' '),
            "newline/space survived into the log field: {stored:?}"
        );

        // The hint built from it carries no line break either — and the
        // suffix is still the honest thing to show the operator.
        set_controller_build("1.0.0+bbbbbbb".to_string());
        let hint = skew_hint("w-hostile");
        assert!(!hint.contains('\n'), "{hint}");
        assert!(
            !hint.contains("builds match"),
            "a forged suffix must not be able to spell out the reassuring wording: {hint}"
        );

        // Escapes and non-ASCII go the same way.
        set_worker_build_cache([(
            "w-esc".to_string(),
            Some("0.1.0+\u{1b}[2Jccccccc\u{202e}".to_string()),
        )]);
        let stored = worker_build("w-esc").expect("kept");
        assert!(
            stored.chars().all(|c| c.is_ascii_graphic()),
            "non-graphic character survived: {stored:?}"
        );

        // Entirely-garbage input is "reported nothing", which the wording
        // must render as unverifiable — never as a match.
        set_worker_build_cache([("w-junk".to_string(), Some("\n\n   ".to_string()))]);
        assert_eq!(worker_build("w-junk"), None);
        assert_eq!(skew_hint("w-junk"), HINT_UNVERIFIABLE);

        // And the value is bounded, so a 10 KB "version" cannot flood a log.
        set_worker_build_cache([("w-long".to_string(), Some("v".repeat(10_000)))]);
        assert_eq!(
            worker_build("w-long").map(|s| s.len()),
            Some(MAX_BUILD_STRING_BYTES)
        );

        set_worker_build_cache(std::iter::empty());
    }

    /// One worker, several registry rows (a key-rotation overlap), and the
    /// rows disagree about the build: the hint must go to "unknown", not to
    /// whichever row the query ordered last. A confident `build-skew:` line
    /// naming a sha the worker already moved off is worse than no line.
    #[test]
    fn disagreeing_rows_for_one_worker_collapse_to_unknown() {
        let _guard = lock_cache();
        set_worker_build_cache([
            ("w-rot".to_string(), Some("0.1.0+aaaaaaa".to_string())),
            ("w-rot".to_string(), Some("0.1.0+bbbbbbb".to_string())),
            // Agreement across rows is NOT ambiguity — it must survive.
            ("w-agree".to_string(), Some("0.1.0+ccccccc".to_string())),
            ("w-agree".to_string(), Some("0.1.0+ccccccc".to_string())),
            // A reporting row plus a pre-handshake row is also a disagreement.
            ("w-half".to_string(), Some("0.1.0+ddddddd".to_string())),
            ("w-half".to_string(), None),
        ]);
        assert_eq!(worker_build("w-rot"), None);
        assert_eq!(worker_build("w-agree").as_deref(), Some("0.1.0+ccccccc"));
        assert_eq!(worker_build("w-half"), None);
        assert_eq!(skew_hint("w-rot"), HINT_UNVERIFIABLE);
        set_worker_build_cache(std::iter::empty());
    }

    /// The controller half is stamped from `TALOS_VERSION` when set — an
    /// environment value, not a compiled constant — so it gets the same
    /// filter. (`OnceLock`: first call wins, so this asserts the FILTER, not
    /// the stored value, which an earlier test in this binary may own.)
    #[test]
    fn controller_build_string_is_sanitized_too() {
        assert_eq!(
            sanitize_build_string("1.0.0+abc\ndef ghi".to_string()).as_deref(),
            Some("1.0.0+abcdefghi")
        );
        assert_eq!(sanitize_build_string("  \n\t".to_string()), None);
    }
}
