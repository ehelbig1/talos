//! Background-task spawn helpers for the controller binary's `main()` —
//! moved VERBATIM out of `controller/src/main.rs` in the 2026-07
//! decomposition. Spawn ORDER within each function is preserved exactly;
//! the ORDER in which `main()` calls these functions is load-bearing and
//! stays in main.rs. Also home to the WASM-log broadcast scrubber
//! (`scrub_wasm_log_for_broadcast`), whose only consumer is the NATS
//! log-subscriber loop below.
use crate::*;

/// Maximum characters of WASM-emitted log content broadcast on the
/// `execution_updates` GraphQL subscription. Mirrors the persistence
/// path's per-row cap (`MAX_MSG_LEN` in
/// `talos_execution_repository::add_workflow_log`); kept in lockstep
/// so the live channel can't carry more than the persisted row.
const MAX_BROADCAST_LOG_CHARS: usize = 8 * 1024;

/// Sanitise a WASM-emitted log message for live broadcast on
/// `execution_updates`. Mirrors the pipeline `add_workflow_log` runs
/// before persisting to `workflow_execution_logs.message`:
///   1. char-count truncate to `MAX_BROADCAST_LOG_CHARS`
///   2. strip control chars except newline/tab/carriage return
///   3. DLP redact (`talos_dlp_provider::redact_str`)
///
/// Extracted as a free function so the discipline is unit-testable
/// (the inline call site is otherwise too deep in the NATS subscriber
/// loop to cover without bringing up a NATS test harness).
/// Same MCP-481 / MCP-1011 class — every operator-visible WASM-log
/// surface needs identical scrubbing.
fn scrub_wasm_log_for_broadcast(message: &str) -> String {
    let truncated: String = if message.chars().count() > MAX_BROADCAST_LOG_CHARS {
        let mut s: String = message.chars().take(MAX_BROADCAST_LOG_CHARS).collect();
        s.push_str("... (truncated)");
        s
    } else {
        message.to_string()
    };
    let sanitized: String = truncated
        .chars()
        .filter(|c| !c.is_control() || matches!(*c, '\n' | '\t' | '\r'))
        .collect();
    // 2026-05-28 audit F3 perf follow-up: per-log-line broadcast is a
    // hot path that runs the DLP scrubber per message × per subscriber.
    // The trait-method `redact_str` allocates a fresh String for every
    // pattern even when nothing matches (~14 patterns × `String::from_owned`
    // per call). Switching to the Cow variant keeps the legitimate-log
    // common case allocation-free.
    talos_dlp_provider::redact_str_cow(&sanitized).into_owned()
}

/// Recompute and publish `talos_worker_build_skew_workers` from one snapshot of
/// the ACTIVE `worker_identities` rows.
///
/// ALWAYS `set`, never `inc`/`dec` — the gauge is derived fresh from the query
/// each sweep, so a worker that catches up, or whose key is deactivated, lowers
/// it without any bookkeeping. A rise-only wiring would pin the alert firing
/// forever after one rolling deploy.
///
/// WHAT THE POPULATION IS, stated because "active" is easy to over-read.
/// The base set is `worker_identities.active` — registered and not explicitly
/// deactivated — which is NOT the same as "currently running". Two exclusions
/// narrow it toward workers that plausibly ARE running:
///
/// * Rows the reaper has already deactivated drop out for free (they are no
///   longer `active`). That is what finally lets this gauge DRAIN: it shipped
///   as a gauge precisely so it could, but it previously had no population that
///   ever shrank, because nothing ever cleared a row.
/// * Rows that PROVED they speak the liveness protocol and have since gone
///   silent past [`departed_liveness_cutoff_hours`] are excluded here too, so
///   the gauge stops counting a departed worker in the window between its last
///   ping and the reaper's next sweep. Without this the gauge would lag the
///   truth by up to a sweep interval on every scale-down.
///
/// Rows with NO liveness evidence (`last_liveness_at IS NULL`) STAY COUNTED,
/// and that asymmetry is deliberate. The reaper refuses to act on them because
/// unknown liveness is not evidence of departure — but a DETECTOR must not go
/// quiet on the same uncertainty, or a genuinely skewed fleet running a
/// pre-liveness build would silence the very alert that exists to catch it
/// (the #625 shape: a detector disabled by exactly the condition it detects).
/// So the reaper under-acts on unknowns and the gauge over-reports them; each
/// errs toward its own safe direction.
///
/// The practical consequence, unchanged from before for that population: on a
/// pod-name-keyed fleet, rows left by pre-liveness pods keep this gauge above
/// zero until either their workers roll onto a build that pings (after which
/// they become reapable normally) or an operator drains them — with
/// `deactivate-worker-identity` per key, or by enabling
/// `TALOS_WORKER_IDENTITY_REAP_PRE_PROTOCOL_HOURS`.
///
/// Do NOT "fix" the NULL case by decaying on `last_seen_at`: that column is
/// written only at boot registration, so it cannot tell a departed pod from a
/// healthy long-lived one, and using it here would blind the gauge to a
/// genuinely stale worker that has been up for days — the case it exists to
/// catch.
///
/// Counted per distinct `worker_id`, not per row: `list_active_builds` returns
/// one row per (worker_id, key) and a worker mid-rotation legitimately holds
/// two, so a row count would render a single skewed worker as two and make the
/// number in the alert summary wrong — the metric is named `..._workers`.
/// `get_platform_info.fleet`'s `skewed_workers` counts ROWS, so the two numbers
/// can differ by the rotation overlap; the BOOLEAN they imply cannot, which is
/// the invariant that matters (`>0` here iff `build_skew: true` there).
///
/// Counts only PROVEN skew, using the same `builds_match` /
/// `build_is_verifiable` pair as the registration WARN and
/// `get_platform_info.fleet`, so the three surfaces cannot disagree about
/// whether the fleet is skewed. A worker (or controller) that reports no usable
/// commit sha is "unverifiable" and is NOT counted: absence of evidence is not
/// evidence of skew (#578). That is a deliberate under-count — an all-
/// unverifiable fleet reads 0 here — and the operator-facing surface for the
/// unverifiable population stays `get_platform_info.fleet`.
///
/// Written by hand rather than through a shared warn-and-count helper; see the
/// detector-metrics block in `talos_metrics::TalosMetrics` for why a macro
/// would re-blind structural check 58.
///
/// TEST SCOPE, stated rather than implied (same residual as the D3/D4 pins):
/// the unit tests drive THIS function. They do not prove the 60s sweep still
/// calls it, and structural check 58 cannot either — it matches the increment
/// textually, so deleting the call in `spawn_metrics_gauge_tasks` leaves both
/// green. The honest guard for the call site is the post-merge live check that
/// `talos_worker_build_skew_workers` is present on `/metrics`.
pub(crate) fn publish_worker_build_skew(
    controller_build: &str,
    rows: &[talos_worker_identity_repository::WorkerBuildRow],
    departed_after_hours: i64,
    now: chrono::DateTime<chrono::Utc>,
    heartbeating: Option<&std::collections::HashSet<String>>,
) {
    let skewed = count_skewed_live_workers(
        controller_build,
        rows,
        departed_after_hours,
        now,
        heartbeating,
    );
    if let Some(m) = metrics::global() {
        m.worker_build_skew_workers
            .set(i64::try_from(skewed).unwrap_or(i64::MAX));
    }
}

/// Whether the operator has asserted that heartbeat SILENCE is meaningful in
/// this fleet — i.e. that every worker here runs a build that publishes fleet
/// heartbeats.
///
/// **This gate exists because the exclusion it enables is not safe by
/// default, and the controller cannot check the fact it depends on.**
///
/// The registry-backed skew gauge counts a row with no liveness evidence, on
/// purpose: unknown liveness is not evidence of departure, and a detector that
/// went quiet on that uncertainty would be silenced by exactly the condition it
/// exists to catch (#625). A fleet heartbeat does NOT remove that ambiguity by
/// its ABSENCE. A worker on a build too old to publish heartbeats and a worker
/// that has departed look identical from here — that is a property of the
/// evidence, not a gap in the implementation, and it is precisely the case
/// during the rolling deploy when build skew matters most.
///
/// So the exclusion is opt-in, in the same shape and for the same reason as
/// `TALOS_WORKER_IDENTITY_REAP_PRE_PROTOCOL_HOURS`: setting it is the operator
/// asserting a fact the controller cannot verify. Turn it on only once the
/// whole fleet is known to run a heartbeat-publishing build; until then, a
/// ghost row keeps the gauge above zero, which is the honest reading.
///
/// The heartbeat-DERIVED gauges (`talos_worker_fleet_*`) are unconditional and
/// unaffected by this flag — they report only positive observations, so they
/// need no such assertion.
pub(crate) fn heartbeat_silence_is_authoritative() -> bool {
    std::env::var("TALOS_WORKER_FLEET_HEARTBEAT_AUTHORITATIVE")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

/// Whether a row is PROVABLY departed: it participated in the liveness protocol
/// and has been silent longer than the reaper's window.
///
/// `None` is NOT departed — it is unknown, and the two must never collapse.
/// Split out as a named predicate so that distinction is a thing a reader (and
/// a test) can point at rather than an inline `is_some_and` to skim past.
///
/// NOTE THE CLOCK, because it differs from the reaper's. The reaper compares
/// `last_liveness_at` against Postgres's own `now()`, so controller clock skew
/// cannot move the TRUST boundary. This predicate compares it against the
/// CONTROLLER's `now`, so skew does move the DETECTOR: a controller clock
/// running far ahead would classify live, currently-pinging workers as departed
/// and drop them from the skew gauge's population — the gauge going quiet on a
/// fleet it should be watching (#625's shape). It cannot cause a reap; only an
/// under-report. Deliberate (the gauge must not add a DB round-trip per tick),
/// but do not read "compared by Postgres" as covering this call.
fn row_is_provably_departed(
    row: &talos_worker_identity_repository::WorkerBuildRow,
    departed_after_hours: i64,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    row.last_liveness_at.is_some_and(|seen| {
        now.signed_duration_since(seen) > chrono::Duration::hours(departed_after_hours)
    })
}

/// Pure half of [`publish_worker_build_skew`] — counts distinct `worker_id`s
/// that are (a) not provably departed and (b) proven to be on a different build
/// than the controller. Extracted so the population rule is unit-testable
/// without a metrics registry or a DB.
///
/// `heartbeating` is `Some(set)` ONLY when [`heartbeat_silence_is_authoritative`]
/// is on AND the fleet view is non-empty; a row absent from that set is then
/// treated as departed. **The non-empty requirement is load-bearing**: an empty
/// fleet view means "the subscription is broken or no worker has published
/// yet", not "no worker exists", and passing it through would zero the gauge on
/// a fleet it should be watching — absent is not zero (#625).
pub(crate) fn count_skewed_live_workers(
    controller_build: &str,
    rows: &[talos_worker_identity_repository::WorkerBuildRow],
    departed_after_hours: i64,
    now: chrono::DateTime<chrono::Utc>,
    heartbeating: Option<&std::collections::HashSet<String>>,
) -> usize {
    use talos_worker_identity_repository::{build_is_verifiable, builds_match};

    let controller_verifiable = build_is_verifiable(controller_build);
    rows.iter()
        .filter(|r| !row_is_provably_departed(r, departed_after_hours, now))
        .filter(|r| match heartbeating {
            None => true,
            Some(live) => live.contains(&r.worker_id),
        })
        .filter(|r| {
            r.build_version.as_deref().is_some_and(|wb| {
                controller_verifiable
                    && build_is_verifiable(wb)
                    && !builds_match(controller_build, wb)
            })
        })
        .map(|r| r.worker_id.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len()
}

/// How recent a liveness proof must be for its worker to count as STILL
/// PINGING in `talos_worker_liveness_recent_participants`.
///
/// Two hours, chosen against the two numbers it sits between rather than
/// picked round:
///   * Above it must clear the worker's ping interval with room to spare. That
///     interval is `TALOS_WORKER_LIVENESS_INTERVAL_SECS`, clamped by the worker
///     to at most 3600s, so 2h is 2× the slowest configuration a worker can be
///     in — a worker must miss two consecutive pings at the worst-case interval
///     (or sixty at the 60s default) before it drops out. That headroom is what
///     stops this gauge flapping, and flapping here would be worse than useless:
///     the alert built on it is the one an operator is asked to trust before
///     enabling a fleet-wide trust-boundary write.
///   * Below it must leave usable warning time inside the trust window. The
///     ALERT'S LEAD TIME IS `window - horizon`, and saying so is the honest form
///     — at defaults that is 24h - 2h = 22h of visible warning before the first
///     key is deactivated, but an operator who sets
///     `TALOS_WORKER_IDENTITY_REAP_HOURS=3` gets one hour, and one who sets it
///     to 2 or less gets NONE. [`liveness_participation_horizon_hours`] clamps
///     the horizon to the window so the gauge can never count a row that is
///     already past the reap cutoff, but no clamp can manufacture lead time
///     that the configuration did not leave. If you shorten the window, shorten
///     the ping interval with it and treat this constant as part of the change.
pub(crate) const LIVENESS_PARTICIPATION_HORIZON_HOURS: i64 = 2;

/// The effective participation horizon: [`LIVENESS_PARTICIPATION_HORIZON_HOURS`],
/// never longer than the configured trust window.
///
/// The clamp is not cosmetic. Without it, an operator running
/// `TALOS_WORKER_IDENTITY_REAP_HOURS=1` would have `recent_participants` count
/// rows whose last ping was 90 minutes ago — rows the reaper is already
/// entitled to deactivate — so `participants - recent` would read 0 while a
/// reap was imminent. The detector would be silent in exactly the
/// configuration that gives an operator the least time to react.
///
/// Written as a `clamp` of the WINDOW rather than a `min`/`max` chain on the
/// constant — same answers for every input, but it says the two bounds in one
/// place (and avoids clippy's `manual_clamp`). The lower bound of 1 is
/// belt-and-braces: [`departed_liveness_cutoff_hours`] already floors the
/// window at 1, and a 0h horizon would classify every row as silent and pin
/// the alert permanently red.
pub(crate) fn liveness_participation_horizon_hours(window_hours: i64) -> i64 {
    window_hours.clamp(1, LIVENESS_PARTICIPATION_HORIZON_HOURS)
}

/// Which reaper arm deactivated a key. A closed, compile-time set — this is a
/// Prometheus label value, and the reaper is the last place that should learn
/// the unbounded-cardinality lesson the hard way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReapArm {
    /// The automatic arm: a worker PROVED liveness and then went silent past
    /// `TALOS_WORKER_IDENTITY_REAP_HOURS`.
    Departed,
    /// The opt-in arm: a row that never participated and has not re-registered
    /// within `TALOS_WORKER_IDENTITY_REAP_PRE_PROTOCOL_HOURS`.
    PreProtocol,
}

impl ReapArm {
    pub(crate) fn label(self) -> &'static str {
        match self {
            ReapArm::Departed => "departed",
            ReapArm::PreProtocol => "pre_protocol",
        }
    }
}

/// Count keys deactivated by one reaper arm onto
/// `talos_worker_identity_reaps_total{arm}`.
///
/// A no-op at `keys == 0` so the counter measures REAPS, not sweeps: the
/// sweep runs every 300s forever and its overwhelmingly common outcome is
/// "nothing to do". Counting those would put a large constant under any
/// `increase()` and drown the signal — the metric exists to answer "did this
/// controller deactivate a signing key, and when", which is the question an
/// operator has after the fleet's results stop verifying.
///
/// TEST SCOPE, stated rather than implied — the same residual
/// [`publish_worker_build_skew`] carries. The unit tests drive THIS function,
/// which is the whole recording path; they do not prove the reaper loop still
/// calls it, and structural check 58 cannot either (it matches the increment
/// textually, so deleting both call sites leaves the lint green — the
/// documented limit (b) on that check). The honest guard for the call sites is
/// review plus the post-merge live check.
pub(crate) fn record_identity_reap(arm: ReapArm, keys: u64) {
    if keys == 0 {
        return;
    }
    if let Some(m) = metrics::global() {
        m.worker_identity_reaps_total
            .with_label_values(&[arm.label()])
            .inc_by(keys as f64);
    }
}

/// Recompute and publish the D2 pair —
/// `talos_worker_liveness_participants` and
/// `talos_worker_liveness_recent_participants` — from one snapshot of the
/// ACTIVE `worker_identities` rows.
///
/// **This is the detector that makes the reaper safe to enable.** The reaper's
/// worst failure is deactivating a LIVE worker's signing key, and that failure
/// is silent for the whole trust window before it presents as fleet-wide
/// signature-verification failure. But it is not silent in its CAUSE: every
/// false reap is preceded, by a full window minus the horizon, by workers that
/// were pinging and stopped. These two gauges make that preceding state a
/// number, and `TalosWorkerLivenessParticipationDropped` alerts on it.
///
/// ALWAYS `set`, never `inc`/`dec`, for the same reason as the skew gauge: both
/// populations must be able to FALL. A worker that resumes pinging re-enters
/// `recent` with no bookkeeping, and a reaped or operator-deactivated row
/// leaves both because it is no longer `active`.
///
/// WHY BOTH, when the alert only needs the difference: because a bare "3 keys
/// have stopped pinging" is unreadable without its denominator — it is the
/// whole fleet at 3 participants and a rounding error at 300 — and the
/// operator reading this during an incident is deciding whether to disable the
/// reaper. Publishing only the difference would repeat the mistake of a judge
/// that cannot see how many runs it scored.
///
/// WHAT IS AND IS NOT IN THE POPULATION, because "participating" is easy to
/// over-read:
///   * Rows with `last_liveness_at IS NULL` are in NEITHER gauge. They have
///     never proved liveness, so the automatic reaper cannot act on them and
///     they are not at risk from it. Counting them as participants would put a
///     permanent floor under the difference on any fleet with pre-protocol
///     rows, and the alert would fire forever on a condition the reaper will
///     never act on — a permanently-firing alert is a disabled one. (They are
///     still counted by `talos_worker_build_skew_workers`, which is a different
///     question with a different safe direction; see that function.)
///   * A row past the trust window is still a participant. It is about to be
///     reaped, which is precisely what the operator needs to see.
///
/// NOTE THE CLOCK. `last_liveness_at` is written by Postgres; `now` here is the
/// CONTROLLER's. Controller clock skew therefore moves this DETECTOR (a
/// controller running fast under-reports `recent` and can make the alert fire
/// on a healthy fleet) but not the reaper, which compares both sides against
/// Postgres's own clock. Same asymmetry, same reason, as
/// [`row_is_provably_departed`]: erring toward firing is the safe direction for
/// a detector whose job is to precede a destructive write.
///
/// Counted per distinct `worker_id`, not per row — a worker mid-rotation holds
/// two rows and must not read as two workers. Both gauges use the same key, so
/// their difference is always a count of WORKERS.
///
/// TEST SCOPE: the unit tests drive this function and its pure half. They do
/// not prove the 60s sweep still calls it — see the identical note on
/// [`publish_worker_build_skew`]; the guard is the post-merge live check that
/// both series are present on `/metrics/prometheus`.
pub(crate) fn publish_worker_liveness_participation(
    rows: &[talos_worker_identity_repository::WorkerBuildRow],
    window_hours: i64,
    now: chrono::DateTime<chrono::Utc>,
) {
    let (participants, recent) = count_liveness_participants(
        rows,
        liveness_participation_horizon_hours(window_hours),
        now,
    );
    if let Some(m) = metrics::global() {
        m.worker_liveness_participants
            .set(i64::try_from(participants).unwrap_or(i64::MAX));
        m.worker_liveness_recent_participants
            .set(i64::try_from(recent).unwrap_or(i64::MAX));
        m.worker_liveness_population_truncated
            .set(i64::from(liveness_population_is_truncated(rows.len())));
    }
}

/// Did the bounded fleet query see the WHOLE active population, or did it stop
/// at the cap?
///
/// **The detector and the reaper must operate on the same population, and
/// without this they do not.** `list_active_builds` is
/// `ORDER BY worker_id, public_key LIMIT MAX_FLEET_BUILD_ROWS` (200);
/// `reap_departed_identities` is an UNBOUNDED `UPDATE`. So at 201+ active rows
/// the row sorting 201st is invisible to both participation gauges and fully
/// reapable — the silent false reap this whole area exists to prevent,
/// reintroduced above a fleet size nothing announced. And the feature's own
/// premise (every registration leaves a permanently ACTIVE row) means a
/// pod-name-keyed fleet doing daily rolls reaches 200 in weeks, so this is not
/// a hypothetical size.
///
/// SATURATING, and deliberately so: `len == LIMIT` means "at least 200 active
/// rows, possibly many more". Learning the true count needs a second query, and
/// it would not change the answer — the reaper must not act either way.
///
/// `>=`, not `>`: a fetch that returned exactly the cap may or may not have
/// been truncated, and "may have been" is the same as "was" for a gate in front
/// of an irreversible write.
pub(crate) fn liveness_population_is_truncated(active_rows_seen: usize) -> bool {
    active_rows_seen as i64 >= talos_worker_identity_repository::MAX_FLEET_BUILD_ROWS
}

/// Pure half of [`publish_worker_liveness_participation`]: returns
/// `(participants, recent_participants)` as distinct-`worker_id` counts.
///
/// `recent` is by construction a SUBSET of `participants` — it filters the
/// same rows further — so the difference the alert computes can never be
/// negative. That is worth stating because a negative difference would make
/// the alert's `> 0` silently correct-looking while measuring nothing.
pub(crate) fn count_liveness_participants(
    rows: &[talos_worker_identity_repository::WorkerBuildRow],
    horizon_hours: i64,
    now: chrono::DateTime<chrono::Utc>,
) -> (usize, usize) {
    let horizon = chrono::Duration::hours(horizon_hours);
    let mut participants = std::collections::HashSet::new();
    let mut recent = std::collections::HashSet::new();
    for row in rows {
        let Some(seen) = row.last_liveness_at else {
            continue;
        };
        participants.insert(row.worker_id.as_str());
        if now.signed_duration_since(seen) <= horizon {
            recent.insert(row.worker_id.as_str());
        }
    }
    (participants.len(), recent.len())
}

/// Default hours of liveness silence after which a PARTICIPATING worker's key
/// is treated as departed — both by the reaper and by the skew gauge's
/// population.
///
/// **This number IS the security property**: a worker's signing key is trusted
/// for at most this long PLUS the two pipeline delays below, after the worker
/// stops proving it is alive. 24h against the worker's default 60s ping
/// interval means 1440 consecutive missed pings.
///
/// STATE THE ADDITIVE TERMS RATHER THAN ROUNDING THEM AWAY — "at most 24h" is
/// the DB predicate, not the end-to-end bound. Deactivation of the row happens
/// on the next reaper tick (this module's sweep interval, 300s), and the key
/// only leaves the in-process verify ring on the next
/// `refresh_worker_key_overlay` (`TALOS_WORKER_KEY_REFRESH_SECS`, default 60s,
/// clamped 10..=3600). A captured ping can also be replayed by an on-path
/// attacker for up to `WORKER_REG_PAST_MS` (300s) past its `issued_at_ms`,
/// which shifts the start of the window by that much. So with defaults the
/// honest statement is **≤ 24h + ~11 minutes** from the worker's last genuine
/// ping; with `TALOS_WORKER_KEY_REFRESH_SECS=3600` it is ≤ 24h + ~1h10m. All
/// three terms are bounded and none can shorten the window.
///
/// Why not shorter, when a tighter bound is strictly better for the key-exposure
/// half: because the cost of being WRONG is asymmetric and severe. A reaped key
/// cannot be re-registered over the network — `register_tofu` refuses to
/// re-activate a deactivated key, which is the anti-revocation-bypass rule we
/// must not weaken — so a falsely-reaped worker needs an operator
/// `register-worker-identity` before its results verify again. 24h is chosen so
/// that no transient outage crosses it, and it is configurable downward by
/// operators who can accept that trade.
///
/// It does NOT follow that "only a genuinely departed worker can cross it".
/// Nothing ever clears `last_liveness_at`, so a worker that has pinged once is
/// permanently in this population, and a LIVE worker crosses the window
/// whenever its pinger stops for a non-departure reason: an image rollback to a
/// pre-liveness build, `TALOS_CONTROLLER_URL` removed, the interval env set to
/// `0`, a one-way worker→controller network block outlasting the window, or —
/// the one with no config change behind it, so auditing recent changes never
/// finds it — a worker clock drifting more than `WORKER_REG_FUTURE_MS` (60s)
/// AHEAD of the controller, which makes every ping fail the freshness check
/// with a 400 while the worker runs perfectly. (A MISTYPED interval is NOT one
/// of these: since #631 a non-numeric value WARNs
/// `worker_liveness_interval_unparseable` and keeps pinging at the default,
/// precisely because silently disabling was the shape that escalated a typo
/// into an outage.) Length is the only defence against those, and length alone
/// is not one. Before disabling a running worker's pinger, disable the reaper.
pub(crate) const DEFAULT_REAP_SILENCE_HOURS: i64 = 24;

/// Hours of liveness silence that mark a participating worker as departed.
/// `TALOS_WORKER_IDENTITY_REAP_HOURS`.
///
/// A non-positive or unparseable value falls back to [`DEFAULT_REAP_SILENCE_HOURS`]
/// (24), NOT to the 1h floor — the `filter(|h| *h > 0)` is what stops a typo
/// producing an instantaneous window, and the trailing `.max(1)` is therefore
/// unreachable belt-and-braces, not the live guard. Pinned by
/// `departed_cutoff_default_and_floor`.
///
/// CLAMPED AT THE TOP END TOO, and that half is not cosmetic (review 2A). The
/// value flows into two consumers that both break on an absurd one:
///   * the gauge's `chrono::Duration::hours(...)`, which PANICS above
///     ~2.56e12 hours — and the gauge sweep is a detached `tokio::spawn`, so
///     one env typo kills it permanently and freezes
///     `talos_worker_build_skew_workers` at its last value; and
///   * Postgres `now() - make_interval(hours => …)`, which raises "timestamp
///     out of range" above ~5.9e7 hours, turning the sweep into a per-tick
///     WARN rather than the "even longer window" the saturating `i32::try_from`
///     was described as producing.
/// [`MAX_REAP_SILENCE_HOURS`] (10 years) is far below both limits, so neither
/// consumer can be driven out of range by configuration. Clamping UP to a very
/// long window is the safe direction (it deactivates less, never more).
pub(crate) fn departed_liveness_cutoff_hours() -> i64 {
    std::env::var("TALOS_WORKER_IDENTITY_REAP_HOURS")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|h| *h > 0)
        .unwrap_or(DEFAULT_REAP_SILENCE_HOURS)
        .clamp(1, MAX_REAP_SILENCE_HOURS)
}

/// Upper bound on the configured trust window: 10 years in hours. Not a policy
/// number — a range guard. See [`departed_liveness_cutoff_hours`] for the two
/// consumers it protects.
pub(crate) const MAX_REAP_SILENCE_HOURS: i64 = 24 * 365 * 10;

/// Recompute and publish the eight `talos_worker_fleet_*` gauges from one
/// read of the NATS heartbeat view.
///
/// **"One read" is a statement about the SOURCE, not about the wire.** All
/// eight values are derived from the same set of accessor calls on the same
/// tick, so they are mutually consistent as computed. They are then `set` into
/// eight independent `IntGauge`s in sequence, and `registry.gather()` runs on
/// the scrape task — so a scrape that lands mid-sequence can observe a MIX of
/// two sweeps and, transiently, an inconsistent decomposition (e.g.
/// `live_builds < skew + unverifiable`). The window is the handful of atomic
/// stores below, sub-microsecond against a 60s sweep, and every alert built on
/// these carries a `for:` of 30m or more, which absorbs it. Do not read this
/// as an atomic multi-series snapshot; there is no such thing in the
/// `prometheus` crate's model.
///
/// Purely ADDITIVE to the registry-backed gauges: it reports only positive
/// observations (workers that just spoke), so unlike a population NARROWING it
/// needs no operator assertion and cannot silence anything. See
/// [`heartbeat_silence_is_authoritative`] for the narrowing that does.
///
/// **TWO POPULATIONS, and conflating them is a reporting defect rather than a
/// rounding error.** `live_worker_ids` / `per_worker_builds` describe
/// heartbeating IDENTITIES; `distinct_builds` describes distinct BUILDS
/// observed. Each population gets its own numerator pair over its own
/// denominator, and each decomposes exactly:
///
/// * `live_builds   == build_skew_builds  + unverifiable_builds  + agreeing`
/// * `live_workers  == build_skew_workers + unverifiable_workers + agreeing`
///
/// Reading a builds numerator against an ids denominator is how "1 skewed of 1
/// live worker" comes to read as a wholly skewed fleet that is really one pod
/// in ten. `unverifiable` is published in BOTH populations for the same
/// reason: it sits in the denominator, so a 0 skew over a population
/// containing it is NOT a clean bill of health, and folding it away would
/// render an absence as a negative result.
///
/// **THE ALERT IS ON THE BUILD POPULATION, and only that one.** The ids
/// population cannot support a skew alert where replicas share a `worker_id`:
/// the fleet map is last-write-wins, so a per-worker skew count alternates on
/// a mixed-build fleet and no `for:` duration elapses. (A UNIFORMLY skewed
/// shared-id fleet was always steady and always alerted — that half was never
/// broken, and under DISTINCT ids, which is the chart default because nothing
/// renders `TALOS_WORKER_ID`, the per-worker count is steady in every case.)
/// The ids population is published anyway because it carries the MAGNITUDE —
/// how many pods, not how many builds — which the build population structurally
/// cannot. See the `talos_worker_fleet` module header.
///
/// `worker_id` never reaches a label here — every accessor hands out its
/// values WITHOUT the identities they belong to, precisely so a caller-supplied
/// string cannot become unbounded series cardinality. Neither does the build
/// string, which is caller-supplied too.
pub(crate) fn publish_worker_fleet_gauges(
    controller_build: &str,
    live_worker_ids: usize,
    distinct_builds: &[Option<String>],
    per_worker_builds: &[Option<String>],
    capacity_drops: u64,
    build_capacity_drops: u64,
) {
    let (skewed, unverifiable) = count_heartbeat_build_skew(controller_build, distinct_builds);
    // Same classifier, second population. `per_worker_builds` has one element
    // per tracked `worker_id`, so its length is `live_worker_ids` and the
    // decomposition documented above holds by construction.
    let (skewed_workers, unverifiable_workers) =
        count_heartbeat_build_skew(controller_build, per_worker_builds);
    if let Some(m) = metrics::global() {
        m.worker_fleet_live_workers
            .set(i64::try_from(live_worker_ids).unwrap_or(i64::MAX));
        m.worker_fleet_live_builds
            .set(i64::try_from(distinct_builds.len()).unwrap_or(i64::MAX));
        m.worker_fleet_build_skew_builds
            .set(i64::try_from(skewed).unwrap_or(i64::MAX));
        m.worker_fleet_unverifiable_builds
            .set(i64::try_from(unverifiable).unwrap_or(i64::MAX));
        m.worker_fleet_build_skew_workers
            .set(i64::try_from(skewed_workers).unwrap_or(i64::MAX));
        m.worker_fleet_unverifiable_workers
            .set(i64::try_from(unverifiable_workers).unwrap_or(i64::MAX));
        m.worker_fleet_capacity_dropped_heartbeats
            .set(i64::try_from(capacity_drops).unwrap_or(i64::MAX));
        m.worker_fleet_capacity_dropped_builds
            .set(i64::try_from(build_capacity_drops).unwrap_or(i64::MAX));
    }
}

/// Pure half of [`publish_worker_fleet_gauges`]: `(provably skewed,
/// unverifiable)` over a slice of self-reported builds.
///
/// **The FUNCTION did not change when the gauges moved to a build-keyed
/// population in 2026-08; only its INPUT did** — from one element per
/// heartbeating `worker_id` to one per distinct build. That is the whole of
/// the fix, and it is why the classification rules below are untouched: what
/// was wrong was never how a build was judged, it was that a last-write-wins
/// map had already discarded the second build before anything got to judge it.
///
/// `None` — reported nothing, or something the fleet view refused to retain —
/// counts as UNVERIFIABLE, never as skew, and is returned rather than
/// discarded so the caller can publish it. A zero skew over a population
/// holding an unverifiable element is not "the fleet agrees".
///
/// Uses the SAME `builds_match` / `build_is_verifiable` pair as the
/// registration WARN, `get_platform_info.fleet` and the registry-backed gauge,
/// so the four surfaces cannot disagree about whether a build is skewed.
/// A worker (or controller) reporting no usable sha is unverifiable and is NOT
/// counted as skewed — absence of evidence is not evidence of skew (#578) —
/// which is why the unverifiable count is returned rather than discarded.
pub(crate) fn count_heartbeat_build_skew(
    controller_build: &str,
    live_builds: &[Option<String>],
) -> (usize, usize) {
    use talos_worker_identity_repository::{build_is_verifiable, builds_match};
    let controller_verifiable = build_is_verifiable(controller_build);
    let mut skewed = 0usize;
    let mut unverifiable = 0usize;
    for b in live_builds {
        match b.as_deref() {
            Some(wb) if controller_verifiable && build_is_verifiable(wb) => {
                if !builds_match(controller_build, wb) {
                    skewed += 1;
                }
            }
            _ => unverifiable += 1,
        }
    }
    (skewed, unverifiable)
}

/// Subscribe to the NATS worker-fleet heartbeat and publish the fleet gauges.
///
/// **This is the call site `start_worker_management` never had.** Until 2026-08
/// it had zero callers, nothing published a heartbeat, and the message keyed on
/// a `Uuid` where the identity registry keys on operator/pod text — so the
/// fleet view was permanently empty AND unjoinable. It nonetheless read as
/// live, and twice led a design toward intersecting the identity registry
/// against it, which would have deactivated the whole fleet's signing keys on
/// the first sweep.
///
/// VERIFY-ONCE (CLAUDE.md). `WorkerManager::handle_heartbeat` is the single
/// primary `verify()` caller for `WorkerHeartbeat` in this process. The gauge
/// task below reads the MAP that verification populates — it never touches the
/// message — so it cannot become a second `verify()` and collide on the shared
/// process-local nonce cache (the r300/r301 total outage).
pub(crate) fn spawn_worker_fleet_tasks(
    worker_manager: std::sync::Arc<talos_worker_fleet::WorkerManager>,
    nats_client: Option<std::sync::Arc<async_nats::Client>>,
) {
    let Some(nats) = nats_client else {
        tracing::warn!(
            target: "talos_worker_fleet",
            "worker-fleet heartbeat listener not started: NATS_URL not configured. \
             talos_worker_fleet_live_workers will stay at 0 — read that as 'not \
             observed', not as 'no workers'."
        );
        return;
    };

    {
        let manager = worker_manager.clone();
        tokio::spawn(async move {
            if let Err(e) =
                talos_worker_fleet::start_worker_management(manager, (*nats).clone()).await
            {
                tracing::error!(
                    target: "talos_worker_fleet",
                    error = %e,
                    "failed to start worker-fleet heartbeat management"
                );
            }
        });
    }

    // Gauge sweep. Same 60s cadence as the registry-backed build-skew sweep so
    // the two views of the fleet are never more than one interval apart when an
    // operator reads them side by side.
    tokio::spawn(async move {
        let controller_build = crate::bootstrap::router::controller_build_version();
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            publish_worker_fleet_gauges(
                &controller_build,
                worker_manager.worker_count(),
                // The ALERTED population. `live_distinct_builds()` retains
                // every build actually observed, so it is steady where
                // `live_build_versions()` — per-`worker_id`, and therefore
                // holding only the last writer's build on a shared-id fleet —
                // alternates.
                &worker_manager.live_distinct_builds(),
                // The MAGNITUDE population, informational only. One element
                // per tracked `worker_id`; meaningful where replicas carry
                // distinct ids (the chart default), 0-or-1 where they share
                // one. No alert is built on the gauges derived from it.
                &worker_manager.live_build_versions(),
                worker_manager.capacity_drops(),
                worker_manager.build_capacity_drops(),
            );
        }
    });
}

// ===========================================================================
// Fuel-headroom detector
// ===========================================================================

/// Utilisation at or above which a `(workflow, node)` pair is reported as
/// having no fuel headroom.
///
/// **Derived, not guessed** — and the derivation is a floor, not a forecast.
/// `docs/fuel-budget-sizing.md` already stated "a node sitting above ~80%
/// utilisation on a full payload has no headroom and should be treated as
/// already failing"; this constant is that sentence made checkable. What the
/// live database says about the choice (2026-08-17, 30-day window, test runs
/// excluded, ceiling taken from each node's most recent enforced limit):
///
/// | threshold | pairs flagged of 77 |
/// |---|---|
/// | 70% | 2 |
/// | 80% | **1** |
/// | 90% | 1 |
///
/// The single pair at ≥80% is `pa-read-later-digest/digest` at 96.9% on two
/// samples — the node this detector exists for. The next-highest pair on the
/// whole fleet is `pa-daily-brief/calendar_work` at 71.0%, so 80% sits in a
/// genuine gap in the distribution rather than on a cliff edge: nothing between
/// 71.0% and 96.9% exists to be moved across by a small change in the number.
/// That gap is also not an accident — adaptive fuel's `2 × p95` ceiling settles
/// a busy node near 50-60%, so the healthy population has a ceiling of its own.
const FUEL_HIGH_UTILISATION_THRESHOLD: f64 = 0.80;

/// Window over which peak consumption is measured. Matches
/// `talos_engine::adaptive_fuel::WINDOW_DAYS` so the detector and the learner
/// describe the same stretch of history — a detector on a shorter window would
/// go quiet on exactly the low-cadence nodes the learner already cannot see.
///
/// Concretely: at 7 days the acceptance case is INVISIBLE. `digest` runs weekly,
/// its two samples are older than a week, and the 7-day fleet maximum is 55.1%.
const FUEL_HEADROOM_WINDOW_DAYS: i32 = 30;

/// Hard bound on aggregate rows pulled per sweep. One row per `(workflow, node)`
/// pair; the live fleet has 77.
///
/// The query orders by utilisation DESC, so truncation drops the LOWEST pairs:
/// the numerator stays complete and only the denominator under-reports. That is
/// the safe direction, and at 65× headroom it is remote — but it is a real
/// limitation rather than an impossibility, so the sweep WARNs when it hits the
/// bound instead of silently publishing a short denominator.
const MAX_FUEL_HEADROOM_ROWS: i64 = 5_000;

/// How many offenders the WARN line names. The metric is unlabelled by design,
/// so this log is one of the two places the operator learns WHICH node — bounded
/// because the other end of "unbounded cardinality" is an unbounded log line.
const FUEL_HEADROOM_LOG_NAMES: usize = 10;

/// Pure half of [`publish_fuel_utilisation`]: classify one snapshot.
///
/// Split out so the acceptance case can be asserted without a database. The
/// unit tests drive THIS function with the real measured numbers.
pub(crate) fn summarise_fuel_utilisation(
    rows: &[talos_analytics_repository::NodeFuelHeadroom],
    threshold: f64,
) -> (i64, i64) {
    let observed = rows.len() as i64;
    let high = rows.iter().filter(|r| r.utilisation() >= threshold).count() as i64;
    (observed, high)
}

/// Recompute and publish the fuel-headroom gauges from one snapshot, and name
/// the offenders in a WARN.
///
/// ALWAYS `set`, never `inc` — an under-provisioned node is durable state, so
/// the gauge must be able to fall when the budget is raised and the node next
/// runs.
///
/// NO SAMPLE FLOOR ANYWHERE ON THIS PATH. The query does not apply one and
/// neither does this function. `pa-read-later-digest/digest` had two samples;
/// `MIN_SAMPLES = 5` is why the adaptive learner could not see it and
/// `min_executions = 3` is why `get_fuel_usage_report` could not either. A floor
/// here would make this the third surface blind to the same node.
///
/// TEST SCOPE, stated rather than implied — the same residual the build-skew
/// gauge carries: the unit tests drive THIS function, and structural check 58
/// matches the `.set()` textually, so deleting the call in
/// `spawn_metrics_gauge_tasks` leaves both the tests and the lint green. The
/// honest guard for the CALL SITE is that
/// `talos_fuel_utilisation_observed_nodes` reads 0 forever on a fleet that has
/// executed workflows — which is precisely what
/// `TalosFuelHeadroomDetectorBlind` alerts on. That alert is this function's
/// call-site test, running continuously in production.
pub(crate) fn publish_fuel_utilisation(
    rows: &[talos_analytics_repository::NodeFuelHeadroom],
    threshold: f64,
) {
    let (observed, high) = summarise_fuel_utilisation(rows, threshold);

    if let Some(m) = metrics::global() {
        m.fuel_utilisation_observed_nodes.set(observed);
        m.fuel_high_utilisation_nodes.set(high);
    }

    if high == 0 {
        return;
    }

    // The metric cannot carry node identity (unbounded cardinality), so this is
    // where the operator finds out which node. Bounded to the worst N.
    let named: Vec<String> = rows
        .iter()
        .filter(|r| r.utilisation() >= threshold)
        .take(FUEL_HEADROOM_LOG_NAMES)
        .map(|r| {
            format!(
                "{}/{} {:.1}% (peak {} of {}, n={})",
                r.workflow_name,
                r.node_label,
                r.utilisation() * 100.0,
                r.peak_fuel,
                r.current_ceiling,
                r.samples
            )
        })
        .collect();

    tracing::warn!(
        target: "talos_fuel",
        event_kind = "fuel_headroom_low",
        high_utilisation_nodes = high,
        observed_nodes = observed,
        threshold_pct = threshold * 100.0,
        window_days = FUEL_HEADROOM_WINDOW_DAYS,
        nodes = %named.join("; "),
        "nodes running with no fuel headroom: peak consumption is at or above \
         the threshold share of the ceiling last enforced for them. A node at \
         this level fails on its next larger payload, and the sample count is \
         NOT a reason to discount it — the case this detector was built for had \
         two samples. Size from the node's configured maximum \
         (docs/fuel-budget-sizing.md), not from the last observed run."
    );
}

/// `actor_memory` rows whose `value_key_id` names a DEK that is gone.
pub(crate) const ACTOR_MEMORY_ORPHAN_SQL: &str = "SELECT COUNT(*) FROM actor_memory am \
     WHERE NOT EXISTS ( \
         SELECT 1 FROM encryption_keys ek WHERE ek.id = am.value_key_id \
     )";

/// `module_executions` rows whose `payload_enc_key_id` names a DEK that is
/// gone. The column is NULLABLE — a row with no encrypted payload is not an
/// orphan, so the `IS NOT NULL` predicate is load-bearing, not defensive.
pub(crate) const MODULE_EXECUTION_ORPHAN_SQL: &str = "SELECT COUNT(*) FROM module_executions me \
     WHERE me.payload_enc_key_id IS NOT NULL \
       AND NOT EXISTS ( \
         SELECT 1 FROM encryption_keys ek WHERE ek.id = me.payload_enc_key_id \
     )";

/// `workflow_executions` rows whose `output_enc_key_id` names a DEK that is
/// gone. Same nullable-column reasoning as [`MODULE_EXECUTION_ORPHAN_SQL`].
pub(crate) const WORKFLOW_EXECUTION_ORPHAN_SQL: &str =
    "SELECT COUNT(*) FROM workflow_executions we \
     WHERE we.output_enc_key_id IS NOT NULL \
       AND NOT EXISTS ( \
         SELECT 1 FROM encryption_keys ek WHERE ek.id = we.output_enc_key_id \
     )";

/// One sweep's worth of crypto-orphan probes: per-table counts, each of which
/// may have failed independently.
///
/// The error is carried as a `String` rather than a `sqlx::Error` for one
/// reason only: [`publish_crypto_orphan_scan`] is the PRODUCTION publisher and
/// a unit test has to be able to hand it a failed probe without a database.
/// `sqlx::Error` is not constructible from outside sqlx for the variants that
/// matter here.
#[derive(Debug, Default)]
pub(crate) struct CryptoOrphanScan {
    pub actor_memory: Option<Result<i64, String>>,
    pub module_executions: Option<Result<i64, String>>,
    pub workflow_executions: Option<Result<i64, String>>,
}

impl CryptoOrphanScan {
    /// True only when every probe returned a count.
    ///
    /// `None` (probe not attempted) counts as NOT complete, which is why the
    /// fields are `Option<Result<..>>` and not `Result<..>`: a future refactor
    /// that skips a probe must not be able to advance the freshness stamp.
    fn is_complete(&self) -> bool {
        matches!(self.actor_memory, Some(Ok(_)))
            && matches!(self.module_executions, Some(Ok(_)))
            && matches!(self.workflow_executions, Some(Ok(_)))
    }
}

/// Run the three orphan probes. Each is independent — one failure does not
/// skip the others, because two measured gauges are strictly better than none
/// and the freshness stamp records that the sweep was incomplete either way.
async fn run_crypto_orphan_scan(pool: &sqlx::PgPool) -> CryptoOrphanScan {
    async fn probe(pool: &sqlx::PgPool, sql: &'static str) -> Option<Result<i64, String>> {
        Some(
            sqlx::query_scalar::<_, i64>(sql)
                .fetch_one(pool)
                .await
                .map_err(|e| e.to_string()),
        )
    }
    CryptoOrphanScan {
        actor_memory: probe(pool, ACTOR_MEMORY_ORPHAN_SQL).await,
        module_executions: probe(pool, MODULE_EXECUTION_ORPHAN_SQL).await,
        workflow_executions: probe(pool, WORKFLOW_EXECUTION_ORPHAN_SQL).await,
    }
}

/// Publish one sweep. Split out from the spawned task so a unit test can drive
/// the PRODUCTION path and assert what a FAILED probe does to the exported
/// state — CLAUDE.md's check-58 guidance, and the same split as
/// `publish_catalog_missing_wasm`.
///
/// **What changed on 2026-08-20 and why.** This was three
/// `if let Ok(row) = …fetch_one(&pool).await { gauge.set(row) }` blocks. On
/// `Err` nothing was set and nothing was logged, so the gauge held its
/// registration-time 0 and all three `critical` / data-loss alerts
/// (`TalosActorMemoryDEKOrphaned`, `TalosModuleExecutionPayloadOrphaned`,
/// `TalosWorkflowOutputPayloadOrphaned`) were permanently unfireable while
/// looking exactly like a clean bill of health. An orphaned row is ciphertext
/// whose DEK no longer exists — unrecoverable data — so the silent 0 was the
/// worst form of the class: a monitor that cannot fire, on the one condition
/// nothing else in the platform reports.
///
/// **The gauges still HOLD their last value on failure; that part was right.**
/// Zeroing a count nobody measured would read as "the orphans were repaired",
/// and publishing a sentinel would make the counts untrustworthy to every
/// other consumer. What was missing was a way to tell a held value from a
/// measured one, and that is a SEPARATE series —
/// `talos_crypto_orphan_scan_last_success_timestamp_seconds`, stamped only
/// when all three probes returned.
///
/// Takes the collector explicitly rather than reading `metrics::global()` so a
/// test does not have to win a race for a process-wide `OnceLock`.
pub(crate) fn publish_crypto_orphan_scan(
    metrics: Option<&talos_metrics::TalosMetrics>,
    scan: &CryptoOrphanScan,
) {
    // No key id, no row content, no tenant identifier reaches a log line or a
    // label — the table name is a compile-time constant and the error text is
    // the driver's, which carries the failing statement, not its data.
    for (table, probe) in [
        ("actor_memory", &scan.actor_memory),
        ("module_executions", &scan.module_executions),
        ("workflow_executions", &scan.workflow_executions),
    ] {
        if let Some(Err(e)) = probe {
            tracing::warn!(
                target: "talos_crypto",
                event_kind = "crypto_orphan_probe_failed",
                table,
                error = %e,
                "crypto-orphan probe failed; talos_{}_orphaned_rows is holding a value \
                 it did not measure and its critical data-loss alert cannot fire until \
                 talos_crypto_orphan_scan_last_success_timestamp_seconds advances again",
                table
            );
        }
    }

    let Some(m) = metrics else {
        return;
    };
    if let Some(Ok(row)) = &scan.actor_memory {
        m.actor_memory_orphaned_rows.set(*row);
    }
    if let Some(Ok(row)) = &scan.module_executions {
        m.module_execution_orphaned_rows.set(*row);
    }
    if let Some(Ok(row)) = &scan.workflow_executions {
        m.workflow_execution_orphaned_rows.set(*row);
    }
    if scan.is_complete() {
        // `unwrap_or(0.0)` on a pre-epoch clock stamps 0, which the alert
        // reads as maximally stale — the fail-SAFE direction. A clock that
        // cannot produce a unix time is not evidence that the sweep ran.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        m.crypto_orphan_scan_last_success_timestamp_seconds.set(now);
    }
}

/// Embedding-provider re-probe loop + crypto-invariant orphan gauges +
/// worker build-skew gauge + DB-pool saturation gauges. Extracted verbatim from
/// `main()`; spawn order preserved.
pub(crate) fn spawn_metrics_gauge_tasks(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    worker_manager: std::sync::Arc<talos_worker_fleet::WorkerManager>,
) {
    // Background refresh — every 5 min, re-probe the provider so that
    // operator config rotations (key swap, URL change, tier upgrade) are
    // picked up without a controller restart. The interval is intentionally
    // long: even Voyage's free 3 RPM tier loses just ~6% of capacity to
    // these probes.
    tokio::spawn(async {
        let mut ticker = tokio::time::interval(crate::mcp::search::PROVIDER_PROBE_INTERVAL);
        // First tick fires immediately — skip it so we don't double-probe at boot.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            crate::mcp::search::refresh_embedding_provider_health().await;
        }
    });

    // Background task: crypto-invariant orphan counts. Runs every 60s
    // and updates three gauges the alerts in
    // deploy/observability/alerts.yaml page on. A value > 0 for any of
    // them means at-rest encrypted data is unrecoverable — the same
    // failure mode that silently bit us on 2026-04-24 before Vault
    // persistence was wired up. See docs/security/operational-runbook.md.
    //
    // COST, stated: three `SELECT COUNT(*)` with a `NOT EXISTS` anti-join
    // against `encryption_keys(id)` (primary key), once a minute — unchanged
    // by the 2026-08-20 blindness fix, which adds no query and no round trip.
    {
        let pool = db_pool.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            // First tick fires immediately — skip it so startup isn't noisy.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let scan = run_crypto_orphan_scan(&pool).await;
                publish_crypto_orphan_scan(metrics::global().map(|m| m.as_ref()), &scan);
            }
        });
    }

    // Background task: fuel-headroom detector. Runs every 5 min and republishes
    // `talos_fuel_high_utilisation_nodes` + its denominator from
    // `execution_cost_rollup`.
    //
    // WHY A SWEEP AND NOT A HOOK. The obvious alternative is to check
    // utilisation inline in `ControllerNodeHook::on_node_completed`, which
    // already writes the rollup row. That would be a per-EXECUTION event, and
    // the condition is not an event: a node stays under-provisioned between
    // runs, and `digest` runs weekly. A counter incremented at completion would
    // be silent for six days out of seven on exactly the node this exists for,
    // and an alert built on `increase(...)` over it could not fire at all. A
    // recomputed gauge is level-triggered — it holds the condition up for as
    // long as the condition holds.
    //
    // WHY 5 MINUTES. The input is a 30-day aggregate; it cannot move
    // meaningfully faster than executions arrive. The query measured ~33 ms
    // against 24k rollup rows on 2026-08-17.
    //
    // Unconditional: no config gate. A detector behind a flag that defaults off
    // is a detector that is off.
    {
        let pool = db_pool.clone();
        tokio::spawn(async move {
            let repo = talos_analytics_repository::AnalyticsRepository::new(pool);
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(300));
            // First tick fires immediately — skip it so the first sweep runs
            // after the rollup has had a moment rather than during boot.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                match repo
                    .get_node_fuel_headroom(
                        None, // fleet-wide: this is an operator gauge, not a tenant surface
                        FUEL_HEADROOM_WINDOW_DAYS,
                        MAX_FUEL_HEADROOM_ROWS,
                    )
                    .await
                {
                    Ok(rows) => {
                        if rows.len() as i64 >= MAX_FUEL_HEADROOM_ROWS {
                            // Ordered utilisation DESC, so the offenders are all
                            // present and only the denominator is short. Say so
                            // rather than publish a number that reads as the
                            // whole fleet.
                            tracing::warn!(
                                target: "talos_fuel",
                                event_kind = "fuel_headroom_truncated",
                                cap = MAX_FUEL_HEADROOM_ROWS,
                                "fuel-headroom sweep hit its row cap; \
                                 talos_fuel_utilisation_observed_nodes \
                                 under-reports the fleet (the high-utilisation \
                                 count is unaffected — the query orders by \
                                 utilisation descending)"
                            );
                        }
                        publish_fuel_utilisation(&rows, FUEL_HIGH_UTILISATION_THRESHOLD);
                    }
                    Err(e) => {
                        // Leave BOTH gauges at their last values rather than
                        // publishing a 0 we did not measure. Zeroing the
                        // denominator on a DB blip would trip the
                        // detector-blind alert on a healthy fleet; zeroing the
                        // numerator would read as "all nodes fixed".
                        tracing::warn!(
                            target: "talos_fuel",
                            error = %e,
                            "fuel-headroom sweep could not read execution_cost_rollup; \
                             gauges left at their previous values"
                        );
                    }
                }
            }
        });
    }

    // Background task: controller↔worker build-skew gauge. Runs every 60s and
    // republishes `talos_worker_build_skew_workers` from the ACTIVE
    // `worker_identities` rows.
    //
    // Why a GAUGE and not a counter on the existing `worker_build_skew` WARN:
    // that WARN fires exactly once per worker, at registration. A counter over
    // it would fire on EVERY rolling deploy (each worker re-registers, briefly
    // ahead of or behind the controller) and would then go SILENT while a
    // fleet sat skewed for days — wrong at both ends. A recomputed gauge is
    // level-triggered: it stays up while the condition holds and falls back to
    // 0 once the fleet converges or the stale rows are deactivated. "Retiring"
    // a worker POD is not enough — see the population caveat on
    // `publish_worker_build_skew` above; nothing reaps rows for pods that are
    // gone, so on a pod-name-keyed fleet this gauge needs an operator to drain
    // it after the first controller upgrade.
    //
    // Unconditional: no config gate, no feature flag. The query is one bounded
    // SELECT over a fleet-sized table (MAX_FLEET_BUILD_ROWS = 200).
    {
        let pool = db_pool.clone();
        let fleet = worker_manager.clone();
        tokio::spawn(async move {
            let repo = talos_worker_identity_repository::WorkerIdentityRepository::new(pool);
            let controller_build = crate::bootstrap::router::controller_build_version();
            let heartbeat_authoritative = heartbeat_silence_is_authoritative();
            if heartbeat_authoritative {
                tracing::info!(
                    target: "worker_registry",
                    "TALOS_WORKER_FLEET_HEARTBEAT_AUTHORITATIVE is set: registry rows with \
                     no recent NATS fleet heartbeat are excluded from \
                     talos_worker_build_skew_workers. This is an OPERATOR ASSERTION that \
                     every worker in this fleet runs a build that publishes heartbeats — \
                     the controller cannot check it, and if it is false a genuinely \
                     skewed worker on an older build is silenced. The heartbeat-derived \
                     talos_worker_fleet_* gauges are unaffected either way."
                );
            }
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            // First tick fires immediately — skip it so startup isn't noisy and
            // workers get a moment to register.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                match repo.list_active_builds().await {
                    Ok(rows) => {
                        let window_hours = departed_liveness_cutoff_hours();
                        let now = chrono::Utc::now();
                        // `Some(..)` ONLY when the operator has asserted that
                        // silence is meaningful AND the view is non-empty. An
                        // empty view means "nothing observed" — passing it
                        // through would zero the gauge on a fleet it should be
                        // watching, which is absent-read-as-zero (#625).
                        let live_ids = if heartbeat_authoritative {
                            let ids = fleet.live_worker_ids();
                            if ids.is_empty() {
                                None
                            } else {
                                Some(ids)
                            }
                        } else {
                            None
                        };
                        publish_worker_build_skew(
                            &controller_build,
                            &rows,
                            window_hours,
                            now,
                            live_ids.as_ref(),
                        );
                        // The D2 pair rides the SAME snapshot, deliberately:
                        // `list_active_builds` already returns
                        // `last_liveness_at` for every active row, so the
                        // liveness-participation gauges cost zero extra
                        // queries and zero extra DB round trips. A separate
                        // sweep would have added a second bounded SELECT for
                        // data already in hand — and would have let the two
                        // gauges disagree about which instant they describe.
                        publish_worker_liveness_participation(&rows, window_hours, now);
                    }
                    Err(e) => {
                        // Leave the gauge at its last value rather than
                        // publishing a 0 we did not measure — a DB blip must
                        // not read as "fleet converged".
                        tracing::warn!(
                            target: "worker_registry",
                            error = %e,
                            "worker build-skew gauge sweep could not list active builds"
                        );
                    }
                }
            }
        });
    }

    // Background task: worker-identity reaper — bounds how long a DEPARTED
    // worker's Ed25519 public key stays in the controller's trusted verify
    // ring.
    //
    // THE PROBLEM IT SOLVES. A key entered the ring at boot registration and
    // left it only via an operator's `deactivate-worker-identity`. So every
    // worker that ever registered — CI container, review rig, scaled-down
    // replica, crashed pod — left a permanently trusted signing identity.
    //
    // WHY IT KEYS ON `last_liveness_at` AND NOT `last_seen_at`. `last_seen_at`
    // is written ONLY at boot registration: there is no periodic re-register,
    // so decaying on it would deactivate a long-lived HEALTHY worker.
    // `last_liveness_at` is written by the worker's periodic Ed25519
    // proof-of-possession ping, so silence on it is real evidence.
    //
    // AND WHY NOT THE NATS FLEET HEARTBEAT, which since 2026-08 IS published
    // by every worker and IS keyed on the same text `worker_id` as this table
    // — i.e. it is now perfectly joinable, which it was not when this comment
    // was first written. Because joinability was never the reason. A heartbeat
    // is an HMAC under the FLEET-SHARED `WORKER_SHARED_KEY`: any process
    // holding that key can mint one naming ANY worker_id, so feeding it into
    // this window would let one fleet member keep every other member's signing
    // key trusted indefinitely — exactly the unbounded trust this reaper
    // exists to bound. The heartbeat is an observability hint; the ping is a
    // credential. `talos-worker-fleet` cannot reach this table at all
    // (structural lint check 67 cuts both the code path and the dependency
    // edge), which is what makes the separation structural rather than a
    // matter of which line got written today.
    //
    // SCOPE — what reaping a row does NOT remove. The verify ring is
    // `union(TALOS_WORKER_PUBLIC_KEYS env base, active DB rows)`, rebuilt by
    // `set_dynamic_worker_public_keys` from an IMMUTABLE env base. So a
    // worker_id pinned in the env keeps verifying after its DB row is reaped —
    // the bound below applies to the DB overlay ONLY. State it that way rather
    // than as "an env-pinned fleet has no rows": it may well have rows (the dev
    // stack pins `dev-worker-fleet` in the env AND has its registered row), and
    // reaping them changes nothing for that identity. Un-pinning the env entry
    // is the only way to put an env-listed key under this window.
    //
    // FAIL-SAFE DIRECTION — argued, not assumed. "Safe" here is DO NOT
    // DEACTIVATE, because the two errors are wildly asymmetric:
    //   * Falsely reaping a LIVE worker breaks verification of its signed
    //     results, and it cannot recover on its own — `register_tofu` refuses
    //     to re-activate a deactivated key (the rule that stops a shared-token
    //     holder undoing a revocation, which we must not weaken). It needs an
    //     operator. A sweep bug therefore manufactures a fleet-wide outage.
    //   * Failing to reap a DEAD worker leaves its PUBLIC key verifying. To
    //     exploit that, an attacker must already hold the corresponding PRIVATE
    //     key — i.e. must already have compromised that worker. So the miss
    //     widens an existing compromise window; it does not create one. It is
    //     also exactly the status quo this task improves on.
    // Every branch below therefore biases toward inaction: disabled unless
    // explicitly configured, NULL-liveness rows untouchable, and a DB error
    // deactivates nothing (the reap is a single guarded UPDATE, so an error
    // leaves the fleet exactly as it was).
    {
        let pool = db_pool.clone();
        tokio::spawn(async move {
            let repo = talos_worker_identity_repository::WorkerIdentityRepository::new(pool);
            let silence_hours = departed_liveness_cutoff_hours();

            // Opt-in second arm for rows that NEVER participated (registered
            // before the liveness protocol existed). Default OFF and separate
            // on purpose: it keys on `last_seen_at`, so it cannot tell a
            // departed pod from a healthy long-lived one on an old build.
            // Setting it is the operator asserting a fact the controller cannot
            // check — that their fleet has finished rolling onto a build that
            // pings. See `reap_pre_protocol_identities`.
            let pre_protocol_hours: Option<i64> =
                std::env::var("TALOS_WORKER_IDENTITY_REAP_PRE_PROTOCOL_HOURS")
                    .ok()
                    .and_then(|v| v.trim().parse::<i64>().ok())
                    .filter(|h| *h > 0)
                    // Same top-end range guard as the automatic arm: an absurd
                    // value must not push `make_interval` past Postgres's
                    // minimum timestamp and turn the sweep into a per-tick
                    // error. See `departed_liveness_cutoff_hours`.
                    .map(|h| h.clamp(1, MAX_REAP_SILENCE_HOURS));

            let enabled = std::env::var("TALOS_WORKER_IDENTITY_REAP_ENABLED")
                .map(|v| {
                    let v = v.trim().to_ascii_lowercase();
                    matches!(v.as_str(), "1" | "true" | "yes" | "on")
                })
                .unwrap_or(false);
            if !enabled {
                tracing::info!(
                    target: "worker_registry",
                    "worker-identity reaper disabled (TALOS_WORKER_IDENTITY_REAP_ENABLED unset); \
                     departed workers' keys stay in the trusted verify ring until an operator \
                     runs deactivate-worker-identity"
                );
                return;
            }
            tracing::info!(
                target: "worker_registry",
                silence_hours,
                pre_protocol_hours = ?pre_protocol_hours,
                sweep_interval_secs = 300,
                "worker-identity reaper enabled: a key stops being trusted at \
                 most silence_hours + one sweep interval + one worker-key \
                 overlay refresh (TALOS_WORKER_KEY_REFRESH_SECS) after its \
                 worker stops proving liveness"
            );

            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(300));
            ticker.tick().await;
            loop {
                ticker.tick().await;

                // ── THE OBSERVABILITY PRECONDITION ────────────────────────
                //
                // REFUSE TO SWEEP WHEN THE DETECTOR CANNOT SEE THE WHOLE
                // POPULATION. The participation gauges — and therefore
                // `TalosWorkerLivenessParticipationDropped`, the only warning
                // that arrives BEFORE a reap — are computed from the bounded
                // `list_active_builds` (LIMIT 200). This UPDATE is unbounded.
                // Above the cap those two populations diverge, and a worker
                // sorting past the 200th row is simultaneously invisible to
                // the alert and fully reapable: exactly the silent false reap
                // the whole feature exists to make impossible.
                //
                // So the invariant is enforced here rather than documented:
                // THE REAPER NEVER ACTS ON A ROW THE DETECTOR CANNOT SEE. It
                // costs one bounded SELECT per 300s sweep (the same query the
                // gauge task already runs) and it fails in the direction that
                // leaves keys trusted, which is the status quo.
                //
                // An ERROR here also skips: we cannot establish that the
                // population is observable, and "could not check" must not
                // read as "checked and fine" in front of an irreversible
                // write. Same fail-safe direction as the reap statement's own.
                match repo.list_active_builds().await {
                    Ok(rows) if liveness_population_is_truncated(rows.len()) => {
                        tracing::warn!(
                            target: "worker_registry",
                            event_kind = "worker_identity_reap_skipped_unobservable",
                            active_rows_seen = rows.len(),
                            "worker-identity reap sweep SKIPPED: the active identity \
                             population is at or past the fleet-query cap, so the \
                             liveness participation gauges no longer describe every row \
                             this sweep could deactivate and no alert could warn before \
                             a false reap. Nothing was deactivated. Drain retired rows \
                             with deactivate-worker-identity until \
                             talos_worker_liveness_population_truncated reads 0"
                        );
                        continue;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(
                            target: "worker_registry",
                            error = %e,
                            "worker-identity reap sweep SKIPPED: could not establish that \
                             the liveness detector sees the whole active population; \
                             nothing was deactivated"
                        );
                        continue;
                    }
                }

                // i32 for the SQL `make_interval(hours => $1::int)` bind
                // (check 27 — the pg arg is int4). Saturating, so an absurd
                // configured value cannot wrap into a SHORT window.
                //
                // Precisely, since "it can only produce a longer interval" is
                // not quite what happens at the top end: above roughly 5.9e7
                // hours (~6700 years, the distance to Postgres's minimum
                // timestamp) `now() - make_interval(...)` raises "timestamp out
                // of range" and the sweep ERRORS instead of widening. That is
                // still the safe direction — an erroring sweep deactivates
                // nothing, i.e. an effectively infinite window — but it is a
                // per-tick WARN, not a silently-longer window. Verified against
                // Postgres 16.

                // Set by either arm when a row actually changed, so the verify
                // ring is republished exactly once per sweep that reaped.
                let mut reaped_any = false;

                let hours_i32 = i32::try_from(silence_hours).unwrap_or(i32::MAX);
                match repo.reap_departed_identities(hours_i32).await {
                    Ok(0) => {}
                    Ok(n) => {
                        // Count only, never worker_id or key material — this is
                        // an operator-facing log on a trust boundary, and the
                        // identifying detail is already available via
                        // list-worker-identities.
                        tracing::warn!(
                            target: "worker_registry",
                            event_kind = "worker_identity_reaped",
                            keys = n,
                            silence_hours,
                            "deactivated worker signing keys whose workers stopped \
                             proving liveness; they must be re-registered by an \
                             operator if those workers return"
                        );
                        record_identity_reap(ReapArm::Departed, n);
                        reaped_any = true;
                    }
                    Err(e) => {
                        // Nothing was deactivated (single guarded statement).
                        tracing::warn!(
                            target: "worker_registry",
                            error = %e,
                            "worker-identity reap sweep failed; no keys were deactivated"
                        );
                    }
                }

                if let Some(hours) = pre_protocol_hours {
                    let hours_i32 = i32::try_from(hours).unwrap_or(i32::MAX);
                    match repo.reap_pre_protocol_identities(hours_i32).await {
                        Ok(0) => {}
                        Ok(n) => {
                            tracing::warn!(
                                target: "worker_registry",
                                event_kind = "worker_identity_reaped_pre_protocol",
                                keys = n,
                                max_age_hours = hours,
                                "deactivated worker signing keys that never participated in \
                                 the liveness protocol and have not re-registered within the \
                                 operator-configured window"
                            );
                            record_identity_reap(ReapArm::PreProtocol, n);
                            reaped_any = true;
                        }
                        Err(e) => tracing::warn!(
                            target: "worker_registry",
                            error = %e,
                            "pre-protocol worker-identity reap sweep failed; no keys were \
                             deactivated"
                        ),
                    }
                }

                // EAGERLY DROP REAPED KEYS FROM THE IN-PROCESS VERIFY RING.
                //
                // Marking the row inactive is NOT what stops a key verifying:
                // verification reads the `ArcSwap` overlay installed by
                // `refresh_worker_key_overlay`, republished by a SEPARATE
                // periodic task (TALOS_WORKER_KEY_REFRESH_SECS, default 60s,
                // clamped up to 3600s). Without this call a reaped key stays
                // trusted for up to one whole refresh interval AFTER the reap —
                // the difference between "trusted for at most 24h" and "24h
                // plus up to an hour", on the one number this feature exists to
                // state. Best-effort: a failure only defers the republish to
                // the next periodic refresh, so it can lengthen the window but
                // never shorten it, and it can never re-trust a live key (the
                // overlay is rebuilt from `WHERE active`).
                if reaped_any {
                    match refresh_worker_key_overlay(&repo).await {
                        Ok(installed) => tracing::info!(
                            target: "talos_engine",
                            event_kind = "worker_key_overlay_refresh",
                            installed,
                            "republished the worker verify-key overlay immediately after \
                             a reap"
                        ),
                        Err(e) => tracing::warn!(
                            target: "talos_engine",
                            error = %e,
                            "post-reap worker-key overlay refresh failed; reaped keys stay \
                             trusted until the next periodic refresh"
                        ),
                    }
                }
            }
        });
    }

    // Background task: Postgres connection-pool saturation gauges. Runs
    // every 15s and exports size / idle / in-use / max so the alert
    // `TalosDBPoolSaturated` (deploy/observability/alerts.yaml) can fire
    // before acquisitions start blocking on the 10s acquire timeout.
    // Pool state was previously un-instrumented — a saturated pool
    // surfaced only as climbing request latency with no direct signal.
    // The pool is process-local, so every controller replica samples its
    // own; the sum across replicas must stay below the backend's
    // server-side connection ceiling (see the per-subject RPC semaphore
    // note in docs/architecture/managed-cloud.md).
    {
        let pool = db_pool.clone();
        let max_connections: i64 = std::env::var("DB_MAX_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(30);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
            loop {
                ticker.tick().await;
                if let Some(m) = metrics::global() {
                    // `size()` is total connections (idle + in-use);
                    // `num_idle()` is the currently-available subset.
                    let size = i64::from(pool.size());
                    let idle = i64::try_from(pool.num_idle()).unwrap_or(i64::MAX);
                    m.db_pool_connections.set(size);
                    m.db_pool_idle_connections.set(idle);
                    m.db_pool_in_use_connections.set((size - idle).max(0));
                    m.db_pool_max_connections.set(max_connections);
                }
            }
        });
    }
}

/// OCI registry background sync loop. Extracted verbatim from `main()` —
/// must start AFTER `seed_templates` / `seed_marketplace`.
pub(crate) fn spawn_registry_sync(registry: std::sync::Arc<ModuleRegistry>) {
    // ---------- Start OCI Registry background sync loop ----------
    let sync_registry = registry.clone();
    tokio::spawn(async move {
        registry::sync::start_registry_sync_loop(sync_registry).await;
    });
}

/// LLM-keys/DEK cache sweeps, audit-chain verification sweep, bcrypt-cache
/// revocation sweep, and the modules-table reconciliation sweep. Extracted
/// verbatim from `main()`; spawn order preserved.
pub(crate) fn spawn_maintenance_sweeps(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    secrets_manager: std::sync::Arc<SecretsManager>,
    bg_shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    // ---------- Start LLM-keys cache sweep loop ----------
    //
    // The LLM-keys cache (`SecretsManager::llm_keys_cache`) evicts expired
    // entries lazily on read, which bounds memory for *active* users. A user
    // who makes one request and then goes silent leaves their entry in the
    // cache forever. This task sweeps expired entries on a fixed interval
    // so total cache size stays bounded under long-running multi-tenant
    // load with churning users.
    //
    // Interval defaults to 300s (5 min) and is bounded to [60s, 3600s] so
    // operators can tighten the sweep under high-churn workloads without
    // risk of a runaway tight loop. Emits a structured event per sweep so
    // operators can see how much is being evicted.
    let sweep_sm = secrets_manager.clone();
    let sweep_interval_secs: u64 = std::env::var("LLM_KEYS_SWEEP_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300)
        .clamp(60, 3600);
    let llm_sweep_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = llm_sweep_shutdown;
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(sweep_interval_secs));
        // Burn the immediate first tick so we don't sweep an empty cache at startup.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let evicted = sweep_sm.sweep_expired_llm_keys();
                    if evicted > 0 {
                        tracing::info!(
                            target: "talos_engine",
                            event_kind = "llm_keys_cache_sweep",
                            evicted,
                            interval_secs = sweep_interval_secs,
                            "swept expired LLM-keys cache entries"
                        );
                    }
                    // MCP-1093: piggyback on the same tick to bound the
                    // DEK cache's plaintext-AES-key memory residency.
                    // Same rationale as the LLM-keys sweep — `get_dek`
                    // evicts on read but historical DEK ids never
                    // re-queried after key rotation stay in the heap.
                    let dek_evicted = sweep_sm.sweep_expired_deks();
                    if dek_evicted > 0 {
                        tracing::info!(
                            target: "talos_engine",
                            event_kind = "dek_cache_sweep",
                            evicted = dek_evicted,
                            interval_secs = sweep_interval_secs,
                            "swept expired DEK cache entries"
                        );
                    }
                    // MCP-1133: sweep the single-slot `active_dek_cache`
                    // alongside the secondary cache. The MCP-1093 fix
                    // missed this slot — low-traffic deploys post-key-
                    // rotation leave the old active-DEK plaintext in
                    // the heap until the next active-DEK request.
                    if sweep_sm.sweep_expired_active_dek().await {
                        tracing::info!(
                            target: "talos_engine",
                            event_kind = "active_dek_cache_sweep",
                            interval_secs = sweep_interval_secs,
                            "swept expired active-DEK cache entry"
                        );
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("LLM-keys cache sweep loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });

    // ---------- Memory-rank provenance retention sweep ----------
    //
    // Adaptive per-actor memory ranking — Phase 1. The
    // `execution_memory_context` table accrues one row per packed memory per
    // actor-bound execution when `ENABLE_MEMORY_RANK_PROVENANCE` is on. This
    // task deletes rows older than the retention window so the training
    // substrate stays bounded. Gated on the flag: when provenance is OFF the
    // table is never written, so there is nothing to sweep — we skip spawning
    // the loop entirely (the DELETE would only ever hit an empty table).
    // Interval defaults to 3600s, clamped [300s, 86400s].
    //
    // Dependency warning: provenance is captured ONLY on the smart-context
    // path, so `ENABLE_MEMORY_RANK_PROVENANCE=1` records nothing unless
    // `ENABLE_SMART_MEMORY_CONTEXT=1` is also set. Warn loudly so an operator
    // expecting a training corpus isn't surprised by an empty table.
    if talos_config::memory_rank_provenance_enabled()
        && !talos_config::smart_memory_context_enabled()
    {
        tracing::warn!(
            "ENABLE_MEMORY_RANK_PROVENANCE is on but ENABLE_SMART_MEMORY_CONTEXT is off — \
             provenance records ONLY on the smart-context path, so NO training data will be \
             collected. Enable ENABLE_SMART_MEMORY_CONTEXT to accrue the memory-rank corpus."
        );
    }
    if talos_config::memory_rank_provenance_enabled() {
        let prov_pool = db_pool.clone();
        let prov_shutdown = bg_shutdown_rx.clone();
        let prov_interval_secs: u64 = talos_config::positive_env_or_default(
            "MEMORY_RANK_PROVENANCE_SWEEP_INTERVAL_SECS",
            3600,
        )
        .clamp(300, 86_400);
        tokio::spawn(async move {
            let mut shutdown = prov_shutdown;
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(prov_interval_secs));
            // Burn the immediate first tick so we don't sweep at startup.
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let retention_days = talos_config::memory_rank_provenance_retention_days();
                        match talos_memory::sweep_execution_memory_context(
                            &prov_pool,
                            retention_days,
                        )
                        .await
                        {
                            Ok(n) if n > 0 => tracing::info!(
                                target: "talos_engine",
                                event_kind = "memory_rank_provenance_sweep",
                                deleted = n,
                                retention_days,
                                "swept expired memory-rank provenance rows"
                            ),
                            Ok(_) => {}
                            Err(e) => tracing::warn!(
                                error = %e,
                                "memory-rank provenance retention sweep failed (non-fatal)"
                            ),
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            tracing::info!(
                                "memory-rank provenance sweep loop received shutdown signal"
                            );
                            break;
                        }
                    }
                }
            }
        });
    }

    // ---------- Embedding-model provenance: one-shot grandfather stamp ----------
    //
    // Legacy rows (embedding present, model NULL) are attributed to the
    // currently-configured EMBEDDING_MODEL on first boot after the
    // provenance migration; semantic reads are strict-equality on the
    // stamp from then on (see migration 20260720190000). Idempotent —
    // the predicate self-empties.
    {
        let gf_pool = db_pool.clone();
        tokio::spawn(async move {
            match talos_memory::grandfather_embedding_model(&gf_pool).await {
                Ok(n) if n > 0 => tracing::info!(
                    rows = n,
                    "embedding provenance: grandfathered actor_memory rows"
                ),
                Ok(_) => {}
                Err(e) => tracing::warn!(
                    error = %e,
                    "embedding provenance grandfather (actor_memory) failed — \
                     legacy rows stay invisible to semantic reads until stamped"
                ),
            }
            match talos_ml::dataset::grandfather_examples_embedding_model(&gf_pool).await {
                Ok(n) if n > 0 => tracing::info!(
                    rows = n,
                    "embedding provenance: grandfathered ml_examples rows"
                ),
                Ok(_) => {}
                Err(e) => tracing::warn!(
                    error = %e,
                    "embedding provenance grandfather (ml_examples) failed"
                ),
            }
        });
    }

    // ---------- Self-monitoring bridge: execution failures → ops_alerts ----------
    //
    // Cursor reconciler over terminal `workflow_executions` rows (see
    // `talos_ops_alerts_repository::self_monitor` for the design: why a
    // cursor beats finalizer hooks, the completed_at-vs-updated_at
    // choice, the safety lag, and the FOR UPDATE SKIP LOCKED
    // single-instance guard). Unattended failures become deduped
    // `source='talos'` ops alerts; a later green run auto-resolves
    // them. Kill switch TALOS_SELF_ALERTS=0; interval
    // TALOS_SELF_ALERTS_INTERVAL_SECS (default 60, clamped 5..=3600).
    if talos_ops_alerts_repository::self_monitor::self_alerts_enabled() {
        let self_monitor_pool = db_pool.clone();
        let self_monitor_shutdown = bg_shutdown_rx.clone();
        // Canonical env parsing (warns on non-positive garbage instead
        // of silently substituting — the zero-env-var footgun class).
        let self_monitor_interval: u64 = talos_config::positive_env_or_default(
            "TALOS_SELF_ALERTS_INTERVAL_SECS",
            talos_ops_alerts_repository::self_monitor::DEFAULT_TICK_INTERVAL_SECS,
        )
        .clamp(5, 3600);
        tokio::spawn(async move {
            let mut shutdown = self_monitor_shutdown;
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(self_monitor_interval));
            // Skip (not Burst, the default) missed ticks: after a
            // laptop sleep or long DB stall, ONE tick drains the whole
            // backlog internally — replaying ~60 queued ticks would
            // just hammer the cursor row with no-op transactions.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Burn the immediate first tick — nothing has finalized yet
            // this boot, and startup is busy enough.
            ticker.tick().await;
            tracing::info!(
                target: "talos_self_alerts",
                interval_secs = self_monitor_interval,
                "self-monitoring bridge reconciler started"
            );
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        talos_ops_alerts_repository::self_monitor::tick_and_log(
                            &self_monitor_pool,
                        )
                        .await;
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            tracing::info!("self-monitoring reconciler received shutdown signal");
                            break;
                        }
                    }
                }
            }
        });
    } else {
        tracing::info!(
            target: "talos_self_alerts",
            "self-monitoring bridge disabled via TALOS_SELF_ALERTS"
        );
    }

    // ---------- RFC 0010 P2 inc.4: dynamic worker-identity key refresh ---------
    //
    // Merges the DB-backed `worker_identities` registry into job_protocol's
    // dynamic verifying-key overlay (union with the static
    // `TALOS_WORKER_PUBLIC_KEYS` env base) so an autoscaling fleet can register
    // keys without an operator editing a ConfigMap. Verify-path reads are
    // lock-free (ArcSwap); this task just re-publishes the active set on an
    // interval, so max staleness for a rotation/revocation = one interval.
    //
    // Initial load is SYNCHRONOUS so DB-registered keys can verify the very first
    // job result after boot; a transient DB error there is non-fatal (env
    // registry stays live, the loop retries). `TALOS_WORKER_KEY_REFRESH_SECS=0`
    // disables the loop for deploys that use the env registry only.
    let worker_key_refresh_secs: u64 = std::env::var("TALOS_WORKER_KEY_REFRESH_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60);
    if worker_key_refresh_secs == 0 {
        tracing::info!(
            "Dynamic worker-identity key refresh disabled (TALOS_WORKER_KEY_REFRESH_SECS=0); \
             TALOS_WORKER_PUBLIC_KEYS env registry only"
        );
    } else {
        let refresh_secs = worker_key_refresh_secs.clamp(10, 3600);
        let worker_id_repo =
            talos_worker_identity_repository::WorkerIdentityRepository::new(db_pool.clone());
        let refresh_shutdown = bg_shutdown_rx.clone();
        tokio::spawn(async move {
            let mut shutdown = refresh_shutdown;
            // Immediate load so DB-registered keys go live shortly after boot; a
            // transient error here is non-fatal (env registry stays active, the
            // loop retries on the interval).
            match refresh_worker_key_overlay(&worker_id_repo).await {
                Ok(n) => tracing::info!(
                    target: "talos_engine",
                    event_kind = "worker_key_overlay_refresh",
                    installed = n,
                    "loaded dynamic worker-identity keys at boot"
                ),
                Err(e) => tracing::warn!(
                    target: "talos_engine",
                    error = %e,
                    "initial worker-identity key load failed; env registry still active, \
                     will retry on interval"
                ),
            }
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(refresh_secs));
            // Burn the immediate first tick — we just loaded above.
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Err(e) = refresh_worker_key_overlay(&worker_id_repo).await {
                            tracing::warn!(
                                target: "talos_engine",
                                error = %e,
                                "worker-identity key refresh failed; keeping last snapshot"
                            );
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            tracing::info!(
                                "worker-identity key refresh loop received shutdown signal"
                            );
                            break;
                        }
                    }
                }
            }
        });
    }

    // ---------- Audit-chain verification sweep (finding #2, Layer 2) ----------
    //
    // Continuously verifies the WORM audit ledger: each tick runs the offline
    // chain verifier over recently-completed executions and emits a loud
    // structured `audit_chain_verification_failed` event for any break
    // (tamper / deletion / reorder / bad HMAC). This is what turns "we CAN
    // verify the chain" into "we continuously DO" — the inline per-message
    // check (`talos_audit_ledger::verify_audit_message`) catches forgery at
    // ingest; this sweep catches gaps/deletions that only the full ordered
    // set reveals. Runs as a trusted system task on the bare pool (the audit
    // ledger is intentionally cross-tenant), so it needs no MCP/RBAC surface.
    //
    // Self-disables when no S3/WORM endpoint is configured (the from_env
    // helper returns None). Interval default 1h, clamped [300s, 86400s];
    // `AUDIT_CHAIN_SWEEP_INTERVAL_SECS=0` disables it. Lookback is 2× the
    // interval so window edges overlap (re-verification is idempotent); the
    // 120s settle floor skips just-finished executions whose audit events may
    // still be batching to S3, avoiding false sequence-gap reports.
    let audit_sweep_interval_secs: u64 = std::env::var("AUDIT_CHAIN_SWEEP_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3600);
    if audit_sweep_interval_secs == 0 {
        tracing::info!(
            "Audit-chain verification sweep disabled (AUDIT_CHAIN_SWEEP_INTERVAL_SECS=0)"
        );
    } else {
        let audit_sweep_interval_secs = audit_sweep_interval_secs.clamp(300, 86400);
        let audit_sweep_pool = db_pool.clone();
        let audit_sweep_shutdown = bg_shutdown_rx.clone();
        let lookback_secs = (audit_sweep_interval_secs as i64).saturating_mul(2);
        const SETTLE_SECS: i64 = 120;
        const MAX_EXECUTIONS_PER_SWEEP: i64 = 500;
        tokio::spawn(async move {
            let mut shutdown = audit_sweep_shutdown;
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(audit_sweep_interval_secs));
            // Burn the immediate first tick — at startup the most-recent
            // executions are still inside the settle window anyway.
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Some(stats) = talos_audit_ledger::run_chain_verification_sweep_from_env(
                            &audit_sweep_pool,
                            lookback_secs,
                            SETTLE_SECS,
                            MAX_EXECUTIONS_PER_SWEEP,
                        )
                        .await
                        {
                            if stats.failed > 0 || stats.errored > 0 {
                                tracing::warn!(
                                    target: "talos_audit",
                                    event_kind = "audit_chain_sweep_summary",
                                    scanned = stats.scanned,
                                    verified_ok = stats.verified_ok,
                                    failed = stats.failed,
                                    errored = stats.errored,
                                    "audit chain verification sweep completed WITH findings"
                                );
                            } else if stats.cap_hit {
                                // 2026-08-19: this branch used to say "completed
                                // clean". It cannot: the sweep takes the NEWEST
                                // `MAX_EXECUTIONS_PER_SWEEP` of a sliding window
                                // and keeps no cursor, so the executions it
                                // dropped age out and are never verified by any
                                // later pass. "No findings" over rows nobody read
                                // is not a clean bill of health, and on a
                                // security assurance the difference matters.
                                tracing::warn!(
                                    target: "talos_audit",
                                    event_kind = "audit_chain_sweep_incomplete",
                                    scanned = stats.scanned,
                                    verified_ok = stats.verified_ok,
                                    cap = MAX_EXECUTIONS_PER_SWEEP,
                                    lookback_secs,
                                    "audit chain verification sweep hit its row cap — the OLDEST                                      executions in this window were not verified and will not be                                      picked up by a later pass (the window slides and no cursor is                                      kept). No findings among the rows that WERE checked; this is                                      NOT a clean bill of health for the window. Lower                                      AUDIT_CHAIN_SWEEP_INTERVAL_SECS so fewer executions land in                                      each window, or raise the sweep cap."
                                );
                            } else if stats.scanned > 0 {
                                tracing::info!(
                                    target: "talos_audit",
                                    event_kind = "audit_chain_sweep_summary",
                                    scanned = stats.scanned,
                                    verified_ok = stats.verified_ok,
                                    "audit chain verification sweep completed clean"
                                );
                            }
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            tracing::info!("Audit-chain verification sweep loop received shutdown signal");
                            break;
                        }
                    }
                }
            }
        });
    }

    // ---------- MCP-991: bcrypt cache revocation sweep ----------
    // Closes the residual revocation gap that the per-entry TTL can't
    // reach when `revoke_mcp_agent` deletes an `mcp_agents` row via
    // GraphQL. The cache lives in talos-mcp-handlers; talos-api can't
    // depend on it (workspace dep direction rule). The sweep runs
    // here at controller startup with the canonical db_pool — a
    // single batched query against ALL cached agent_ids drops the
    // revocation window from 10 s (TTL only) to ~3 s.
    crate::mcp::auth::spawn_bcrypt_cache_revocation_sweep(db_pool.clone(), bg_shutdown_rx.clone());

    // ---------- Phase 1.3 / Phase 5 residual reconciliation sweep ----------
    // Historical context: originally a dual-write safety net that mirrored
    // legacy table rows into the new `modules` table. Post-Phase-5 migration
    // all live write paths land directly in `modules` and the legacy tables
    // are frozen, so this sweep is a no-op in steady state — kept wired up
    // because the repository method is idempotent (ON CONFLICT DO NOTHING)
    // and it catches any stray residual row during the Phase 5 wind-down
    // window. Safe to remove after the legacy tables drop.
    {
        let recon_repo =
            std::sync::Arc::new(module_repository::ModuleRepository::new(db_pool.clone()));
        let recon_interval_secs: u64 = std::env::var("MODULES_RECONCILE_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(600)
            .clamp(60, 3600);
        // MCP-1042: subscribe to bg_shutdown_rx so SIGTERM exits the
        // sweep loop cleanly between ticks. Without this, an INSERT
        // statement issued mid-tick can wedge its connection-pool
        // entry on abort.
        let recon_shutdown = bg_shutdown_rx.clone();
        tokio::spawn(async move {
            let mut shutdown = recon_shutdown;
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(recon_interval_secs));
            // First tick fires immediately — sweep on startup so a fresh
            // boot picks up anything new without waiting one interval.
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        match recon_repo.reconcile_modules_table().await {
                            Ok((wasm_added, template_added)) => {
                                if wasm_added > 0 || template_added > 0 {
                                    tracing::info!(
                                        target: "talos_engine",
                                        event_kind = "modules_reconcile_sweep",
                                        wasm_added,
                                        template_added,
                                        interval_secs = recon_interval_secs,
                                        "mirrored legacy module rows into modules table"
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    target: "talos_engine",
                                    error = %e,
                                    "modules-table reconciliation sweep failed"
                                );
                            }
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            tracing::info!(
                                target: "talos_engine",
                                "modules-table reconciliation sweep received shutdown signal"
                            );
                            break;
                        }
                    }
                }
            }
        });
        tracing::info!(
            target: "talos_engine",
            interval_secs = recon_interval_secs,
            "modules-table reconciliation sweep enabled"
        );
    }

    tracing::info!(
        "LLM-keys cache sweep loop started (interval: {}s)",
        sweep_interval_secs
    );
}

/// Cleanup / retention / archival sweeps (sessions, API keys, OAuth state
/// tokens, executions, audit logs, suspensions, WASM cache, webhook +
/// IP rate limiters, stuck executions), the one-shot crash-recovery resume
/// sweep (RFC 0003), the DEK cache cleanup, and the actor-memory TTL sweep.
/// Extracted verbatim from `main()`; spawn order preserved.
pub(crate) fn spawn_cleanup_tasks(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    nats_client: Option<std::sync::Arc<async_nats::Client>>,
    core: &CoreServices,
    services: &PlatformServices,
    limiters: &RateLimiters,
    bg_shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let secrets_manager = core.secrets_manager.clone();
    let registry = core.registry.clone();
    let auth_service = services.auth_service.clone();
    let api_key_service = services.api_key_service.clone();
    let oauth_service = services.oauth_service.clone();
    let webhook_router = services.webhook_router.clone();
    let module_execution_service = services.module_execution_service.clone();
    let worker_shared_key = services.worker_shared_key.clone();
    let auth_rate_limiter = services.auth_rate_limiter.clone();
    let api_limiter = limiters.api_limiter.clone();
    let webhook_limiter = limiters.webhook_limiter.clone();
    // ---------- Start background session cleanup task ----------
    // MCP-1043 (2026-05-15): the three auth-data DELETE sweeps below
    // (sessions / API keys / OAuth state tokens) now subscribe to
    // bg_shutdown_rx via tokio::select. Each issues
    // `DELETE FROM <credential_table>` statements; a mid-tick
    // SIGTERM abort can wedge the connection-pool entry on
    // Postgres-side until the server-side query timeout fires.
    // Same pattern as the canonical LLM-keys / bcrypt-cache /
    // stale_execution_cleanup (MCP-1042) sweeps.
    let cleanup_auth_service = auth_service.clone();
    let session_cleanup_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = session_cleanup_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match cleanup_auth_service.cleanup_expired_sessions().await {
                        Ok(count) => {
                            if count > 0 {
                                tracing::info!("Cleaned up {} expired sessions", count);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to cleanup expired sessions: {}", e);
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Session cleanup loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("Session cleanup task started (runs every 5 minutes)");

    // ---------- Start background API key cleanup task ----------
    let cleanup_api_key_service = api_key_service.clone();
    let api_key_cleanup_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = api_key_cleanup_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match cleanup_api_key_service.cleanup_expired_keys().await {
                        Ok(count) => {
                            if count > 0 {
                                tracing::info!("Deactivated {} expired API keys", count);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to cleanup expired API keys: {}", e);
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("API key cleanup loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("API key cleanup task started (runs every hour)");

    // ---------- Start background OAuth state token cleanup task ----------
    let cleanup_oauth_service = oauth_service.clone();
    let oauth_cleanup_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = oauth_cleanup_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match cleanup_oauth_service.cleanup_expired_state_tokens().await {
                        Ok(count) => {
                            if count > 0 {
                                tracing::info!("Cleaned up {} expired OAuth state tokens", count);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to cleanup expired OAuth state tokens: {}", e);
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("OAuth state token cleanup loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("OAuth state token cleanup task started (runs every hour)");

    // ---------- Start workflow execution cleanup task ----------
    let cleanup_pool = db_pool.clone();
    // MCP-622 (2026-05-12): use `talos_config::execution_retention_days()`
    // instead of a hardcoded `7`. Pre-fix the helper existed (defaulting
    // to 30) but had ZERO callers — operators who set
    // `EXECUTION_RETENTION_DAYS=90` thinking they were extending
    // retention had data silently deleted at 7 days. The
    // `execution_max_rows()` sibling helper also has no callers but is
    // not used by this task (separate ceiling concern). Cache the value
    // once at task start so a mid-process env mutation can't make the
    // window jitter unpredictably between iterations; operators
    // re-deploy to change retention.
    let retention_days = talos_config::execution_retention_days();
    // MCP-1044: subscribe to bg_shutdown_rx so SIGTERM exits the
    // retention-DELETE loop cleanly between top-level ticks. Inner
    // batched-DELETE chunks still run to natural completion within
    // one tick (5K-row chunks complete in seconds); the shutdown
    // select gates the OUTER 6-hour ticker only.
    let exec_retention_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = exec_retention_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(6 * 3600));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Delete executions older than `retention_days` (skip queued executions).
                    // Batched in chunks of 5000 to avoid long-held row locks and
                    // WAL bloat on the first run (or after a long outage).
                    let mut total_deleted = 0u64;
                    loop {
                        match sqlx::query(
                            "DELETE FROM workflow_executions \
                             WHERE id IN ( \
                                 SELECT id FROM workflow_executions \
                                 WHERE started_at < NOW() - INTERVAL '1 day' * $1 \
                                   AND status != 'queued' \
                                 LIMIT 5000 \
                             )",
                        )
                        .bind(retention_days)
                        .execute(&cleanup_pool)
                        .await
                        {
                            Ok(result) => {
                                let batch = result.rows_affected();
                                total_deleted += batch;
                                if batch < 5000 {
                                    break; // last batch — done
                                }
                                // Yield between batches to avoid monopolising the pool.
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }
                            Err(e) => {
                                tracing::error!("Failed to cleanup old workflow executions: {}", e);
                                break;
                            }
                        }
                    }
                    if total_deleted > 0 {
                        tracing::info!(
                            "Cleaned up {} old workflow executions (older than {} days)",
                            total_deleted,
                            retention_days
                        );
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Workflow execution retention loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!(
        retention_days,
        "Workflow execution cleanup task started (runs every 6 hours, EXECUTION_RETENTION_DAYS)"
    );

    // ---------- Start execution archival task ----------
    // MCP-1044: subscribe to bg_shutdown_rx — this daily sweep issues
    // a transactional CTE that DELETEs from workflow_executions and
    // INSERTs into workflow_executions_archive in a single statement.
    // Mid-statement abort on SIGTERM would leave the transaction in
    // an uncommitted state (rolled back by Postgres) but the
    // connection-pool entry stuck until the server-side timeout. The
    // shutdown gate makes the exit point predictable.
    let archive_pool = db_pool.clone();
    let archive_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = archive_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400)); // daily
        loop {
            let tick_result = tokio::select! {
                _ = interval.tick() => Some(()),
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Execution archival loop received shutdown signal");
                        None
                    } else {
                        Some(())
                    }
                }
            };
            if tick_result.is_none() {
                break;
            }
            // Prefer DB setting over env var.
            // MCP-758 (2026-05-13): filter `db_days <= 0` so the DB-stored
            // override path matches the env-side hardening from MCP-643.
            // Pre-fix a `system_settings.value = 0` row took
            // db_days.unwrap_or(env_days) → 0, then bound 0 into
            // `make_interval(days => $1::int)` below — "completed_at < NOW() -
            // 0 days" matches every completed/failed/cancelled execution
            // ever, archiving the entire table at the next daily tick.
            // Negative DB values would have the same effect (Postgres
            // accepts negative make_interval; "older than -7 days" =
            // "older than now + 7 days" = also everything). Same =0
            // destructive class as MCP-703 (DB-stored fuel_budget) and
            // MCP-643 (env-side ARCHIVE_AFTER_DAYS). The DB row can be
            // written via admin SQL — there's no public API path that
            // sets it today, but defense-in-depth before a future admin
            // surface is cheap. Warn on the misconfiguration so an
            // operator who deliberately wrote 0/negative gets a clear
            // signal that the value was ignored.
            // MCP-961 sibling: saturating i64→i32 conversion. Sibling
            // of the advanced.rs fix — operator-supplied DB value
            // could exceed i32::MAX and silently wrap pre-fix.
            // #661 (error-as-absence): the retention setting must be READ, not
            // guessed. `.unwrap_or(None)` made an unreadable `system_settings`
            // row indistinguishable from an unset one, so a DB fault silently
            // substituted the env default (30) for whatever the operator had
            // configured. Everything the MCP-758 comment above is about — this
            // number binding into `make_interval(days => $1::int)` on a
            // statement that DELETEs from `workflow_executions` — applies just
            // as much when the number is wrong because the read failed. An
            // operator running 365-day retention would have had ~11 months of
            // executions swept out of the live table on the next daily tick.
            //
            // The sweep is periodic and idempotent, so the correct response to
            // "cannot tell what the retention is" is to skip THIS tick and
            // re-read tomorrow, not to archive on a guess.
            let db_days_read = sqlx::query_scalar::<_, serde_json::Value>(
                "SELECT value FROM system_settings WHERE key = 'archive_after_days'",
            )
            .fetch_optional(&archive_pool)
            .await;
            let db_days: Option<i32> = match db_days_read {
                Ok(v) => v.and_then(|v| {
                    v.as_i64()
                        .map(|n| i32::try_from(n).unwrap_or(i32::MAX))
                        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                }),
                Err(e) => {
                    tracing::error!(
                        target: "talos_engine",
                        event_kind = "archive_after_days_unreadable_skipped",
                        error = %e,
                        "could not READ system_settings.archive_after_days — skipping this \
                         archival tick rather than sweeping workflow_executions on the \
                         env-derived default, which may be far shorter than the configured \
                         retention"
                    );
                    continue;
                }
            };
            let env_days = talos_config::positive_env_or_default::<i32>("ARCHIVE_AFTER_DAYS", 30);
            let days = match db_days {
                Some(d) if d > 0 => d,
                Some(d) => {
                    tracing::warn!(
                        target: "talos_engine",
                        event_kind = "archive_after_days_nonpositive_substituted",
                        configured = d,
                        fallback = env_days,
                        "system_settings.archive_after_days = {} is non-positive — \
                         ignored to prevent archiving every completed execution; \
                         falling back to env-derived value",
                        d
                    );
                    env_days
                }
                None => env_days,
            };
            // Move old completed/failed/cancelled executions to archive
            let result = sqlx::query(
                "WITH archived AS (
                    DELETE FROM workflow_executions
                    WHERE status IN ('completed', 'failed', 'cancelled')
                    AND completed_at < NOW() - make_interval(days => $1::int)
                    AND is_pinned = false
                    RETURNING *
                )
                INSERT INTO workflow_executions_archive SELECT * FROM archived",
            )
            .bind(days)
            .execute(&archive_pool)
            .await;
            if let Ok(r) = result {
                if r.rows_affected() > 0 {
                    tracing::info!(count = r.rows_affected(), "Archived old executions");
                }
            }
        }
    });
    tracing::info!("Execution archival task started (runs daily, archives executions older than ARCHIVE_AFTER_DAYS env var, default 30)");

    // ---------- Start audit log cleanup task ----------
    // MCP-1045: subscribe to bg_shutdown_rx so SIGTERM exits the
    // hourly check loop cleanly. Audit log cleanup issues 3 DELETE
    // calls (auth + secret + webhook) once per day at 2 AM; outer
    // hourly ticker is what needs interruptibility.
    let cleanup_auth = auth_service.clone();
    let cleanup_secrets = secrets_manager.clone();
    let cleanup_webhooks = webhook_router.clone();
    let audit_cleanup_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = audit_cleanup_shutdown;
        // Run daily at 2 AM (check every hour, but only execute once per day)
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        let mut last_cleanup_day: Option<u32> = None;

        loop {
            let should_proceed = tokio::select! {
                _ = interval.tick() => true,
                _ = shutdown.changed() => !*shutdown.borrow(),
            };
            if !should_proceed {
                tracing::info!("Audit log cleanup loop received shutdown signal");
                break;
            }

            // Only run cleanup once per day at 2 AM
            use chrono::{Datelike, Timelike};
            let now = chrono::Utc::now();
            let current_day = now.ordinal(); // Day of year (1-indexed)
            let current_hour = now.hour();

            if current_hour == 2 && last_cleanup_day != Some(current_day) {
                // MCP-643: =0 would delete every audit log row (anything
                // older than 0 days = everything). Destructive class.
                let retention_days =
                    talos_config::positive_env_or_default::<i64>("AUDIT_LOG_RETENTION_DAYS", 90);

                tracing::info!(
                    "Starting audit log cleanup (retention: {} days)",
                    retention_days
                );

                // Clean up auth audit logs
                match cleanup_auth.cleanup_audit_logs(retention_days).await {
                    Ok(count) => {
                        if count > 0 {
                            tracing::info!("Cleaned up {} auth audit log entries", count);
                        }
                    }
                    Err(e) => tracing::error!("Failed to cleanup auth audit logs: {}", e),
                }

                // Clean up secret audit logs
                match cleanup_secrets.cleanup_audit_logs(retention_days).await {
                    Ok(count) => {
                        if count > 0 {
                            tracing::info!("Cleaned up {} secret audit log entries", count);
                        }
                    }
                    Err(e) => tracing::error!("Failed to cleanup secret audit logs: {}", e),
                }

                // Clean up webhook request logs
                match cleanup_webhooks.cleanup_request_logs(retention_days).await {
                    Ok(count) => {
                        if count > 0 {
                            tracing::info!("Cleaned up {} webhook request log entries", count);
                        }
                    }
                    Err(e) => tracing::error!("Failed to cleanup webhook request logs: {}", e),
                }

                // Clean up webhook dead-letter-queue rows. Dropped-request
                // payloads (DLP-redacted) accumulate forever without this
                // sweep — an unbounded storage-exhaustion vector under a
                // circuit-breaker / rate-limit flood against a known trigger.
                match cleanup_webhooks.cleanup_dlq(retention_days).await {
                    Ok(count) => {
                        if count > 0 {
                            tracing::info!("Cleaned up {} webhook DLQ entries", count);
                        }
                    }
                    Err(e) => tracing::error!("Failed to cleanup webhook DLQ: {}", e),
                }

                last_cleanup_day = Some(current_day);
                tracing::info!("Audit log cleanup completed");
            }
        }
    });
    tracing::info!("Audit log cleanup task started (runs daily at 2 AM)");

    // ---------- Expire timed-out workflow suspensions every 5 minutes ----------
    // MCP-1044: subscribe to bg_shutdown_rx — issues UPDATE
    // workflow_suspensions; mid-statement abort wedges the
    // connection pool until server-side timeout.
    let suspension_expiry_pool = db_pool.clone();
    let suspension_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = suspension_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match sqlx::query(
                        "UPDATE workflow_suspensions \
                         SET status = 'expired', resumed_by = 'timeout_expiry', resumed_at = now() \
                         WHERE status = 'waiting' AND timeout_at IS NOT NULL AND timeout_at < now()",
                    )
                    .execute(&suspension_expiry_pool)
                    .await
                    {
                        Ok(r) if r.rows_affected() > 0 => {
                            tracing::info!(
                                expired = r.rows_affected(),
                                "Expired timed-out workflow suspensions"
                            );
                        }
                        Err(e) => tracing::error!("Failed to expire workflow suspensions: {}", e),
                        _ => {}
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Suspension expiry loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("Suspension expiry task started (runs every 5 minutes)");

    // ---------- Start WASM module cache cleanup task ----------
    let cleanup_registry = registry.clone();
    tokio::spawn(async move {
        // Run every 6 hours
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(21600));

        loop {
            interval.tick().await;

            // MCP-643: =0 on any of these would purge the entire WASM
            // cache on the next sweep (retention=0 days, max=0 entries,
            // size cap=0 MB). Recoverable (re-pull from OCI) but
            // operationally costly. Substitute defaults + WARN.
            let retention_days =
                talos_config::positive_env_or_default::<i64>("WASM_CACHE_RETENTION_DAYS", 30);
            let max_modules =
                talos_config::positive_env_or_default::<i64>("WASM_CACHE_MAX_MODULES", 1000);
            let max_size_mb =
                talos_config::positive_env_or_default::<i64>("WASM_CACHE_MAX_SIZE_MB", 500);

            // Clean up old modules
            match cleanup_registry.cleanup_old_modules(retention_days).await {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!(
                            "Cleaned up {} old WASM modules (>{}d)",
                            count,
                            retention_days
                        );
                    }
                }
                Err(e) => tracing::error!("Failed to cleanup old WASM modules: {}", e),
            }

            // Enforce cache size limits
            match cleanup_registry
                .enforce_cache_limits(max_modules, max_size_mb)
                .await
            {
                Ok((modules_deleted, bytes_freed)) => {
                    if modules_deleted > 0 || bytes_freed > 0 {
                        tracing::info!(
                            "Evicted {} WASM modules (freed {} modules, {} MB)",
                            modules_deleted,
                            modules_deleted,
                            bytes_freed
                        );
                    }
                }
                Err(e) => tracing::error!("Failed to enforce WASM cache limits: {}", e),
            }

            // Log cache stats
            match cleanup_registry.get_cache_stats().await {
                Ok(stats) => {
                    tracing::debug!(
                        "WASM cache stats: {} modules, {:.2} MB, {} total uses",
                        stats.module_count,
                        stats.total_size_mb,
                        stats.total_usage_count
                    );
                }
                Err(e) => tracing::error!("Failed to get WASM cache stats: {}", e),
            }
        }
    });
    tracing::info!("WASM cache cleanup task started (runs every 6 hours)");

    // ---------- Start webhook rate-limiter + circuit-breaker cleanup task ----------
    // Prevents unbounded growth of in-memory token buckets and CB records as unique
    // webhook tokens and IPs accumulate over the process lifetime.
    let cleanup_webhook_rl = webhook_router.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // Every 5 min
        loop {
            interval.tick().await;
            cleanup_webhook_rl.cleanup_rate_limiter();
            cleanup_webhook_rl.cleanup_circuit_breaker();
        }
    });
    tracing::info!(
        "Webhook rate-limiter + circuit-breaker cleanup task started (runs every 5 minutes)"
    );

    // ---------- Start IP rate-limiter cleanup task (MCP-694) ----------
    // The governor `RateLimiter<String, DashMapStateStore<String>>` for
    // `api_limiter` and `webhook_limiter` retains one DashMap entry per
    // distinct source IP forever. Under sustained traffic from many
    // distinct IPs (botnet sweeps, public internet exposure) the maps
    // grow without bound — at ~150 bytes per entry, 1M unique IPs
    // ≈ 150 MB per limiter. `retain_recent()` drops keys whose buckets
    // are indistinguishable from a "fresh" state (idle long enough that
    // they hit no rate-limit cost on next encounter); `shrink_to_fit()`
    // reclaims the DashMap capacity. Both are governor-provided
    // (governor 0.6.3 src/state/keyed.rs:180,191).
    //
    // Same 5-min cadence as the webhook cleanup above so operators see
    // one consistent rate-limiter-hygiene heartbeat in logs.
    let cleanup_api_limiter = api_limiter.clone();
    let cleanup_webhook_ip_limiter = webhook_limiter.clone();
    // MCP-718 (2026-05-13): add the `DistributedRateLimiter`'s in-memory
    // fallback to the same sweep. Under FailOpen Redis outages the
    // fallback accumulates one DashMap entry per distinct auth-attempt
    // identifier; entries SURVIVE Redis recovery (governor's keyed
    // state store has no auto-eviction). Wiring through the new
    // `cleanup_fallback()` helper keeps the contract identical to the
    // raw-limiter sweep above without leaking the inner `IpRateLimiter`
    // out of `DistributedRateLimiter`.
    let cleanup_auth_limiter = auth_rate_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        // First tick fires immediately — burn it so a fresh boot doesn't
        // do an empty-map walk before any request has been admitted.
        interval.tick().await;
        loop {
            interval.tick().await;
            let api_before = cleanup_api_limiter.len();
            cleanup_api_limiter.retain_recent();
            cleanup_api_limiter.shrink_to_fit();
            let api_after = cleanup_api_limiter.len();

            let wh_before = cleanup_webhook_ip_limiter.len();
            cleanup_webhook_ip_limiter.retain_recent();
            cleanup_webhook_ip_limiter.shrink_to_fit();
            let wh_after = cleanup_webhook_ip_limiter.len();

            let auth_before = cleanup_auth_limiter.fallback_len();
            cleanup_auth_limiter.cleanup_fallback();
            let auth_after = cleanup_auth_limiter.fallback_len();

            if api_before > api_after || wh_before > wh_after || auth_before > auth_after {
                tracing::info!(
                    target: "talos_rate_limit",
                    event_kind = "ip_rate_limiter_sweep",
                    api_before, api_after,
                    webhook_before = wh_before,
                    webhook_after = wh_after,
                    auth_fallback_before = auth_before,
                    auth_fallback_after = auth_after,
                    "IP rate-limiter cleanup: dropped idle buckets"
                );
            }
        }
    });
    tracing::info!(
        "IP rate-limiter cleanup task started (runs every 5 minutes, retain_recent + shrink_to_fit; covers api + webhook + auth-fallback)"
    );

    // ---------- Start stuck execution cleanup task ----------
    // Transitions orphaned `pending`/`running` executions to `timeout` when a
    // worker crashes without reporting a result.
    //
    // MCP-1044: subscribe to bg_shutdown_rx — issues
    // UPDATE workflow_executions; mid-statement abort wedges the
    // connection pool. Same MCP-1042/1043 discipline.
    let cleanup_exec_service = module_execution_service.clone();
    let stuck_cleanup_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = stuck_cleanup_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // MCP-643: =0 would mark every running execution as stuck
                    // immediately (anything older than 0 mins = everything),
                    // including healthy in-progress jobs.
                    let max_age_mins =
                        talos_config::positive_env_or_default::<i64>("STUCK_EXECUTION_TIMEOUT_MINS", 30);
                    match cleanup_exec_service
                        .cleanup_stuck_executions(max_age_mins)
                        .await
                    {
                        Ok(count) if count > 0 => tracing::warn!(
                            "Cleaned up {} stuck executions (idle > {} min)",
                            count,
                            max_age_mins
                        ),
                        Ok(_) => {}
                        Err(e) => tracing::error!("Failed to cleanup stuck executions: {}", e),
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Stuck execution cleanup loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("Stuck execution cleanup task started (runs every 5 minutes, timeout after 30 min by default)");

    // ---------- Crash recovery: resume checkpointed executions ----------
    // RFC 0003 (durable execution). On a controller restart, executions that
    // were mid-flight are wedged in `running` — their in-process engine task
    // died with the process. When EXECUTION_CHECKPOINTING_ENABLED is on, the
    // engine persisted node-result checkpoints; this one-shot startup sweep
    // claims those orphans (`running -> resuming`, FOR UPDATE SKIP LOCKED so
    // it's exactly-once across replicas) and resumes each from its last
    // checkpoint via the NATS seed path.
    //
    // ONE-SHOT at startup (not periodic) on purpose: at startup there are no
    // live in-process engine tasks from THIS process, so any orphaned
    // `running` row is genuinely dead. A periodic sweep in a single-replica
    // deployment could claim a long-running-but-alive execution (one whose
    // current node runs longer than the stale window without a checkpoint
    // heartbeat) and double-dispatch it.
    //
    // Requires NATS (the resume dispatch goes over signed NATS-RPC) and the
    // checkpointing flag — without checkpoints there is nothing to resume.
    if talos_config::bool_env_or_default("EXECUTION_CHECKPOINTING_ENABLED", false) {
        if let Some(nats_for_recovery) = nats_client.clone() {
            // Resume orphans idle beyond this window. MUST be smaller than
            // STUCK_EXECUTION_TIMEOUT_MINS (default 30) so a recoverable
            // execution is resumed before any cleanup path could fail it.
            let resume_stale_mins =
                talos_config::positive_env_or_default::<i64>("EXECUTION_RESUME_STALE_MINS", 5);
            let stuck_timeout_mins =
                talos_config::positive_env_or_default::<i64>("STUCK_EXECUTION_TIMEOUT_MINS", 30);
            if resume_stale_mins >= stuck_timeout_mins {
                tracing::warn!(
                    resume_stale_mins,
                    stuck_timeout_mins,
                    "EXECUTION_RESUME_STALE_MINS >= STUCK_EXECUTION_TIMEOUT_MINS — orphaned \
                     executions may be failed by stuck-cleanup before crash recovery can claim them"
                );
            }
            let recovery_deps = talos_execution_orchestration::RecoveryDeps {
                db_pool: db_pool.clone(),
                registry: registry.clone(),
                secrets_manager: secrets_manager.clone(),
                actor_repo: std::sync::Arc::new(actor_repository::ActorRepository::new(
                    db_pool.clone(),
                )),
                execution_repo: std::sync::Arc::new(
                    crate::execution_repository::ExecutionRepository::new(db_pool.clone()),
                ),
                worker_shared_key: worker_shared_key.clone(),
                nats_client: nats_for_recovery,
            };
            tokio::spawn(async move {
                talos_execution_orchestration::recover_stuck_executions(
                    recovery_deps,
                    resume_stale_mins,
                )
                .await;
            });
            tracing::info!(
                "Crash-recovery startup sweep spawned (EXECUTION_CHECKPOINTING_ENABLED on); \
                 resuming executions idle > {} min from their last checkpoint",
                resume_stale_mins
            );
        } else {
            tracing::warn!(
                "EXECUTION_CHECKPOINTING_ENABLED is on but NATS is unavailable — \
                 crash-recovery sweep skipped (resume dispatch needs NATS)"
            );
        }
    }

    // ---------- Start DEK cache cleanup task ----------
    // Evicts expired DEK entries from the in-memory HashMap to prevent unbounded
    // growth in long-lived processes.  DEK rotation is rare, so the cache stays
    // small in practice, but the cleanup ensures stale entries are released.
    let cleanup_secrets_dek = secrets_manager.clone();
    tokio::spawn(async move {
        // Run every 10 minutes — DEK TTL is 5 min by default, so this evicts
        // entries within one extra TTL period of expiry.
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
        loop {
            interval.tick().await;
            cleanup_secrets_dek.cleanup_expired_cache_entries().await;
        }
    });
    tracing::info!("DEK cache cleanup task started (runs every 10 minutes)");

    // ---------- Start actor memory TTL cleanup task ----------
    // Deletes expired actor_memory rows (working=1h, episodic=7d,
    // scratchpad=24h TTLs stored in expires_at; semantic rows never
    // expire). Goes through `talos_memory::sweep_expired` so the
    // single canonical service owns every direct write to the
    // table — no inline DELETE queries elsewhere in the codebase.
    let agent_memory_pool = db_pool.clone();
    let actor_memory_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = actor_memory_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(900)); // Every 15 min
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Grace = 0: expired rows are deleted immediately on each
                    // tick. Override here if we ever want to retain
                    // tombstones longer than their TTL for forensics.
                    match talos_memory::sweep_expired(&agent_memory_pool, 0).await {
                        Ok(0) => {}
                        Ok(n) => tracing::debug!(count = n, "Cleaned up expired actor_memory entries"),
                        Err(e) => tracing::error!("Failed to cleanup actor_memory TTL: {}", e),
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Actor-memory TTL sweep loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("Actor memory TTL cleanup task started (runs every 15 minutes)");
}

/// Actor-memory embedding backfill (one-shot), readiness-score
/// recomputation, and SLA degradation alerting. Extracted verbatim from
/// `main()`; spawn order preserved.
pub(crate) fn spawn_analytics_tasks(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    bg_shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    // ---------- Start actor memory embedding backfill (one-shot on startup) ----------
    {
        let backfill_pool = db_pool.clone();
        tokio::spawn(async move {
            // Small delay to let Ollama warm up after restart.
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            match actor_memory_service::backfill_embeddings(&backfill_pool, 100).await {
                Ok(n) => {
                    if n > 0 {
                        tracing::info!(embedded = n, "Actor memory embedding backfill completed");
                    }
                }
                Err(e) => tracing::warn!("Actor memory embedding backfill failed: {}", e),
            }
        });
    }

    // ---------- Start readiness score background recomputation task ----------
    // MCP-1045: subscribe to bg_shutdown_rx — issues per-workflow
    // UPDATE actor_readiness statements; mid-batch SIGTERM aborts
    // can leave readiness rows partially updated and wedge the
    // connection-pool entry on the in-flight UPDATE.
    let readiness_pool = db_pool.clone();
    let readiness_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = readiness_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // Every hour
        loop {
            let should_proceed = tokio::select! {
                _ = interval.tick() => true,
                _ = shutdown.changed() => !*shutdown.borrow(),
            };
            if !should_proceed {
                tracing::info!("Readiness recomputation loop received shutdown signal");
                break;
            }

            // Fetch all workflows with stale or missing readiness scores
            let workflows: Vec<(
                uuid::Uuid,
                uuid::Uuid,
                Option<String>,
                Vec<String>,
                Option<String>,
            )> = match sqlx::query_as(
                "SELECT id, user_id, description, capabilities, graph_json \
                 FROM workflows \
                 WHERE readiness_computed_at IS NULL \
                    OR readiness_computed_at < NOW() - INTERVAL '1 hour' \
                 LIMIT 500",
            )
            .fetch_all(&readiness_pool)
            .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::error!("Readiness score batch query failed: {}", e);
                    continue;
                }
            };

            if workflows.is_empty() {
                continue;
            }

            let mut updated = 0u64;
            // MCP-778 (2026-05-13): track UPDATE failures alongside successes
            // so the operator-facing summary surfaces partial-batch DB issues.
            // See the `if updated > 0` log at the loop tail.
            let mut update_failed = 0u64;
            for (wf_id, wf_user_id, wf_desc, wf_caps, graph_json_str) in &workflows {
                let graph: serde_json::Value = graph_json_str
                    .as_deref()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or_else(|| serde_json::json!({"nodes":[],"edges":[]}));

                // Reliability (50%): success_rate * min(exec_count/10, 1.0)
                // Saturates at 10 runs — consistent with get_readiness_breakdown handler.
                // 5 perfect runs → 50% reliability credit (not alarming on operator dashboards).
                //
                // MCP-503: pair every `.unwrap_or` zero-fallback in this
                // background task with a `tracing::warn!`. Pre-fix the
                // inner queries silently swallowed DB errors, so a
                // column rename / FK violation / schema drift would
                // quietly downgrade every workflow's readiness score
                // with no operator-visible signal. Same lint-check-8
                // pattern fixed in MCP-488 (cost-attribution) and
                // MCP-489 (retry-intelligence). The outer batch query
                // at line ~1691 ALREADY logs-and-continues; this fix
                // brings the inner queries to parity.
                let perf_row: Option<(Option<f64>, i64)> = sqlx::query_as(
                    "SELECT \
                        (COUNT(*) FILTER (WHERE status = 'completed'))::float / NULLIF(COUNT(*), 0), \
                        COUNT(*) \
                     FROM workflow_executions \
                     WHERE workflow_id = $1 AND started_at > NOW() - interval '30 days'"
                ).bind(wf_id).fetch_optional(&readiness_pool).await.unwrap_or_else(|e| {
                    tracing::warn!(
                        %wf_id,
                        error = %e,
                        "readiness: workflow_executions perf query failed — using neutral reliability"
                    );
                    None
                });

                let (success_rate, exec_count) = perf_row.unwrap_or((None, 0));
                let reliability =
                    success_rate.unwrap_or(0.0) * (exec_count as f64 / 10.0).min(1.0) * 50.0;

                // Documentation (20%): has_desc=10, has_node_desc=5, has_caps=5
                // Consistent with get_readiness_breakdown handler.
                let has_desc = if wf_desc.as_ref().map(|d| !d.is_empty()).unwrap_or(false) {
                    10.0
                } else {
                    0.0
                };
                let has_node_desc = if graph
                    .get("nodes")
                    .and_then(|n| n.as_array())
                    .map(|nodes| {
                        nodes.iter().any(|n| {
                            n.get("description")
                                .and_then(|d| d.as_str())
                                .map(|s| !s.is_empty())
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false)
                {
                    5.0
                } else {
                    0.0
                };
                let has_caps = if !wf_caps.is_empty() { 5.0 } else { 0.0 };
                let documentation = has_desc + has_node_desc + has_caps;

                // Freshness (20%)
                let last_exec: Option<(Option<chrono::DateTime<chrono::Utc>>,)> = sqlx::query_as(
                    "SELECT MAX(started_at) FROM workflow_executions WHERE workflow_id = $1",
                )
                .bind(wf_id)
                .fetch_optional(&readiness_pool)
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!(
                        %wf_id,
                        error = %e,
                        "readiness: workflow_executions last-exec query failed — freshness scored 0"
                    );
                    None
                });

                let freshness = match last_exec.and_then(|r| r.0) {
                    Some(last) => {
                        let days_ago = chrono::Utc::now().signed_duration_since(last).num_days();
                        if days_ago <= 7 {
                            20.0
                        } else if days_ago <= 30 {
                            10.0
                        } else {
                            0.0
                        }
                    }
                    None => 0.0,
                };

                // Risk (10%)
                let has_timeout = graph.get("execution_timeout_secs").is_some();
                let has_error_edges = graph
                    .get("edges")
                    .and_then(|e| e.as_array())
                    .map(|edges| {
                        edges
                            .iter()
                            .any(|e| e.get("edge_type").and_then(|t| t.as_str()) == Some("error"))
                    })
                    .unwrap_or(false);
                let expiring_secrets: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM secrets WHERE created_by = $1 AND expires_at IS NOT NULL AND expires_at < NOW() + interval '7 days'"
                ).bind(wf_user_id).fetch_one(&readiness_pool).await.unwrap_or_else(|e| {
                    tracing::warn!(
                        %wf_user_id,
                        error = %e,
                        "readiness: expiring-secrets query failed — risk score will not reflect expiry"
                    );
                    0
                });

                let mut risk = 10.0_f64;
                if !has_timeout {
                    risk -= 3.0;
                }
                if !has_error_edges {
                    risk -= 3.0;
                }
                if expiring_secrets > 0 {
                    risk -= 4.0;
                }
                let risk = risk.max(0.0);

                let total = (reliability + documentation + freshness + risk).round() as i32;

                // MCP-778 (2026-05-13): replace `.is_ok()` swallow with a
                // success/failure split. Pre-fix the UPDATE error was
                // discarded — under sustained DB pressure (long-running
                // statement timeout, FK churn, partition lock), the
                // background recomputation showed "Recomputed readiness
                // scores for 0 workflows" even though hundreds of UPDATEs
                // were attempted-and-failed. Operators saw stale dashboard
                // readiness scores with NO log signal correlating the
                // staleness to DB health. Same MCP-503 observability rule
                // applied to the read-side queries in this same task
                // (line ~1911); this brings the write-side to parity.
                // High-volume loop → log a SUMMARY at end (not per-row)
                // to avoid spamming.
                match sqlx::query(
                    "UPDATE workflows SET readiness_score = $1, readiness_computed_at = NOW() WHERE id = $2"
                )
                .bind(total)
                .bind(wf_id)
                .execute(&readiness_pool)
                .await
                {
                    Ok(_) => updated += 1,
                    Err(_) => update_failed += 1,
                }
            }

            if updated > 0 || update_failed > 0 {
                if update_failed == 0 {
                    tracing::info!(
                        target: "talos_audit",
                        updated,
                        "Recomputed readiness scores for {} workflows", updated
                    );
                } else {
                    tracing::warn!(
                        target: "talos_audit",
                        updated,
                        update_failed,
                        total_processed = updated + update_failed,
                        "Recomputed readiness scores: {} succeeded, {} UPDATE failures — DB may be under pressure; readiness dashboard will show stale scores for the failed rows until next hourly tick",
                        updated,
                        update_failed
                    );
                }
            }
        }
    });
    tracing::info!("Readiness score recomputation task started (runs every hour)");

    // ---------- Start SLA degradation alerting task ----------
    // MCP-1045: subscribe to bg_shutdown_rx — issues INSERTs into
    // workflow_sla_alerts on threshold breach. Outer 15-min ticker
    // gated; inner per-workflow alert-emit loop runs to natural
    // completion within one tick.
    let sla_pool = db_pool.clone();
    let sla_degradation_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = sla_degradation_shutdown;
        // Wait 2 minutes after startup before first check to let executions settle
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(900)); // 15 min
                                                                                       // MCP-469: disable redirect following for SLA notification
                                                                                       // webhooks. The SSRF check at fire time validates the literal
                                                                                       // URL, but reqwest's default `Policy::limited(10)` would follow
                                                                                       // a 302/303 to an internal host beneath the SSRF gate. Matches
                                                                                       // the canonical pattern in approval_gate / failure_webhook.
                                                                                       //
                                                                                       // Fallback to `Client::new()` removed: that path re-enabled the
                                                                                       // default redirect policy and would silently reopen the SSRF
                                                                                       // gap. `.build()` rarely fails (TLS init issues only), and
                                                                                       // `Client::new()` would also panic on the same failure mode —
                                                                                       // so a loud `.expect()` is functionally equivalent and removes
                                                                                       // the false sense of recovery.
                                                                                       // MCP-1034: explicit connect_timeout (2s on 5s budget) so a
                                                                                       // black-holed SLA-webhook endpoint fails on connect rather than
                                                                                       // burning the whole loop tick.
                                                                                       // Built via the shared SSRF-safe builder: redirect(none) + the
                                                                                       // connect-time ControllerSsrfResolver. The SLA-alert webhook URL is
                                                                                       // user/workflow-supplied (SLA threshold config) and SSRF-checked at fire
                                                                                       // time, but that call-time check can't stop DNS rebinding — the same gap
                                                                                       // PR #162 closed for the sibling fire sites.
        let http_client = talos_http_utils::outbound::build_outbound_webhook_client_with_timeout(
            "talos-sla-webhook/1.0",
            std::time::Duration::from_secs(5),
        )
        .expect("SLA monitor: failed to build HTTP client with no-redirect policy");
        let analytics_repo = analytics_repository::AnalyticsRepository::new(sla_pool.clone());

        loop {
            let should_proceed = tokio::select! {
                _ = interval.tick() => true,
                _ = shutdown.changed() => !*shutdown.borrow(),
            };
            if !should_proceed {
                tracing::info!("SLA degradation alerting loop received shutdown signal");
                break;
            }

            // 1. Check workflows with explicit SLA thresholds
            let sla_rows: Vec<(
                uuid::Uuid,
                uuid::Uuid,
                String,
                Option<f64>,
                Option<f64>,
                Option<String>,
            )> = match sqlx::query_as(
                "SELECT t.workflow_id, w.user_id, w.name, \
                            t.success_rate_pct::float8, t.p95_latency_ms::float8, \
                            t.notification_webhook \
                     FROM workflow_sla_thresholds t \
                     JOIN workflows w ON w.id = t.workflow_id \
                     LIMIT 500",
            )
            .fetch_all(&sla_pool)
            .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::error!("SLA check: failed to fetch thresholds: {}", e);
                    continue;
                }
            };

            for (wf_id, wf_user_id, wf_name, target_rate, target_p95, webhook) in &sla_rows {
                // Use centralized AnalyticsRepository::get_sla_window_stats so
                // SLA alerting and readiness scoring share identical PERCENTILE
                // computations.
                let stats = match analytics_repo.get_sla_window_stats(*wf_id, 24).await {
                    Some(s) if s.total >= 3 => s, // Minimum volume: 3 executions
                    _ => continue,
                };
                let (total, successes, p95_ms) = (stats.total, stats.successes, stats.p95_ms);

                let actual_rate = (successes as f64 / total as f64) * 100.0;

                // Check success rate SLA
                if let Some(target) = target_rate {
                    if actual_rate < *target {
                        let msg = format!(
                            "SLA violation: {} success rate {:.1}% < threshold {:.1}% (last 24h, {}/{})",
                            wf_name, actual_rate, target, successes, total
                        );
                        // Create alert (dedup handles repeated violations).
                        // If the alert insert fails, the next tick won't see
                        // the existing dedup row and would re-insert — log
                        // so the dedup behavior is observable.
                        // N-L (2026-05-06): snapshot workflow_name into the
                        // alert row so the operator dashboard surfaces the
                        // name even after the workflow is deleted.
                        if let Err(e) = sqlx::query(
                            "INSERT INTO workflow_alerts (id, user_id, workflow_id, execution_id, alert_type, message, workflow_name) \
                             VALUES ($1, $2, $3, $4, 'sla_violation', $5, $6) \
                             ON CONFLICT (workflow_id, message) WHERE acknowledged = false \
                             DO UPDATE SET occurrence_count = workflow_alerts.occurrence_count + 1, \
                                          last_occurred_at = NOW()",
                        )
                        .bind(uuid::Uuid::new_v4())
                        .bind(wf_user_id)
                        .bind(wf_id)
                        .bind(uuid::Uuid::nil()) // no specific execution
                        .bind(&msg)
                        .bind(wf_name)
                        .execute(&sla_pool)
                        .await
                        {
                            tracing::error!(
                                workflow_id = %wf_id,
                                error = %e,
                                "SLA monitor: failed to insert/dedup workflow_alert (success-rate)"
                            );
                        }

                        tracing::warn!(workflow = %wf_name, actual = actual_rate, target = target, "SLA violation detected");

                        // Fire notification webhook if configured
                        if let Some(url) = webhook {
                            if !url.is_empty()
                                && mcp::utils::check_outbound_url_no_ssrf(url).is_ok()
                            {
                                let payload = serde_json::json!({
                                    "event": "sla_violation",
                                    "workflow_id": wf_id,
                                    "workflow_name": wf_name,
                                    "metric": "success_rate",
                                    "actual": actual_rate,
                                    "threshold": target,
                                    "period": "24h",
                                    "timestamp": chrono::Utc::now().to_rfc3339()
                                });
                                let client = http_client.clone();
                                let url = url.clone();
                                // MCP-774 (2026-05-13): log delivery failures
                                // on the SLA-degradation webhook fire. Pre-fix
                                // `let _ = ...await` discarded both Ok-status
                                // and Err — if the operator's notification
                                // endpoint (PagerDuty / Slack / incident-mgmt)
                                // was unreachable (DNS / TLS / 5xx / network
                                // partition), the SLA violation was DETECTED
                                // and ALERTED locally (via workflow_alerts
                                // INSERT above) but NEVER delivered, with zero
                                // log signal correlating the delivery failure
                                // to controller health. Same operator-visibility
                                // class as MCP-742 (failure_webhook.rs sibling)
                                // and MCP-733..746. The 5-minute SLA threshold
                                // breach task in this same file (~line 3729 /
                                // 3756) already follows the canonical shape;
                                // this 15-minute degradation task was drifted.
                                tokio::spawn(async move {
                                    match client.post(&url).json(&payload).send().await {
                                        Ok(resp) if resp.status().is_success() => {
                                            tracing::debug!(
                                                webhook = %url,
                                                status = resp.status().as_u16(),
                                                "SLA-degradation webhook delivered"
                                            );
                                        }
                                        Ok(resp) => {
                                            tracing::warn!(
                                                target: "talos_rpc",
                                                webhook = %url,
                                                status = resp.status().as_u16(),
                                                "SLA-degradation webhook returned non-success status — operator notification may not have reached its destination"
                                            );
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                target: "talos_rpc",
                                                webhook = %url,
                                                error = %e,
                                                "SLA-degradation webhook POST failed — operator notification undelivered"
                                            );
                                        }
                                    }
                                });
                            }
                        }
                    }
                }

                // Check p95 latency SLA
                if let (Some(target), Some(actual)) = (target_p95, p95_ms) {
                    if actual > *target {
                        let msg = format!(
                            "SLA violation: {} p95 latency {:.0}ms > threshold {:.0}ms (last 24h)",
                            wf_name, actual, target
                        );
                        // N-L: workflow_name snapshot, see above.
                        if let Err(e) = sqlx::query(
                            "INSERT INTO workflow_alerts (id, user_id, workflow_id, execution_id, alert_type, message, workflow_name) \
                             VALUES ($1, $2, $3, $4, 'sla_violation', $5, $6) \
                             ON CONFLICT (workflow_id, message) WHERE acknowledged = false \
                             DO UPDATE SET occurrence_count = workflow_alerts.occurrence_count + 1, \
                                          last_occurred_at = NOW()",
                        )
                        .bind(uuid::Uuid::new_v4())
                        .bind(wf_user_id)
                        .bind(wf_id)
                        .bind(uuid::Uuid::nil())
                        .bind(&msg)
                        .bind(wf_name)
                        .execute(&sla_pool)
                        .await
                        {
                            tracing::error!(
                                workflow_id = %wf_id,
                                error = %e,
                                "SLA monitor: failed to insert/dedup workflow_alert (p95-latency)"
                            );
                        }
                    }
                }
            }

            // 2. Catch catastrophic failures for workflows WITHOUT explicit thresholds
            // Alert when success rate < 50% with at least 5 executions in the last 24h
            let catastrophic: Vec<(uuid::Uuid, uuid::Uuid, String, i64, i64)> = sqlx::query_as(
                "SELECT w.id, w.user_id, w.name, \
                        COUNT(*), \
                        COUNT(*) FILTER (WHERE we.status = 'completed') \
                 FROM workflows w \
                 JOIN workflow_executions we ON we.workflow_id = w.id \
                 WHERE we.started_at > NOW() - INTERVAL '24 hours' \
                   AND w.status = 'active' \
                   AND w.id NOT IN (SELECT workflow_id FROM workflow_sla_thresholds) \
                 GROUP BY w.id, w.user_id, w.name \
                 HAVING COUNT(*) >= 5 \
                    AND (COUNT(*) FILTER (WHERE we.status = 'completed'))::float / COUNT(*) < 0.5 \
                 LIMIT 100",
            )
            .fetch_all(&sla_pool)
            .await
            .unwrap_or_default();

            for (wf_id, wf_user_id, wf_name, total, successes) in &catastrophic {
                let rate = (*successes as f64 / *total as f64) * 100.0;
                let msg = format!(
                    "Catastrophic failure rate: {} at {:.1}% success ({}/{} in 24h). \
                     Set an SLA threshold with set_workflow_sla_threshold to customize alerting.",
                    wf_name, rate, successes, total
                );
                if let Err(e) = sqlx::query(
                    "INSERT INTO workflow_alerts (id, user_id, workflow_id, execution_id, alert_type, message) \
                     VALUES ($1, $2, $3, $4, 'catastrophic_failure_rate', $5) \
                     ON CONFLICT (workflow_id, message) WHERE acknowledged = false \
                     DO UPDATE SET occurrence_count = workflow_alerts.occurrence_count + 1, \
                                  last_occurred_at = NOW()",
                )
                .bind(uuid::Uuid::new_v4())
                .bind(wf_user_id)
                .bind(wf_id)
                .bind(uuid::Uuid::nil())
                .bind(&msg)
                .execute(&sla_pool)
                .await
                {
                    tracing::error!(
                        workflow_id = %wf_id,
                        error = %e,
                        "SLA monitor: failed to insert/dedup workflow_alert (catastrophic-failure)"
                    );
                }

                tracing::warn!(workflow = %wf_name, success_rate = rate, "Catastrophic failure rate detected");
            }
        }
    });
    tracing::info!("SLA degradation alerting task started (runs every 15 minutes)");
}

/// Gmail watch renewal, Google Calendar channel renewal, and the OAuth
/// proactive token refresh loops. Extracted verbatim from `main()`; spawn
/// order preserved.
pub(crate) fn spawn_integration_renewal_tasks(
    services: &PlatformServices,
    bg_shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let gmail_watch_service = services.gmail_watch_service.clone();
    let google_calendar_service = services.google_calendar_service.clone();
    let oauth_credential_service = services.oauth_credential_service.clone();
    // ---------- Start Gmail watch renewal task ----------
    if let Some(ref gmail_watch) = gmail_watch_service {
        let renewal = gmail_watch.clone();
        let gmail_renewal_shutdown = bg_shutdown_rx.clone();
        tokio::spawn(async move {
            gmail::scheduler::gmail_renewal_task(renewal, gmail_renewal_shutdown).await;
        });
        tracing::info!("Gmail watch renewal task started (runs every hour)");

        // Sweep the per-(user,integration) create-lock map hourly so
        // it doesn't grow unbounded in a long-running controller.
        let cleanup_gmail = gmail_watch.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                cleanup_gmail.cleanup_create_locks();
            }
        });
    }

    // ---------- GCP watch create-lock sweep ----------
    // No renewal task for GCP (the user owns the upstream subscription;
    // nothing on our side expires). We only sweep the create-lock map so
    // it can't grow unbounded over the controller's lifetime.
    if let Some(gcp_watch) = services.gcp_watch_service.clone() {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                gcp_watch.cleanup_create_locks();
            }
        });
    }

    // ---------- Start Google Calendar channel renewal task ----------
    if google_calendar_service.is_configured() {
        let renewal_service = google_calendar_service.clone();
        let gcal_renewal_shutdown = bg_shutdown_rx.clone();
        tokio::spawn(async move {
            google_calendar::scheduler::channel_renewal_task(
                renewal_service,
                gcal_renewal_shutdown,
            )
            .await;
        });
        tracing::info!("Google Calendar channel renewal task started (runs every hour)");

        // Per-channel webhook rate-limiter cleanup (runs every 5 minutes).
        // Also sweeps the create_channel_locks DashMap to prevent
        // unbounded growth over the controller's lifetime.
        let cleanup_gcal_rl = google_calendar_service.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                cleanup_gcal_rl.cleanup_webhook_channel_limits();
                cleanup_gcal_rl.cleanup_create_channel_locks();
            }
        });

        // Event sync task will be started after Redis/NATS are initialized
    }

    // ---------- Start OAuth proactive token refresh task ----------
    {
        let cred_service_bg = oauth_credential_service.clone();
        tokio::spawn(async move {
            oauth::refresh_task::proactive_token_refresh_task(cred_service_bg).await;
        });
        tracing::info!("OAuth proactive token refresh task started (5-minute interval)");
    }
}

/// `kind` label values for `talos_wasm_log_orphaned_total`. A closed set of
/// `&'static str`, and it must stay closed: `/metrics/prometheus` is
/// scrapeable, and the thing being counted is a log line whose body is
/// guest-authored module output. Neither the message, nor the execution id, nor
/// the NATS subject may ever become a label.
pub(crate) const WASM_LOG_ORPHAN_NO_EXECUTION_ROW: &str = "no_execution_row";
pub(crate) const WASM_LOG_ORPHAN_UNPARSEABLE_ID: &str = "unparseable_id";

/// Handle ONE `wasm.log.*` message: broadcast it live, persist it to whichever
/// log table owns its execution id, and — when neither owns it — say so loudly
/// on both the operator log and `talos_wasm_log_orphaned_total`.
///
/// Extracted VERBATIM out of the subscriber loop in `spawn_nats_log_subscribers`
/// (2026-08) so the discard branches are reachable from a test at all: the loop
/// needs a live NATS server, this function needs only a payload. The
/// `unparseable_id` branch runs before any DB call and is therefore driven
/// end-to-end offline; the `no_execution_row` branch sits behind two Postgres
/// round-trips and is NOT covered by an offline test — the test module at the
/// bottom of this file says so rather than implying otherwise.
///
/// Neither increment goes through a shared warn-and-count helper; see the
/// detector-metrics block in `talos_metrics::TalosMetrics` for why a macro
/// would re-blind structural check 58.
async fn handle_wasm_log_message(
    msg: &async_nats::Message,
    exec_repo_for_wasm_logs: &crate::execution_repository::ExecutionRepository,
    exec_service_for_logs: &ModuleExecutionService,
    tx_for_wasm_logs: &tokio::sync::broadcast::Sender<ExecutionEvent>,
) {
    // DEBUG: Log when message is received
    tracing::info!("📩 Received WASM log from NATS topic: {}", msg.subject);

    // Parse log message from NATS
    match serde_json::from_slice::<serde_json::Value>(&msg.payload) {
        Ok(log_msg) => {
            // Extract fields with defaults
            let execution_id = log_msg
                .get("execution_id")
                .and_then(|v| v.as_str())
                .and_then(|s| uuid::Uuid::parse_str(s).ok());

            let level_str = log_msg
                .get("level")
                .and_then(|v| v.as_str())
                .unwrap_or("info");

            // Convert string to LogLevel enum. Case-insensitive
            // because the worker emits UPPERCASE ("INFO", "WARN",
            // ...) while older test paths used lowercase. Without
            // the fold, every uppercase line collapsed to Info.
            let level = match level_str.to_ascii_lowercase().as_str() {
                "debug" => LogLevel::Debug,
                "warn" => LogLevel::Warn,
                "error" => LogLevel::Error,
                _ => LogLevel::Info,
            };

            let message = log_msg
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let metadata = log_msg.get("metadata").cloned();
            let trace_id = log_msg
                .get("trace_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let span_id = log_msg
                .get("span_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            // Save to database (best-effort - don't crash on error)
            if let Some(exec_id) = execution_id {
                let node_id = metadata
                    .as_ref()
                    .and_then(|m| m.get("node_id"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| uuid::Uuid::parse_str(s).ok());

                // MCP-1011 sibling: scrub the broadcast `message`
                // the same way `add_workflow_log` scrubs before
                // persisting. Pre-fix the persistence path
                // (`workflow_execution_logs.message`) applied
                // MCP-481 truncation + control-char strip +
                // `redact_str`, but the parallel `tx_for_wasm_logs`
                // broadcast used the raw `message` — a WASM module
                // emitting a Bearer / sk- / ghp_ token leaked it
                // to live `execution_updates` GraphQL subscribers
                // even though the persisted row was clean. See
                // `scrub_wasm_log_for_broadcast` (above) for the
                // canonical pipeline — kept in lockstep with the
                // persistence path so the live channel can't
                // carry more than the persisted row.
                let scrubbed_for_broadcast = scrub_wasm_log_for_broadcast(&message);

                // Broadcast the live log to all connected GraphQL clients!
                let _ = tx_for_wasm_logs.send(ExecutionEvent {
                    execution_id: exec_id,
                    node_id,
                    status: ExecutionStatus::Running,
                    trace_id,
                    span_id,
                    log_message: Some(format!(
                        "[{}] {}",
                        level_str.to_uppercase(),
                        scrubbed_for_broadcast
                    )),
                    iteration_index: None,
                    iteration_total: None,
                    duration_ms: None,
                    output: None,
                });

                // Route to the right log table:
                //   - workflow_execution_logs when exec_id is a workflow_executions.id
                //     (the common case — every run via trigger_workflow / call_workflow / scheduled)
                //   - module_execution_logs when exec_id is a module_executions.id
                //     (standalone module runs via webhook / test_module)
                // `add_workflow_log` does a `WHERE EXISTS`-guarded insert and
                // returns `Ok(false)` (rather than tripping the FK constraint)
                // when exec_id isn't a workflow execution — so the standalone-
                // module case no longer emits a Postgres FK-violation ERROR per
                // log line. Single round trip for the common (workflow) case.
                let level_upper = match level {
                    LogLevel::Debug => "DEBUG",
                    LogLevel::Info => "INFO",
                    LogLevel::Warn => "WARN",
                    LogLevel::Error => "ERROR",
                };
                match exec_repo_for_wasm_logs
                    .add_workflow_log(exec_id, node_id, level_upper, &message, metadata.as_ref())
                    .await
                {
                    Ok(true) => {} // landed in workflow_execution_logs
                    Ok(false) => {
                        // Not a workflow execution → standalone module run.
                        let outcome = exec_service_for_logs
                            .add_log_best_effort(exec_id, level, message, metadata)
                            .await;
                        // BOTH routes missed: `exec_id` names
                        // neither a `workflow_executions` row nor a
                        // `module_executions` row, so this line has
                        // been DISCARDED. This is the terminal hop —
                        // if we don't say it here, nobody does, and
                        // `get_execution_logs` will return `[]`,
                        // byte-identical to an execution that
                        // genuinely logged nothing. That silence is
                        // how every Loop-node iteration lost all of
                        // its logs (host diagnostics AND guest
                        // `logging::log`) unnoticed until 2026-07-30.
                        //
                        // Only `NoExecutionRow` warns: a `RateLimited`
                        // drop is deliberate back-pressure and a
                        // `WriteFailed` already warned inside
                        // `add_log_best_effort` — calling either
                        // "orphaned" would be the misleading-signal
                        // bug in the fix for a misleading signal.
                        //
                        // CONTENT: execution id + level ONLY. The
                        // message body is guest-authored and may carry
                        // anything the module printed; it must not be
                        // copied into the controller's operator log by
                        // a diagnostic about routing.
                        //
                        // VOLUME: one warn per orphaned line is
                        // bounded, not unbounded — a producer's
                        // per-execution log budget is capped in the
                        // worker (MAX_LOG_MESSAGES_PER_EXECUTION for
                        // guest lines, HOST_DIAG_CAP for host
                        // diagnostics), so a single pathological module
                        // cannot emit more warns than it can emit logs.
                        //
                        // EXPECTED RATE: zero on ordinary
                        // trigger / schedule / webhook / push traffic
                        // — every routine dispatch path pre-INSERTs its
                        // row before publishing (single-node
                        // `engine_dispatch_single.rs`, pipeline steps via
                        // the parent `workflow_executions.id`, loop bodies
                        // as of 2026-07-30, and the live webhook path at
                        // `talos-webhooks/src/router.rs`). It is NOT
                        // zero everywhere, and the earlier draft of this
                        // comment claiming otherwise was the same
                        // unearned-certainty class the warn exists to
                        // close.
                        //
                        // The 2026-07-30 audit listed three residual
                        // producers here. Two of them — webhook DLQ
                        // replay (no row at all) and Google Calendar
                        // push (random `job_id` when `create_execution`
                        // errored) — were closed on 2026-07-31, along
                        // with a fourth the audit itself had missed: the
                        // LIVE webhook INSERT, which on error logged and
                        // dispatched anyway. All three webhook/GCal paths
                        // now fail closed. Do not re-derive that list
                        // from this comment: it is a snapshot, and this
                        // is the second time it has gone stale. The warn
                        // below is the live detector — trust it over the
                        // prose.
                        //
                        // ONE deliberate producer remains, and it is not
                        // a bug: either engine `record_started` failing
                        // is non-fatal by design (always paired with a
                        // nearby `tracing::error!`), so a DB blip during
                        // a node dispatch still orphans that node's
                        // lines.
                        //
                        // A burst of these named by `exec_id` therefore
                        // means either that, or a NEW dispatch path that
                        // mints an id without recording a row — which is
                        // what this warn is FOR. Fix the producer; do
                        // not silence the warn.
                        if outcome.is_orphaned() {
                            // The metric twin of the WARN below. The label is a
                            // closed-set &'static str — never the guest-authored
                            // message body, never `exec_id` (per-execution labels
                            // are unbounded cardinality on a scrapeable endpoint,
                            // and an orphaned line is exactly the content that
                            // must not leak there).
                            if let Some(m) = metrics::global() {
                                m.wasm_log_orphaned_total
                                    .with_label_values(&[WASM_LOG_ORPHAN_NO_EXECUTION_ROW])
                                    .inc();
                            }
                            tracing::warn!(
                                target: "talos_controller",
                                event_kind = "wasm_log_orphaned",
                                %exec_id,
                                level = level_upper,
                                "WASM log line discarded: execution id matches \
                                 neither workflow_executions nor module_executions. \
                                 The dispatching path minted an id without \
                                 recording an execution row — its logs are being \
                                 lost and will not appear in get_execution_logs."
                            );
                        }
                    }
                    Err(e) => {
                        // exec_id IS a workflow execution but the insert failed
                        // (5000-entry rate-limit trigger, DB outage). Don't
                        // misroute a real workflow log to the module table.
                        tracing::debug!(
                            %exec_id,
                            error = %e,
                            "workflow_execution_logs insert failed (capped or DB error)"
                        );
                    }
                }
            } else {
                // Same class as `wasm_log_orphaned` one branch up:
                // the line is discarded here and nothing downstream
                // will ever mention it. A `debug!` (off in every
                // real deployment) meant an entire producer could
                // publish malformed ids forever and read as silence.
                // No message body — see the content rule above.
                if let Some(m) = metrics::global() {
                    m.wasm_log_orphaned_total
                        .with_label_values(&[WASM_LOG_ORPHAN_UNPARSEABLE_ID])
                        .inc();
                }
                tracing::warn!(
                    target: "talos_controller",
                    event_kind = "wasm_log_unparseable_execution_id",
                    subject = %msg.subject,
                    "WASM log line discarded: missing or unparseable execution_id"
                );
            }
        }
        Err(e) => {
            tracing::debug!("Failed to parse WASM log message: {}", e);
        }
    }
}

/// WASM-log subscriber + job-result subscriber (both supervisor-wrapped,
/// MCP-1121/1122). Extracted verbatim from `main()`; spawn order preserved.
/// The per-message body of the WASM-log loop now lives in
/// [`handle_wasm_log_message`] above.
pub(crate) fn spawn_nats_log_subscribers(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    nats_client: Option<std::sync::Arc<async_nats::Client>>,
    services: &PlatformServices,
    buses: &EventBuses,
) -> anyhow::Result<()> {
    let module_execution_service = services.module_execution_service.clone();
    let worker_shared_key = services.worker_shared_key.clone();
    let tx = buses.tx.clone();
    let workflow_execution_tx = buses.workflow_execution_tx.clone();
    // ---------- Start WASM log subscriber (automatic logging from worker) ----------
    // This background task receives logs from WASM executions and persists them to database
    // Provides guaranteed observability for all WASM module executions
    if let Some(nats) = nats_client.clone() {
        let exec_service_for_logs = module_execution_service.clone();
        let tx_for_wasm_logs = tx.clone();
        // Build a lightweight ExecutionRepository for the wasm-log subscriber
        // so it can persist workflow-execution logs to the new
        // workflow_execution_logs table. Output encryption isn't needed —
        // the subscriber only writes logs, never reads encrypted outputs.
        let exec_repo_for_wasm_logs = std::sync::Arc::new(
            crate::execution_repository::ExecutionRepository::new(db_pool.clone())
                .with_workflow_execution_sender(workflow_execution_tx.clone()),
        );
        tokio::spawn(async move {
            tracing::info!("Starting WASM log subscriber on topic: wasm.log.*");

            // MCP-1121 (2026-05-16): supervisor loop wraps the inner
            // subscriber. Sibling sweep of MCP-1119/1120 (audit-ledger
            // JetStream + worker-fleet heartbeats). Pre-fix when
            // `subscriber.next()` returned None (NATS disconnect,
            // server-side unsubscribe, client reconnect window), the
            // spawned task exited and workflow execution logs stopped
            // persisting until controller restart — `workflow_execution_logs`
            // table received nothing, the UI's live log stream went
            // silent, and operators couldn't see workflow progress
            // mid-execution. Workers continue publishing to NATS but
            // without a JetStream durable here the messages drop on
            // the floor.
            //
            // Same audit rule (MCP-1119/1120): every background-spawned
            // message-consumer that processes external infrastructure
            // events MUST be supervisor-wrapped. Exponential backoff
            // caps at 60s, resets on successful bind.
            let mut backoff_secs: u64 = 1;
            'supervisor: loop {
                // Subscribe to all WASM log topics (wasm.log.{execution_id})
                let mut subscriber = match nats.subscribe("wasm.log.*").await {
                    Ok(sub) => sub,
                    Err(e) => {
                        tracing::error!(
                            target: "talos_controller",
                            event_kind = "wasm_log_subscribe_failed",
                            error = %e,
                            backoff_secs,
                            "Failed to subscribe to WASM logs; retrying after backoff"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(60);
                        continue 'supervisor;
                    }
                };
                backoff_secs = 1;

                tracing::info!("WASM log subscriber active - waiting for messages");

                // Process messages as they arrive
                while let Some(msg) = subscriber.next().await {
                    handle_wasm_log_message(
                        &msg,
                        &exec_repo_for_wasm_logs,
                        &exec_service_for_logs,
                        &tx_for_wasm_logs,
                    )
                    .await;
                }

                // MCP-1121: stream ended — supervisor re-binds.
                tracing::warn!(
                    target: "talos_controller",
                    event_kind = "wasm_log_subscriber_rebinding",
                    "WASM log subscriber stream ended; supervisor re-binding (no controller restart required)"
                );
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            } // end 'supervisor
        });
        tracing::info!("WASM log subscriber task started");

        // ---------- Start job result subscriber ----------
        // The worker publishes JobResult messages to talos.results.{job_id} after each
        // WASM execution completes.  This subscriber receives those results and updates
        // the module_executions record status to 'completed' or 'failed' so the UI can
        // display the outcome.
        let exec_service_for_results = module_execution_service.clone();
        let nats_for_results = nats_client
            .clone()
            .ok_or_else(|| anyhow::anyhow!("NATS client missing"))?;
        // Clone the shared key into a verify-ring (current + any staged
        // WORKER_SHARED_KEY_PREVIOUS) so this audit observer accepts results
        // signed under a previous key during a rolling rotation, consistent
        // with the primary verifier in the engine dispatcher. Moved into the
        // spawn; the original `worker_shared_key` is still used later for the
        // Extension layer.
        let worker_key_ring_for_results = worker_shared_key.clone().map(|signing| {
            talos_workflow_engine_core::WorkerKeyRing::new(
                signing,
                talos_workflow_job_protocol::load_worker_shared_key_previous().unwrap_or_default(),
            )
        });
        tokio::spawn(async move {
            tracing::info!("Starting job result subscriber on topic: talos.results.*");

            // MCP-1122 (2026-05-16): supervisor loop wraps the inner
            // subscriber. Fourth site in the MCP-1119/1120/1121 sweep.
            // The comment further down at line ~2960 notes this
            // subscriber is "mostly dormant" today (every NATS-dispatched
            // path uses request-reply), but it's the canonical landing
            // point for future async-dispatch / work-queue patterns —
            // when those land, the subscriber silently exiting on
            // stream-end (NATS reconnect, server-side unsubscribe,
            // client reconnect window) would be a latent reliability
            // gap. Bring it into supervisor parity with siblings now
            // so a future regression doesn't surface as "results
            // mysteriously stopped updating after a NATS hiccup."
            let mut backoff_secs: u64 = 1;
            'supervisor: loop {
                let mut sub = match nats_for_results
                    .subscribe(talos_workflow_job_protocol::subjects::RESULTS_WILDCARD)
                    .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(
                            target: "talos_controller",
                            event_kind = "job_result_subscribe_failed",
                            error = %e,
                            backoff_secs,
                            "Failed to subscribe to job results; retrying after backoff"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(60);
                        continue 'supervisor;
                    }
                };
                backoff_secs = 1;

                tracing::info!("Job result subscriber active");

                while let Some(msg) = sub.next().await {
                    match serde_json::from_slice::<talos_workflow_job_protocol::JobResult>(
                        &msg.payload,
                    ) {
                        Ok(result) => {
                            let job_id = result.job_id;

                            // SECURITY: Verify HMAC-SHA256 signature + freshness
                            // window. Rejects results injected by any process that
                            // can publish to NATS but does not know the pre-shared
                            // key.
                            //
                            // Post-r301 the worker single-publishes: it sends a
                            // result to EITHER the request-reply inbox OR
                            // `talos.results.{job_id}` based on whether the
                            // requester awaited the reply, never both. So this
                            // subscriber only sees results that no other in-process
                            // verifier has handled — there's no second verify to
                            // race.
                            //
                            // We still call `verify_no_replay` here (not `verify`)
                            // as defense-in-depth: it keeps this subscriber
                            // safe-by-default if a future code path re-introduces a
                            // dual-publish or a sibling subscriber, and the side
                            // effect (`UPDATE module_executions WHERE status IN
                            // ('pending','running')`) is idempotent under replay
                            // anyway. HMAC + freshness still catch forgery and
                            // stale-replay; the worker is the primary
                            // replay-cache writer for fire-and-forget results.
                            //
                            // Today every NATS-dispatched code path uses
                            // request-reply, so this subscriber is mostly dormant
                            // — kept as the canonical landing point for future
                            // truly-async dispatches (work-queue style).
                            // L-4: typed Observer verifier — this audit
                            // subscriber on `talos.results.*` only writes
                            // an idempotent UPDATE; primary verification
                            // happens at the request-reply inbox in the
                            // engine dispatcher / webhook handler. Using
                            // `Verifier::Observer` documents the role at
                            // the type level so a future refactor can't
                            // accidentally convert this site to a primary
                            // verifier and reintroduce the r300 regression.
                            if let Some(ref ring) = worker_key_ring_for_results {
                                // RFC 0010 P2: scheme-routing Observer verify —
                                // Ed25519 against the keys registered for this
                                // worker_id, or legacy HMAC against the ring
                                // while `result_accept_legacy_hmac()`. NEVER
                                // records the replay cache (Observer role): the
                                // request-reply dispatcher is the sole Primary
                                // verifier, per the verify-once rule.
                                let worker_ed_keys =
                                    talos_workflow_job_protocol::worker_public_keys(
                                        &result.worker_id,
                                    );
                                if let Err(e) = result.verify_no_replay_dispatch(
                                    ring,
                                    &worker_ed_keys,
                                    300,
                                    talos_workflow_job_protocol::result_accept_legacy_hmac(),
                                ) {
                                    tracing::warn!(
                                    "Rejected job result {}: signature verification failed — {}",
                                    job_id,
                                    e
                                );
                                    continue;
                                }
                            }
                            tracing::debug!(
                                "📥 Received job result: {} ({:?}, {}ms)",
                                job_id,
                                result.status,
                                result.execution_time_ms
                            );

                            match result.status {
                                talos_workflow_job_protocol::JobStatus::Success => {
                                    if let Err(e) = exec_service_for_results
                                        .complete_execution_from_worker(
                                            job_id,
                                            // Storage takes the PARSED payload; the
                                            // signature that covered the raw wire text
                                            // was already verified above.
                                            Some(result.output_payload.into_value()),
                                        )
                                        .await
                                    {
                                        tracing::warn!(
                                            "Failed to mark execution {} as completed: {}",
                                            job_id,
                                            e
                                        );
                                    } else {
                                        tracing::info!(
                                            "✅ Execution {} completed ({}ms)",
                                            job_id,
                                            result.execution_time_ms
                                        );
                                    }
                                }
                                talos_workflow_job_protocol::JobStatus::Failed
                                | talos_workflow_job_protocol::JobStatus::TimedOut => {
                                    let error_msg = result
                                        .output_payload
                                        .value()
                                        .get("error")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("Worker reported failure")
                                        .to_string();
                                    let error_type = matches!(
                                        result.status,
                                        talos_workflow_job_protocol::JobStatus::TimedOut
                                    )
                                    .then_some("timeout".to_string());

                                    if let Err(e) = exec_service_for_results
                                        .fail_execution_from_worker(
                                            job_id,
                                            error_msg.clone(),
                                            error_type,
                                        )
                                        .await
                                    {
                                        tracing::warn!(
                                            "Failed to mark execution {} as failed: {}",
                                            job_id,
                                            e
                                        );
                                    } else {
                                        // MCP-989 (2026-05-15): DLP-redact the
                                        // failure preview at the operator-log
                                        // boundary. `fail_execution_from_worker`
                                        // redacts before persisting to
                                        // `module_executions.error_message`
                                        // (MCP-968), but this INFO log was
                                        // taking the first 100 chars of the
                                        // ORIGINAL worker-supplied error_msg.
                                        // Worker failures regularly carry
                                        // upstream auth errors that echo the
                                        // rejected token in the body; secret-
                                        // shaped prefixes must not land in
                                        // operator log pipelines. Same
                                        // wrapper class as the two
                                        // talos-module-executions sites
                                        // closed in this MCP.
                                        let preview: String =
                                            talos_dlp_provider::redact_str(&error_msg)
                                                .chars()
                                                .take(100)
                                                .collect();
                                        tracing::info!(
                                            "❌ Execution {} failed: {}",
                                            job_id,
                                            preview
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!("Failed to parse job result message: {}", e);
                        }
                    }
                }

                // MCP-1122: stream ended — supervisor re-binds.
                tracing::warn!(
                    target: "talos_controller",
                    event_kind = "job_result_subscriber_rebinding",
                    "Job result subscriber stream ended; supervisor re-binding"
                );
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            } // end 'supervisor
        });
        tracing::info!("Job result subscriber task started");
    } else {
        tracing::warn!("NATS not configured - WASM automatic logging disabled");
    }

    // Note: Periodic event sync task removed — sync_channel_events() advances the sync
    // token each time it runs, which would silently consume the token before the webhook
    // handler could use it, causing missed events. Syncing is driven exclusively by
    // real-time push notifications (webhook_notification_handler).

    Ok(())
}

/// Stale-execution cleanup, the workflow scheduler, and the SLA threshold
/// breach check. Extracted verbatim from `main()`; spawn order preserved
/// (these three started after router assembly in the original body).
pub(crate) fn spawn_late_background_tasks(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    nats_client: Option<std::sync::Arc<async_nats::Client>>,
    core: &CoreServices,
    services: &PlatformServices,
    tx_for_scheduler: broadcast::Sender<ExecutionEvent>,
    bg_shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let secrets_manager = core.secrets_manager.clone();
    let registry = core.registry.clone();
    let worker_manager = services.worker_manager.clone();
    let module_execution_service = services.module_execution_service.clone();
    let worker_shared_key = services.worker_shared_key.clone();
    // ---------- Start stale execution cleanup task ----------
    // Marks executions stuck in 'running' state beyond a configurable threshold
    // as 'failed'. Prevents ghost executions from accumulating indefinitely.
    //
    // MCP-1042 (2026-05-15): subscribe to `bg_shutdown_rx` so SIGTERM
    // exits the loop cleanly between ticks instead of aborting the
    // task (and any in-flight UPDATE) when the tokio runtime drops at
    // process end. Sibling discipline to the LLM-keys cache sweep
    // (line 1075) and the actor-memory TTL sweep — DB-writing
    // background loops need explicit shutdown wiring to avoid
    // wedging a connection-pool entry on a half-issued statement.
    let cleanup_pool = db_pool.clone();
    let cleanup_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = cleanup_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // MCP-665 (2026-05-13): route through `positive_env_or_default`
                    // so `STALE_EXECUTION_MINUTES=0` doesn't mass-fail every
                    // in-flight execution on the next tick. With `=0`,
                    // `make_interval(mins => 0)` is zero, so
                    // `started_at < NOW() - 0` matches every running row →
                    // catastrophic auto-cleanup that terminates every workflow.
                    // Negative values are equally destructive (NOW() - negative =
                    // future time, also matches everything). Same `=0` footgun
                    // class as MCP-638/643/661/663/664 — this one's the highest-
                    // blast-radius of the set (mass execution kill).
                    let stale_minutes: i32 =
                        talos_config::positive_env_or_default("STALE_EXECUTION_MINUTES", 60i32);
                    let result = sqlx::query(
                        "UPDATE workflow_executions SET status = 'failed', \
                         error_message = 'Auto-cleaned: execution stale (running > configured threshold)', \
                         completed_at = NOW() \
                         WHERE status IN ('running') AND status != 'queued' AND started_at < NOW() - make_interval(mins => $1::int)"
                    ).bind(stale_minutes).execute(&cleanup_pool).await;
                    if let Ok(r) = result {
                        if r.rows_affected() > 0 {
                            tracing::info!(count = r.rows_affected(), "Auto-cleaned stale executions");
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Stale execution cleanup loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("Stale execution auto-cleanup task started (runs every 5 minutes, threshold configurable via STALE_EXECUTION_MINUTES)");

    // ---------- Start workflow scheduler ----------
    // Polls every 15 seconds for due schedules and triggers workflow executions.
    // Requires NATS (already required by WebhookRouter, so always available if server started).
    if let Some(nats) = nats_client.clone() {
        let scheduler = std::sync::Arc::new(crate::scheduler::SchedulerService::new(
            db_pool.clone(),
            tx_for_scheduler,
            registry.clone(),
            secrets_manager.clone(),
            worker_manager.clone(),
            module_execution_service.clone(),
            worker_shared_key.clone(),
            nats,
        ));
        let scheduler_shutdown = bg_shutdown_rx.clone();
        tokio::spawn(async move {
            scheduler.run_with_shutdown(scheduler_shutdown).await;
        });
        tracing::info!("Workflow scheduler started (polls every 15 seconds, backfills null next_trigger_at on startup; graceful-shutdown enabled)");
    } else {
        tracing::warn!(
            "Workflow scheduler not started: NATS_URL not configured. \
             Scheduled workflows will not fire automatically."
        );
    }

    // ---------- Start SLA threshold breach check task (Round 43) ----------
    // MCP-1045: subscribe to bg_shutdown_rx — issues per-threshold
    // INSERTs into workflow_sla_alerts on breach detection. Outer
    // 5-min ticker gated; inner per-threshold INSERT runs to natural
    // completion within one tick.
    let sla_pool = db_pool.clone();
    let sla_breach_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = sla_breach_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // Every 5 min
                                                                                       // MCP-497: same SSRF-via-redirect fix as MCP-469/470 — the
                                                                                       // `check_outbound_url_no_ssrf` gate below catches the literal
                                                                                       // URL but a 302 from the validated host to an internal host
                                                                                       // bypasses it if reqwest's default redirect policy is in
                                                                                       // effect. `Client::default()` (the prior fallback) re-enables
                                                                                       // following up to 10 hops, so a build-time TLS failure here
                                                                                       // silently reopened the SSRF gap. `.expect()` makes the
                                                                                       // failure loud at startup; `.redirect(Policy::none())` makes
                                                                                       // the SSRF re-check load-bearing.
                                                                                       // MCP-1034: explicit connect_timeout — fast-fail on black-holed
                                                                                       // SLA-alert endpoint.
                                                                                       // Built via the shared SSRF-safe builder (redirect(none) + connect-time
                                                                                       // ControllerSsrfResolver) — same user-supplied SLA-webhook + DNS-rebinding
                                                                                       // rationale as the sibling SLA-monitor client above (PR #162).
        let client =
            talos_http_utils::outbound::build_outbound_webhook_client("talos-sla-webhook/1.0")
                .expect("SLA monitor: failed to build hardened reqwest client");
        loop {
            let should_proceed = tokio::select! {
                _ = interval.tick() => true,
                _ = shutdown.changed() => !*shutdown.borrow(),
            };
            if !should_proceed {
                tracing::info!("SLA threshold breach loop received shutdown signal");
                break;
            }

            // Load all thresholds with their workflow's user_id for scoped queries
            let thresholds = sqlx::query(
                "SELECT t.workflow_id, t.user_id, t.p95_latency_ms, \
                        t.success_rate_pct::float8 AS success_rate_pct, \
                        t.notification_webhook \
                 FROM workflow_sla_thresholds t",
            )
            .fetch_all(&sla_pool)
            .await;

            let thresholds = match thresholds {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!("SLA threshold check: failed to load thresholds: {}", e);
                    continue;
                }
            };

            for row in &thresholds {
                use sqlx::Row;
                let workflow_id: uuid::Uuid = row.get("workflow_id");
                let user_id: uuid::Uuid = row.get("user_id");
                let p95_threshold: Option<i64> = row.get("p95_latency_ms");
                let success_threshold: Option<f64> = row.get("success_rate_pct");
                let webhook: String = row.get("notification_webhook");

                // Re-validate at fire time. Stored URLs that predate the
                // r285 SSRF hardening (obfuscated IPv4 — octal/hex/integer
                // encodings) were accepted at write time but resolve to
                // internal IPs at fire time. Skip rather than fire.
                if let Err(reason) = crate::mcp::utils::check_outbound_url_no_ssrf(&webhook) {
                    tracing::warn!(
                        workflow_id = %workflow_id,
                        "SLA monitor: skipping fire — stored webhook fails SSRF re-check: {reason}"
                    );
                    continue;
                }

                // Query last-24h stats
                let stats = sqlx::query(
                    "SELECT \
                        COUNT(*) FILTER (WHERE status = 'completed')::bigint AS succeeded, \
                        COUNT(*)::bigint AS total, \
                        PERCENTILE_CONT(0.95) WITHIN GROUP \
                            (ORDER BY EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000) \
                            AS p95_ms \
                     FROM workflow_executions \
                     WHERE workflow_id = $1 AND user_id = $2 \
                       AND started_at > NOW() - INTERVAL '24 hours' \
                       AND completed_at IS NOT NULL",
                )
                .bind(workflow_id)
                .bind(user_id)
                .fetch_one(&sla_pool)
                .await;

                let stats = match stats {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let total: i64 = stats.get("total");
                if total == 0 {
                    continue;
                }
                let succeeded: i64 = stats.get("succeeded");
                let p95_ms: Option<f64> = stats.get("p95_ms");
                let actual_success_pct = (succeeded as f64 / total as f64) * 100.0;

                let now = chrono::Utc::now().to_rfc3339();

                // Check p95 latency breach
                if let (Some(threshold), Some(actual)) = (p95_threshold, p95_ms) {
                    if actual > threshold as f64 {
                        let payload = serde_json::json!({
                            "event": "sla_breach",
                            "workflow_id": workflow_id,
                            "metric": "p95_latency_ms",
                            "threshold": threshold,
                            "actual": actual as i64,
                            "timestamp": now,
                        });
                        tracing::warn!(
                            workflow_id = %workflow_id,
                            threshold = threshold,
                            actual = actual as i64,
                            "SLA breach: p95 latency exceeded"
                        );
                        let client = client.clone();
                        let webhook = webhook.clone();
                        // MCP-809 (2026-05-14): canonical 3-arm match.
                        // Pre-fix this fire only logged on Err — an
                        // operator-supplied webhook returning 4xx/5xx
                        // (e.g. PagerDuty rate-limited / Slack 503 /
                        // OpsGenie 502) was silently treated as
                        // success. The sibling 15-min SLA-degradation
                        // fire at ~line 2209 already follows the canonical
                        // shape (MCP-774); this 5-min SLA-breach task
                        // had drifted. Same misleading-success class as
                        // MCP-737/738/800/801. WARN+target talos_rpc so
                        // dashboards correlate delivery-failure rate
                        // with controller health.
                        tokio::spawn(async move {
                            match client.post(&webhook).json(&payload).send().await {
                                Ok(resp) if resp.status().is_success() => {
                                    tracing::debug!(
                                        webhook = %webhook,
                                        status = resp.status().as_u16(),
                                        "SLA-breach (p95) webhook delivered"
                                    );
                                }
                                Ok(resp) => {
                                    tracing::warn!(
                                        target: "talos_rpc",
                                        webhook = %webhook,
                                        status = resp.status().as_u16(),
                                        "SLA-breach (p95) webhook returned non-success status — operator notification may not have reached its destination"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        target: "talos_rpc",
                                        webhook = %webhook,
                                        error = %e,
                                        "SLA-breach (p95) webhook POST failed — operator notification undelivered"
                                    );
                                }
                            }
                        });
                    }
                }

                // Check success rate breach
                if let Some(threshold) = success_threshold {
                    if actual_success_pct < threshold {
                        let payload = serde_json::json!({
                            "event": "sla_breach",
                            "workflow_id": workflow_id,
                            "metric": "success_rate_pct",
                            "threshold": threshold,
                            "actual": (actual_success_pct * 100.0).round() / 100.0,
                            "timestamp": now,
                        });
                        tracing::warn!(
                            workflow_id = %workflow_id,
                            threshold = threshold,
                            actual = actual_success_pct,
                            "SLA breach: success rate below threshold"
                        );
                        let client = client.clone();
                        let webhook = webhook.clone();
                        // MCP-809 (2026-05-14): same misleading-success drift
                        // as the p95 sibling above; mirror the canonical
                        // 3-arm match. See p95 comment for rationale.
                        tokio::spawn(async move {
                            match client.post(&webhook).json(&payload).send().await {
                                Ok(resp) if resp.status().is_success() => {
                                    tracing::debug!(
                                        webhook = %webhook,
                                        status = resp.status().as_u16(),
                                        "SLA-breach (success-rate) webhook delivered"
                                    );
                                }
                                Ok(resp) => {
                                    tracing::warn!(
                                        target: "talos_rpc",
                                        webhook = %webhook,
                                        status = resp.status().as_u16(),
                                        "SLA-breach (success-rate) webhook returned non-success status — operator notification may not have reached its destination"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        target: "talos_rpc",
                                        webhook = %webhook,
                                        error = %e,
                                        "SLA-breach (success-rate) webhook POST failed — operator notification undelivered"
                                    );
                                }
                            }
                        });
                    }
                }
            }
        }
    });
    tracing::info!("SLA threshold breach check task started (runs every 5 minutes)");
}

#[cfg(test)]
mod scrub_wasm_log_for_broadcast_tests {
    use super::{scrub_wasm_log_for_broadcast, MAX_BROADCAST_LOG_CHARS};

    #[test]
    fn redacts_anthropic_secret() {
        // MCP-1011 sibling: a WASM module emitting `sk-ant-...` must
        // have it redacted BEFORE the broadcast lands on the live
        // `execution_updates` channel. The persistence path
        // (`add_workflow_log`) applied this; the broadcast didn't.
        let raw = "thinking response sk-ant-abcdefghijklmnopqrstuvwxyz0123456789 returned";
        let out = scrub_wasm_log_for_broadcast(raw);
        assert!(
            !out.contains("sk-ant-abcdefghijklmnopqrstuvwxyz0123456789"),
            "DLP scrubber must remove the secret. Got: {out}"
        );
    }

    #[test]
    fn redacts_bearer_token() {
        let raw = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig";
        let out = scrub_wasm_log_for_broadcast(raw);
        assert!(
            !out.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"),
            "Bearer JWT must be redacted. Got: {out}"
        );
    }

    #[test]
    fn redacts_github_token() {
        let raw = "git push uses ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // secret-scan-allow: DLP redaction test fixture
        let out = scrub_wasm_log_for_broadcast(raw);
        assert!(
            !out.contains("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), // secret-scan-allow: DLP redaction test fixture
            "GitHub PAT must be redacted. Got: {out}"
        );
    }

    #[test]
    fn strips_control_chars_except_whitespace() {
        // ANSI escape sequences and other control chars must not
        // reach operator dashboards (terminal-render attacks). \n,
        // \t, \r preserved so multi-line logs format correctly.
        let raw = "before\x1b[31mafter\nnext\ttabbed\rret\x07bell";
        let out = scrub_wasm_log_for_broadcast(raw);
        assert!(!out.contains('\x1b'));
        assert!(!out.contains('\x07'));
        assert!(out.contains('\n'));
        assert!(out.contains('\t'));
        assert!(out.contains('\r'));
    }

    #[test]
    fn truncates_oversize_input() {
        // Char-based truncation must respect the 8 KiB cap so the
        // broadcast can't carry more than `add_workflow_log` persists.
        let raw: String = "a".repeat(MAX_BROADCAST_LOG_CHARS + 1000);
        let out = scrub_wasm_log_for_broadcast(&raw);
        assert!(out.contains("... (truncated)"));
        // After truncation the prefix is exactly MAX chars, then the
        // marker; total chars <= cap + marker length.
        assert!(out.chars().count() <= MAX_BROADCAST_LOG_CHARS + "... (truncated)".chars().count());
    }

    #[test]
    fn small_input_passes_through_clean() {
        let raw = "user logged in successfully";
        let out = scrub_wasm_log_for_broadcast(raw);
        assert_eq!(out, raw);
    }
}

/// D1 + D5 pins for `talos_wasm_log_orphaned_total` and
/// `talos_worker_build_skew_workers`.
///
/// Both drive REAL production functions and read the counter/gauge back —
/// deliberately NOT `render_prometheus` shape tests, which is exactly what let
/// dead metrics look alive until #620.
///
/// NOTE ON CI: these live in the controller BIN target. `quality.yml`'s unit
/// step ran `cargo nextest run --workspace --lib`, which selects lib targets
/// ONLY — so every `#[cfg(test)]` in `controller/src/bootstrap/*` (including
/// #620's own `oauth_auth_metric_tests`) executed nowhere. `--bins` was added
/// to that step in the same change as these tests.
#[cfg(test)]
mod detector_metric_tests {
    use super::*;
    use talos_worker_identity_repository::WorkerBuildRow;

    /// `set_global` is a process-wide one-shot `OnceLock` shared with sibling
    /// tests in this binary, so read DELTAS back through
    /// `talos_metrics::global()`, never absolutes off a local `Arc`.
    fn install_metrics() -> &'static std::sync::Arc<talos_metrics::TalosMetrics> {
        talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
        talos_metrics::global().expect("global installed")
    }

    fn orphan_count(kind: &str) -> f64 {
        talos_metrics::global()
            .expect("global installed")
            .wasm_log_orphaned_total
            .with_label_values(&[kind])
            .get()
    }

    /// A pool that can never connect. The `unparseable_id` branch returns
    /// before any DB call, so nothing here is ever awaited against Postgres —
    /// if that stops being true this test hangs/fails rather than passing
    /// silently, which is the behaviour we want.
    fn dead_pool() -> sqlx::Pool<sqlx::Postgres> {
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(250))
            .connect_lazy("postgres://127.0.0.1:1/talos_never_connects")
            .expect("lazy pool build")
    }

    fn nats_msg(subject: &str, payload: &str) -> async_nats::Message {
        async_nats::Message {
            subject: subject.to_string().into(),
            reply: None,
            payload: payload.as_bytes().to_vec().into(),
            headers: None,
            status: None,
            description: None,
            length: payload.len(),
        }
    }

    /// Drives the production `handle_wasm_log_message` — the function the NATS
    /// subscriber loop calls once per message — down its `unparseable_id`
    /// discard branch, end to end, with no NATS and no Postgres.
    ///
    /// SCOPE, stated rather than implied: the sibling `no_execution_row` branch
    /// sits behind two Postgres round-trips (`add_workflow_log` must return
    /// `Ok(false)` and `add_log_best_effort` must return `NoExecutionRow`),
    /// which a dead pool turns into `Err` instead — so that arm is NOT covered
    /// offline. What IS covered for it: it is the same function, the same
    /// `metrics::global()` idiom and the same counter, and structural check 58
    /// sees both increments. The honest guard for that arm is the post-merge
    /// live check.
    #[tokio::test]
    async fn unparseable_execution_id_is_counted_on_the_production_path() {
        install_metrics();
        let repo = crate::execution_repository::ExecutionRepository::new(dead_pool());
        let service = ModuleExecutionService::new(
            dead_pool(),
            std::sync::Arc::new(talos_dlp_provider::DlpService::from_env()),
        );
        let (tx, _rx) = tokio::sync::broadcast::channel(8);

        // No `execution_id` key at all.
        let before = orphan_count(WASM_LOG_ORPHAN_UNPARSEABLE_ID);
        handle_wasm_log_message(
            &nats_msg("wasm.log.nope", r#"{"level":"INFO","message":"hi"}"#),
            &repo,
            &service,
            &tx,
        )
        .await;
        assert_eq!(
            orphan_count(WASM_LOG_ORPHAN_UNPARSEABLE_ID) - before,
            1.0,
            "a log line with no execution_id must reach kind=\"unparseable_id\""
        );

        // Present but not a UUID — same branch, and the branch that a
        // malformed publisher actually produces.
        let before = orphan_count(WASM_LOG_ORPHAN_UNPARSEABLE_ID);
        handle_wasm_log_message(
            &nats_msg(
                "wasm.log.garbage",
                r#"{"execution_id":"not-a-uuid","level":"WARN","message":"x"}"#,
            ),
            &repo,
            &service,
            &tx,
        )
        .await;
        assert_eq!(orphan_count(WASM_LOG_ORPHAN_UNPARSEABLE_ID) - before, 1.0);

        // A malformed PAYLOAD is a different failure (unparseable JSON, not an
        // unparseable id) and must NOT be counted here — conflating them would
        // make the alert's `kind` label lie about what to go grep.
        let before = orphan_count(WASM_LOG_ORPHAN_UNPARSEABLE_ID);
        handle_wasm_log_message(
            &nats_msg("wasm.log.x", "not json at all"),
            &repo,
            &service,
            &tx,
        )
        .await;
        assert_eq!(orphan_count(WASM_LOG_ORPHAN_UNPARSEABLE_ID) - before, 0.0);
    }

    /// The two `kind` values are exactly what
    /// `deploy/helm/talos/files/alerts.yaml` documents and what the alert's
    /// `{{ $labels.kind }}` annotation names. A selector or runbook naming a
    /// value the code cannot emit is the #620 `provider="both"` defect.
    #[test]
    fn orphan_kind_label_values_are_the_documented_ones() {
        assert_eq!(WASM_LOG_ORPHAN_NO_EXECUTION_ROW, "no_execution_row");
        assert_eq!(WASM_LOG_ORPHAN_UNPARSEABLE_ID, "unparseable_id");
    }

    /// The two gauge tests below assert ABSOLUTE values (a gauge has no
    /// meaningful delta), and `set_global` hands every test in this binary the
    /// SAME registry. Under nextest's process-per-test that is already safe;
    /// under a plain `cargo test`'s thread parallelism it is not, so serialise
    /// them. Same shape as `talos-module-payload-encryption`'s `metric_guard`.
    static GAUGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn gauge_guard() -> std::sync::MutexGuard<'static, ()> {
        GAUGE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A row with NO liveness evidence — the shape every pre-liveness worker
    /// and every row predating the feature has. These STAY in the gauge's
    /// population (unknown liveness must not silence a detector), so the
    /// existing expectations below are unchanged by the population rule.
    fn row(worker: &str, build: Option<&str>) -> WorkerBuildRow {
        WorkerBuildRow {
            worker_id: worker.to_string(),
            build_version: build.map(str::to_string),
            supports_sealing: true,
            last_seen_at: chrono::Utc::now(),
            last_liveness_at: None,
        }
    }

    /// A row whose worker pinged `hours_ago`.
    fn row_pinged(worker: &str, build: Option<&str>, hours_ago: i64) -> WorkerBuildRow {
        WorkerBuildRow {
            last_liveness_at: Some(chrono::Utc::now() - chrono::Duration::hours(hours_ago)),
            ..row(worker, build)
        }
    }

    /// Drive the gauge with a fixed 24h departure cutoff and `now`, so the
    /// tests below read as "what population is counted", not "what time is it".
    fn publish(controller_build: &str, rows: &[WorkerBuildRow]) {
        publish_worker_build_skew(controller_build, rows, 24, chrono::Utc::now(), None);
    }

    /// The gauge must RISE with skewed workers and RETURN TO 0 when they
    /// converge. A rise-only (inc-on-detect) wiring passes the first half and
    /// fails the second — which is the whole reason this is a gauge recomputed
    /// from a query rather than a counter over the registration WARN.
    #[test]
    fn build_skew_gauge_rises_and_returns_to_zero() {
        let _g = gauge_guard();
        let m = install_metrics();
        let controller = "1.0.0-r400+aaaaaaa";

        // Two provably different commits + one match.
        publish(
            controller,
            &[
                row("w1", Some("0.1.0+bbbbbbb")),
                row("w2", Some("0.1.0+ccccccc")),
                row("w3", Some("0.1.0+aaaaaaa")),
            ],
        );
        assert_eq!(m.worker_build_skew_workers.get(), 2);

        // The skewed workers redeploy onto the controller's commit. The gauge
        // must fall on its own — nothing decrements it explicitly.
        publish(
            controller,
            &[
                row("w1", Some("0.1.0+aaaaaaa")),
                row("w2", Some("9.9.9+aaaaaaa")),
                row("w3", Some("0.1.0+aaaaaaa")),
            ],
        );
        assert_eq!(m.worker_build_skew_workers.get(), 0);

        // A skewed worker leaving the fleet also lowers it (empty row set).
        publish(controller, &[row("w1", Some("0.1.0+bbbbbbb"))]);
        assert_eq!(m.worker_build_skew_workers.get(), 1);
        publish(controller, &[]);
        assert_eq!(m.worker_build_skew_workers.get(), 0);
    }

    /// UNVERIFIABLE is not skew (#578). A worker that reported no build, or an
    /// `unknown` sha, or a controller built outside a git checkout, must all
    /// read 0 — the alert says "provably different", and counting these would
    /// make it fire on every non-git build.
    #[test]
    fn build_skew_gauge_does_not_count_unverifiable_workers() {
        let _g = gauge_guard();
        let m = install_metrics();
        let controller = "1.0.0-r400+aaaaaaa";

        publish(
            controller,
            &[
                row("pre-handshake", None),
                row("no-git", Some("0.1.0+unknown")),
                row("no-git-dirty", Some("0.1.0+unknown-dirty")),
                row("no-suffix", Some("1.2.3")),
            ],
        );
        assert_eq!(m.worker_build_skew_workers.get(), 0);

        // Controller itself unverifiable → nothing is provable either way.
        publish("0.1.0+unknown", &[row("w1", Some("0.1.0+bbbbbbb"))]);
        assert_eq!(m.worker_build_skew_workers.get(), 0);

        // A -dirty tree on ONE side only IS skew: same commit, different bytes.
        publish(controller, &[row("w1", Some("0.1.0+aaaaaaa-dirty"))]);
        assert_eq!(m.worker_build_skew_workers.get(), 1);
    }

    /// The metric is named `..._workers`, and `list_active_builds` returns one
    /// row per (worker_id, key) — a worker mid-rotation legitimately holds two
    /// ACTIVE keys. Counting ROWS would render one skewed worker as two and put
    /// a wrong number in the alert summary, so the count is per distinct
    /// `worker_id`.
    #[test]
    fn build_skew_gauge_counts_workers_not_rows() {
        let _g = gauge_guard();
        let m = install_metrics();
        let controller = "1.0.0-r400+aaaaaaa";

        // One worker, two active keys, both reporting the same skewed build.
        publish(
            controller,
            &[
                row("w1", Some("0.1.0+bbbbbbb")),
                row("w1", Some("0.1.0+bbbbbbb")),
            ],
        );
        assert_eq!(m.worker_build_skew_workers.get(), 1);

        // Mid-rotation disagreement: one key already on the controller's build,
        // the other still stale. The worker is still (partly) skewed — once.
        publish(
            controller,
            &[
                row("w1", Some("0.1.0+aaaaaaa")),
                row("w1", Some("0.1.0+bbbbbbb")),
            ],
        );
        assert_eq!(m.worker_build_skew_workers.get(), 1);

        // Distinct workers still add up.
        publish(
            controller,
            &[
                row("w1", Some("0.1.0+bbbbbbb")),
                row("w2", Some("0.1.0+bbbbbbb")),
            ],
        );
        assert_eq!(m.worker_build_skew_workers.get(), 2);
    }

    /// The population rule that finally lets this gauge DRAIN: a worker that
    /// PROVED it speaks the liveness protocol and then went silent past the
    /// window is excluded, so the gauge stops counting it immediately rather
    /// than waiting for the reaper's next sweep to clear the row.
    #[test]
    fn build_skew_gauge_drops_provably_departed_workers() {
        let _g = gauge_guard();
        let m = install_metrics();
        let controller = "1.0.0-r400+aaaaaaa";

        // Skewed and pinging 1h ago → still counted; it is really out there.
        publish(controller, &[row_pinged("w1", Some("0.1.0+bbbbbbb"), 1)]);
        assert_eq!(m.worker_build_skew_workers.get(), 1);

        // Same worker, same skew, but silent for 48h under the 24h cutoff →
        // provably departed, so it is no longer evidence of a skewed FLEET.
        publish(controller, &[row_pinged("w1", Some("0.1.0+bbbbbbb"), 48)]);
        assert_eq!(m.worker_build_skew_workers.get(), 0);

        // Boundary: just inside the window is still counted.
        publish(controller, &[row_pinged("w1", Some("0.1.0+bbbbbbb"), 23)]);
        assert_eq!(m.worker_build_skew_workers.get(), 1);
    }

    /// The asymmetry between the reaper and the gauge, asserted so a future
    /// edit cannot quietly "unify" them. The reaper refuses to act on a row
    /// with NO liveness evidence; the gauge KEEPS counting it. If the gauge
    /// dropped unknown-liveness rows too, a fleet running an entirely
    /// pre-liveness build would silence the build-skew alert — a detector
    /// disabled by exactly the condition it exists to detect (#625).
    #[test]
    fn build_skew_gauge_still_counts_workers_with_unknown_liveness() {
        let _g = gauge_guard();
        let m = install_metrics();
        let controller = "1.0.0-r400+aaaaaaa";

        // No liveness evidence at all, registered long ago. Unknown ≠ departed.
        let mut ancient = row("w1", Some("0.1.0+bbbbbbb"));
        ancient.last_seen_at = chrono::Utc::now() - chrono::Duration::days(365);
        publish(controller, &[ancient]);
        assert_eq!(
            m.worker_build_skew_workers.get(),
            1,
            "a row with unknown liveness must stay visible to the detector"
        );
    }

    /// The gauge half of the 2026-08-04 reproduction: drive
    /// `talos_worker_build_skew_workers` with the EXACT rows observed live and
    /// show it go 1 → 0 through the mechanism, not through an assertion.
    ///
    /// Live state, controller on `3ffb611`:
    /// ```text
    /// dev-worker-fleet   0.1.0+3ffb611  (running)
    /// worker-wt-cddef6d  0.1.0+cddef6d  (container deleted hours earlier)
    /// ```
    /// The gauge read 1, and nothing could ever lower it: the ghost row was
    /// `active` forever and its build was provably skewed forever.
    #[test]
    fn reproduces_the_2026_08_04_skew_gauge_and_drains_it() {
        let _g = gauge_guard();
        let m = install_metrics();
        let controller = "1.0.0-r400+3ffb611";

        // BEFORE — both rows active, neither has liveness evidence (nothing
        // pinged yet). This is the observed reading, and it is stuck.
        publish(
            controller,
            &[
                row("dev-worker-fleet", Some("0.1.0+3ffb611")),
                row("worker-wt-cddef6d", Some("0.1.0+cddef6d")),
            ],
        );
        assert_eq!(
            m.worker_build_skew_workers.get(),
            1,
            "reproduce the live reading before claiming to fix it"
        );

        // AFTER — both workers roll onto a build that pings. The live one keeps
        // pinging; the ghost's last ping recedes past the window. The gauge
        // drains on its own, before the reaper's sweep even clears the row.
        publish(
            controller,
            &[
                row_pinged("dev-worker-fleet", Some("0.1.0+3ffb611"), 0),
                row_pinged("worker-wt-cddef6d", Some("0.1.0+cddef6d"), 48),
            ],
        );
        assert_eq!(m.worker_build_skew_workers.get(), 0);

        // ...and once the reaper deactivates it, the row is gone from
        // `list_active_builds` entirely, so the gauge stays at 0 for the second
        // reason too.
        publish(
            controller,
            &[row("dev-worker-fleet", Some("0.1.0+3ffb611"))],
        );
        assert_eq!(m.worker_build_skew_workers.get(), 0);
    }

    /// The window is the security property, so pin its default and the shape of
    /// its override rather than leaving both to a code read.
    #[test]
    fn departed_cutoff_default_and_floor() {
        // Mutates process env; borrow the same lock the gauge tests use so a
        // thread-parallel `cargo test` can't interleave with them.
        let _g = gauge_guard();
        // The stated property: "a key is trusted for at most 24h (plus one
        // sweep interval and one key-overlay refresh — see
        // DEFAULT_REAP_SILENCE_HOURS) after its worker stops proving liveness."
        assert_eq!(DEFAULT_REAP_SILENCE_HOURS, 24);
        // Unset → the default. (Set via the env only in the two cases below,
        // which are read through the same accessor the sweep uses.)
        std::env::remove_var("TALOS_WORKER_IDENTITY_REAP_HOURS");
        assert_eq!(departed_liveness_cutoff_hours(), 24);

        std::env::set_var("TALOS_WORKER_IDENTITY_REAP_HOURS", "6");
        assert_eq!(departed_liveness_cutoff_hours(), 6);

        // Zero / negative / garbage fall back to the default rather than
        // producing an instantaneous window — a typo must not reap the fleet.
        for bad in ["0", "-5", "immediately", ""] {
            std::env::set_var("TALOS_WORKER_IDENTITY_REAP_HOURS", bad);
            assert_eq!(
                departed_liveness_cutoff_hours(),
                24,
                "a bad window value must fall back to the safe default, got {bad:?}"
            );
        }
        std::env::remove_var("TALOS_WORKER_IDENTITY_REAP_HOURS");
    }

    /// REGRESSION GUARD (review 2A): a huge but i64-parseable window must be
    /// clamped, not passed through.
    ///
    /// Pre-fix, `departed_liveness_cutoff_hours` only filtered `<= 0`, so
    /// `TALOS_WORKER_IDENTITY_REAP_HOURS=9223372036854775807` flowed through to
    /// two consumers that both break on it — asserted here in BOTH directions
    /// so the guard cannot rot into a tautology:
    ///   * the raw value still panics `chrono::Duration::hours` (the hazard is
    ///     real, and the gauge sweep is a detached `tokio::spawn`, so the panic
    ///     would kill it and freeze `talos_worker_build_skew_workers` forever);
    ///   * the CLAMPED value does not — which is what production now passes.
    #[test]
    fn huge_reap_window_is_clamped_before_it_reaches_chrono() {
        let _g = gauge_guard();
        std::env::set_var("TALOS_WORKER_IDENTITY_REAP_HOURS", "9223372036854775807");
        let clamped = departed_liveness_cutoff_hours();
        std::env::remove_var("TALOS_WORKER_IDENTITY_REAP_HOURS");
        assert_eq!(clamped, MAX_REAP_SILENCE_HOURS, "clamped to the 10y guard");
        // Well inside Postgres's `make_interval` range too (~5.9e7 hours), so
        // the sweep widens rather than erroring.
        assert!(clamped < 59_000_000);
        assert_eq!(
            i32::try_from(clamped).unwrap(),
            MAX_REAP_SILENCE_HOURS as i32
        );

        let rows = vec![talos_worker_identity_repository::WorkerBuildRow {
            worker_id: "w-1".to_string(),
            build_version: Some("0.1.0+aaaaaaa".to_string()),
            supports_sealing: false,
            last_seen_at: chrono::Utc::now(),
            last_liveness_at: Some(chrono::Utc::now()),
        }];
        // The hazard, still live if the clamp is ever removed.
        let raw = std::panic::catch_unwind(|| {
            count_skewed_live_workers("0.1.0+bbbbbbb", &rows, i64::MAX, chrono::Utc::now(), None)
        });
        assert!(
            raw.is_err(),
            "chrono::Duration::hours(i64::MAX) is expected to panic — that is WHY \
             the clamp exists; if this stops panicking, re-derive the bound"
        );
        // The clamped value is safe: an un-departed row still counts as skewed.
        assert_eq!(
            count_skewed_live_workers("0.1.0+bbbbbbb", &rows, clamped, chrono::Utc::now(), None),
            1
        );
    }

    // ── NATS fleet heartbeat: the live-process view (2026-08) ──────────────

    fn live(ids: &[&str]) -> std::collections::HashSet<String> {
        ids.iter().map(|s| (*s).to_string()).collect()
    }

    /// **THE DEFAULT IS UNCHANGED, and this is the assertion that says so.**
    /// With `heartbeating: None` — what every deployment gets unless an
    /// operator sets `TALOS_WORKER_FLEET_HEARTBEAT_AUTHORITATIVE` — a row with
    /// no liveness evidence still counts, exactly as before. The heartbeat
    /// cannot silently narrow this detector.
    #[test]
    fn heartbeat_absence_does_not_narrow_the_population_by_default() {
        let rows = vec![row("ghost", Some("0.1.0+bbbbbbb"))];
        assert_eq!(
            count_skewed_live_workers("0.1.0+aaaaaaa", &rows, 24, chrono::Utc::now(), None),
            1,
            "unknown liveness must keep a row counted — a detector must not go \
             quiet on the same uncertainty the reaper refuses to act on"
        );
    }

    /// With the operator assertion ON, a row that is not heartbeating leaves
    /// the population — this is the ONLY thing that drains a ghost row's
    /// contribution to `TalosWorkerBuildSkew` without deactivating it.
    #[test]
    fn an_authoritative_fleet_view_excludes_a_row_that_is_not_heartbeating() {
        let rows = vec![
            row("ghost", Some("0.1.0+bbbbbbb")),
            row("running", Some("0.1.0+ccccccc")),
        ];
        let now = chrono::Utc::now();
        assert_eq!(
            count_skewed_live_workers("0.1.0+aaaaaaa", &rows, 24, now, Some(&live(&["running"]))),
            1,
            "only the heartbeating worker is counted"
        );
        assert_eq!(
            count_skewed_live_workers("0.1.0+aaaaaaa", &rows, 24, now, Some(&live(&["ghost"]))),
            1
        );
        assert_eq!(
            count_skewed_live_workers(
                "0.1.0+aaaaaaa",
                &rows,
                24,
                now,
                Some(&live(&["ghost", "running"]))
            ),
            2,
            "both heartbeating ⇒ both counted, i.e. the exclusion is not a \
             blanket reduction"
        );
    }

    /// The two rules compose in the SAFE direction: a heartbeating row that is
    /// nonetheless provably departed by the liveness clock stays excluded.
    /// Whichever rule says "gone" wins.
    #[test]
    fn a_provably_departed_row_stays_excluded_even_if_something_heartbeats_as_it() {
        let rows = vec![row_pinged("w", Some("0.1.0+bbbbbbb"), 48)];
        assert_eq!(
            count_skewed_live_workers(
                "0.1.0+aaaaaaa",
                &rows,
                24,
                chrono::Utc::now(),
                Some(&live(&["w"]))
            ),
            0
        );
    }

    /// `count_heartbeat_build_skew` splits skewed from unverifiable rather than
    /// folding the second into the first — so a 0 skew count can be read
    /// correctly. 0 out of 0 comparable workers is not "the fleet agrees".
    #[test]
    fn heartbeat_skew_keeps_unverifiable_builds_separate() {
        let builds = vec![
            Some("0.1.0+aaaaaaa".to_string()),
            Some("0.1.0+bbbbbbb".to_string()),
            Some("0.1.0+unknown".to_string()),
            None,
        ];
        assert_eq!(
            count_heartbeat_build_skew("0.1.0+aaaaaaa", &builds),
            (1, 2),
            "one provably skewed; the unknown-sha and the absent build are \
             unverifiable, not agreeing"
        );
        // An unverifiable CONTROLLER build makes every comparison impossible:
        // the count must fall to 0, not read every worker as skewed.
        assert_eq!(count_heartbeat_build_skew("0.1.0+unknown", &builds), (0, 4));
        // Empty fleet view: nothing observed, nothing claimed.
        assert_eq!(count_heartbeat_build_skew("0.1.0+aaaaaaa", &[]), (0, 0));
    }

    /// The gauges are published from the production function, and they FALL as
    /// well as rise — a heartbeat view that only ever grew would pin the alert
    /// on forever after one rolling deploy, the exact defect the registry gauge
    /// was made level-triggered to avoid.
    #[test]
    fn fleet_gauges_rise_and_fall_and_never_carry_a_worker_label() {
        let _g = gauge_guard();
        let m = install_metrics();

        // ONE worker_id (the shared-id posture) publishing three distinct
        // builds — so the two populations differ, which is the case that
        // makes reading one against the other a defect. The per-worker slice
        // has ONE element because the map has one entry: this is precisely
        // the magnitude loss the shared-id posture imposes.
        publish_worker_fleet_gauges(
            "0.1.0+aaaaaaa",
            1,
            &[
                Some("0.1.0+aaaaaaa".to_string()),
                Some("0.1.0+bbbbbbb".to_string()),
                None,
            ],
            &[Some("0.1.0+bbbbbbb".to_string())],
            7,
            2,
        );
        assert_eq!(m.worker_fleet_live_workers.get(), 1, "IDENTITIES");
        assert_eq!(
            m.worker_fleet_live_builds.get(),
            3,
            "BUILDS — a different population"
        );
        assert_eq!(m.worker_fleet_build_skew_builds.get(), 1);
        assert_eq!(m.worker_fleet_unverifiable_builds.get(), 1);
        assert_eq!(
            m.worker_fleet_build_skew_workers.get(),
            1,
            "the one retained map entry is on the skewed build"
        );
        assert_eq!(m.worker_fleet_unverifiable_workers.get(), 0);
        assert_eq!(m.worker_fleet_capacity_dropped_heartbeats.get(), 7);
        assert_eq!(m.worker_fleet_capacity_dropped_builds.get(), 2);

        // THE DECOMPOSITION IDENTITY the annotation and the HELP strings both
        // promise: live == skew + unverifiable + agreeing. If it stopped
        // holding, "0 skewed" would stop being readable against a denominator.
        // It is asserted for BOTH populations — shipping the ids numerator
        // without its own denominator decomposition would repeat the defect
        // the builds trio exists to avoid, one population over.
        let agreeing = 1; // only 0.1.0+aaaaaaa matches the controller
        assert_eq!(
            m.worker_fleet_live_builds.get(),
            m.worker_fleet_build_skew_builds.get()
                + m.worker_fleet_unverifiable_builds.get()
                + agreeing
        );
        let agreeing_workers = 0; // the single entry is the skewed build
        assert_eq!(
            m.worker_fleet_live_workers.get(),
            m.worker_fleet_build_skew_workers.get()
                + m.worker_fleet_unverifiable_workers.get()
                + agreeing_workers
        );

        // DISTINCT ids — the chart DEFAULT, where nothing renders
        // TALOS_WORKER_ID and each pod is its own map entry. Here the ids
        // population carries the MAGNITUDE the builds population cannot:
        // three pods on one skewed build read 3 here and 1 there.
        publish_worker_fleet_gauges(
            "0.1.0+aaaaaaa",
            4,
            &[
                Some("0.1.0+aaaaaaa".to_string()),
                Some("0.1.0+bbbbbbb".to_string()),
            ],
            &[
                Some("0.1.0+aaaaaaa".to_string()),
                Some("0.1.0+bbbbbbb".to_string()),
                Some("0.1.0+bbbbbbb".to_string()),
                Some("0.1.0+bbbbbbb".to_string()),
            ],
            7,
            2,
        );
        assert_eq!(m.worker_fleet_live_workers.get(), 4);
        assert_eq!(m.worker_fleet_build_skew_builds.get(), 1, "ONE build");
        assert_eq!(
            m.worker_fleet_build_skew_workers.get(),
            3,
            "THREE pods — the magnitude the builds gauge structurally cannot \
             carry, and the reason this gauge was restored"
        );

        // Fleet converges: the rolled-away build leaves the view.
        publish_worker_fleet_gauges(
            "0.1.0+aaaaaaa",
            1,
            &[Some("0.1.0+aaaaaaa".to_string())],
            &[Some("0.1.0+aaaaaaa".to_string())],
            7,
            2,
        );
        assert_eq!(m.worker_fleet_live_workers.get(), 1);
        assert_eq!(m.worker_fleet_live_builds.get(), 1);
        assert_eq!(m.worker_fleet_build_skew_builds.get(), 0);
        assert_eq!(m.worker_fleet_unverifiable_builds.get(), 0);
        assert_eq!(m.worker_fleet_build_skew_workers.get(), 0);
        assert_eq!(m.worker_fleet_unverifiable_workers.get(), 0);

        // `worker_id` is caller-supplied on the bus, so it must not appear in
        // the exposition at all — these are plain label-free IntGauges and the
        // rendered text is the proof.
        let rendered = m.render_prometheus().expect("render");
        for line in rendered.lines() {
            if line.starts_with("talos_worker_fleet_") {
                assert!(
                    !line.contains('{'),
                    "fleet gauges must carry NO labels (unbounded cardinality \
                     from a caller-supplied worker_id): {line}"
                );
            }
        }
    }

    /// The operator assertion is OFF unless explicitly set, and only the
    /// documented truthy spellings turn it on. Fail-closed: an unrecognised
    /// value leaves the detector at its safe, over-reporting default.
    #[test]
    fn the_heartbeat_authority_gate_is_off_by_default_and_fails_closed() {
        let _g = gauge_guard();
        std::env::remove_var("TALOS_WORKER_FLEET_HEARTBEAT_AUTHORITATIVE");
        assert!(!heartbeat_silence_is_authoritative());
        for on in ["1", "true", "TRUE", "yes", "on"] {
            std::env::set_var("TALOS_WORKER_FLEET_HEARTBEAT_AUTHORITATIVE", on);
            assert!(heartbeat_silence_is_authoritative(), "{on} must enable it");
        }
        for off in ["0", "false", "no", "maybe", ""] {
            std::env::set_var("TALOS_WORKER_FLEET_HEARTBEAT_AUTHORITATIVE", off);
            assert!(
                !heartbeat_silence_is_authoritative(),
                "{off:?} must leave it off"
            );
        }
        std::env::remove_var("TALOS_WORKER_FLEET_HEARTBEAT_AUTHORITATIVE");
    }
}

/// The worker-identity liveness/reaper observability wiring — the D1/D2 half
/// of "make the reaper safely enableable".
///
/// These drive the PRODUCTION recording functions, not copies of them, and
/// assert the counter moved. That is deliberate and it is the whole point: the
/// defect this instrumentation exists to prevent is a registered metric with
/// no live increment, which renders every alert built on it permanently
/// unfireable (#620), and a test that only re-implements the arithmetic or
/// asserts the series renders would pass in exactly that state.
#[cfg(test)]
mod worker_liveness_reaper_metric_tests {
    use super::*;
    use talos_worker_identity_repository::WorkerBuildRow;

    fn install_metrics() -> &'static std::sync::Arc<talos_metrics::TalosMetrics> {
        talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
        talos_metrics::global().expect("global installed")
    }

    fn reaps(arm: &str) -> f64 {
        talos_metrics::global()
            .expect("global installed")
            .worker_identity_reaps_total
            .with_label_values(&[arm])
            .get()
    }

    fn row(worker: &str, pinged_hours_ago: Option<i64>) -> WorkerBuildRow {
        WorkerBuildRow {
            worker_id: worker.to_string(),
            build_version: Some("0.1.0+aaaaaaa".to_string()),
            supports_sealing: true,
            last_seen_at: chrono::Utc::now(),
            last_liveness_at: pinged_hours_ago
                .map(|h| chrono::Utc::now() - chrono::Duration::hours(h)),
        }
    }

    // ── talos_worker_identity_reaps_total ───────────────────────────────

    /// The counter must move by the NUMBER OF KEYS, on the same function the
    /// reaper sweep calls. Deltas rather than absolutes: the global registry
    /// is shared with every other test in this binary.
    #[test]
    fn a_reap_counts_keys_on_the_production_recording_path() {
        install_metrics();
        let before = reaps("departed");
        record_identity_reap(ReapArm::Departed, 3);
        assert_eq!(
            reaps("departed") - before,
            3.0,
            "the counter measures KEYS deactivated, not sweeps that reaped"
        );

        let before = reaps("pre_protocol");
        record_identity_reap(ReapArm::PreProtocol, 1);
        assert_eq!(reaps("pre_protocol") - before, 1.0);
    }

    /// The arms must stay separable. A reap on the opt-in `pre_protocol` arm
    /// is an operator asserting a fact the controller cannot check; a reap on
    /// `departed` is the automatic trust-boundary write. Collapsing them would
    /// make the reap alert unable to say which one just fired.
    #[test]
    fn the_two_arms_do_not_contaminate_each_other() {
        install_metrics();
        let (d0, p0) = (reaps("departed"), reaps("pre_protocol"));
        record_identity_reap(ReapArm::Departed, 2);
        assert_eq!(
            reaps("pre_protocol"),
            p0,
            "departed must not move pre_protocol"
        );
        assert_eq!(reaps("departed") - d0, 2.0);
        assert_eq!(ReapArm::Departed.label(), "departed");
        assert_eq!(ReapArm::PreProtocol.label(), "pre_protocol");
    }

    /// A sweep that reaped nothing must not move the counter. The sweep runs
    /// every 300s forever and almost always reaps zero; counting those would
    /// put a large constant under `increase(...)` and make the reap alert
    /// meaningless.
    #[test]
    fn a_sweep_that_reaped_nothing_is_not_counted() {
        install_metrics();
        let before = reaps("departed");
        record_identity_reap(ReapArm::Departed, 0);
        assert_eq!(reaps("departed"), before);
    }

    /// Inert without a registry, like every other `metrics::global()` caller.
    /// The reaper task runs in processes (and tests) where `set_global` may
    /// not have happened, and a panic there would kill the sweep permanently.
    #[test]
    fn recording_is_inert_without_a_global_registry() {
        record_identity_reap(ReapArm::Departed, 5);
        record_identity_reap(ReapArm::PreProtocol, 0);
    }

    // ── the D2 pair ─────────────────────────────────────────────────────

    fn participants() -> (i64, i64) {
        let m = talos_metrics::global().expect("global installed");
        (
            m.worker_liveness_participants.get(),
            m.worker_liveness_recent_participants.get(),
        )
    }

    /// A healthy pinging fleet: every participant is recent, so the DIFFERENCE
    /// the alert reads is 0. This is the state the alert must stay silent in.
    #[test]
    fn a_pinging_fleet_has_zero_silent_participants() {
        install_metrics();
        let rows = [
            row("w-1", Some(0)),
            row("w-2", Some(0)),
            row("w-3", Some(0)),
        ];
        publish_worker_liveness_participation(&rows, 24, chrono::Utc::now());
        assert_eq!(participants(), (3, 3));
    }

    /// THE CASE THIS WHOLE DELIVERABLE EXISTS FOR. A fleet that was pinging
    /// and stopped — an image rollback, a dropped TALOS_CONTROLLER_URL, a
    /// one-way network block — shows up here 22h before the reaper touches a
    /// key, as `participants` holding at 3 while `recent` falls to 0.
    #[test]
    fn a_fleet_that_stopped_pinging_is_visible_before_the_reap() {
        install_metrics();
        // Silent for 6h: well past the 2h horizon, nowhere near the 24h
        // window, so NOTHING has been reaped yet and every one of these keys
        // is still trusted. That gap is the warning.
        let rows = [
            row("w-1", Some(6)),
            row("w-2", Some(6)),
            row("w-3", Some(6)),
        ];
        publish_worker_liveness_participation(&rows, 24, chrono::Utc::now());
        let (all, recent) = participants();
        assert_eq!((all, recent), (3, 0));
        assert!(
            all - recent > 0,
            "the alert's expression must be positive here"
        );
    }

    /// THE OTHER DIRECTION, which matters just as much: a fleet that has NEVER
    /// participated must read (0, 0), so the alert cannot fire on it. This is
    /// the chart default — the liveness ping is blocked at the network layer
    /// unless two opt-in NetworkPolicy rules are enabled — and an alert that
    /// fired there would be permanently red on every default install, i.e.
    /// trained-to-ignore, i.e. no alert at all.
    #[test]
    fn a_fleet_that_never_participated_cannot_fire_the_alert() {
        install_metrics();
        let rows = [row("w-1", None), row("w-2", None), row("w-3", None)];
        publish_worker_liveness_participation(&rows, 24, chrono::Utc::now());
        let (all, recent) = participants();
        assert_eq!((all, recent), (0, 0));
        assert_eq!(
            all - recent,
            0,
            "no liveness evidence is not evidence of silence"
        );
    }

    /// Mixed fleet: pre-protocol rows must not dilute the signal in either
    /// direction. Two pinging + two never-pinged reads (2, 2) — a NULL row is
    /// not a silent participant, because the automatic reaper cannot act on it.
    #[test]
    fn null_liveness_rows_are_in_neither_population() {
        install_metrics();
        let rows = [
            row("w-live-1", Some(0)),
            row("w-live-2", Some(0)),
            row("w-legacy-1", None),
            row("w-legacy-2", None),
        ];
        publish_worker_liveness_participation(&rows, 24, chrono::Utc::now());
        assert_eq!(participants(), (2, 2));
    }

    /// Counted per WORKER, not per row. A worker mid-key-rotation legitimately
    /// holds two active rows; counting rows would render one worker as two and
    /// make every number in the alert annotation wrong.
    #[test]
    fn a_rotating_worker_counts_once_in_both_gauges() {
        install_metrics();
        let rows = [row("w-rotating", Some(0)), row("w-rotating", Some(0))];
        publish_worker_liveness_participation(&rows, 24, chrono::Utc::now());
        assert_eq!(participants(), (1, 1));
        // ...and once even when only ONE of its two keys is fresh: the worker
        // IS pinging. The difference stays 0, which is correct — no key of a
        // pinging worker is heading for a reap on the automatic arm... except
        // the stale one, which is exactly why this gauge pair is a fleet-level
        // detector and `list-worker-identities` is the per-key surface.
        let rows = [row("w-rotating", Some(0)), row("w-rotating", Some(9))];
        publish_worker_liveness_participation(&rows, 24, chrono::Utc::now());
        assert_eq!(participants(), (1, 1));
    }

    /// The gauges must FALL, not just rise — they are recomputed and `set`
    /// each sweep. A rise-only wiring would pin the alert firing forever after
    /// the first scale-down, which is the failure mode that made the
    /// build-skew signal a gauge in the first place.
    #[test]
    fn the_gauges_drain_when_rows_leave_the_active_set() {
        install_metrics();
        publish_worker_liveness_participation(
            &[row("w-1", Some(0)), row("w-2", Some(9))],
            24,
            chrono::Utc::now(),
        );
        assert_eq!(participants(), (2, 1));
        // The reaper deactivates w-2, so it leaves `list_active_builds`
        // entirely: both gauges follow, and the alert clears.
        publish_worker_liveness_participation(&[row("w-1", Some(0))], 24, chrono::Utc::now());
        assert_eq!(participants(), (1, 1));
        // Fleet scaled to zero.
        publish_worker_liveness_participation(&[], 24, chrono::Utc::now());
        assert_eq!(participants(), (0, 0));
    }

    /// `recent` is a subset of `participants` by construction, so the alert's
    /// expression can never go negative. Asserted over a spread of ages
    /// because a negative difference would make `> 0` read as "healthy" while
    /// measuring nothing at all.
    #[test]
    fn recent_is_always_a_subset_of_participants() {
        for hours in [0i64, 1, 2, 3, 12, 23, 24, 100] {
            let rows = [row("w-1", Some(hours)), row("w-2", None)];
            let (all, recent) = count_liveness_participants(&rows, 2, chrono::Utc::now());
            assert!(
                recent <= all,
                "recent {recent} > participants {all} at {hours}h"
            );
        }
    }

    // ── the horizon ─────────────────────────────────────────────────────

    /// The horizon must clear the worker's slowest legal ping interval. The
    /// worker clamps TALOS_WORKER_LIVENESS_INTERVAL_SECS to at most 3600s, so
    /// a 2h horizon gives two whole intervals of slack at the worst case and
    /// sixty at the 60s default. If this constant is ever lowered below 1h the
    /// gauge starts flapping on a legally-configured fleet.
    #[test]
    fn the_horizon_clears_the_slowest_legal_ping_interval() {
        assert!(
            LIVENESS_PARTICIPATION_HORIZON_HOURS >= 2,
            "the worker's max ping interval is 3600s; a horizon under 2h flaps"
        );
        let now = chrono::Utc::now();
        let h = liveness_participation_horizon_hours(24);
        // A worker on the maximum 1h interval that just missed ONE ping is
        // still counted as pinging.
        let rows = [row("w-slow", Some(1))];
        assert_eq!(count_liveness_participants(&rows, h, now), (1, 1));
    }

    /// The clamp: a configured window SHORTER than the horizon must shrink the
    /// horizon, or `recent` would count rows the reaper is already entitled to
    /// deactivate and the detector would read 0 while a reap was imminent —
    /// silent in exactly the configuration that leaves the least time to react.
    #[test]
    fn a_short_window_shrinks_the_horizon_rather_than_blinding_the_detector() {
        assert_eq!(liveness_participation_horizon_hours(24), 2);
        assert_eq!(liveness_participation_horizon_hours(2), 2);
        assert_eq!(liveness_participation_horizon_hours(1), 1);
        // Never zero or negative: a 0h horizon would make EVERY row silent and
        // the alert permanently red. `departed_liveness_cutoff_hours` already
        // floors the window at 1, so this is belt-and-braces.
        assert_eq!(liveness_participation_horizon_hours(0), 1);
        assert_eq!(liveness_participation_horizon_hours(-5), 1);

        // With a 1h window, a row silent for 90m is past the reap cutoff and
        // MUST NOT be counted as recent.
        install_metrics();
        publish_worker_liveness_participation(&[row("w-1", Some(2))], 1, chrono::Utc::now());
        assert_eq!(participants(), (1, 0));
    }

    /// The boundary itself: at exactly the horizon a row is still recent
    /// (`<=`), one hour past it is not. Pinned so the comparison direction
    /// cannot be flipped silently — an off-by-one here changes when the alert
    /// fires on every fleet.
    #[test]
    fn the_horizon_boundary_is_inclusive() {
        let now = chrono::Utc::now();
        // Exactly 2h old, built from `now` so the arithmetic is exact.
        let at_boundary = WorkerBuildRow {
            last_liveness_at: Some(now - chrono::Duration::hours(2)),
            ..row("w-1", None)
        };
        assert_eq!(count_liveness_participants(&[at_boundary], 2, now), (1, 1));
        let past = WorkerBuildRow {
            last_liveness_at: Some(now - chrono::Duration::hours(2) - chrono::Duration::seconds(1)),
            ..row("w-1", None)
        };
        assert_eq!(count_liveness_participants(&[past], 2, now), (1, 0));
    }

    /// A `last_liveness_at` in the FUTURE (Postgres ahead of the controller,
    /// or a clock step) must count as recent, not as silent. The signed
    /// duration goes negative there, and a `>=`-shaped comparison would have
    /// classified a worker that pinged one second ago as departed — the #625
    /// shape, a detector silenced by a benign condition, except firing rather
    /// than silent.
    #[test]
    fn a_future_timestamp_counts_as_recent_not_as_silent() {
        let now = chrono::Utc::now();
        let ahead = WorkerBuildRow {
            last_liveness_at: Some(now + chrono::Duration::minutes(5)),
            ..row("w-1", None)
        };
        assert_eq!(count_liveness_participants(&[ahead], 2, now), (1, 1));
    }

    // ── detector/reaper population agreement ────────────────────────────

    /// THE INVARIANT: the reaper must never act on a row the detector cannot
    /// see. The detector reads a query capped at `MAX_FLEET_BUILD_ROWS`; the
    /// reap `UPDATE` has no cap. So the cap is where the two populations
    /// diverge, and this pins the boundary in both directions — an off-by-one
    /// here is a row that is reapable and un-alertable.
    #[test]
    fn the_truncation_flag_trips_exactly_at_the_fleet_query_cap() {
        let cap = talos_worker_identity_repository::MAX_FLEET_BUILD_ROWS as usize;
        assert!(!liveness_population_is_truncated(0));
        assert!(!liveness_population_is_truncated(cap - 1));
        // `>=`, not `>`: a fetch that returned exactly the cap MAY have been
        // truncated, and "may have been" is "was" in front of an
        // irreversible write.
        assert!(liveness_population_is_truncated(cap));
        assert!(liveness_population_is_truncated(cap + 1));
    }

    /// The flag is PUBLISHED, not merely computed — an unpublished fail-safe
    /// is a silent state, which is the same defect one level up. Driven
    /// through the production publisher so a gauge that stopped being set
    /// fails here.
    #[test]
    fn the_truncation_flag_is_published_and_drains() {
        install_metrics();
        let truncated = || {
            talos_metrics::global()
                .expect("global installed")
                .worker_liveness_population_truncated
                .get()
        };
        let cap = talos_worker_identity_repository::MAX_FLEET_BUILD_ROWS as usize;
        let big: Vec<WorkerBuildRow> = (0..cap)
            .map(|i| row(&format!("w-{i:04}"), Some(0)))
            .collect();
        publish_worker_liveness_participation(&big, 24, chrono::Utc::now());
        assert_eq!(truncated(), 1, "at the cap the detector is not whole");
        // ...and it must FALL again once the ghost rows are drained, or the
        // alert on it is permanently red and therefore ignored.
        publish_worker_liveness_participation(&big[..cap - 1], 24, chrono::Utc::now());
        assert_eq!(truncated(), 0);
    }
}

// ===========================================================================
// Fuel-headroom detector tests
// ===========================================================================
//
// THE ACCEPTANCE TEST IS `the_detector_flags_the_node_it_was_built_for`. Every
// number in it is a real measurement off the live database on 2026-08-17, not
// a fixture chosen to make the assertion pass — which matters here more than
// usual, because the failure mode this detector exists to prevent is a number
// that was in the database and never compared to anything. A synthetic fixture
// would reproduce that defect one level up: it would prove the arithmetic and
// prove nothing about whether the arithmetic sees the case.
#[cfg(test)]
mod fuel_headroom_tests {
    use super::*;
    use talos_analytics_repository::NodeFuelHeadroom;

    fn install_metrics() -> &'static std::sync::Arc<talos_metrics::TalosMetrics> {
        talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
        talos_metrics::global().expect("global installed")
    }

    fn node(name: &str, samples: i64, peak: i64, ceiling: i64) -> NodeFuelHeadroom {
        NodeFuelHeadroom {
            workflow_id: uuid::Uuid::nil(),
            workflow_name: "wf".into(),
            node_label: name.into(),
            samples,
            peak_fuel: peak,
            current_ceiling: ceiling,
        }
    }

    /// The whole fleet as measured on 2026-08-17: 30-day window, test
    /// executions excluded, each node's ceiling taken from its most recent
    /// enforced limit. Top of the distribution only — the tail is all lower and
    /// changes no assertion below.
    fn live_fleet_head() -> Vec<NodeFuelHeadroom> {
        vec![
            // pa-read-later-digest/digest — 96.9%, TWO samples. The case.
            node("digest", 2, 1_359_999, 1_404_000),
            // pa-daily-brief/calendar_work — 71.0%, the next-highest pair on
            // the whole fleet.
            node("calendar_work", 23, 5_032_346, 7_084_790),
            node("cal_work", 19, 5_682_721, 8_234_228),
            node("organize_work", 217, 2_368_012, 3_791_044),
            node("calendar", 23, 1_788_697, 2_969_360),
            node("classify_severity", 530, 3_413_240, 5_732_830),
        ]
    }

    /// **THE ACCEPTANCE TEST.** `pa-read-later-digest/digest` sat at 96.9% of
    /// its budget for 16 days, across a SUCCESSFUL run, on two samples, and
    /// then failed. If this detector would not have flagged it, it does not
    /// solve the problem it was built for.
    ///
    /// The `samples == 2` is the load-bearing part, not the ratio. Two samples
    /// is below `adaptive_fuel::MIN_SAMPLES` (5) and below
    /// `get_fuel_usage_report`'s `min_executions` default (3) — the node was
    /// invisible to both, which is why nothing caught it.
    #[test]
    fn the_detector_flags_the_node_it_was_built_for() {
        let digest = node("digest", 2, 1_359_999, 1_404_000);
        assert!(
            (digest.utilisation() - 0.9687).abs() < 0.001,
            "utilisation must reproduce the measured 96.9%, got {:.4}",
            digest.utilisation()
        );
        let (observed, high) =
            summarise_fuel_utilisation(&[digest], FUEL_HIGH_UTILISATION_THRESHOLD);
        assert_eq!((observed, high), (1, 1), "n=2 must NOT suppress the flag");
    }

    /// The negative half, and it has to be the real fleet rather than one
    /// hand-picked healthy node: a detector that fires on everything is as
    /// useless as one that fires on nothing, and this is the only evidence
    /// that 80% is a threshold rather than a wish.
    #[test]
    fn the_detector_is_silent_on_the_rest_of_the_live_fleet() {
        let fleet = live_fleet_head();
        let (observed, high) = summarise_fuel_utilisation(&fleet, FUEL_HIGH_UTILISATION_THRESHOLD);
        assert_eq!(observed, fleet.len() as i64);
        assert_eq!(
            high, 1,
            "exactly one node on the live fleet is above threshold; if this \
             number grows, the threshold is producing noise"
        );
        // The margin, pinned. The runner-up is 71.0% and the flagged node is
        // 96.9%, so 80% sits inside a 26-point gap with nothing in it. A
        // threshold that had to be tuned to one decimal place would be a
        // threshold fitted to one sample.
        let runner_up = fleet
            .iter()
            .filter(|n| n.utilisation() < FUEL_HIGH_UTILISATION_THRESHOLD)
            .map(|n| n.utilisation())
            .fold(0.0_f64, f64::max);
        assert!(
            runner_up < 0.72,
            "the healthy fleet must not crowd the threshold, got {runner_up:.3}"
        );
    }

    /// The threshold mutation the plan demands, applied to the DETECTOR rather
    /// than only to the alert: the same input must classify differently on
    /// either side of the boundary, or the test above is asserting a constant.
    #[test]
    fn the_classification_actually_depends_on_the_threshold() {
        let fleet = live_fleet_head();
        assert_eq!(summarise_fuel_utilisation(&fleet, 0.60).1, 5);
        assert_eq!(summarise_fuel_utilisation(&fleet, 0.70).1, 2);
        assert_eq!(summarise_fuel_utilisation(&fleet, 0.80).1, 1);
        assert_eq!(summarise_fuel_utilisation(&fleet, 0.99).1, 0);
    }

    /// A node that has run EXACTLY ONCE must be flagged. Stated as its own
    /// test because "no sample floor" is the property that distinguishes this
    /// detector from everything the platform already had, and a floor is the
    /// single most likely thing a future author adds to reduce noise.
    #[test]
    fn a_single_sample_is_enough() {
        let (_, high) = summarise_fuel_utilisation(
            &[node("first_run", 1, 990, 1_000)],
            FUEL_HIGH_UTILISATION_THRESHOLD,
        );
        assert_eq!(
            high, 1,
            "n=1 must flag — a first-run mis-size has no history"
        );
    }

    /// A ceiling that has since been LOWERED can put peak consumption above
    /// 100%. It must flag, not saturate away or divide into a NaN.
    #[test]
    fn utilisation_above_one_is_representable_and_flags() {
        let n = node("shrunk", 4, 2_000, 1_000);
        assert!((n.utilisation() - 2.0).abs() < f64::EPSILON);
        assert_eq!(
            summarise_fuel_utilisation(&[n], FUEL_HIGH_UTILISATION_THRESHOLD).1,
            1
        );
    }

    /// A zero/absent ceiling must not become a division by zero (which reads
    /// as `inf >= threshold`, i.e. a flag on a node about which nothing is
    /// known). The SQL already filters `max_fuel > 0`; this pins the type's own
    /// behaviour so the guarantee does not live only in a query string.
    #[test]
    fn a_missing_ceiling_reads_as_no_evidence_not_as_infinite_utilisation() {
        assert_eq!(node("x", 3, 5_000, 0).utilisation(), 0.0);
        assert_eq!(
            summarise_fuel_utilisation(&[node("x", 3, 5_000, 0)], FUEL_HIGH_UTILISATION_THRESHOLD)
                .1,
            0
        );
    }

    /// Both gauges are PUBLISHED, driven through the production publisher — a
    /// computed-but-unpublished detector is a silent state. This is also the
    /// per-metric live-increment test structural check 58 cannot substitute
    /// for: 58 matches `.set()` textually, so it would pass on a publisher
    /// whose body no longer ran.
    ///
    /// ONE TEST, not three, deliberately. `talos_metrics::set_global` is a
    /// `OnceLock::set` — the first caller in the whole test BINARY wins and
    /// every later call is a silent no-op — so the registry these gauges live
    /// in is shared process-wide and cargo runs tests in parallel threads.
    /// Splitting the empty case, the firing case and the drain into separate
    /// `#[test]`s would make them race each other on the same two gauges and
    /// fail intermittently, which trains re-running (the #634 lesson). The
    /// cold-registry seeding assertion is NOT made here for the same reason —
    /// it belongs to, and is made by, `talos-metrics`' own render test over a
    /// freshly constructed registry.
    #[test]
    fn both_gauges_are_published_and_the_numerator_drains() {
        install_metrics();
        let read = || {
            let m = talos_metrics::global().expect("global installed");
            (
                m.fuel_utilisation_observed_nodes.get(),
                m.fuel_high_utilisation_nodes.get(),
            )
        };

        // The empty snapshot — the case the denominator exists to make
        // readable: 0-of-0 and 0-of-77 both render the numerator as 0, and
        // only the denominator tells "healthy" from "measured nothing".
        publish_fuel_utilisation(&[], FUEL_HIGH_UTILISATION_THRESHOLD);
        assert_eq!(read(), (0, 0));

        publish_fuel_utilisation(&live_fleet_head(), FUEL_HIGH_UTILISATION_THRESHOLD);
        assert_eq!(read(), (6, 1));

        // ...and the numerator must FALL once the budget is raised and the node
        // next runs, or the alert is permanently red and therefore ignored.
        let fixed: Vec<NodeFuelHeadroom> = live_fleet_head()
            .into_iter()
            .map(|mut n| {
                if n.node_label == "digest" {
                    n.current_ceiling = 8_000_000; // what #642 set
                }
                n
            })
            .collect();
        publish_fuel_utilisation(&fixed, FUEL_HIGH_UTILISATION_THRESHOLD);
        assert_eq!(
            read(),
            (6, 0),
            "raising the budget must clear the flag once the node has run at \
             the new ceiling — the denominator does NOT change, because the \
             node is still observed"
        );
    }
}

/// The crypto-orphan sweep's blindness guarantee.
///
/// These drive the PRODUCTION publisher (`publish_crypto_orphan_scan`), not a
/// re-implementation, and each builds its OWN `TalosMetrics` registry — the
/// publisher takes the collector explicitly precisely so these do not have to
/// win a race for the process-wide `OnceLock` (the reason the fuel tests above
/// had to be collapsed into one).
#[cfg(test)]
mod crypto_orphan_blindness_tests {
    use super::{publish_crypto_orphan_scan, CryptoOrphanScan};

    fn metrics() -> std::sync::Arc<talos_metrics::TalosMetrics> {
        talos_metrics::TalosMetrics::new().expect("fresh registry")
    }

    fn ok_scan() -> CryptoOrphanScan {
        CryptoOrphanScan {
            actor_memory: Some(Ok(0)),
            module_executions: Some(Ok(0)),
            workflow_executions: Some(Ok(0)),
        }
    }

    /// A cold registry exports the stamp as 0, and 0 is the MAXIMALLY STALE
    /// reading — `time() - 0` is ~1.8e9, far over the alert's 600s threshold.
    ///
    /// This is the property that makes the alert cover "the sweep task never
    /// spawned", which a `blind == 1` boolean could not: nothing would set the
    /// boolean either, and it would read "not blind" forever.
    #[test]
    fn a_sweep_that_never_ran_reads_as_maximally_stale() {
        let m = metrics();
        assert_eq!(
            m.crypto_orphan_scan_last_success_timestamp_seconds.get(),
            0.0,
            "the stamp must start at 0 so the never-ran case is loud"
        );
        let rendered = m.render_prometheus().expect("render");
        assert!(
            rendered.contains("talos_crypto_orphan_scan_last_success_timestamp_seconds 0"),
            "a registered Gauge must be EXPORTED before anything sets it, or the \
             alert is silenced by absence instead of firing on staleness\n{rendered}"
        );
    }

    /// THE CORE CLAIM. A failing probe must produce a state distinguishable
    /// from "zero orphans" — which, before 2026-08-20, it did not: the gauge
    /// held 0 and there was no second series to contradict it.
    #[test]
    fn a_failing_probe_is_distinguishable_from_zero_orphans() {
        let m = metrics();

        // A healthy sweep over a clean database: every count is 0.
        publish_crypto_orphan_scan(Some(&m), &ok_scan());
        let healthy_stamp = m.crypto_orphan_scan_last_success_timestamp_seconds.get();
        assert_eq!(m.actor_memory_orphaned_rows.get(), 0);
        assert!(
            healthy_stamp > 1_700_000_000.0,
            "a completed sweep must stamp a real unix time, got {healthy_stamp}"
        );

        // Now the actor_memory probe fails. The COUNT is identical — 0, held
        // from the previous sweep — which is exactly why the old code was
        // silent. The stamp is what differs.
        let failed = CryptoOrphanScan {
            actor_memory: Some(Err("relation \"actor_memory\" does not exist".into())),
            ..ok_scan()
        };
        publish_crypto_orphan_scan(Some(&m), &failed);
        assert_eq!(
            m.actor_memory_orphaned_rows.get(),
            0,
            "the count must HOLD its last value, not zero and not a sentinel — \
             every other consumer reads it as a row count"
        );
        assert_eq!(
            m.crypto_orphan_scan_last_success_timestamp_seconds.get(),
            healthy_stamp,
            "an incomplete sweep must NOT advance the stamp; if it does, the \
             blind alert can never fire"
        );
    }

    /// Two measured tables plus one broken one is still blind. Partial data is
    /// not a completed sweep, and for a data-loss detector over-reporting
    /// blindness is the right side to err on.
    #[test]
    fn partial_success_does_not_advance_the_stamp() {
        for failed in [
            CryptoOrphanScan {
                module_executions: Some(Err("timeout".into())),
                ..ok_scan()
            },
            CryptoOrphanScan {
                workflow_executions: Some(Err("permission denied".into())),
                ..ok_scan()
            },
        ] {
            let m = metrics();
            publish_crypto_orphan_scan(Some(&m), &failed);
            assert_eq!(
                m.crypto_orphan_scan_last_success_timestamp_seconds.get(),
                0.0,
                "partial success must leave the stamp untouched"
            );
        }
    }

    /// A probe that was never ATTEMPTED is not a success either. This pins the
    /// `Option<Result<..>>` shape: a future refactor that conditionally skips a
    /// table must not be able to certify the sweep complete.
    #[test]
    fn a_skipped_probe_does_not_advance_the_stamp() {
        let m = metrics();
        publish_crypto_orphan_scan(
            Some(&m),
            &CryptoOrphanScan {
                workflow_executions: None,
                ..ok_scan()
            },
        );
        assert_eq!(
            m.crypto_orphan_scan_last_success_timestamp_seconds.get(),
            0.0
        );
    }

    /// Measured counts still reach their gauges — the fix must not break the
    /// thing it is protecting.
    #[test]
    fn measured_counts_are_published() {
        let m = metrics();
        publish_crypto_orphan_scan(
            Some(&m),
            &CryptoOrphanScan {
                actor_memory: Some(Ok(7)),
                module_executions: Some(Ok(1)),
                workflow_executions: Some(Ok(2)),
            },
        );
        assert_eq!(m.actor_memory_orphaned_rows.get(), 7);
        assert_eq!(m.module_execution_orphaned_rows.get(), 1);
        assert_eq!(m.workflow_execution_orphaned_rows.get(), 2);
        assert!(m.crypto_orphan_scan_last_success_timestamp_seconds.get() > 0.0);
    }

    /// The publisher must not panic when metrics are not installed — the
    /// sweep loop calls it unconditionally now, where the old code skipped
    /// the whole block (and therefore the queries too).
    #[test]
    fn no_collector_is_not_a_panic() {
        publish_crypto_orphan_scan(None, &ok_scan());
    }
}
