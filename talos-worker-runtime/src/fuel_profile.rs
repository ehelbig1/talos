//! Where a run's fuel went, by the host call that preceded it.
//!
//! A module's fuel is spent by GUEST code; a host call costs none. So the
//! useful question after "it used 9.6 M" is "between which host calls?" — the
//! code that builds a request, or the code that parses the response. Until
//! this existed that took probe builds with early exits (two compiles and
//! fourteen rehearsals for one Gmail reader on 2026-10-01).
//!
//! The runtime installs a wasmtime call hook for a run that asks for a
//! profile. At each guest→host transition it reads the fuel left and charges
//! what the guest burned since the previous transition to the host call that
//! came BEFORE that stretch (`"start"` for the stretch before the first one).
//! Fuel burned while a host call is in progress — the guest's allocator being
//! called to receive a result — is charged to that call.
//!
//! Only a host call that NAMES itself ends a stretch. wasmtime fires the same
//! hook for its own internal calls — the epoch check, memory growth — and for
//! WASI imports, and the epoch check is timing-dependent: on a slow machine
//! one lands in the middle of a parse. If those ended a stretch, the fuel
//! after `http::fetch` would be reported under a row that names nothing, by
//! an amount that changes from run to run. They are counted
//! (`unnamed_host_calls`) and the stretch they interrupt carries on.
//!
//! Requested only by the controller's `test_module`; a dispatched job never
//! carries one (`SecurityPolicy::fuel_profile` is not on the wire), so no
//! production execution pays for the hook.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// The label of the stretch before the first host call.
pub const START: &str = "start";
/// What a host transition is labelled when nothing named it: a WASI import
/// (clocks, random, stdio) or one of wasmtime's own calls (the epoch check,
/// memory growth). Never a row of the report.
pub const UNNAMED: &str = "";

#[derive(Default)]
struct Inner {
    /// Fuel left at the last transition; `None` before the run starts.
    last: Option<u64>,
    /// The host call the current guest stretch follows.
    after: &'static str,
    /// Fuel burned so far in the current stretch.
    stretch: u64,
    /// Host transitions that named nothing.
    unnamed: u64,
    /// label → (fuel the guest burned after it, number of stretches).
    guest: BTreeMap<&'static str, (u64, u64)>,
    /// label → (calls, fuel burned while the call was in progress).
    host: BTreeMap<&'static str, (u64, u64)>,
}

/// One row of [`FuelProfile::report`]: guest fuel burned after `after`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestStretch {
    pub after: &'static str,
    pub fuel: u64,
    pub stretches: u64,
}

/// One row of [`FuelProfile::report`]: a host call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCall {
    pub call: &'static str,
    pub count: u64,
    /// Guest fuel burned while the call was in progress.
    pub fuel_during: u64,
}

/// What [`FuelProfile::report`] returns: both lists sorted by fuel, largest
/// first, then by label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuelReport {
    pub guest: Vec<GuestStretch>,
    pub host_calls: Vec<HostCall>,
    /// Host transitions that named nothing (see [`UNNAMED`]). They end no
    /// stretch and have no row.
    pub unnamed_host_calls: u64,
    /// The sum of every row; equals the fuel the run consumed when the hook
    /// saw the whole run.
    pub accounted: u64,
}

/// A run's fuel, charged to the host calls it was spent between.
#[derive(Default)]
pub struct FuelProfile {
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for FuelProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuelProfile")
            .field("accounted", &self.report().accounted)
            .finish()
    }
}

impl Inner {
    /// Charge the current stretch to the call it followed. A stretch that
    /// ends at a named host call is counted even when it burned nothing (two
    /// calls back to back); the last one of a run only if it burned
    /// something, or if it is the whole run.
    fn close_stretch(&mut self, ended_by_call: bool) {
        let fuel = std::mem::take(&mut self.stretch);
        if ended_by_call || fuel > 0 || self.guest.is_empty() {
            let row = self.guest.entry(self.after).or_default();
            row.0 = row.0.saturating_add(fuel);
            row.1 += 1;
        }
    }
}

impl FuelProfile {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        // A poisoned lock means a panic elsewhere; the profile is a report,
        // so it keeps what it has.
        f(&mut self.inner.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// The run (or a retry of it) starts with `remaining` fuel.
    pub fn start(&self, remaining: u64) {
        self.with(|p| {
            // An attempt that ended without `finish` still burned its fuel.
            if p.last.is_some() {
                p.close_stretch(false);
            }
            p.last = Some(remaining);
            p.after = START;
        });
    }

    /// The guest is about to leave for the host: what it burned since the
    /// last transition belongs to the current stretch.
    pub fn calling_host(&self, remaining: u64) {
        self.with(|p| {
            let Some(last) = p.last else { return };
            p.stretch = p.stretch.saturating_add(last.saturating_sub(remaining));
            p.last = Some(remaining);
        });
    }

    /// The host returned. `label` is the host call that named itself, or
    /// [`UNNAMED`]; only a named call ends the stretch.
    pub fn returned_from_host(&self, remaining: u64, label: &'static str) {
        self.with(|p| {
            let Some(last) = p.last else { return };
            let during = last.saturating_sub(remaining);
            p.last = Some(remaining);
            if label == UNNAMED {
                p.unnamed += 1;
                p.stretch = p.stretch.saturating_add(during);
                return;
            }
            p.close_stretch(true);
            let row = p.host.entry(label).or_default();
            row.0 += 1;
            row.1 = row.1.saturating_add(during);
            p.after = label;
        });
    }

    /// The guest returned (or was stopped): charge the last stretch.
    pub fn finish(&self, remaining: u64) {
        self.with(|p| {
            let Some(last) = p.last.take() else { return };
            p.stretch = p.stretch.saturating_add(last.saturating_sub(remaining));
            p.close_stretch(false);
        });
    }

    #[must_use]
    pub fn report(&self) -> FuelReport {
        self.with(|p| {
            let mut guest: Vec<GuestStretch> = p
                .guest
                .iter()
                .map(|(after, (fuel, stretches))| GuestStretch {
                    after,
                    fuel: *fuel,
                    stretches: *stretches,
                })
                .collect();
            guest.sort_by(|a, b| b.fuel.cmp(&a.fuel).then(a.after.cmp(b.after)));
            let mut host_calls: Vec<HostCall> = p
                .host
                .iter()
                .map(|(call, (count, fuel_during))| HostCall {
                    call,
                    count: *count,
                    fuel_during: *fuel_during,
                })
                .collect();
            host_calls.sort_by(|a, b| b.fuel_during.cmp(&a.fuel_during).then(a.call.cmp(b.call)));
            let accounted = guest
                .iter()
                .map(|g| g.fuel)
                .chain(host_calls.iter().map(|h| h.fuel_during))
                .fold(0u64, u64::saturating_add);
            FuelReport {
                guest,
                host_calls,
                unnamed_host_calls: p.unnamed,
                accounted,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1000 fuel: 100 before the fetch, 20 inside it (the allocator receiving
    /// the body), 700 parsing after it, two log calls with 30 after each, and
    /// 120 to finish — every unit lands on one row.
    #[test]
    fn fuel_is_charged_to_the_call_it_followed() {
        let p = FuelProfile::new();
        p.start(1000);
        p.calling_host(900);
        p.returned_from_host(880, "http::fetch");
        p.calling_host(180);
        p.returned_from_host(180, "logging::log");
        p.calling_host(150);
        p.returned_from_host(150, "logging::log");
        p.finish(0);
        let r = p.report();
        assert_eq!(
            r.guest,
            vec![
                GuestStretch {
                    after: "http::fetch",
                    fuel: 700,
                    stretches: 1
                },
                GuestStretch {
                    after: "logging::log",
                    fuel: 180,
                    stretches: 2
                },
                GuestStretch {
                    after: START,
                    fuel: 100,
                    stretches: 1
                },
            ]
        );
        assert_eq!(
            r.host_calls,
            vec![
                HostCall {
                    call: "http::fetch",
                    count: 1,
                    fuel_during: 20
                },
                HostCall {
                    call: "logging::log",
                    count: 2,
                    fuel_during: 0
                },
            ]
        );
        assert_eq!(
            r.accounted, 1000,
            "every unit of fuel is on exactly one row"
        );
    }

    #[test]
    fn a_run_with_no_host_call_is_one_stretch() {
        let p = FuelProfile::new();
        p.start(500);
        p.finish(120);
        let r = p.report();
        assert_eq!(
            r.guest,
            vec![GuestStretch {
                after: START,
                fuel: 380,
                stretches: 1
            }]
        );
        assert!(r.host_calls.is_empty());
        assert_eq!(r.accounted, 380);
    }

    /// A retry starts again from a full tank: the profile sums the attempts
    /// and never charges the refill as fuel burned.
    #[test]
    fn a_second_attempt_adds_to_the_first() {
        let p = FuelProfile::new();
        p.start(100);
        p.calling_host(60);
        p.returned_from_host(60, "http::fetch");
        p.finish(50);
        p.start(100);
        p.calling_host(70);
        p.returned_from_host(70, "http::fetch");
        p.finish(40);
        let r = p.report();
        assert_eq!(r.accounted, 50 + 60);
        assert_eq!(r.host_calls[0].count, 2);
    }

    /// An unnamed transition — wasmtime's epoch check landing mid-parse, a
    /// WASI clock read — ends no stretch: the 700 burned around it stay on
    /// the fetch they followed, including what was burned while it ran.
    #[test]
    fn an_unnamed_transition_does_not_end_a_stretch() {
        let p = FuelProfile::new();
        p.start(1000);
        p.calling_host(1000);
        p.returned_from_host(1000, UNNAMED); // before the guest burned anything
        p.calling_host(900);
        p.returned_from_host(900, "http::fetch");
        p.calling_host(600);
        p.returned_from_host(590, UNNAMED);
        p.finish(200);
        let r = p.report();
        assert_eq!(
            r.guest,
            vec![
                GuestStretch {
                    after: "http::fetch",
                    fuel: 700,
                    stretches: 1
                },
                GuestStretch {
                    after: START,
                    fuel: 100,
                    stretches: 1
                },
            ]
        );
        assert_eq!(r.host_calls.len(), 1, "an unnamed call has no row: {r:?}");
        assert_eq!(r.unnamed_host_calls, 2);
        assert_eq!(r.accounted, 800);
    }

    /// An attempt that ends without `finish` keeps what it burned when the
    /// next one starts.
    #[test]
    fn an_unfinished_attempt_is_not_lost() {
        let p = FuelProfile::new();
        p.start(100);
        p.calling_host(60);
        p.start(100);
        p.finish(90);
        assert_eq!(p.report().accounted, 40 + 10);
    }

    /// Transitions outside a run (before `start`, after `finish`) are not
    /// charged to anything.
    #[test]
    fn transitions_outside_a_run_are_ignored() {
        let p = FuelProfile::new();
        p.calling_host(10);
        p.returned_from_host(5, "http::fetch");
        p.start(100);
        p.finish(90);
        p.calling_host(1);
        assert_eq!(p.report().accounted, 10);
        assert!(p.report().host_calls.is_empty());
    }
}
