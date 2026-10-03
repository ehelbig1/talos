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
//! Requested only by the controller's `test_module`; a dispatched job never
//! carries one (`SecurityPolicy::fuel_profile` is not on the wire), so no
//! production execution pays for the hook.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// The label of the stretch before the first host call.
pub const START: &str = "start";
/// A host call that did not name itself (WASI clocks, random, stdio).
pub const OTHER: &str = "other";

#[derive(Default)]
struct Inner {
    /// Fuel left at the last transition; `None` before the run starts.
    last: Option<u64>,
    /// The host call the current guest stretch follows.
    after: &'static str,
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
            p.last = Some(remaining);
            p.after = START;
        });
    }

    /// The guest is about to enter a host call: charge the stretch since the
    /// last transition to the call it followed.
    pub fn calling_host(&self, remaining: u64) {
        self.with(|p| {
            let Some(last) = p.last else { return };
            let row = p.guest.entry(p.after).or_default();
            row.0 = row.0.saturating_add(last.saturating_sub(remaining));
            row.1 += 1;
            p.last = Some(remaining);
        });
    }

    /// The host call named `label` returned.
    pub fn returned_from_host(&self, remaining: u64, label: &'static str) {
        self.with(|p| {
            let Some(last) = p.last else { return };
            let row = p.host.entry(label).or_default();
            row.0 += 1;
            row.1 = row.1.saturating_add(last.saturating_sub(remaining));
            p.last = Some(remaining);
            p.after = label;
        });
    }

    /// The guest returned (or was stopped): charge the last stretch.
    pub fn finish(&self, remaining: u64) {
        self.with(|p| {
            let Some(last) = p.last.take() else { return };
            let burned = last.saturating_sub(remaining);
            if burned > 0 || p.guest.is_empty() {
                let row = p.guest.entry(p.after).or_default();
                row.0 = row.0.saturating_add(burned);
                row.1 += 1;
            }
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
