# 2026-10-01 — a module can ask for a time zone's offset

**Context.** A guest has no zone database, and the `datetime` host interface
had now / parse / format / add / diff only. A module that needs "today" where
its owner lives therefore carried a fixed `UTC_OFFSET_HOURS` in its config,
which is right for half the year. Two live modules on the reference
deployment do (`commitments`, `bills`); the week-ahead planner avoided it
only by having the calendar provider convert times for it.

Measured impact, stated narrowly: a one-hour-wrong offset changes the DATE
only for a run between 7 pm and midnight local time, so the morning schedules
are unaffected by the 2026-11-01 clock change. The gap is in what a module
can express, not a live incident.

**Change.** One function on the existing `datetime` interface, in both WIT
copies:

    local-offset-seconds: func(zone: string, timestamp: u64) -> result<s32, error>

Seconds EAST of UTC in an IANA zone at an instant, by the zone's own rules.
A minimal primitive: the guest adds it to a timestamp and formats, with the
`chrono` it already has. Host side: `zone_offset_seconds` in
`talos-worker-runtime/src/host/data.rs` over `chrono-tz` (already in the
workspace at this version, for the scheduler). Pure, no I/O, no state; the
zone name is bounded at 64 bytes and matched exactly (case-sensitive); an
unknown zone or an unrepresentable instant is `invalidformat`, never a guess.
Available wherever `datetime` is: every world.

**Compatibility.** Additive. A component that imports `datetime` without the
new function — every module compiled before it — instantiates and runs
unchanged (driven by test). A module that CALLS it needs a worker that has
it: roll workers first or together with the controller, as for any new host
function.

**Deliberately not done.**
- A richer API (local date parts, formatting in a zone): the offset is enough
  to build them guest-side, and every extra host function is interface
  surface to keep forever.
- Putting the schedule's zone in the trigger input: it would cover scheduled
  runs only.
- Migrating the two live modules: an operator's hot update once this is
  deployed.

**Tests.** Unit (`zone_offset_tests`): zone rules either side of a
daylight-saving change, the exact instant of the change, a half-hour zone,
and what is refused (unknown, wrong case, overlong, path-shaped, a bare
offset, an unrepresentable instant). End to end
(`worker/tests/datetime_local_offset_tests.rs`): a real `minimal-node`
component built from WAT calls the function through the minimal-tier linker
and gets -14400, -18000 and an error; a component importing only `now-unix`
from the same interface still runs.

**Stated limits.** The zone rules are the ones compiled into the worker
image (`chrono-tz`'s bundled database); a rule change by a government needs
a rebuild. `cargo test` of `talos-worker-runtime --lib` in one process shows
one unrelated order-dependent failure in `wasi_http` (the known env-sharing
limit; `cargo nextest`, which CI uses, passes 879 of 879).
