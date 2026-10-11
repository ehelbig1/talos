# The scheduler waits for a host that just woke (2026-10-11)

The reference deployment runs on a laptop. Its lid was closed from
2026-10-09 21:08 to 2026-10-11 18:50 UTC.

## Measured

* `pmset -g log` for that window: 201 background wake-ups in 45 h 41 min,
  15 minutes awake in total, median 2 s, longest 29 s.
* `get_error_report(days: 3)`: 36 failed runs (2 of them the author's own
  test runs). Shapes: a node that started and never reported, swept as stale
  (11); `api.github.com could not be reached` (7); a model first-byte
  timeout (2); a fetch timeout (2); a Gmail 401 whose token refresh then
  failed (2); a job result rejected as 1,755 s old (1).
* Five runs matched by hand against the log — three failures and the two
  morning runs, which went out 55 and 81 minutes late — each sat inside a
  2-second wake-up window.
* Scheduled runs per day on the main actor: about 440 on a normal day, 141
  and 118 on the two days asleep.

## The class

The poll timer is overdue whenever the host wakes, so every wake-up
dispatched. Package M (2026-09-11) bounded HOW MANY runs a resume starts
(`phase = catchup`, the backlog ceiling); nothing asked WHETHER the host was
going to stay up.

## Decided

* **Resume settle** (`talos_scheduler::decide_resume_settle`). A poll that
  starts 45 s or more (`RESUME_GAP_SECS`, three intervals) after the previous
  one finished saw a resume. That poll holds, and dispatch starts again after
  `SCHEDULER_RESUME_SETTLE_POLLS` (default 2) further polls arrive on time:
  30 s of continuous running, longer than the longest wake-up measured. A
  gap during the settle restarts it. A hold opens no transaction, so nothing
  is advanced or lost; the backlog then drains as a `catchup` batch as before.
* **Wall clock, not monotonic.** A paused VM's monotonic clock does not move;
  the wall clock is stepped on resume. A clock stepped backwards reads as no
  gap. The gap is measured from the END of the previous poll, so a slow poll
  is not a resume.
* **It cannot wedge a host that is up**: it holds only on a measured gap.
  `0` turns it off; values above 20 read as 20; an unreadable value is said
  and the default (which holds) is used.
* **Counted and reported**: `talos_scheduler_resume_holds_total`,
  `talos_host_suspended_seconds_total` (both exported at 0), one INFO line
  per resume, and `session_start.host_sleep` — resumes, seconds asleep and
  the longest gap in the last 24 h, with `observed_since` /
  `covers_whole_window` because the ledger is process memory and a restart
  forgets it.
* **The token-refresh sentence no longer claims a cause it does not know.**
  `force_refresh_vault_paths` answers `false` for a refused refresh and for a
  token endpoint that could not be reached alike; the failure text said
  "was refused — the integration most likely needs to be re-authorised".
  Both times it appeared in this window the next run succeeded. It now names
  both causes and says a single occurrence after sleep is expected.

## Deliberately NOT done

* **A network probe before dispatch.** The settle already covers the
  measured case, and a probe needs a host to probe: the controller must not
  call a third party to learn whether it is online.
* **Making the refresh result three-valued** (refreshed / refused /
  unreachable) so an unreachable token endpoint earns a retry. It changes
  `SecretsResolver::force_refresh_vault_paths` in three crates on the
  credential path; the service already tells the three apart internally
  (`Ok(true)` / `Ok(false)` / `Err`). Worth its own package.
* **Classing "could not be reached" as transient for non-GET-only nodes.**
  Unchanged; with the settle those runs are not started into a sleeping host.
* **A per-workflow policy for a missed schedule** (run once on wake vs skip).
  Today every missed cron runs once on resume; a morning message sent at
  3 pm is the consequence.

## Stated limits

* A wake-up longer than 30 s with no network still dispatches into it.
* A run already in flight when the host sleeps is unaffected: it is swept as
  stale on resume, as before.
* Not seen live: the change is unit-tested against the measured sequence
  (`resume_settle_tests`); the next closed-lid stretch is the live proof.
