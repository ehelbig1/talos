# 2026-10-01 — the calendar template returns what a planner needs

**Context.** `google-calendar-list-events` returned display fields (summary,
times, location, attendees). Building a week-ahead planner on it was not
possible: it could not tell an event that holds the time from one marked
free, a focus block from a meeting, one invitation on two calendars from two
events, or whether the owner had answered; it stopped at 50 events and 7
days, did not follow pages, and gave no sign when it had cut the list. A
custom module was written instead.

**Also found.** The error path quoted the provider's body with
`&body[..body.len().min(200)]` — a byte slice, which panics when byte 200
falls inside a multi-byte character.

**Change (additive; every field the template returned before is unchanged).**
- Per event: `busy` (not marked free), `event_type`, `response` (the
  calendar owner's own answer; `""` for an entry with no guest list),
  `guests` (other people, rooms excluded), `uid` (the invitation's iCalUID,
  the same on every calendar it sits on), `organizer_self`, `recurring`.
  Cancelled entries are dropped.
- Output: `truncated` (the calendar holds more in the window than were
  returned) and `time_zone` (the zone the times are in).
- Config: `TIME_ZONE` (optional IANA name, validated before it reaches a
  URL). The provider then returns local wall-clock times with the right
  offset per event, so a module can group by local day across a
  daylight-saving change without a zone database — modules have none.
- Limits: `MAX_RESULTS` up to 250 (default still 20), `HOURS_AHEAD` up to 336;
  pages are followed (at most three requests).
- The request names the fields it reads (`fields=`), so conference data,
  reminders and extended properties are no longer fetched and parsed.
- The error body is cut on a character boundary.
- `recommended_fuel` declared; version `v1.1.0`.

**Measured (the new source compiled as a temporary module on the reference
deployment, run read-only against two calendars, then deleted).** 35 events
over 14 days: 9,191,270 fuel, about 265 K per event on a calendar whose
events carry long descriptions and guest lists; about 137 K per event on a
calendar of plain entries. `recommended_fuel` resolves to 18.15 M, which
covers 50 such events with about a third to spare; the schema says to set
`max_fuel` on the node above 50. `truncated` was true with `MAX_RESULTS` 5
and false with 50; an invalid zone was refused before any request.

**Tests.** In the template, run natively with the host bindings stubbed (CI
compiles templates and does not run their tests): the planner fields; free,
all-day, own and focus entries; the request's encoding and that every field
the struct reads is asked for; zone validation; the character-boundary cut.

**Stated limits.** Installed copies do not change until reinstalled. The
custom `calendar-week-fetch` module on the reference deployment is not
migrated to this template here.
