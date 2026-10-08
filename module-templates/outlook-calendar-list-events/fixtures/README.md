# Recorded run

Made-up data with the shape and size of a real Microsoft Graph reply: a
busy week (`HOURS_AHEAD` 168) on a made-up Microsoft 365 calendar, 64 events
read in two calendarView pages, as Graph answers a `$top=50` request with
`Prefer: outlook.timezone="America/New_York"`:

* page 1 (about 110 KB): 50 events and an `@odata.nextLink` on
  `graph.microsoft.com/v1.0/` with `$skip=50`, which the module follows;
* page 2 (about 30 KB): the last 14 events and no next link. Two of them are
  meetings cancelled but still on the calendar (`isCancelled: true`), which
  the module leaves out, so the run returns 62 events, not truncated.

Events have 0 to 9 attendees (some with a room), Teams join links on most,
recurring-series ids on some, a few all-day and out-of-office entries, and
every `showAs` and `responseStatus` value. Every value was replaced: people
and rooms are `@example.com`, ids and links are random, and only field
names, enumerations and formats are Graph's.

`config.json` is the node config (its `AUTH_HEADER` names a made-up vault
path; a rehearsal resolves no secret), `input.json` the upstream output
(none), and `http.json` Graph's two answers in the order they are asked for.
Nothing is sent: the run is answered from `http.json`.

`make check-catalog-fuel TEMPLATE=outlook-calendar-list-events` builds the
template the way the platform does, runs it against this recording, and
fails if the fuel used is above 80% of the limit `talos.json` declares.
Measured 2026-10-08: 11.27M fuel for this recording (about 176K per event)
against a declared limit of 25.6M (44%). The limit is sized for about 100
events of this size; a node that sets `MAX_RESULTS` above that should set
its own `max_fuel`.
