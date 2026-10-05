# The ops-alerts digest node can be narrowed to some sources (2026-10-05)

## Why

A workflow is to send the platform's own failure alerts (`source = talos`,
and the backup drill's) to the operator's phone. The `ops_alerts_digest`
node returns at most 25 active alerts, severity-ranked. Measured on the
running stack: one critical and 13 high-severity alerts from work email
outrank everything, and the one active `talos` alert (medium) competes with
36 others for the remaining 11 places. A reader of that list can miss
exactly the alerts it exists for.

## Changed

- `SystemNodeKind::OpsAlertsDigest` gains `sources: Option<Vec<String>>`.
  `None` = every source; the node serialises exactly as before (no key).
  `Some(list)` = `top_active` holds only those sources.
- **A filter never widens.** The graph parser reads a present but unusable
  `sources` value (a string, malformed names) as `Some(vec![])`, which
  matches NO alert. The MCP tool `add_ops_alerts_digest_node` refuses such a
  value outright (an author's typo should be heard, not turned into an empty
  feed). One rule for a usable name, `usable_alert_source`, in core.
- `OpsAlertsReader::snapshot` takes the filter; the repository gains
  `list_active_ranked_from` (`AND ($3::text[] IS NULL OR source = ANY($3))`);
  `list_active_ranked` is that with `None`.
- The digest COUNTS stay over every active alert; only `top_active` is
  narrowed.
- `top_active` entries gain `reopened_at` beside the existing `reopened`
  flag, so a reader that remembers what it reported can tell a reopened
  alert from the same one.

## Tests

- Parser/builder: a filter round-trips; no filter writes no key; a string
  or all-malformed list parses to "matches nothing".
- `controller/tests/ops_alerts_digest_sources_tests`: thirty high alerts
  rank a watched medium alert out of the unfiltered top 25; the filter
  returns it; an empty filter returns nothing; another user's alert is
  never returned; the Postgres reader passes the filter, keeps the counts
  global and reports `reopened_at` after a resolve and re-raise. Making the
  SQL condition always true fails both tests.
