# report_ops_alert, and the backup drill reports its result (2026-10-05)

The weekly backup restore drill (`scripts/drills/backup-restore.sh`, launchd
on the operator's Mac) failed every week from 2026-09-14 and nobody was told:
its result reached only a Prometheus textfile metric, and the alert on that
metric goes to an Alertmanager with no delivering receiver. This package gives
an operator-side reporter a way to raise and resolve an ops alert, and makes
the drill use it. Forwarding ops alerts to a phone is a separate workflow.

## Decided

- **A new MCP tool, `report_ops_alert`** (`talos-mcp-handlers/src/ops_alerts.rs`),
  raising or resolving an alert for the CALLING user. Arguments: `source`,
  `dedup_key` (required), `title` (required unless resolving), optional
  `severity_hint` (critical|high|medium|low|info), `resource`, `external_id`,
  `raw` (object), `status_event` ("resolved" only). Response:
  `{result: created|bumped|reopened|resolved|no_active_alert, alert_id?,
  occurrence_count?}` — never `raw` or any other caller field.
- **One home for the per-entry rules: `talos_ops_alerts_repository::envelope::apply_entry`.**
  The envelope loop and the tool both call it: classify (reserved `talos`
  source / `talos/` dedup prefix REFUSED before any statement; `status_event`
  routing) → `redacted_alert` (DLP on every free-text field; `raw` through
  `redact_json_bounded`, then the store's 64 KiB cap) → ingest or
  `resolve_by_dedup_key`. It also does the counting
  (`ops_alert_ingest_failures_total{reason}`, `ops_alert_auto_resolved_total`),
  so both doors count alike. The envelope loop now only logs; its log lines,
  metric labels and behaviour are unchanged. No new SQL.
- **Tenancy is the authenticated caller's `user_id`.** The handler takes the
  bare `agent.user_id` and refuses `None`, rather than the nil-UUID default the
  other ops-alert handlers' `dispatch` computes — a nil user is not "no
  tenant" (see `auth::refuse_unscoped_agent`). Every route already resolves a
  user, so the refusal is defence in depth.
- **`org_id` = the caller's PERSONAL org**, via
  `SecretsManager::resolve_personal_org_id` (documented as the Rust twin of the
  `set_org_id_from_personal_org` trigger the user-scoped tables use). Every
  existing ingest caller takes the org from an actor or an execution row; there
  was no actor-less precedent, so this follows the user-scoped writers. The
  column is stamped on CREATE only, nothing reads it yet and `ops_alerts` has
  no RLS. A resolve reads no org. An unreadable org REFUSES (database error)
  rather than writing NULL in its place; a user with no personal org writes
  NULL, as the trigger would.
- **Stricter argument validation at the tool than the envelope applies**:
  a mistyped field (non-string `source`, non-object `raw`, non-string
  `status_event`) is refused, and an unknown `severity_hint` is refused rather
  than degraded to unclassified. The entry handed to `apply_entry` is built
  from the declared arguments only. The reserved namespace is deliberately NOT
  checked in the handler — one gate, so it cannot drift.
- **The drill** (`scripts/lib/drill-ops-alert.sh`, sourced by
  `backup-restore.sh`): `emit_metric` writes the textfile metric
  (`write_metric_file`, the old body) and then calls
  `drill_report_ops_alert` — once per run, on the `die`, abort-trap, signal and
  success paths alike. Failure raises `backup-drill|<--source>` at
  `severity_hint: high`, titled with the step from a CLOSED label table
  (`log` records the N of each `[N/8]` line; step 0b sets it by hand), with
  `raw` = drill id, step, first line of the `die` message. Success resolves the
  same key. Best effort: every command guarded, always returns 0, one WARN
  naming the endpoint and HTTP status (plus curl's exit code when there was no
  response), never a body, never the key; `curl -m 10`.
- **Transport**: `TALOS_DRILL_REPORT_KEY_FILE` set → `${TALOS_URL}/mcp` with
  `Authorization: Bearer <token>` from a 0600 temp file (`-H @file`), removed
  after; unset → `/mcp/local`. `schedule.sh` carries `TALOS_DRILL_REPORT_KEY_FILE`
  (the path) and `TALOS_URL` into the plist.

## Deviation from the brief, measured

- **`Authorization: Bearer`, not `X-API-Key`.** The brief named `X-API-Key`.
  `/mcp`'s middleware (`talos-mcp-handlers/src/auth.rs`, token extraction) reads
  only `Authorization: Bearer` or `?token=`; `X-API-Key` is read only by the
  GraphQL route (`controller/src/bootstrap/router.rs`). A drill sending
  `X-API-Key` to `/mcp` would be refused on every run. The key file therefore
  holds an MCP agent token.

## Deliberately NOT done

- No per-call duplicate guard on the namespace in the handler (see above).
- No `noise` in the tool's `severity_hint` enum: it is a triage verdict, not
  something a source reports about itself.
- `raw` is not echoed, and neither is `dedup_key` or `title`; the reply names
  the row by id only.
- The drill does not truncate the failure reason client-side (byte truncation
  in bash can split a UTF-8 sequence and make the body invalid JSON); it sends
  the first line, and the store caps text by chars.
- No change to the Alertmanager receiver: its webhook body is fixed and cannot
  be a JSON-RPC `tools/call`. `observability/alertmanager/alertmanager.yml`'s
  "no other surface" sentence is corrected in place.

## Tests

- `talos-ops-alerts-repository` (lib): `apply_entry` refuses the reserved
  namespace (raise by key, raise by source, resolve by key) and an unknown
  `status_event` BEFORE any statement — run against a lazy pool that cannot
  connect, so a refusal that reached the database would come back as a db
  error instead; `redacted_alert` redacts title/resource/external_id/raw and
  keeps the dedup key; the refusal metric labels keep the envelope's vocabulary.
- `talos-mcp-handlers` (lib, `ops_alerts::report_tests`): argument validation
  (13 refused shapes, each naming its field), only declared fields reach the
  entry, a resolve needs no title, the namespace is left to the shared gate,
  outcomes carry only `result`/`alert_id`/`occurrence_count`.
- `controller/tests/report_ops_alert_tests.rs` (DB, real MCP dispatch over a
  real `McpState`): raise → created (row is the caller's, personal org
  stamped, severity high, title and raw DLP-redacted) → bumped → resolved
  (`resolved_source = 'signal'`) → no_active_alert → reopened; the reserved
  namespace refused in four shapes, including a bump and a resolve aimed at a
  seeded self-monitoring row, which stays untouched; another user's resolve
  finds nothing and writes nothing; invalid arguments write nothing.
- `scripts/tests/drill-ops-alert-test.sh` (CI: quality.yml audit job), fake
  `curl` on PATH: success → resolve; failure → raise naming the step, JSON
  escaping; key file → `/mcp`, Bearer header from a private file, key in no
  argv, header file removed; unusable or missing key file → not sent, one WARN;
  endpoint down / HTTP 500 / tool error → one WARN, no body, return 0, no temp
  file left. Then the REAL drill, failing at `docker info` with a fake docker:
  exit 1, failure metric, metric written before the report, one raise titled
  "step 0/8: pre-flight" with the `die` message as reason; with the endpoint
  down or answering 500 the exit status and metric are byte-identical. Run
  under macOS bash 3.2 and the CI bash.

## Mutation (tenancy / reserved namespace)

- `classify_entry`'s reserved-namespace condition made `false && (…)`:
  CAUGHT — `reserved_namespace_is_refused_in_both_directions`,
  `apply_entry_refuses_the_reserved_namespace_before_any_statement` (lib) and
  `the_reserved_namespace_is_refused_and_nothing_is_written` (DB) all failed;
  restored, all green.

## Stated limits

- The drill's SUCCESS path is covered at the reporter level only; no fake
  makes the real drill reach step 8.
- `/mcp/local` attributes the alert to the dev stack's first user, which is
  what every other `/mcp/local` call does.
- `ops_alert_ingest_failures_total{reason="namespace"}` now also counts a
  reporter's refused call, not only a module's; its HELP text says so.

## Added in review: the drill drills Vault only when it holds the key

Found while reviewing this package: `backup-restore.sh` required a Vault
backup no older than 7 days (`assert_artifact_fresh … vault artifact`), even
with `KEK_PROVIDER=env`, where the drill's own output says Vault "is not on
the KEK path". #1103 stopped starting Vault (and its backup container) in the
dev stack, so from about 2026-10-12 the drill would have failed for a
component the restore does not need — and with this package, reported it.

`TALOS_DRILL_VAULT` (`auto` default): `auto` drills Vault exactly when
`TALOS_DRILL_KEK_PROVIDER=vault`; `on` forces it; `off` with `vault` is
refused. A skipped Vault emits no `kind_verified{kind="vault"}` line (that
series' own meaning of "not attempted"), and the banner keeps its fixed
denominator of 3 (reads 2/3 with the reason printed), as decided for a host
without a graph. `scripts/tests/drill-vault-gate-test.sh` runs the real drill
with a fake docker and an empty backup folder through all five cases; making
`auto` always drill Vault fails three of its checks.


**Found by that test in CI: the drill could not read a file date on Linux.**
It tried BSD `stat -f %m` first; on Linux that is the filesystem report and
succeeds with text, so the artifact "mtime" was `  File: …` and the age check
died on `File: unbound variable`. `date -u -r <seconds>` was BSD-only too
(GNU reads a file there), so dates printed `?`. Pre-existing — the drill has
only ever run on macOS — and fixed with `file_mtime` (GNU form first, digits
only) and `epoch_utc` (`-r`, then `-d @`), used at all three artifact sites.
The test now also checks that the date and age are read; it passes on macOS
and in a `python:3.12-slim` container, and failed there before the fix.
