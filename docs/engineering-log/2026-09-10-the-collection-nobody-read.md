# The collection nobody read — `pg_stat_statements` gets a reader (2026-09-10)

Narrative for the CLAUDE.md digest section "The database was the last
unmeasured layer".

## What #786 shipped, and what it did not

`#786` added `shared_preload_libraries=pg_stat_statements` to
`docker-compose.yml` and the guarded migration
`20260908120000_pg_stat_statements_when_preloaded.sql`, whose own header ends
*"Nothing in the application reads this extension. It is an operator
instrument."* Because `shared_preload_libraries` is a POSTMASTER GUC, the
preload took effect only when Postgres next restarted — **2026-09-10 02:14
UTC**. From that minute every statement this platform issues has been timed by
the server and read by nothing.

The measurement that says the reader is worth having is not an argument, it is
the first fifteen minutes of that window:

```
calls | mean_ms | statement
   36 |   0.136 | SELECT MAX(started_at) FROM workflow_executions WHERE workflow_id = $1
   36 |   0.284 | SELECT (COUNT(*) FILTER (WHERE status = $2))::float / NULLIF(...) FROM workflow_executions ...
   36 |   0.780 | UPDATE workflows SET readiness_score = $1, readiness_computed_at = NOW() WHERE id = $2
```

36 is the number of workflows on this fleet, and CLAUDE.md already records
*"a loop already issuing THREE queries per workflow (108 for the 36-workflow
fleet)"*. So the instrument independently reproduced a documented N+1 from the
outside, with no code read — which is what this file records having found BY
HAND twice.

## Every premise of the brief was wrong in a way that changed the design

The brief's constraint was: *"`pg_stat_statements` normalises BIND PARAMETERS
to `$1`, but it does NOT normalise literals that were embedded in the SQL text,
and the sandbox path runs caller-authored SQL — so `talos_guest` statements are
tenant data."*

**The role half is false.** The view holds two `userid`s — `talos` (oid 10,
SUPERUSER, the controller's own connection) and `talos_app` (the RLS
`SET LOCAL ROLE` scope). `talos_guest` has **zero rows**, and not because no
sandbox SQL ran: `guest_role_for_query` gates the `SET LOCAL ROLE` on
`TALOS_RPC_GUEST_ROLE`, that variable is UNSET on this deployment, and
`enforce_production_db_sandbox_posture` forces it only in production. So on a
default deployment guest SQL runs as the APP USER and is **indistinguishable in
this view from the controller's own statements**. "Exclude `talos_guest`" would
have been a control that does not exist.

**The normalisation half is backwards.** Measured directly in a scratch
database:

```sql
SELECT * FROM t_secret WHERE email = 'alice@example.com';
SELECT * FROM t_secret WHERE email = 'bob@example.com';
```
became ONE entry, `SELECT * FROM t_secret WHERE email = $1`, with `calls = 2`.
Jumbling replaces `Const` nodes and does not care how the constant reached the
parser, so a literal embedded in the SQL text is normalised exactly like a bind
parameter. The sandbox's own CTE wrap normalises completely, down to the
interpolated `LIMIT 101` becoming `LIMIT $3`.

**What it does NOT normalise is where the risk actually is**, and each was
measured rather than reasoned:

```
1|SELECT $1 AS "exfil-via-alias: card 4111-1111-1111-1111"
1|SELECT $1 /* comment-channel: secret-in-comment */
1|CREATE TABLE IF NOT EXISTS "tenant_9f8e_pii"(x int)
1|SET LOCAL app.probe_marker = 'utility-verbatim-ABC123'
```

Identifiers — above all column ALIASES — comments, and utility statements
(`track_utility` defaults ON) are stored verbatim. A column alias is arbitrary
caller-chosen text, and two `database-node` modules exist on this fleet. So
query text in this view is, in the general case, **arbitrary caller-authorable
bytes**.

**And a live instance of tenant data was already in it, from a path with
nothing to do with the sandbox:**

```
talos_app|11|SET LOCAL app.current_user_id = '00000000-0000-0000-0000-000000000000'
```

`SET LOCAL` cannot bind parameters, so
`talos_tenancy::TenantReadScope::set_local_user_sql` formats the UUID into the
statement text. The choice is correct for injection safety — the value is a
`Uuid`, so there is no injectable text, and its doc comment says exactly that —
and the consequence is that every distinct acting user mints its own entry
carrying that user's id.

**A fourth state nobody had named: Postgres redacts the text itself.**

```
BEGIN; SET LOCAL ROLE talos_app;
SELECT count(*) FILTER (WHERE query='<insufficient privilege>'), count(*) FROM pg_stat_statements;
 redacted | total
      239 |   252
```

A non-superuser without `pg_read_all_stats` reads the literal string
`<insufficient privilege>` in the `query` column for every statement it did not
issue. The migration's own header names a managed-Postgres non-superuser
migration role as the common case, so this is the ordinary posture and not an
exotic one. A reader that renders that column blind reports 239 statements
whose text is a Postgres error marker.

**A statement that fails PARSE ANALYSIS is not recorded at all**
(`SELECT * FROM no_such_table_xyz` produced no entry), which is worth knowing
before anyone reads an absence as evidence.

## The five availability states, four of them reproduced on a real server

| state | SQLSTATE / mechanism | how it was reproduced |
|---|---|---|
| `not_installed` | none — read from `pg_extension` | `DROP EXTENSION` in an isolated test clone |
| `not_loaded` | `55000` | a throwaway `pgvector/pgvector:pg17` container with no preload: `CREATE EXTENSION` SUCCEEDS and the first read raises `55000: pg_stat_statements must be loaded via "shared_preload_libraries"` |
| `unreadable{catalog_unreadable}` | connection failure | a lazily-built pool pointed at a dead host |
| `unreadable{view_missing}` / `{denied}` | `42P01` / `42501` | unit-tested on the SQLSTATE; NOT reproduced live |
| `available` (rows / none) | — | DB test |

The extension's PRESENCE is established from `pg_extension` — a catalog that
always exists — rather than by classifying a `42P01`, so "not installed" is a
positive finding and not an error classification.

And a sixth fact the classification has to carry: `pg_stat_statements_info` is
**1.9+ (PG 14)**, so a server below that cannot say whether entries were
evicted. `entries_evicted: None` means "nothing can tell you", which is not the
claim `0` makes. This was reproduced rather than simulated — PG 17 still ships
the 1.8 script, so `CREATE EXTENSION pg_stat_statements VERSION '1.8'` is a
real pre-`_info` install, and the DB test drives one.

## Cost, measured rather than assumed

`pg_stat_statements.track` is a `superuser`-context GUC, so it can be toggled
per session with no restart. A/B with `pgbench -S` (select-only, the
overhead-dominated worst case) against a scratch database, six interleaved reps
of 8 s, single client:

```
none: 19872 19865 20293 19219 19217 19101   median 19542 tps
all : 19685 19739 20287 18686 26843 18909   median 19712 tps
```

**Not distinguishable from noise** at ~51 µs/txn. A 4-client run gave
none 23875 / all 22666 on the mean (−5.1 %) with one rep in the opposite
direction, so the noise band on this machine is wider than the effect.

Against the fleet's actual rate that is irrelevant: **1450 calls in 12.5
minutes = 1.9 statements/second**. Even a pessimistic 5 µs/statement is 9.5 µs
of CPU per second.

Memory and disk are bounded and small: 2 896 + 64 bytes of NAMED shared memory
plus a hash sized for `pg_stat_statements.max = 5000` at postmaster start, and
39 523 bytes of `pgss_query_texts.stat` on disk for 211 entries (~187 B/entry,
garbage-collected, capped).

Reading the view costs **0.15–0.20 ms warm at 259 entries** (`EXPLAIN ANALYZE`,
indistinguishable with and without the `query` column), so ~3–4 ms at the cap.

## What was built, and the two things that were not

A read-only MCP tool, `get_sql_statement_report`. **No metric, no alert, no
Helm change, and no `pg_stat_statements_reset()`.**

The metric rejection is not about cost — the scan is cheap enough for a 15 s
scrape. It is about the LABEL. The only actionable content of this view is
PER-STATEMENT, and per-statement identity cannot be a Prometheus label:
`query` is unbounded caller-authorable text (check 58's DoS rule and #787's
closed-compile-time-set rule) and `queryid` is an unbounded int. Every
aggregate that IS expressible with a closed label set — total calls, total exec
time, entries tracked, `dealloc` — is either not actionable or duplicates the
tool, and nothing would alert on any of them: `dealloc` is the one real "the
instrument stopped measuring" signal and it is **0** here, so a threshold would
be a guess. And on most deployments the series would be permanently 0 because
the extension is absent by design, which is the absent-vs-zero defect this
package exists to remove.

## The tenancy decision

`pg_stat_statements` has **no tenancy dimension at all** — its `userid` is a
Postgres ROLE, not a Talos user — so there is no correct per-tenant slice of
it, of the text OR of the aggregates. Four measured facts, and "the operator is
the only user on this fleet" is not among them:

1. Query text is caller-authorable (the alias and comment channels above).
2. Other tenants' identifiers are already in it (`SET LOCAL app.current_user_id`).
3. Sandbox SQL is not separable on a default deployment (the guest fence is off).
4. Even the AGGREGATES are deployment-wide: the entry COUNT discloses how many
   distinct users a deployment has, because each mints its own
   `SET LOCAL app.current_user_id` entry.

So the tool is gated on `users.is_platform_admin`, and a non-admin is REFUSED
rather than given a narrowed answer — there is no honest narrowed answer to
give. `handle_query_paginated` is the precedent, gated on the same flag for the
same stated reason ("arbitrary SELECT spans all tenants"). A platform admin can
already read every tenant row, so the text discloses nothing new to them.

The text is SANITISED even for that admin, and not for confidentiality: a
`database`-world module must not be able to plant an ANSI escape, a
right-to-left override or a forged line break in an operator's console. That is
pinned END TO END by a DB test that plants a real escape in a real column alias
and reads it back through the real report.

Deliberately NOT `talos_validation::reject_control_chars`: that function
REJECTS an input the platform is about to store, this one SANITISES a value
already on disk that cannot be rejected. Different question, so a separate
implementation rather than a second answer to one question.

## The side effect this work had on the instrument it was measuring

`pg_stat_statements` is CLUSTER-wide with a shared 5 000-entry cap, and an
entry OUTLIVES the database that minted it. The controller DB harness gives
every test its own `CREATE DATABASE … TEMPLATE` clone, so every test run mints
a fresh set of entries under a fresh `dbid` and leaves them behind. Measured on
the live cluster after this session's runs:

```
 cluster_entries | headroom | entries_for_dropped_databases
            3462 |     1538 |                          2552  (73.7 %)
 dealloc: 0
```

`dealloc` is still 0, so nothing the operator cares about has been evicted —
but the headroom is 1 538 and most of what filled it is this session's. That
measurement is why `coverage.entries_for_dropped_databases` exists in the
report; it was added AFTER it, not before. `pg_stat_statements_reset()` was NOT
called: it is shared operator state and it would destroy the 421 real `talos`
entries as well.

## The harness bug that produced a false mutation result

`shutil.copy` does not preserve mtime, so a reverted file came back OLDER than
the mutated build's fingerprint and **cargo reused the MUTATED artifact** — the
M2 failures reappeared verbatim under the M3 run and would have been read as
"M3 broke the crate's unit tests". `os.utime` after the restore fixes it, and a
BASELINE probe (a comment-only edit, which must be green) now runs first every
time. The project's own rule — print the diff and confirm the mutation landed —
needs a second clause: confirm the REVERT landed too.

## Two mutations that were not what they looked like

**M12 SURVIVED.** `classify_view_error`'s SQLSTATE arms are the one place a
DEPLOYMENT FACT is asserted from an error, and nothing drove them: the DB suite
runs on a cluster that HAS the preload, so it cannot produce `55000` at all,
and the unit tests constructed `NotLoaded` directly. `55000 => NotInstalled` —
telling an operator they never installed an extension they have, instead of
telling them to restart — passed every unit test, every DB test and the whole
lint. Closed with a test-only `sqlx::error::DatabaseError` stub, since
`PgDatabaseError` has no public constructor.

**M14 was a NO-OP before it was a catch, and this is the sharper lesson.** The
mutation added a message-based shortcut ahead of the SQLSTATE match. It passed
— but not because anything guarded it: the stub's `Display` rendered
`"stub database error 42P01"`, so the shortcut never fired and the mutation was
inert. **A stub that does not render like the thing it stands in for makes
every assertion against it prove less than it appears to.** The stub now
renders its MESSAGE the way a real `PgDatabaseError` does, every stub carries
the not-loaded message text, and the same mutation is now caught — which is
what makes "decide from the SQLSTATE, never from the text" an actual test
rather than a comment.

**And a process trap worth carrying**: `until ! pgrep -f "/tmp/m3.sh"; do
sleep; done` never terminates, because `pgrep -f` MATCHES THE WAITER'S OWN
COMMAND LINE. Eight waiter processes deadlocked on themselves and the batch
they were waiting to launch never started. Killed by explicit PID only — never
`pkill -f`, which is how a previous session killed a sibling's lint run.

## The first thing the new instrument measured was the repo's own lint

`TALOS_LINT_CLIPPY=1 TALOS_LINT_SQL_PREPARE=1 make lint` ran green. The
`pg_stat_statements` snapshot either side of it did not:

```
before: 4640 entries, dealloc 0, 438 for the `talos` database
after : 4392 entries, dealloc 1, 429 for the `talos` database
```

Check 88 emits, per statement, `PREPARE sN AS <sql>;` and `DEALLOCATE sN;`.
Both are UTILITY statements and both carry a UNIQUE NAME, so neither
normalises — at the 951 statements it scans that is ~1900 entries per run
against a default `pg_stat_statements.max = 5000`.

The attribution matters and is stated precisely rather than dramatically: the
cap pressure was ~74 % this session's own per-test database clones (3428
entries whose database no longer exists), so on a clean instrument
438 + 1900 = ~2340 would not have evicted anything. The CHURN is
unconditional; the EVICTION was the combination. Nobody could have seen this
before today — the preload is twelve hours old and nothing read the view.

The fix is one line at the head of the psql script,
`SET pg_stat_statements.track_utility = off;`, and it was measured rather than
asserted: a full check-88 run now adds **2** entries (the two queries that
measured it), leaves `dealloc` unchanged, leaves ZERO `prepare s%` /
`deallocate s%` entries behind, and still reports
`scanned 951 static statement(s) … ✓`.

The servers where that SET is REFUSED were reproduced rather than reasoned
about. `pg_stat_statements.track_utility` is a `superuser`-context GUC, so a
non-superuser lint role gets `42501` and a server without the extension gets
`42704 unrecognized configuration parameter`. Pointing the SET at a GUC that
does not exist and re-running the script gives its normal counts and exit 0 —
two things make that safe: psql runs with `ON_ERROR_STOP=0`, and the
attribution loop ignores every `ERROR:` line that arrives before the first
`@@@` marker, because `cur` is still `None`.

## The first CI run failed, and the defect was the validation, not the code

**10 of 12 `statement_stats_tests` failed in CI on #793's first run, every one
reading `reason: "not_installed"`, while `main` was green at the same base.**
The suite had been validated against a scratch database on the COMPOSE Postgres,
which preloads `pg_stat_statements`. CI's integration job does not use that
cluster: `scripts/test-integration.sh` starts its OWN throwaway
`pgvector/pgvector:pg17`, and that `docker run` passed no preload. So migration
`20260908120000` no-oped exactly as designed, the `talos_ctl` template carried
no extension, and every per-test clone could only answer `not_installed`. This
file's header had already said *"this suite runs against a cluster that has the
preload"* — true of the cluster it was validated on, false of the one that gates.

Two changes. The harness now starts Postgres with
`-c shared_preload_libraries=pg_stat_statements` — parity with
`docker-compose.yml`, the only place a POSTMASTER GUC can be set. And a
precondition test, `the_suite_runs_on_a_cluster_that_preloads_the_library`,
asserts the setting directly, so the next environment that lacks it fails ONCE
with the cause named instead of as ten assertions about a report. The tests were
deliberately NOT made to skip without the preload: a green run over zero
assertions is worse than an honest red (check 64's `embedding_determinism` rule).

The first edit of that `docker run` put the explanatory `#` lines INSIDE the `\`
continuation. `bash -n` accepted it, and bash would have ended the command at the
first `#` and run `-p … -c …` as a separate command. The comment now sits above
the command and says why.

**Verified with the real harness, not a retyped copy**: `test-integration.sh`
has no filter flag, so a scratch copy stubbed `cargo` to run only this binary
and changed nothing else. Against `HEAD`'s harness it reproduced CI's failures;
against the fixed harness it passed. The method is the durable part.
