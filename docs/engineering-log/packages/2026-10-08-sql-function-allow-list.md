# One function allow list for caller SQL, and a parsed gate for `query_paginated` (2026-10-08)

Talos runs SQL that a caller writes in two places: module SQL (the `database`
capability world, checked by the worker's validator and again by the
controller's re-parse of `talos.database.query`) and the platform-admin MCP
tool `query_paginated`. This package changes what both may call and what
`query_paginated` may read. It follows
`2026-10-08-query-paginated-read-only.md` (the read-only transaction, #1201)
and `2026-10-08-sql-deny-list-text-search-evaluators.md` (#1202), whose
"deliberately not done" sections named it.

## Decided

* **One walk for "which functions does this statement call"**:
  `talos_sql_classify::try_for_each_called_function`, beside
  `try_for_each_carried_statement`. The worker (`check_disallowed_functions`)
  and the controller (`controller_side_denied_function`) each walked the
  parsed statement by hand. The walk reaches calls in any expression, a
  set-returning function in `FROM` (a table factor with arguments, and the
  function table factor), the table factors that are calls with no name in
  the tree (`XMLTABLE`, `UNNEST`, `JSON_TABLE`, reported as syntax), and calls
  held outside an expression (`CALL`, a pipe `CALL`,
  `INSERT INTO TABLE FUNCTION`). Every `TableFactor` variant is matched by
  name without a wildcard, so a sqlparser release that adds one does not
  compile until someone decides whether it is a call. A name with a part
  that is not an identifier is reported as unreadable and refused. Moving
  both gates onto it (commit 1) changed no corpus verdict: the three
  snapshots were not re-recorded and their tests passed.
* **The function policy is an allow list**:
  `talos_workflow_job_protocol::ALLOWED_SQL_FUNCTIONS`, asked through ONE
  matcher, `is_allowed_sql_function`, and ONE gate,
  `talos_sql_classify::first_function_not_admitted(stmt, admits)` (the
  classify crate stays a leaf by taking the matcher as an argument). The
  worker, the controller and `query_paginated` all ask exactly that. A
  function not on the list — including one nobody has reviewed — is refused,
  and the refusal names it as written.
* **What the matcher reads.** A bare name or a `pg_catalog.` name, without
  regard to case, whose function part is a plain identifier on the list.
  Refused: any other schema (`public.lower` is whatever a deployment put
  there), three or more parts, and a QUOTED part — `"LOWER"(x)` is a
  different function to Postgres, and `"lower"(x)` is refused too, which
  costs nothing.
* **The deny lists are a PIN, not the policy.** `DISALLOWED_SQL_FUNCTIONS`,
  `DISALLOWED_SQL_FUNCTION_PREFIXES` and `SQL_TEXT_EVALUATOR_FUNCTIONS` stay;
  no gate asks them. `allowed_sql_function_tests::nothing_the_deny_lists_cover_is_admitted`
  holds that no name they list (bare, upper-case, `pg_catalog.`-qualified),
  no member of the Postgres 17 advisory-lock / large-object families, and no
  allow-list entry starting with a deny prefix is admitted.
* **`query_paginated` gets a parsed gate**, in a new pure crate,
  `talos-admin-query-gate` (`validate_paginated_query`), which the handler
  calls; the handler holds no validation logic now. The gate: the Postgres
  dialect parses it; exactly one statement; a read
  (`talos_sql_classify::is_read_only`); every function admitted by the allow
  list; every relation bare or `public.`-qualified, not `pg_*`, and not on
  `BLOCKED_TABLES_LIST`. `BLOCKED_TABLES_LIST` (and its regex set and tests)
  moved into that crate and remains the one list of withheld tables; the
  MCP-1002 rationale comment moved with it. The relation walk is
  `talos_sql_classify::try_for_each_relation`.
* **The gate crate parses SQL itself**, under structural check 85 (c)'s
  sanctioned marker (`allow-new-sqlparser-dep`, with its reason in the
  manifest) rather than a change to the check: it parses and reads
  identifiers, and every classification — read or not, which functions,
  which relations — comes from `talos-sql-classify`, which is what the check
  asks.
* **The text rules stay in front of the parsed gate**, unchanged, with their
  messages (`text_rule_refusal`). Removing any is a later decision.
* **A fourth recorded gate.** `talos-sql-classify/corpus/query_paginated.snapshot`
  records both layers per statement (`T=` text rules, `P=` parsed gate on its
  own), so the snapshot itself shows which text rules the parsed gate makes
  redundant. Seventeen statements (made-up names) were added to the corpus for
  the relation rules.
* **`CLAUDE.md`** gained one rule line (added, none edited): which functions a
  statement calls is asked of `try_for_each_called_function`, never of a
  hand-written walk.

## How the allow list was chosen

By category, from the rule "changes nothing, reads no stored data beyond its
arguments and the rows of the statement, runs no SQL handed to it":
aggregates, window functions, string, numeric, date and time, type formatting
(`to_char`, `to_date`, `to_number`, `to_timestamp`), JSON and JSONB builders and
readers, arrays, ranges, conditionals and null handling, row construction,
UUID / randomness / hashing, text search that runs no query, and row
generators (`generate_series`, `generate_subscripts`, `unnest`). Built-in
functions only: no extension function (`pg_trgm`, `pgcrypto` and `vector` are
installed by the migrations; none is listed).

Seeded from what the repository uses. Every function the admitted reads in
`statements.sql` call is listed (`array`, `coalesce`, `count`,
`generate_series`, `greatest`, `jsonb_to_recordset`, `length`, `max`, `now`,
`nullif`, `row`, `row_number`, `sum`, `to_tsquery`, `to_tsvector`, `unnest`).
The two catalog templates in the `database` world (`database-query`,
`data-pipeline-etl`) carry no fixed SQL that calls a function: the first runs
the query its config names, the second issues one `INSERT`. No document in the
repository gives an example query that calls a function. How the operator
calls `query_paginated` on their own deployment was not measured (no access to
the live database from this session; #1201's record notes the statement
statistics had just been reset).

**268 names.** Checked on Postgres 17.11 from the image `scripts/test-integration.sh`
pins (a throwaway container), reading `pg_proc` / `pg_namespace`:

* 252 are functions in `pg_catalog`, with **543 overloads**; every overload is
  kind `a`, `f` or `w` (no procedure), none is `SECURITY DEFINER`, and **six
  are volatile**: `clock_timestamp`, `gen_random_uuid` and four `random`
  overloads. The 14 overloads written in SQL rather than C call only other
  built-ins (`age(ts)` → `age(current_date, ts)`, `log10(n)` → `log(10, n)`,
  `quote_literal(anyelement)` → `quote_literal(text)`, …).
* 16 are not functions at all but syntax sqlparser 0.63 reports as a call by
  name: `array` (`ARRAY(subquery)`), `row`, `coalesce`, `nullif`, `greatest`,
  `least`, `grouping`, `current_date`, `current_time`, `current_timestamp`,
  `localtime`, `localtimestamp`, `json_array`, `json_exists`, `json_query`,
  `json_value`.

Exceptions to "reads nothing outside the statement", stated in the list's
doc: the clock, randomness, and `age(xid)` (the transaction counter). The text
search functions look their configuration up by name, as a cast looks up its
type.

## How sqlparser 0.63 represents built-in syntax (measured)

Parsed with the Postgres dialect and walked:

* **Own node, fixed syntax, no entry needed:** `CAST` and `::`, `CASE`,
  `EXTRACT`, `SUBSTRING` (both the `FROM … FOR` and the comma form),
  `TRIM` (both forms), `POSITION`, `OVERLAY`, `CEIL`, `FLOOR`,
  `AT TIME ZONE`, `COLLATE`, `IS NORMALIZED`, `ARRAY[…]`, `INTERVAL '…'`,
  typed literals (`DATE '…'`), `EXISTS`, `IN (subquery)`, `ANY` / `ALL`,
  `LIKE` / `ILIKE` / `SIMILAR TO`, `IS DISTINCT FROM`, JSON operators.
  Pinned by `fixed_syntax_is_not_a_named_call`.
* **Parsed as an ordinary call by name, so listed:** `COALESCE`, `NULLIF`,
  `GREATEST`, `LEAST`, `GROUPING`, `ROW(…)`, `ARRAY(subquery)`, the clock
  keywords (`CURRENT_TIMESTAMP` etc., with no argument list), `NORMALIZE`,
  `CHAR_LENGTH` / `CHARACTER_LENGTH` / `OCTET_LENGTH`, `JSON_OBJECT`,
  `JSON_ARRAY`, `JSON_VALUE`, `JSON_QUERY`, `JSON_EXISTS`. `CURRENT_USER`,
  `SESSION_USER` and `USER` also parse as calls; they read the session and are
  not listed.
* `CURRENT_ROLE` and `CURRENT_SCHEMA` parse as plain identifiers, not calls,
  so no gate built on the walk sees them (a stated limit below).
* `UNNEST`, `XMLTABLE` and `JSON_TABLE` in `FROM` are table factors with no
  name; the walk reports them by the name Postgres uses. `unnest` is listed;
  the other two are not.
* **A parser disagreement that matters to the relation rule:** sqlparser
  reads `FROM ONLY t` as a table named `ONLY` aliased `t` (Postgres reads table
  `t`), and `FROM ONLY (t)` as a call to a function named `ONLY`. The relation
  check refuses an unquoted relation named `only`; the call is refused because
  it is not on the list.

## The per-deployment extension: deliberately left out

The brief allowed an environment variable of extra names, read through
`talos-config` on both the worker and the controller. Not built, because no
need exists: module SQL is not in use on the operator's deployment (#1202's
record), the repository's own uses are all built-ins, and the only caller of
`query_paginated` is the operator. It would also be a second place a function
is admitted without the per-overload review the list's doc asks for, and a
setting that two processes must agree on (a worker with a longer list than its
controller forwards calls the controller then refuses).

**An operator who needs their own function** adds its name to
`ALLOWED_SQL_FUNCTIONS` in a reviewed change (the function must meet the
list's rule for every overload), re-records the corpus snapshots, and rolls
the worker and the controller together. The function must be callable by its
bare name (or `pg_catalog.`): a schema-qualified call to the deployment's own
schema is refused by design, since the gate cannot see what that schema holds.

## Measured: verdict changes

Module SQL (both `worker.snapshot` and `controller.snapshot`, commit 2):
eight statements moved from admitted to refused, or changed refusal reason —
`current_user`, `current_setting('x')`, `nextval('s')`, `setval('s', 1)`,
`pg_stat_reset()`, `public.set_config(…)`, `a.b.set_config(…)` (all three
admitted before) and `"set_config"(…)` (refused before as `set_config`, now as
the quoted name). The worker's two `CALL p()` lines are now refused by the
function gate (the procedure is not listed) where the operation allowlist
refused them before; the controller refuses `CALL` outright and its lines did
not move. **Nothing moved from refused to admitted.** `classify.snapshot`
cannot move (it has no function rule).

Commit 3 added 17 statements; the three existing snapshots gained those lines
and nothing else.

`query_paginated` (465 statements):

* **59 admitted** by the tool (both layers `ok`).
* **102 pass the text rules and are refused by the parsed gate.** Before this
  package all 102 reached the database (since #1201 inside `BEGIN READ ONLY`,
  which stops a write but not a read or a server function). By reason: calls
  to functions the deny lists pin (`set_config`, `query_to_xml` and family,
  `ts_stat`, `ts_rewrite`, `crosstab`, `xmltable`, the advisory-lock and
  large-object families, `pg_sleep`, `pg_read_file`, `pg_terminate_backend`,
  `dblink`, …), `current_setting` / `current_user` / `nextval` / `setval` /
  `pg_stat_reset`, data-modifying subqueries and `SELECT … INTO` (not a read),
  relations outside `public` or named `pg_*`, `FROM ONLY t`, and six the
  parser cannot read (`ROWS FROM`, `FOR NO KEY UPDATE NOWAIT`, `EXCLUDE`, a
  pipe, `FETCH FIRST <expr>`, `JOIN LATERAL xmltable(…)`).
* **26 are refused by a text rule and admitted by the parsed gate alone**:
  set operations (4), statements not beginning `SELECT` — CTEs, `VALUES`,
  `(SELECT …) UNION …` (8), a comment (4), a `;` (10: a trailing `;`, `;` in a
  string, a dollar-quoted string, a quoted identifier or a comment).

## Which text rules the parsed gate makes redundant

* **Redundant as a safety rule:** begins-with-`SELECT` (the parsed gate admits
  only a read, and a `WITH` or `VALUES` read is a read), no
  `UNION`/`INTERSECT`/`EXCEPT` (each side's relations and calls are checked),
  no `WITH` and no `EXPLAIN` (both also unreachable behind the `SELECT` prefix
  rule, which was already true before this package), the system-schema
  substring rule (the relation rule refuses every schema but `public` and every
  `pg_*` name), and the withheld-table regex as far as relations go (it also
  refuses a column or string that happens to spell a withheld table's name,
  which the parsed gate does not).
* **Not redundant:** no `;` and no comments. These are where a lexer
  difference between sqlparser and Postgres would make the gate read a
  different statement from the one the server runs; the corpus's comment and
  string cases parse identically in both today (nested block comments, `E''`
  escapes, dollar quotes), and the two text rules keep that from being the
  only thing standing there. Note also that the repository wraps the query
  (`SELECT * FROM (<query>) AS _paginated_subquery …`), which the parsed gate
  does not see.

## Mutations

Each applied to the committed tree, the guarding suites run, the file
restored from a copy and its SHA-256 compared with the original (equal in all
13). Suites: the worker's `sql_validator` unit tests and its corpus test, the
controller crate's unit tests (which hold its corpus test), the
`talos-admin-query-gate` tests, the job-protocol allow-list tests and the
classify crate's tests, as relevant to each. `cargo test` stops a crate at its
first failing test binary, so a crate whose unit tests failed did not also run
its corpus test; the counts are a floor.

| mutation | caught by (failing tests) |
|---|---|
| allow list: `count` removed | worker + controller corpus snapshots, both crates' benign-function tests, two `query_paginated` gate tests (6) |
| matcher: check skipped (admits every name) | the pin test and the qualification test, 24 worker unit tests, both worker corpus rule tests and its snapshot, 8 controller tests and both its corpus tests, 3 gate tests (42) |
| matcher: any schema read as `pg_catalog` | the qualification test, the worker's and the controller's other-schema tests, the gate's function test (4) |
| matcher: no plain-identifier check (a quoted name read unquoted) | the qualification test, the worker's and the controller's quoted-name tests (3) |
| worker: function gate not called | 24 worker unit tests, both corpus rule tests and the snapshot (27) |
| controller: function gate returns `None` | 8 controller function tests, both corpus tests (10) |
| `query_paginated`: function gate not asked | 3 gate tests |
| `query_paginated`: relation check not asked | 4 gate tests |
| `query_paginated`: any schema admitted | 2 gate tests |
| `query_paginated`: `pg_` rule removed | `a_system_catalog_is_refused` |
| `query_paginated`: `BLOCKED_TABLES_LIST` not asked by the parsed gate | `a_blocked_table_is_refused_by_the_parsed_gate` |
| walk: a `FROM` call with arguments not reported | the walk's test, 4 worker tests and its snapshot, the controller's family test and snapshot, the gate's `ONLY` test (9) |
| walk: expression calls not reported | 3 walk tests, 22 worker tests and its snapshot, 8 controller tests and its snapshot, 2 gate tests (37) |

The pre-change behaviour is the first mutation's opposite: the corpus diff of
commit 2 is the list of statements the deny list admitted and the allow list
refuses.

## Run

In a cloud session (Linux), not on the operator's machine; no access to the
operator's live database, so nothing here was measured there.

* `cargo clippy --workspace --all-targets -- -D warnings`: clean.
* `make lint`: passes. Legs that did not run here: check 5 and 93 (no
  `helm`), 7 (clippy — run separately, above), 36 (networked audit), 72 (no
  personal-marker list; the diff was searched by hand), 88's database leg.
* `make test-unit` (nextest, every workspace lib and bin): 7476 run, 7476 passed, 2 skipped.
* The corpus tests of all four gates (`talos-sql-classify`,
  `talos-worker-runtime --test sql_corpus`, `talos-rpc-subscribers --lib`,
  `talos-admin-query-gate`), and the job-protocol allow-list tests: pass.
* Database tests that cover module SQL and `query_paginated`, on a throwaway
  Postgres from the pinned image (`scripts/dev-test-db.sh`, 362 migrations)
  and NATS from the image `scripts/test-integration.sh` pins:
  `controller --test rpc_write_ceiling_tests` (1 test, the database-query
  phases included), `talos-rpc-subscribers` `guest_session::db_tests` (5) and
  `talos-advanced-repository --test paginated_select_session` (4): all pass,
  none skipped. Containers removed afterwards.
* The allow list against Postgres 17.11 (above): a throwaway container,
  removed afterwards.

## Deploy note

The worker and the controller roll together. A worker built with this change
refuses calls the old controller would have run (harmless: refused earlier);
an old worker forwards calls the new controller refuses (the module sees the
controller's refusal). Module SQL is not in use on the operator's deployment,
so neither order breaks anything there today.

## Stated limits

* **The allow list is reviewed by people.** An entry is only as safe as that
  review; the list's doc states the rule and a test pins it against every name
  the deny lists record, but no test can show a listed function meets the rule.
* **Names, not overloads or resolution.** A parsed statement carries no
  argument types, so an entry admits every overload of its name (each was
  checked on Postgres 17.11; a future Postgres can add one). A bare name is
  resolved by the server on the session's `search_path`; `pg_catalog` is
  searched first unless the path names it later, which the gate does not see.
* **What the walk cannot see:** operators (Postgres implements each with a
  function the statement does not name, and a deployment can define its own),
  casts (a type's input and output functions run), the attribute notation
  Postgres accepts for a one-argument function, and the two session keywords
  sqlparser parses as identifiers (`CURRENT_ROLE`, `CURRENT_SCHEMA`). The
  read-only transaction and, for `query_paginated`, the role the statement
  runs as are what bound these.
* **The relation rule checks names.** An unqualified name resolves on the
  `search_path` (a schema named after the pool's role, if one existed, would
  come first); a view in `public` reads its tables as its owner; a CTE that
  shadows a table's name is checked as that name. Package B's role is the
  boundary for what a name resolves to.
* **No resource bound.** The list admits functions whose cost grows with their
  arguments (`repeat`, `generate_series`, regular expressions); the pool's
  statement timeout is the bound, as before.
* **`query_paginated` still runs as the pool's role** (a superuser on the
  operator's deployment). This package is the function gate the least-privilege
  role (Package B) depends on: the role is not a boundary while a statement can
  change the role setting, and the function that does so is now refused by an
  allow list rather than a deny list.

## Deliberately not done

* The per-deployment extension variable (above).
* Removing any text rule from `query_paginated`.
* The least-privilege role for `query_paginated` (Package B, after this merges).
* A second database login for the tool, and setting `TALOS_RPC_GUEST_ROLE` on
  the operator's deployment: deployment changes for the operator to decide.
* Any change to which statement kinds the gates admit (already an allow list).
