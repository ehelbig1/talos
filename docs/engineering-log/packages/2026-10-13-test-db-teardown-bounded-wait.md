# 2026-10-13 — a test database's teardown waits a bounded second, not a login timeout

**Context.** Every controller database test that drove the MCP
`create_workflow` handler took 60.5 s locally. The suspects were inside the
handler: an embedding or LLM call to an unreachable provider, a NATS request,
a name-collision search with a 60 s deadline.

**Measured — it is not the handler.** One test
(`create_workflow_node_controls_tests`,
`a_module_nodes_controls_are_stored_where_the_engine_reads_them`), a timer
round the handler call and connection logging on the scratch Postgres:

| | |
|---|---|
| `create_workflow`, call to response | 50 ms |
| the harness's `DROP DATABASE … WITH (FORCE)` | 59 965 ms |
| the test, as cargo reports it | 60.44 s |

The server's log names the wait. A connection to the test's database is
received 214 ms before the drop's own connection and never authenticates; the
drop logs `still waiting for backend with PID N to accept ProcSignalBarrier`
every 5 s for that PID; the PID ends with `canceling authentication due to
timeout` at 60.2 s and the drop returns 10 ms later.

So the reading the 2026-10-06 record (`2026-10-06-ci-test-jobs.md`) gave as
"not proven" is what happens:

1. `create_workflow` returns and leaves two background tasks on the pool
   (`spawn_workflow_post_create_tasks`: the workflow's embedding and its
   capability tags). They open pool connections of their own.
2. The test body ends. `TestDb::drop` ran the drop on another thread and
   JOINED it. That thread is the test's current-thread runtime, so nothing on
   it moves again: a connection one of those tasks was opening stops in the
   middle of its login.
3. `DROP DATABASE` needs every backend on the server to answer it. A backend
   waiting on its client's login answers when `authentication_timeout` ends
   it, and not before.

It was 60 s here and 5 s in CI because the scratch container on this machine
was created on 2026-09-12, before `scripts/dev-test-db.sh` started one with
`authentication_timeout=5s` (`SHOW authentication_timeout` → `1min`, source
`default`). In CI the same binary's weight is 6 s for a body of about one.

**Also measured: one stopped login holds up every drop on the server.** The
new regression binary has two tests. On the unfixed harness the one that
stops a login took 60.02 s to drop its database — and so did the other, which
stops nothing and drops a different database. That is the 2026-10-06
observation of "two to four of them at once".

**Decided.** `TestDb::drop` (`controller/tests/common/mod.rs`) waits for its
drop for at most `TEST_DB_DROP_WAIT` (1 s) and then returns. Returning is what
ends the wait: the test function returns, its runtime is dropped, the task and
its socket go, the backend exits, and the drop finishes on its own thread. An
unobstructed drop takes about 50 ms (the statement 16 ms, measured three
times; a login about 30), so the ordinary teardown still has removed the
database when it returns.

This is a harness defect, not a production one. Nothing in production drops a
database from inside a runtime, and the handler answered in 50 ms with its
two tasks detached.

**Measured after.**

| | before | after |
|---|---|---|
| `create_workflow_node_controls_tests`, the binary | 60.5 s | 1.48 s |
| the regression test's teardown with a login stopped | 60.02 s | under 3 s (asserted) |
| clones left on the server after the processes exit | 0 | 0 |

Every controller database binary (156 `ctrl` and `ctrl-serial` targets of
`scripts/ci_test_targets.py`, one `cargo test --no-fail-fast` against the
scratch database, 2026-10-13):

* no test ran for 60 s; the binaries' own times sum to 250 s;
* 24 teardowns reached the one-second wait. Their drops took 1.00–1.83 s
  (median 1.02) on the server: each finished as soon as its test's runtime
  was gone;
* the server logged no `still waiting for backend` (it logs at 5 s) and no
  `canceling authentication due to timeout`;
* 0 clones were left.

152 of the 156 passed. The four that failed fail the same way, test for test,
on the unfixed harness, and none is about teardown — they are this machine:
`statement_stats_tests` (11 tests: the scratch container predates
`shared_preload_libraries=pg_stat_statements` too), `rpc_instrument_tests`
and `rpc_write_ceiling_tests` (one each: the developer `.env` names the
stack's NATS, which refuses the test's login), `ml_reembed_tests` (three: the
`.env` names a live embedding provider). CI gives each its own service.

**Tests.** `controller/tests/test_db_teardown_tests.rs`. The login is stopped
by hand (a startup packet, then silence), held by a task of the test's own
runtime, so nothing depends on a race: the teardown returns inside 3 s — it
took 60.02 s on the unfixed harness, and would take 5 s on CI's server — and
once the runtime has gone the database is gone too. A second test holds that
an ordinary teardown has removed the database by the time it returns. The two
take a lock: run together, the first would slow the second's drop.

**Deliberately NOT done.**

* **A shorter wait.** Every test that leaves such a task now costs the wait,
  so a quarter of a second would give most of it back. But a teardown that
  stops waiting before its statement has reached the server can lose the drop
  if the process then ends, and one second is twenty times an unobstructed
  drop. Not measured: how long a drop takes on a loaded CI runner.
* **Stopping the tasks, or closing the pool, before the drop.** Both need the
  runtime to run, and `Drop` cannot let it: that is the defect.
* **Bringing an older scratch container to 5 s** (`ALTER SYSTEM` from
  `dev-test-db.sh up`). With the bounded wait the setting no longer decides
  how long any test takes. The 5 s on the servers this repository starts
  stays: it is now the bound on a drop nothing is waiting for.
* **Changing `create_workflow`.** Its two post-create tasks are what a test
  database's teardown met; they are not slow, and a harness has to survive a
  handler that spawns.

**Stated limits.**

* A test that leaves a task opening a connection takes about a second longer
  than its body. That is the wait, not a timeout in the code under test.
* If the test process ends while a drop it stopped waiting for is still in
  flight, the server finishes the statement (seen: 0 clones left, including
  after the single-test run whose last act was such a drop). A drop whose
  connection had not been made yet would be lost; `scripts/dev-test-db.sh
  status` counts such clones and `rebuild` removes them. The comment that
  said they were "swept on the next run" was wrong — nothing sweeps them —
  and is corrected.
* Seen in passing, not measured and not changed: `create_workflow` asks the
  LLM for config suggestions inline when `include_config_suggestions` is true
  (the default), a client is configured and a node is missing config. That
  wait is the LLM client's own timeout. It played no part here — the harness
  has no LLM client and the tests pass `false`.

**One home.** `common::TEST_DB_DROP_WAIT` and the `Drop for TestDb` beside it.
