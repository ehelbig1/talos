# `query_paginated` runs read-only, on a connection of its own (2026-10-08)

`query_paginated` is the platform-admin MCP tool that runs SQL the caller
writes. Whether that SQL is a read was decided by rules over its text (begins
with `SELECT`, no `;`, no comments, deny lists), and it then ran in autocommit
on a connection borrowed from the controller's main pool, as the role that pool
connects as — a superuser on this deployment. The `sqlx` 0.9 record
(`2026-10-07-sqlx-0.9.md`) listed that as a stated limit. This closes the part
of it the database can enforce by itself.

## Measured before the change

A throwaway Postgres from the pinned image, superuser, each statement wrapped
exactly as the repository wraps it (`SELECT * FROM (<query>) AS
_paginated_subquery LIMIT … OFFSET …`). Every statement below begins with
`SELECT` and, by reading the handler's rules, is admitted by them.

| what the SELECT does | autocommit (before) | `BEGIN READ ONLY` |
|---|---|---|
| calls a function that inserts a row | row written | refused |
| `nextval` / `setval` on a sequence | sequence moved | refused |
| creates a large object | created | refused |
| `SELECT … FOR UPDATE` | rows locked | refused |
| sets `transaction_read_only` off, then `nextval`, in one statement | sequence moved | refused ("must be set before any query") |
| changes a session setting (`set_config(…, false)`) | changed | changed |
| takes a session-level advisory lock | taken | taken |
| resets statistics, signals another backend, reloads configuration | done | done |
| reads a server file or a system catalog | read | read |
| writes a WAL message, sends a `NOTIFY` | done | done |

So a read-only transaction stops every change to stored data that was tried,
and nothing else. Two rows matter for the pool: a session setting and an
advisory lock made by a SELECT stayed on the connection, and that connection
went back to the pool for the next request to borrow. A session setting is
undone by a rollback; a session-level advisory lock is not.

The live database (read-only): the pool's role is a superuser; the `public`
schema has 214 functions, 48 of them volatile.

## Changed

`AdvancedRepository::execute_paginated_select` (the one place this SQL runs):

* **`BEGIN READ ONLY`** before the caller's statement. Postgres refuses a
  write with SQLSTATE 25006.
* **The connection is closed, never returned to the pool.** It is marked
  close-on-drop as soon as it is acquired, before the first statement, so a
  request dropped mid-statement cannot hand back a connection that is inside
  an open transaction with a statement still running. Closing ends every kind
  of session state without listing the kinds. It still counts against the
  pool's `max_connections` while open, and it keeps the pool's connect-time
  settings (the 60 s statement timeout).
* **The handler says what happened.** A refusal for writing used to come back
  as "Ensure the SQL syntax is valid"; `is_read_only_refusal` now maps 25006
  to a message that says the query tried to change something (`-32602`).
* The tool's description said it required "admin capability ('*' or 'admin')".
  It has required platform admin since MCP-323; the description now says so,
  and says the query runs read-only.

## Cost

Per call, one connection each, loopback, release build, 3 × 300 calls of a
200-row select: median 0.50 ms before, 3.7 ms after (p95 0.57 → 4.4). The
3.2 ms is the pool opening a replacement connection. How often the tool is
called on this deployment was not measured: the statement statistics
restarted today.

## Tests

`talos-advanced-repository/tests/paginated_select_session.rs` (store
`selfcontained`), through the real repository method:

* a function that inserts, `nextval`, `setval`, `FOR UPDATE` and the
  switch-to-read-write attempt are each refused, and afterwards the table has
  its five rows and the sequence has never been called;
* an ordinary select still pages, in offset and cursor mode;
* with a pool of ONE connection: after a select that sets a session setting
  and takes an advisory lock, the lock is held by no backend and the pool's
  next statement runs on a different backend;
* a call abandoned mid-statement: the pool's next statement runs on a
  different backend, outside any transaction.

Mutations (each restored, the tree's hash compared):

| mutation | result |
|---|---|
| `BEGIN` without `READ ONLY` | the refusal test fails |
| no close-on-drop (close only at the end) | the abandoned-call test fails |
| `ROLLBACK`, then hand the connection back | the session test fails on the advisory lock; the abandoned-call test fails |
| the behaviour before this change | three of the four fail |

## Stated limits

* **This does not limit what the SQL may read or which server functions it
  may call.** The table and schema deny lists read the statement's text, and
  the statement runs as the pool's role. The last four rows of the table above
  are unchanged by this package: on a deployment whose pool connects as a
  superuser, a platform admin's SELECT can still reset statistics, signal
  other backends, read server files and read system catalogs. A statement can
  also reach a table without its text containing the table's name.
* The transaction is not a security boundary against the role itself: it is
  what stops a statement that was meant to be a read from writing.
* The statement can still run for the pool's statement timeout and return a
  page of rows of any width, as before.

## Deliberately not done

* **Running the statement as a lesser role with `SET LOCAL ROLE`, in this
  package.** Measured afterwards on a throwaway Postgres: inside a read-only
  transaction, a role with SELECT on one table was refused an ungranted
  table (directly and through functions that run SQL they are handed), the
  server's files, the role catalog, the statistics reset and the
  configuration reload, each by Postgres's own privilege check. The role is
  not a boundary alone: a statement can change the role setting from inside
  itself. The function that does so is on the parsed deny list the module
  SQL path already uses (`talos_workflow_job_protocol::
  is_disallowed_sql_function`), and `query_paginated` does not yet parse its
  statement. So the two belong together and follow this package: the parsed
  gate first, then the role behind it.
* **An allow list of functions, in this package.** It is the better rule
  than the deny list (a function nobody has read about is refused, not
  admitted), and it belongs to the parsed gate that follows, as the ONE
  function policy for this tool and for module SQL, not a second one.
* Rolling back and returning the connection: a rollback does not release a
  session-level advisory lock (measured), and listing what to undo is the
  weaker design at 3 ms a call on an operator's tool.
