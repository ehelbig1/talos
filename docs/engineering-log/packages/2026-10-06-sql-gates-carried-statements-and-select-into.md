# The SQL gates: what a statement carries, and `SELECT … INTO` (2026-10-06)

Found while preparing the `sqlparser` 0.53 → 0.63 bump, on the tree BEFORE
the bump. The plan was to record what the three SQL gates say about a corpus
of statements, bump, and review the differences. Recording it was enough: a
rule asserted per statement failed on the unchanged tree.

The three gates a guest's SQL passes: `talos_sql_classify::classify` (read,
write or neither — what the write ceiling is asked), the worker's
`validate_sql_with_policy` (admission and the operation allowlist), and the
controller's admission functions for `talos.database.query`.

## Measured

A corpus of 437 made-up statements (`talos-sql-classify/corpus/`), each
gate's verdict recorded per statement. On the tree before this change:

1. **The worker admitted 11 statements that carry an `INSERT` or `UPDATE`
   with NO operation granted** — the empty allowlist with mutations denied,
   which is the only configuration any dispatch site sends. Its check was a
   hand-written walk over CTE bodies and derived tables; the statements sat
   where it did not look: the body of the query a `WITH` introduces
   (`WITH a AS (…) UPDATE t SET … RETURNING a`, and the `INSERT` form), a
   subquery in `WHERE … IN`, in `EXISTS`, in the select list, in `ORDER BY`,
   in `LIMIT`, a derived table that is itself an `INSERT` or `UPDATE`, and a
   parenthesised `INSERT`.
2. **A grant of one operation admitted another**: under an `INSERT`-only
   grant, `INSERT INTO t (a) WITH upd AS (UPDATE u …) SELECT …` was admitted.
   The walk ran only when the ROOT was a query.
3. **`SELECT … INTO new_table` was a read to all three gates.** It creates a
   table. sqlparser parses it as an ordinary query with a field set on the
   `Select`, so nothing that matches on statement kind sees it: `classify`
   said read-only, the worker admitted it, and the controller's admission
   gate — which exists to refuse DDL — passed it as a read, past the write
   ceiling as well.

For (1) and (2) `classify` already said "mutates", so the write ceiling
refused them for a `readonly` actor. Nothing else did, and the worker's
allowlist is the rule that applies to every other actor.

### Which of these PostgreSQL actually runs

Measured through the real `talos.database.query` handler against a real
PostgreSQL (`controller/tests/rpc_write_ceiling_tests.rs`), not argued:

* `WITH src AS (…) UPDATE t SET … RETURNING a` **runs.** The worker labels
  it a query and sends it on the fetch path; the handler wraps it in a CTE,
  where PostgreSQL executes it. The test's row changes. So (1) was a real
  write through an honest worker, for a module granted nothing.
* `SELECT … INTO` **creates the table when sent with `is_fetch = false`**,
  and only then. On the fetch path the handler's CTE wrap makes PostgreSQL
  refuse `INTO`, and an honest worker fetches every query — so (3) was not
  reachable through one. `is_fetch` is the sender's word, though, and the
  controller's gates exist for a sender that holds the fleet key and is not
  honest. With the controller's refusal mutated away, the test's table is
  created.

Not run against a server: the other ten statements of (1). The expectation,
untested, is that PostgreSQL refuses most of them — the `INSERT` form with
`RETURNING` is a parse error in sqlparser 0.53 and without it the fetch wrap
has nothing to select from, and a data-modifying statement in a subquery or
as a derived table is outside PostgreSQL's documented grammar. They are
closed anyway: the gate should not depend on the server saying no.

**Latent on this fleet.** Three catalog modules are in a world that can
issue SQL; none has ever executed (`module_executions`, 2026-10-06).

## Changed

* `talos_sql_classify::try_for_each_carried_statement` — the walk the
  classifier was already built on, made public: every statement below the
  root that is not itself a query, in any position, through sqlparser's own
  derived visitor. The worker's allowlist now asks it, for every root, and
  puts each carried statement through the gates a root goes through (DDL,
  the always-blocked list, the unknown-kind refusal, the allowlist).
* The worker's hand-written walk is deleted (six functions). This is the
  third version of that check; the first two were lists of positions, each
  patched for the positions the last one missed.
* `talos_sql_classify::selects_into_table`. `classify` returns
  `Unclassified` for it; the worker refuses it as DDL (`SELECT INTO`); the
  controller's `controller_permits_data_statement` refuses it.
* The corpus, three snapshot tests, and beside each a rule asserted from the
  SQL text and not from the snapshot (`talos-sql-classify/corpus/README.md`).

Verdicts that changed, of 437: `classify` 5, the controller 5 (the
`SELECT … INTO` rows, now refused), the worker 19 — those 5, the 11 of (1),
the statement of (2), and 2 whose refusal reason changed (a carried write is
now reported before the root's).

`rpc_write_ceiling_tests` gains the two measurements above: the carried
`UPDATE` refused for a `readonly` actor and landing for a write-ceiling one,
and `SELECT … INTO` refused for both with no table in the catalog.

## Mutation proof

Nine mutations, each applied alone; a test fails on every one: `classify`
ignoring `SELECT … INTO`; `SELECT … INTO` unseen behind a set operation; the
carried walk reporting nothing; the carried walk reporting the root; the
worker never asking what is carried; the worker asking only when the root is
a query; a carried statement skipping the allowlist; the worker admitting
`SELECT … INTO`; the controller admitting it. The last was also run against
the handler-level test, which fails on it. Its first draft did NOT: it sent
`SELECT … INTO` on the fetch path, where PostgreSQL refuses it whatever the
gate does. That surviving mutation is what showed which path matters.

## Not done

* `SELECT nextval('s')` / `setval` are still reads to all three gates. A
  function with a side effect is invisible to a statement-shape classifier;
  that is the function deny-list's job and is stated in the classifier's
  crate docs.
* `SELECT … FOR UPDATE` stays a read, by the decision already recorded
  there.
* The controller has no operation allowlist: it admits a data statement and
  asks the write ceiling. Unchanged.
* The `sqlparser` bump itself. It is the next change, and the corpus is what
  it will be reviewed against.
