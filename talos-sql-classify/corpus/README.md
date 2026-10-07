# The SQL corpus

`statements.sql` is one SQL statement per line (made-up tables and values).
Each of the three gates a guest's SQL passes records its verdict for every
line:

| Snapshot | Gate | Test |
|---|---|---|
| `classify.snapshot` | `talos_sql_classify::classify` — read, write, or neither | `talos-sql-classify/tests/corpus.rs` |
| `worker.snapshot` | the worker's `validate_sql_with_policy`, under three allowlist configurations | `talos-worker-runtime/tests/sql_corpus.rs` |
| `controller.snapshot` | the controller's admission functions for `talos.database.query` | `talos-rpc-subscribers/src/sql_corpus_tests.rs` |

A test fails when a verdict differs from its snapshot, and prints each
difference. That is the point: the gates are built on `sqlparser`'s syntax
tree, and a new release can parse a statement it used to refuse, or parse one
differently — silently changing what a gate admits.

## When a snapshot test fails

A changed verdict is a decision, not noise. Read each one:

* **refused → admitted** must be argued for. Nothing here should start being
  admitted because the parser learned new syntax.
* **admitted → refused**, or one refusal reason for another, is usually fine;
  say why in the change.

Then record the new verdicts and commit the snapshots with the change:

```bash
SQL_CORPUS_BLESS=1 cargo test -p talos-sql-classify --test corpus
SQL_CORPUS_BLESS=1 cargo test -p talos-worker-runtime --test sql_corpus
SQL_CORPUS_BLESS=1 cargo test -p talos-rpc-subscribers --lib sql_corpus_tests
```

`git diff talos-sql-classify/corpus/` is then the review.

## What a re-recorded snapshot cannot hide

Beside each snapshot comparison is a test that asserts a rule per statement,
from the SQL text and not from the snapshot: with no operation granted the
worker admits nothing that names a write; an `INSERT`-only grant admits no
other write; what the controller calls a read carries no write and creates no
table. Re-recording a snapshot does not make those pass.

## Adding a statement

Add the line, re-record, and look at the three new verdicts. Add one whenever
a gate is found admitting something it should not — the corpus found such
statements the day it was written (2026-10-06,
`docs/engineering-log/packages/2026-10-06-sql-gates-carried-statements-and-select-into.md`).
