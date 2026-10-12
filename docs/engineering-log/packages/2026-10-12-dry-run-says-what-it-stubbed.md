# A dry run says what it stubbed (2026-10-12)

Under `test_workflow(dry_run: true)` a send node returned `sent: true` with
an empty `message_id`. Nothing in the node's output said the call had been
answered by a stub. It was impossible to tell from the output whether a test
had just messaged the owner.

## The class

A dry-run stub answers the MODULE with a success (a 200, an `Ok(())`), which
is the point: the module's own logic runs on. So the module reports success
in its own words, and the fact that the call never left the worker existed
only as an INFO log line on the worker.

## Decided

* **The worker counts each stubbed call**, by host surface, in a per-run
  `DryRunLedger`. All seven stub sites record: `http::fetch` and `fetch_all`
  (non-GET), `wasi:http` (mutating), `webhook::send`, both `messaging`
  publishes, and the agent `invoke` / `send`. A refused call is not a
  stubbed one.
* **The worker stamps the count on the module's output**, under
  `__dry_run__`: `{"stubbed_calls": n, "by_surface": {"http": 2, …}}`.
  * Set-or-REMOVE (`talos_worker_runtime::dry_run::stamp_output`). On a dry
    run it is written whatever the module returned under the key, zero
    included. On an ordinary run a module's own copy is removed, so a real
    send cannot be made to read as a rehearsal.
  * Zero is written, not omitted: a node that used a surface a dry run does
    NOT stub shows `stubbed_calls: 0`, which is the truth about it.
  * It rides inside the signed `output_payload`. No wire field, no signing
    change, and the all-default snapshot is untouched.
  * In the output because that is what survives into `get_node_output`,
    `get_execution_output` and the stored `output_data`.
* **One writer and one reader of the shape**, both in
  `talos-workflow-job-protocol` (`dry_run_report`, `read_dry_run_report`),
  with a round-trip test. The worker and the controller cannot drift on it.
* **`test_workflow(dry_run: true)` returns a `dry_run` block**:
  `nodes_with_stubbed_calls`, each module node's `stubbed_calls` /
  `by_surface`, and a `not_mocked` sentence.
* **`get_execution_status` carries the same block** for a run whose stored
  outputs have a report, in both modes. That is also how a stored run is
  told from a rehearsal: nothing else on the row records `dry_run`.

## What a dry run does not stub (stated, not changed)

`email::send`, `graphql::execute` (a mutation is a POST), `database`,
`object_storage::put`/`delete`, `files::write`/`delete` and `http_stream`
have no dry-run branch. Memory writes and LLM calls are real too. The tool
description and the `dry_run` block now say so. Whether those should be
stubbed is a separate decision: an email stub is clear, but a database write
that later reads its own row, or a GraphQL query sent as a POST, is not a
call a stub can answer truthfully.

## Stated limits

* A module output that is not a JSON object carries no report.
* A system node that passes a module's output through unchanged (an
  `action_links` node) carries that module's report as if its own.
* A pipeline chain has no `dry_run` on its wire and is not stamped. Every
  production entry point passes chains disabled.
* A trigger payload that carries its own `__dry_run__` key is not stripped;
  every module output downstream of it is stamped by the worker regardless.

## Tests

* `talos_worker_runtime::dry_run`: the stamp on a dry run, zero, a
  module-authored value replaced on a dry run and removed on an ordinary
  one, an ordinary output byte-identical, a non-object left alone.
* Host tests, on the production host functions: one `fetch`, three
  `fetch_all` entries of which one is refused, and a webhook send are counted
  1, 2 and 1 by surface; an ordinary run counts none; agent `invoke` and
  `send` count 2 and a refused one adds nothing.
* `talos-workflow-job-protocol`: what the worker writes is what the
  controller reads; another shape under the key (the stub response's own
  `true`) is not a report.
* `talos-workflow-validation` and the handler helper: a stubbed send is
  named, a node with nothing stubbed reads zero, a stored dry run is told
  from an ordinary run.

**Not tested:** a real WASM module run through `execute_job` under dry run.
The pieces on either side of that boundary are.
