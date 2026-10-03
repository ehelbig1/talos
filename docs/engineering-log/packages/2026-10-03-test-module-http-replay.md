# `test_module` can answer a module's HTTP requests from recorded responses

2026-10-03

## What was wrong

A module that reads a third-party API could only be exercised by calling that
API. Three costs, all met while building the bank-reading modules on
2026-10-03:

* Fuel could not be measured before the first live call. The module was
  budgeted from the "about 11 fuel per byte" guidance at ~16 K per
  transaction; the first live read cost 110–127 K per transaction, and the
  design (paging to 5,000 rows) had to be redone.
* A module could not be run at all until the service was connected and its
  secret stored: `test_module` refuses an unresolvable `vault://` reference.
* Error handling (a 429, a 500, a truncated page) could not be exercised
  without the provider producing one.

## What changed

`test_module` takes `http_fixtures`, an ordered list of recorded responses
(`{method?, url_contains?, status?, headers?, body?}`). When given, the run is
a rehearsal:

* `http::fetch` and each `fetch_all` entry are answered by the next recording.
  Nothing is sent; no DNS lookup, no circuit breaker, no secret resolution.
* The gates that decide whether the request MAY be made run first and
  unchanged: capability world, URL admission (allowed hosts, tier-1 and
  egress rules, private addresses), write ceiling, rate limits, cancellation,
  and the method allowlist. The method check has one home,
  `refuse_undeclared_method`, used by the live path and the rehearsal.
* A request the next recording does not expect is refused and the recording
  is kept; a request after the last recording is refused. The module receives
  `networkerror`, the reason is a host diagnostic, and no network reason class
  is latched (a missing recording is not a transient failure).
* webhook, GraphQL, SSE and `wasi:http` calls are refused in a rehearsal
  (`TalosContext::rehearsal_refuses`), so "nothing is sent" holds for every
  HTTP surface and not only the two that are replayed.
* The run is not retried in-process (`RetryPolicy::controller_dispatched()`):
  recordings are consumed in order, so a second attempt would run against
  what was left.
* `vault://` references are not checked for a rehearsal.
* The reply carries `http_replay`: each request (method, host, path, request
  size — no query string, no body), the recording that answered it or why it
  was refused, and how many recordings were unused.

One home: `talos_worker_runtime::http_replay` (`HttpFixture`, `HttpReplay`).
Limits: 64 recordings, 8 MiB of bodies in total, each body within
`WASM_HTTP_MAX_RESPONSE_BYTES` (a larger one could never have arrived).

The fuel guidance (`FUEL_PER_BYTE_GUIDANCE`, the `compute_max_fuel_with_rates`
doc, `docs/fuel-budget-sizing.md`) now states the 2026-10-03 measurements and
points at the rehearsal as the way to measure.

## Decisions

* **Controller-side only.** `SecurityPolicy::http_replay` is not on the wire.
  Both policies the worker builds are full struct literals that state
  `http_replay: None`; `worker/src/rehearsal_pin.rs` pins that. A dispatched
  job that received canned answers would report success over data nobody
  fetched.
* **Sequential, with optional expectations**, not a URL-keyed table. Order is
  what a paging module depends on, and a mismatch is a refusal — a module is
  never handed the response recorded for another endpoint.
* **Grants still apply.** A rehearsal that skipped the host or verb gate would
  pass for a module that fails on its first real run.
* **No new `reason_class` value.** The closed set drives retry decisions; a
  rehearsal miss says so in a host diagnostic instead.
* **Not replayed:** webhook, GraphQL, SSE, `wasi:http` (refused); LLM, email,
  object storage, messaging, memory (unchanged — a rehearsal is about the
  module's own HTTP requests).

## Measured

* Bank transaction records, ~2 KB and several dozen fields each, typed structs
  with most fields skipped: 110–127 K fuel per record (60 K per item plus
  about 30 per byte).
* A combining module over number-heavy JSON: about 210 fuel per byte of input.
* Both are above what the earlier guidance (11 per byte for fetch plus typed
  parse, measured on mail bodies) predicts, because parse cost follows token
  count.

## Stated limits

* A rehearsal proves the module against the responses it was given. It does
  not prove the request the module builds is one the provider accepts; the
  request body is not compared with anything.
* The `wasi:http` refusal is logged, not written as a host diagnostic (that
  path is synchronous).
* The handler wiring in `handle_test_module` (retry policy choice, skipping
  the vault-reference check) is covered by the parse/render unit tests and the
  runtime tests, not by a test that drives the handler end to end.

## Tests

`talos-worker-runtime`: `http_replay::tests` (order, mismatch keeps the
recording, limits, no query string in the record); host tests in
`host/http.rs` — answered with no network (control: the same request without a
rehearsal needs DNS), refuses what a real run refuses, a miss says why, a batch
is answered in request order, the other HTTP surfaces send nothing.
`talos-mcp-handlers`: `sandbox::http_fixture_tests`. `worker`:
`rehearsal_pin`.
