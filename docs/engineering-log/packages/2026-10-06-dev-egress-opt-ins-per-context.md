# The worker's dev egress opt-ins are read once per execution, and no unit test sets them (2026-10-06)

## Measured

`cargo test -p talos-worker-runtime --lib` on a developer machine, before:
three runs, three failures (900 tests each).

* 3 of 3: `host::wasi_http::tests::the_send_path_refuses_a_name_that_resolves_private_where_upstream_connected`
  — "the hardened path refuses the resolved loopback address: Ok(200)".
* 1 of 3: `host::http_admission_characterization_tests::insecure_scheme_refusal`
  — the plaintext request was sent (`Timeout`) instead of refused.

`cargo nextest run` (one process per test, what `quality.yml` runs) passed
all of them, so CI never showed it.

Cause: four tests set `WORKER_ALLOW_PRIVATE_HOST_TARGETS` and/or
`WASM_ALLOW_INSECURE_HTTP` in the process environment — three in
`host_impl_tests.rs` (one of which removed them at its end), one in
`host/sibling_egress_reason_tests.rs` (never removed) — plus one in
`ssrf_resolver.rs` that set and removed. Every gate read the environment per
call, so under plain `cargo test` an egress-refusal test saw whatever a
neighbour had set.

After: five runs in a row pass (905 tests), `cargo nextest run -p
talos-worker-runtime` passes (906: the library plus the new binary).

## The brief was wrong on one point

The brief said the code already had a constructor-level path for the setting.
It did not. The "per-context flag" in the resolver's docs is the explicit-host
set, which is ANDed with the environment toggle; the toggle itself was read by
`SsrfFilteringResolver::resolve` and by each pre-check at call time. Passing
the setting explicitly therefore needed a change to production code, below.

## Decided

* **`DevEgressOptIns`** (`talos-worker-runtime/src/context.rs`):
  `{ private_host_targets, insecure_http }`. `TalosContext::new` reads the
  environment once (`DevEgressOptIns::from_env`), builds the resolver with
  `private_host_targets`, and keeps the value in `TalosContext::dev_egress`
  (`pub(crate)`; outside the crate it is read-only through `dev_egress()`).
* **Every gate reads the context**: the DNS pre-checks in `http::fetch`,
  `http::fetch_all` and `validate_no_dns_rebinding`
  (`private_host_bypass_applies` now takes the toggle as an argument), and the
  scheme gates in `url_policy` (fetch / fetch_all), `webhook::send`,
  `graphql::execute`, `http_stream::connect` and the `wasi:http` handler.
  `SsrfFilteringResolver::for_allowed_hosts` takes the toggle as a third
  argument and no longer reads the environment.
* **A test states its opt-ins**: `TalosContext::with_dev_egress` (`#[cfg(test)]`)
  rebuilds the two egress clients through `build_egress_clients`, the function
  `new` uses. The four tests above use it; none sets a variable.
* **The one environment test is its own binary**:
  `talos-worker-runtime/tests/dev_egress_env.rs` — a process of its own under
  both runners. One test walks unset → insecure only → both → both under
  `RUST_ENV=production` → cleared, through `TalosContext::new` and a real
  `fetch` to a loopback listener. Its `EnvGuard` holds a lock for its lifetime
  and restores the three variables on drop.

Production behaviour: the read moved from per call to per execution. For a
process whose environment does not change that is the same answer. The
production refusal is unchanged and still lives in
`host::allow_private_host_targets`; its one-time WARN now fires when the first
context is built rather than at the first private lookup.

## Mutations (egress control)

Each applied to the final tree, the test binaries rebuilt (build succeeded in
all thirteen), `cargo test --lib` run with no name filter plus the new binary,
then reverted and `git diff --quiet` checked.

| # | Mutation | Caught by |
|---|---|---|
| 1 | connect-time private-address refusal removed (`resolved_addr_permitted`: private ⇒ permitted) | `the_send_path_refuses_a_name_that_resolves_private_where_upstream_connected`, 3 resolver tests |
| 2 | resolver ignores the context's toggle (always on) | `the_send_path_refuses_…` |
| 3 | `new()` ignores the environment, both always ON | 7 library refusal tests, `dev_egress_env` |
| 4 | `new()` ignores the environment, both always OFF | `dev_egress_env` only |
| 5 | `with_dev_egress` sets the field without rebuilding the clients | the 3 loopback tests, `the_send_path_refuses_…` (its control leg) |
| 6 | `fetch` DNS pre-check ignores the toggle | `dev_egress_gate_tests::fetch_refuses_…`, `dev_egress_env` |
| 7 | URL admission ignores the insecure-HTTP opt-in | 4 library tests, `dev_egress_env` |
| 8 | `fetch_all` DNS pre-check ignores the toggle | `dev_egress_gate_tests::fetch_all_refuses_…` |
| 9 | `validate_no_dns_rebinding` ignores the toggle | `dev_egress_gate_tests::the_shared_dns_pre_check_…` |
| 10–12 | graphql / webhook / http-stream scheme gate ignores the opt-in | one `sibling_egress_reason_tests` test each |
| 13 | `wasi:http` gate ignores the opt-in | `wasi_http::tests::a_plaintext_request_is_refused_unless_this_context_opted_in` |

8, 9 and 13 SURVIVED the first pass: no test distinguished those three lines
before this package either. `host/dev_egress_gate_tests.rs` and the
`wasi_http` test were added for them and the pass repeated.

## Deliberately NOT done

* **One lock taken by every egress test.** The set of tests whose verdict
  depends on the toggles is open (any test that builds a context and expects a
  refusal), and one that forgets the lock brings the defect back.
* **A `#[cfg(test)]` branch in `new()` that ignores the environment.** It
  would make the library's tests independent of a developer's shell, and it
  would mean no library test runs the line a job runs.
* **A lint against `set_var` of the two names.** Not measured, not written.
* **The other environment-mutating tests in the crate**
  (`TALOS_SIGSTORE_REQUIRED` / `RUST_ENV` / `WORKER_MAX_OCI_LAYER_BYTES` under
  `module_fetcher`'s `ENV_LOCK`, `CIRCUIT_BREAKER_*`, `OLLAMA_URL`). Each is
  serialised within its own module and none failed in the runs above. The
  loopback tests no longer depend on `RUST_ENV`, which the sigstore test sets
  to `production` for a moment: their opt-in is stated, not derived.

## Stated limits

* A library test that does not pin its opt-ins still gets the environment's
  answer from `new()`. A shell that exports either variable makes the unpinned
  refusal tests fail — every run, under either runner, not intermittently.
  Pinned: the `wasi_http` send-path test and the tests added here.
* `WASM_ALLOW_INSECURE_HTTP` has no production refusal (only the
  private-target toggle does). Unchanged by this package; recorded because
  the new environment test makes it visible.
* `SsrfFilteringResolver::for_allowed_hosts` is `pub` and gained a parameter.
  It has no caller outside the crate (`grep -rn 'SsrfFilteringResolver::'`).

## One home

`talos_worker_runtime::context::DevEgressOptIns` — the two opt-ins as one
execution sees them. Rule added to `CLAUDE.md`, Testing Conventions.
