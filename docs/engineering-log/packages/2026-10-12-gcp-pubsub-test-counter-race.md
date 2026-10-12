# A Google Cloud push test failed two runs in three under plain `cargo test` (2026-10-12)

`talos-google-cloud`
`handlers::pubsub_tests::valid_jwt_but_unreadable_lookup_defers_for_redelivery`
asserts that `google_push_deferred_total{gcp, watch_lookup_unreadable}` on
the process-global registry moved by exactly one.
`a_verified_push_for_no_watch_is_not_counted_as_accepted`, in the same
binary, drives the same handler arm and moves the same series.

## Measured

`cargo test -p talos-google-cloud --lib`, whole crate: failed 7 of 12 runs
before, 0 of 20 after. It passed with `--test-threads=1` and in CI, which
runs one process per test.

## Decided

The two tests that reach that arm hold one async mutex
(`UNREADABLE_LOOKUP_SERIES`) for their duration. The other 38 tests in the
binary still run in parallel.

## Deliberately NOT done

* **A label only this test uses.** The label set is written by the handler
  (`defer_unreadable_watch(PushIntegration::Gcp)`), not by the test.
* **An explicit registry** (`record_google_push_deferred_on`). The handler
  records on the global one; threading a registry through the handler state
  to suit a test changes production code for it.
* **Serialising the binary.**
