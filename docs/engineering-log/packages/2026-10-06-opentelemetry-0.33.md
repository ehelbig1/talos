# The OpenTelemetry family moves to 0.33 (2026-10-06)

Backlog item (`2026-10-06-major-version-backlog.md`): `opentelemetry`,
`opentelemetry_sdk`, `opentelemetry-otlp` and `opentelemetry-prometheus`
0.32 → 0.33, with `tracing-opentelemetry` 0.33 → 0.34 (which requires
`opentelemetry` 0.33). The first bump made in the workspace table: four of
the five versions are one line each in the root manifest.

## Measured

* **Lockfile:** six packages change version (the five named and
  `opentelemetry-proto`). Nothing is added or removed. `opentelemetry-otlp`
  0.33 would bring `reqwest` 0.13 with its default features; the workspace
  entry's `default-features = false` keeps it out, as before.
* **No source change.** The whole workspace compiles against 0.33 with no
  error and no new warning.
* **What the worker exports is unchanged.** The risk in an exporter bump is
  not a compile error: the exporter decides each series' final name (it
  appends `_total`, splits histograms, adds `otel_scope_name`), and a
  renamed series silences the alerts and dashboards written against it. So
  the comparison was of the output: with one measurement recorded on every
  instrument, the name and type of each of the 28 metric families and the
  label keys of every series were captured under 0.32 and under 0.33. They
  are identical (66 lines).

## Changed

* The five versions.
* `talos-worker-runtime/tests/metrics_shape.rs`: that comparison, kept. It
  asserts the exact shape, in both directions. It is its own test binary
  because the Prometheus registry is process-global: inside the crate's
  unit tests it would record into the registry the existing "an idle worker
  reads zero" test depends on being untouched (it did, the first time it
  was written there, and failed that test under plain `cargo test`).

## Verified

`make test-unit` (7,407 pass, including the trace-context propagation tests
of `talos-trace` and `talos-trace-nats`), `make test-dbfree` (which runs the
new binary), `make clippy`, `make lint`.

## Not verified here

Span export to a collector over OTLP. Nothing in the tests receives spans,
and the reference stack does not set a traces endpoint. After the deploy the
worker's `/metrics` output can be compared with this record directly.
