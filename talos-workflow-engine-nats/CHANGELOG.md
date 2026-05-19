# Changelog

All notable changes to `talos-workflow-engine-nats` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0: breaking changes may occur in any minor version. Once the public
API stabilizes alongside `talos-workflow-engine-core`, the crate will move to
1.0 and normal semver applies.

## [Unreleased]

### Added

- `retry_skipped` events now populate `NodeEventWrite::error_class`
  with the `RetryClassifier` tag that short-circuited the retry
  decision (`"auth"`, `"invalid_input"`, `"unknown"`, …). Downstream
  analysis tools can correlate "why did the retry_count get ignored"
  without substring-parsing `log_message`.

## [0.2.0] — 2026-04-20

### Changed

- **Breaking**: `NatsNodeDispatcher::new`, `run_with_nats`, and
  `run_with_seed_via_nats` now take `Option<WorkerSharedKey>` instead of
  `Option<Arc<Vec<u8>>>` for the HMAC shared signing key. See
  `talos-workflow-engine-core`'s changelog for the newtype rationale and
  migration (`Some(Arc::new(bytes))` → `Some(WorkerSharedKey::new(bytes))`).
- **Breaking**: `run_with_nats` and `run_with_seed_via_nats` now
  return `Result<_, talos_workflow_engine::WorkflowEngineError>`,
  matching the typed-error contract on
  `ParallelWorkflowEngine::run_with_transport` /
  `run_with_seed_with_transport`. Migrate by changing your error
  binding from `String` to `WorkflowEngineError` (or any
  `Box<dyn std::error::Error>` ancestor) — call-site `?` and
  `e.to_string()` continue to work without change.

## [0.1.0] — Initial release

- `NatsNodeDispatcher` — `NodeDispatcher` impl that publishes signed jobs
  via NATS request/reply and parses worker responses.
- `NatsTransport` — `JobTransport` impl wrapping an `async_nats::Client`.
- `run_with_nats`, `run_with_seed_via_nats` — convenience runners that
  wire a `ParallelWorkflowEngine` to a NATS-backed dispatcher.
- Topic-level priority lanes (jobs with priority ≥ 200 route to a
  `.priority` sub-topic).
- Optional edge routing (`ENABLE_EDGE_ROUTING=true`) that scopes subjects
  by user id for per-tenant worker subscriptions.
- Retry with exponential backoff on transient NATS delivery errors;
  timeouts are not retried.
