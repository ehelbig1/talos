# `trigger_workflow(dry_run: true)` starts a dry run (2026-10-12)

`trigger_workflow(dry_run: true, wait_ms: …)` answered
`{"validate_input": true, "valid": true}` and started nothing, though
`validate_input` was not passed. `test_workflow(dry_run: true)` on the same
workflow ran it.

## The class

`TriggerInput` had one boolean, `dry_run`. The MCP handler sent
`dry_run: dry_run || validate_only`, and the service read that one field
twice: as the validator's `validate_only` (answer with a schema report and
start nothing) and as the engine's `.with_dry_run(…)`. The second read was
dead: any call with the field true returned at the first. A comment at the
handler described the merge as intended. The tool description did not: it
said a dry run mocks outbound calls.

## Decided

* **Two fields.** `TriggerInput { validate_only, dry_run }`.
  `validate_only` goes to the input-schema check; `dry_run` goes to the
  engine. A required field, so the compiler named the five callers
  (`talos-mcp-handlers`, `talos-api`, `talos-webhooks` action links,
  `talos-evaluation`, `talos-google-calendar`); the four that are not the MCP
  handler pass `false` for both, as before.
* **The validation-only types no longer say "dry run".**
  `TriggerOutcome::DryRun(DryRunResult)` is
  `TriggerOutcome::ValidatedOnly(InputValidationReport)`;
  `InputSchemaCheck::DryRun` is `InputSchemaCheck::ValidateOnly`. A variant
  named `DryRun` that is returned when `dry_run` is false, and never when it
  is true, is how the merge read as correct.
* **Both flags set: `validate_input` wins** and nothing is started. The note
  says which flag to drop.
* **A reply that started nothing says so**: `started: false` and a note that
  begins "No execution was started".
* **A reply that started a dry run says so**: the first line, and
  `dry_run: true` in the JSON block. An ordinary trigger's block is unchanged.

## Behaviour that changed for a caller

`trigger_workflow(dry_run: true)` now STARTS an execution. It used to start
nothing. Its non-GET HTTP requests, webhook sends and messaging publishes are
mocked, as the description always said, and it counts toward the actor's
budget like any run.

## Found on the way, not changed here

A dry run mocks `http::fetch` / `fetch_all` (non-GET), `wasi:http` (mutating),
`webhook::send`, `messaging` and the agent `orchestration` calls. It does
**not** mock `email::send`, `graphql::execute` (a mutation is a POST),
`database`, `object_storage::put`/`delete`, `files::write`/`delete` or
`http_stream`. Memory writes and LLM calls are real too. The `dry_run`
description now lists what is not mocked. Whether those calls should be
mocked is a separate change.

## Tests

`talos-mcp-handlers` `trigger_reply_tests`:
* `dry_run` alone builds a request with `validate_only: false`, and the
  service's input check over that request lets the run proceed. With the old
  merge put back in `trigger_request`, this test fails.
* `validate_input` starts nothing, with or without `dry_run`.
* The validation reply carries `started: false` and the note; both flags
  names the one to drop; a started dry run is marked and an ordinary trigger's
  JSON block is byte-identical to before.

## Stated limits

* No test starts a run through `ExecutionOrchestrationService::trigger`: it
  needs Postgres, NATS and a registry. What is pinned is the request the
  handler builds and the decision the service makes on it.
* The trace returned when `wait_ms` sees the run finish does not say the run
  was a dry run.
