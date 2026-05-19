# talos-workflow-engine-test-utils — contributor guide

This crate ships **test-only trait implementations** for every trait
defined in `talos-workflow-engine-core`. Consumers pull it in as a
`dev-dependency` to wire a `ParallelWorkflowEngine` in unit tests
without a database, transport, or secrets backend.

This document (recognized by `AGENTS.md` tooling conventions and
intended for both human contributors and AI pair-programmers) captures
the non-obvious rules for working in this crate.

## Organization

Impls are grouped by role, one module per role:

| Module | Role | Representative types |
|---|---|---|
| `capture` | Record every call for assertions | `CaptureEventSink`, `CaptureNodeLifecycleHook`, `CaptureModuleExecutionStore` |
| `memory` | Plain `HashMap`-backed stores | `InMemoryModuleFetcher`, `InMemoryCheckpointStore`, `InMemoryWorkflowGraphStore`, `InMemorySecretsResolver` |
| `noop` | Pass-through policy impls | `PassthroughSanitizer`, `StubExpressionEvaluator`, `NothingTransientClassifier` / `EverythingTransientClassifier` |
| `dispatch` | Scripted `NodeDispatcher` | `ScriptedDispatcher` |
| `approval` | Constant-outcome `ApprovalGate` | always-approve / always-pending / always-deny |

## Prime directives

1. **Matches the core trait surface 1:1.** Every trait in
   `talos-workflow-engine-core` must have at least one impl here. When
   a core trait gains a method, add the default-safe impl here in the
   same PR — the test-utils crate is how consumers learn the contract.
2. **No production-only deps.** `tokio` is not a dep; impls are
   runtime-agnostic. If a test needs a runtime, the *test* adds
   `tokio = { features = ["macros", "rt"] }` as its own dev-dep.
3. **`Send + Sync` everywhere.** Every public type must be safe to
   share across spawned tasks. Use `DashMap` / `std::sync::Mutex`
   guarded interiors, never `RefCell` or `Rc`.
4. **Capture stores return owned clones.** `.events()` / `.records()`
   / etc. MUST return cloned snapshots. Test assertions must never be
   able to mutate the live log through an accessor.
5. **Mutex-poison is `.expect("poisoned")`.** A poisoned mutex in test
   utilities is genuinely unrecoverable and the panic is the right
   signal. Do not swallow with `.unwrap_or_default()`.
6. **Builder `with_*` methods return `Self` by value.** Fluent
   construction is the whole point; `#[must_use]` is intentionally not
   applied per-method (see the Cargo.toml lint carve-out).

## Naming conventions

- `Capture*` — records every call, returns owned snapshots.
- `InMemory*` — backing store impl (holds real data).
- `Scripted*` — test declares `(input → response)` up front.
- `Passthrough*` / `Stub*` / `NothingTransient*` — no-op policy impl.

Keep these prefixes. The top-level README advertises them; drifting
names would break every consumer's test suite.

## Post-change checks

```bash
cargo fmt --all
cargo clippy -p talos-workflow-engine-test-utils --all-targets -- -D warnings
cargo test -p talos-workflow-engine-test-utils
cargo doc -p talos-workflow-engine-test-utils --no-deps
```

The lib.rs doctest is load-bearing — it exercises the minimum viable
import chain and catches rename drift immediately. Don't delete it.

## When adding a new core trait

1. Add the in-memory impl under `memory.rs` (data-carrying traits) or
   `noop.rs` (policy traits).
2. If the trait emits observable events, add a `Capture*` impl under
   `capture.rs`.
3. Update `lib.rs` module docs and the table at the top of this file.
4. Mention the new impl in `README.md`.

When adding a new impl here, open a PR against the core trait change
in the same branch so the two merge atomically.
