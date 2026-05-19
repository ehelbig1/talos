# talos-workflow-engine-core — contributor guide

This crate defines the **trait surface** for a portable workflow executor.
It is types + traits only: no I/O, no runtime, no backing store. Sibling
crates layer implementations on top.

This document (recognized by `AGENTS.md` tooling conventions and intended
for both human contributors and AI pair-programmers) captures the non-
obvious rules for working in this crate. The short version: **be paranoid
about leaks**. Every dependency, every runtime coupling, every concrete
type that creeps in here undermines the "portable, no-I/O" contract the
crate commits to.

## Sibling crates

```
talos-workflow-engine-core      ← you are here (types + traits only)
    │
    ├── talos-workflow-engine                 DAG scheduler + dispatch loop
    │        └── talos-workflow-engine-nats   NATS-backed NodeDispatcher
    │
    └── talos-workflow-engine-test-utils       in-memory + capture trait impls
```

Every sibling depends on this crate; this crate depends on none of
them. Adding a dep to any sibling here would be a cycle. If a sibling
needs something declared here, add it; if it needs something impl'd,
that belongs in the sibling.

## Prime directives

1. **No async runtime dependency.** `tokio`, `async-std`, `smol`, etc. are
   banned at the `Cargo.toml` level. Only `async-trait` is allowed, and
   only to express the dyn-compatible trait signatures. If you find
   yourself reaching for `tokio::spawn` or `tokio::time::sleep`, the
   logic belongs in the consumer crate, not here. Same for `tokio::sync`
   primitives — use `std::sync` where thread-safety is needed at all.
2. **No I/O dependency.** No `sqlx`, no `reqwest`, no `async-nats`, no
   filesystem crates. Traits describe what the executor asks for; they
   do not perform the action themselves.
3. **No concrete types from downstream crates.** Controller types
   (`ModuleRegistry`, `SecretsManager`, `WasmModule`) MUST NOT appear in
   any signature. If a trait method needs shape that a consumer type
   provides, define a protocol type here (see `WasmModuleArtifact` for the
   pattern — a flat `struct` with only the fields the executor reads).
4. **Every trait is `dyn`-compatible.** The executor holds `Arc<dyn
   Trait>`. No generic methods, no associated types, no `where Self:
   Sized`. Use `async_trait::async_trait` for async methods. Test dyn
   compatibility by writing `fn _takes_dyn(_: &dyn YourTrait) {}` in a
   doc example if unsure.
5. **Every trait is `Send + Sync`.** The engine calls methods from
   spawned tasks. Forgetting the bound fails at call-site, not at
   trait-definition, so set it on every new trait: `pub trait Foo:
   Send + Sync`.

## The `BoxError` convention

All fallible trait methods return `Result<T, crate::BoxError>` —
`Box<dyn std::error::Error + Send + Sync>`. Rationale:

- Implementers can return their own error types (`sqlx::Error`, custom
  enums) without this crate knowing about them.
- The executor never pattern-matches on the error type — it only logs
  and propagates.
- Using a fixed concrete type here would force every impl into a
  `map_err(|e| MyEngineError::FooFailed(e.to_string()))` adapter.

When you add a new trait method, return `Result<T, BoxError>` unless you
genuinely cannot fail (then return `T` or `()` directly — see
`ModuleFetcher::load_rate_limits` for the "soft-fail = empty map" pattern).

## Default method bodies for non-breaking additions

When adding a method that not every impl needs to fill in, give it a
sensible default so existing downstream impls don't break. Examples in
this crate:

- `NodeLifecycleHook::on_node_failed` — default no-op (not every hook
  cares about failures).
- `NodeLifecycleHook::on_pipeline_step_completed` — default no-op.
- `WorkflowGraphStore::resolve_by_name` / `resolve_by_capabilities` —
  default `Ok(None)` (not every store supports name resolution).
- `ModuleFetcher::load_rate_limits` — default `HashMap::new()` (not
  every fetcher has a rate-limit concept).
- `SecretsResolver::refresh_vault_paths` — default no-op.
- `NodeDispatcher::dispatch_chain` — delegates to
  `dispatch_chain_sequential` so non-batch impls don't need to write
  anything.

Prefer a default body over a required method when:
(a) the trait's existing consumers would all implement it the same
"empty" way, OR
(b) the behavior is genuinely optional (e.g. rate limiting).

**Don't** add a default body that silently papers over a correctness
concern. `NodeDispatcher::dispatch` has no default because every
consumer must supply one — a no-op dispatch would mean "all nodes
succeed with empty output," which is a silent bug factory.

## Data model patterns

### Struct args over long parameter lists

When a hook or trait method takes >4 arguments, wrap them in a context
struct. Adding a new field to the struct is a non-breaking change;
adding a new parameter to a method is breaking for every impl.

See `NodeCompletionContext` — carries `workflow_id`, `execution_id`,
`node_id`, `node_label`, `module_id`, `actor_id`, `wall_time_ms` as one
argument. When we later added `wall_time_ms`, zero impls broke.

### Redacting `Debug` impls

Types that carry secret material MUST implement `Debug` by hand, eliding
the sensitive fields. See `DispatchJob::fmt` for the full pattern:

- `input_payload` → `"<redacted — may contain plaintext secrets>"`
- `encrypted_secrets_ciphertext` → `"<{N} bytes>"`
- `wasm_bytes` → `"<{N} bytes>"`

If you add a new type that holds plaintext secrets, a shared key, or a
wasm blob, write the `Debug` impl manually. `#[derive(Debug)]` on such
types is a security regression.

### Don't take `&str` when owned is needed

Trait methods that store their input need `String` (not `&str`). This
avoids forcing impls to `to_string()` internally. Same for `Vec<T>` vs
`&[T]` — if the impl needs ownership (like a background `tokio::spawn`
that outlives the call), take `Vec<T>`.

## Security invariants

- **Plaintext secrets are per-request data, not persistent.**
  `SecretsResolver` returns `HashMap<String, String>`. Trait impls may
  hold caches internally but must use `zeroize`-style discipline at
  their own layer. This crate's traits do not try to enforce that —
  it's an impl-level policy.
- **`ExecutionSanitizer` is sub-trait not variant.** The stateless
  `OutputSanitizer` + per-run `ExecutionSanitizer` split mirrors how a
  realistic DLP implementation factors stateless pattern scrubbing
  separately from per-run dynamic redaction. When adding sanitizer
  methods, decide deliberately which layer they belong on.
- **No trait method silently drops a failure.** Fire-and-forget paths
  are explicit (`EventSink::emit` returns `()` because the trait-level
  docs say so; `refresh_vault_paths` returns `()` for the same
  documented reason). Everywhere else returns `Result`.

## Cargo.toml discipline

- `async-trait`, `serde`, `serde_json`, `uuid`. That's the full
  allowlist. New deps require an explicit "why this can't be a
  downstream impl detail" rationale.
- `unsafe_code = "forbid"` in `[lints.rust]` — NOT just `warn`.
- `missing_docs = "warn"` — every `pub` item documented.
- `clippy::pedantic = "warn"` with targeted allows. New allows need
  justification in the `Cargo.toml` comment (see existing allow for
  `module_name_repetitions` etc.).

## Testing

- Unit tests live alongside their module (`#[cfg(test)] mod tests { ...
  }`). Keep them terse — this crate has type-level correctness, so
  most value comes from compile-time checks, not runtime tests.
- **For integration-style testing of traits, use the sibling
  `talos-workflow-engine-test-utils` crate.** When you add a new trait here,
  add a matching `InMemoryFoo` or `CaptureFoo` impl there in the same
  PR.
- Dyn-compatibility check: write a compile-time assertion in your new
  trait's module — `fn _takes_dyn(_: &dyn MyTrait) {}` — so the
  compiler fails the build if the trait accidentally becomes
  non-dispatchable.

## When NOT to modify this crate

If you find yourself wanting to:

- Add a `tokio` dep because "it's convenient" → the logic belongs in
  `talos-workflow-engine` or a consumer crate.
- Add a method that takes a concrete controller type → define a
  protocol type or add a trait method that returns what the controller
  would have given.
- Add a function that does work (not just defines shape) → probably
  belongs in `talos-workflow-engine`. This crate is almost entirely
  declaration.

## What good PR patterns look like here

- **Adding a trait**: new file under `src/`, declared in `lib.rs`,
  with a `Send + Sync`-bounded async-trait definition, default bodies
  for optional methods, rich doc comments covering (a) what the trait
  is for, (b) the security/ordering contract, (c) when to implement
  vs. use a default. Then add a companion impl in
  `talos-workflow-engine-test-utils`.
- **Extending a trait**: add a method WITH a default body (see the
  patterns above). Update the test-utils impl to exercise the default.
- **Adding a protocol type**: new file under `src/`, flat `struct`
  with only the fields consumers actually use (err on the side of
  fewer — a field you never read is a compatibility burden). Derive
  `Clone`. Write `Debug` by hand if ANY field is sensitive.

## Post-change checks

Before committing any change to this crate:

```
cargo check -p talos-workflow-engine-core
cargo clippy -p talos-workflow-engine-core --all-targets -- -D warnings
cargo doc -p talos-workflow-engine-core --no-deps       # zero warnings
cargo test -p talos-workflow-engine-core
```

Then verify downstream:

```
cargo check --workspace
cargo clippy -p talos-workflow-engine --lib -- -D warnings
cargo test -p talos-workflow-engine-test-utils
```

A change that compiles here but breaks `talos-workflow-engine` means a trait
contract changed breakingly. That may be fine — just call it out in the
commit message so reviewers see the ripple.
