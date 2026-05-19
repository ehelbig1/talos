# talos-workflow-job-protocol — contributor guide

This crate defines the **wire format** between a workflow engine and
its worker pool. Every change here affects two independent processes
that must agree byte-for-byte on the signed payload.

This document (recognized by `AGENTS.md` tooling conventions and
intended for both human contributors and AI pair-programmers)
captures the non-obvious rules for working in this crate. The short
version: **the HMAC covers the wire bytes, so wire-format drift is
security drift**.

## Sibling crates

```
talos-workflow-job-protocol       ← you are here (wire format + HMAC)
talos-workflow-engine-core        trait surface
talos-workflow-engine             scheduler (builds JobRequests)
    └── talos-workflow-engine-nats   transport (signs, publishes, verifies)
talos-workflow-engine-test-utils  in-memory trait impls
```

This crate depends on none of the above. It's a pure types-+-crypto
crate consumed by every side of the wire.

## Prime directives

1. **Do not change an existing field's semantics without bumping the
   major version.** Downstream signers and verifiers pin the struct
   shape. A reinterpreted field silently rejects signatures across
   versions.
2. **New optional fields are non-breaking** provided (a) they have
   `#[serde(default)]`, (b) they have `#[serde(skip_serializing_if =
   "Option::is_none")]`, and (c) they are appended to the canonical
   signing-byte order.
3. **The HMAC signs canonical bytes, not serde output.** Any field
   that participates in authentication must appear in the hand-rolled
   `write_canonical_bytes` path. Adding a field to `serde` but not to
   the canonical-bytes writer produces signatures that the verifier
   accepts but an attacker can mutate the un-covered field.
4. **`job_nonce` is load-bearing.** The ms timestamp + random hex is
   the only anti-replay defense. The future-skew window
   (`MAX_FUTURE_SKEW_SECS`) is asymmetric by design: past tolerance
   is large (minutes) to absorb queue latency; future tolerance is
   tight (seconds) to bound replay-forgery lifetime.
5. **Secret transport is envelope-encrypted, not just signed.**
   `EncryptedSecrets::encrypt` uses AES-256-GCM with a fresh key +
   nonce per dispatch. The key itself rides in the encrypted
   envelope — the wire-level HMAC protects the envelope's integrity.

## Canonical byte encoding

`write_canonical_bytes` is the source of truth for what the HMAC
covers. Rules:

- **Fixed field order** — changing order changes all signatures.
- **Length-prefix every variable-length field** (strings, vecs, opt
  presence) so concatenation ambiguity is impossible.
- **Reject `NaN` / `Inf` in signed numeric fields** — they have
  non-deterministic bit representations and let a forger slip the
  same value through two different byte streams.
- **Sorted-key recursive JSON for nested `serde_json::Value`** — the
  signing function walks the value and emits in sorted-key order so
  `{"a":1,"b":2}` and `{"b":2,"a":1}` sign identically.
- **`MAX_CANONICAL_DEPTH` = 128** — matches serde_json's default.
  Deeper payloads fail signing closed rather than recursing into a
  stack overflow.

## Reserved vault paths

`LLM_PROVIDER_VAULT_PATHS` and the three public helpers
(`is_llm_provider_vault_path`, `is_reserved_host_secret_path`,
`vault_path_permitted`) are a **security-invariant registry**. They
are imported by:

- Engine-side: pre-inject these paths into every worker job's
  encrypted secrets map so host-function LLM calls can resolve them.
- Worker-side: deny-list these paths from guest-reachable secret
  resolution even under a module grant of `allowed_secrets: ["*"]`.

Adding a new provider is a one-line change here and automatically
flows into both consumers. Removing or re-ordering entries is a
breaking change.

## Testing

- Unit tests live in `src/lib.rs` under `#[cfg(test)] mod tests`.
- `tests/security_tests.rs` exercises HMAC tampering, wrong-key
  rejection, replay-window boundaries, and canonical-bytes drift.
- `tests/serialization.rs` pins the canonical wire format for
  representative `JobRequest` / `JobResult` / `PipelineJobRequest`
  cases — a failing test here signals a breaking change.

When modifying a signed field or the canonical-bytes writer, **run
the security tests first** and audit the serialization snapshot
diffs by hand.

## Post-change checks

```
cargo check -p talos-workflow-job-protocol
cargo clippy -p talos-workflow-job-protocol --all-targets -- -D warnings
cargo test  -p talos-workflow-job-protocol
cargo doc   -p talos-workflow-job-protocol --no-deps   # zero warnings
```

Then verify downstream:

```
cargo check --workspace
cargo test -p talos-workflow-engine-nats
```

A change that compiles here but breaks `talos-workflow-engine` or
`talos-workflow-engine-nats` means a wire-format contract changed. That
may be fine — just call it out in the commit message so reviewers
see the ripple, and bump the version accordingly.
