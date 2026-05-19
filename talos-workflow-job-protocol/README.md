# talos-workflow-job-protocol

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

The signed, HMAC-authenticated wire format used between a workflow
engine and its worker pool. Shared by:

- **`talos-workflow-engine`** (the DAG scheduler) — constructs `JobRequest`s
  from internal engine state.
- **`talos-workflow-engine-nats`** (the NATS dispatcher) — signs, serializes,
  publishes, and verifies replies.
- **Worker pools** — deserialize, verify the signature, decrypt secrets,
  run the module, and reply with a signed `JobResult`.

## What's on the wire

- **`JobRequest`** — a single-node dispatch: module identity + artifact
  pointer, input payload, encrypted secrets, capability + integration
  scope, fuel / timeout budgets, retry policy hints, `job_nonce`, and an
  HMAC-SHA256 signature over the canonical byte form.
- **`JobResult`** — the reply: status, output JSON (on success), error
  message (on failure), plus an HMAC over the result for reply
  authentication.
- **`PipelineJobRequest` / `PipelineJobResult` / `PipelineStep`** —
  batched dispatch for a linear chain of steps sharing one sandbox.
- **`EncryptedSecrets`** — AES-256-GCM envelope around the
  `HashMap<String, String>` of plaintext secrets. Fresh key +
  nonce per dispatch; nothing in the envelope is attacker-influenced
  once sealed.

## Security invariants

- **HMAC-SHA256 over canonical bytes**, so serialization re-ordering
  can't bypass signing.
- **Shared-key authentication** (pre-shared `WORKER_SHARED_KEY`) — no
  PKI, no broker trust assumption.
- **`job_nonce`** (millisecond timestamp + 16 random hex chars) bounds
  the replay window; receivers enforce a max age and a ±5 s future
  skew tolerance.
- **AES-256-GCM envelope on secrets** so the broker, a shared NATS
  cluster, or any on-path observer sees ciphertext only.
- **Reserved vault-path allowlist** (`LLM_PROVIDER_VAULT_PATHS`,
  `is_llm_provider_vault_path`) — canonical list of host-reserved
  secret paths. Used by controllers to pre-inject LLM keys into every
  job, and by workers to deny-list these from guest-reachable secret
  resolution even under a wildcard grant.

## Quickstart

```toml
[dependencies]
talos-workflow-job-protocol = "0.1"
```

```rust,ignore
use talos_workflow_job_protocol::{JobRequest, JobResult, JobStatus};

// Producer: fill in a JobRequest, then sign in-place before publishing.
let mut req: JobRequest = build_job_request();
req.sign(&worker_shared_key).expect("sign ok");
let bytes = serde_json::to_vec(&req)?;
// publish `bytes` on your transport

// Consumer: deserialize, verify against the same shared key and a
// freshness window in seconds (typical: 60).
let req: JobRequest = serde_json::from_slice(&bytes)?;
req.verify(&worker_shared_key, 60).expect("verify ok");

// Reply path: workers populate a `JobResult` and sign it. `sign`
// generates `result_nonce` from the current time plus random bytes.
let mut result = JobResult {
    job_id: req.job_id,
    status: JobStatus::Success,
    output_payload: serde_json::json!({ "ok": true }),
    logs: vec![],
    execution_time_ms: 12,
    signature: vec![],
    result_nonce: String::new(),
};
result.sign(&worker_shared_key).expect("sign ok");
```

Same `sign` / `verify` method pair exists on `PipelineJobRequest`,
`PipelineJobResult`, and the heartbeat/status-update payloads.

The crate is pure types + signing / verification helpers. It doesn't
pick a transport, doesn't pick a serialization format (callers
typically use `serde_json` as above), and doesn't own any I/O.

## Stability

Pre-1.0. Wire format may change until the first tagged release. Once
stable, backward-compatibility rules: new optional fields are
non-breaking; changing field semantics or adding required fields bumps
the major version.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual-licensed as above, without any additional terms or
conditions.
