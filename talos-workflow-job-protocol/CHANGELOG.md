# Changelog

All notable changes to `talos-workflow-job-protocol` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0: wire-format breaking changes may occur in any minor version.
Once stable, new optional fields are non-breaking; changed semantics
or new required fields bump the major version.

## [Unreleased]

## [0.2.0] — 2026-04-20

### Added

- Wire-format snapshot tests in `tests/wire_format_snapshots.rs`.
  Byte-level JSON snapshots for `EncryptedSecrets`, `JobRequest`,
  `JobResult`, `PipelineJobRequest`, `PipelineJobResult` plus an
  HMAC-SHA256 signature snapshot for `JobRequest`. Catches
  accidental field reorders / renames / signing-payload format
  drift before they ship to deployed workers. Update the literal
  in the test file when the wire format intentionally changes —
  the test docstring documents the failure-resolution workflow.

### Changed

- **Breaking**: `load_worker_shared_key` now returns
  `Result<talos_workflow_engine_core::WorkerSharedKey, String>` instead of
  `Result<Vec<u8>, String>`. The new return type is the opaque,
  cheap-to-clone, redacted-in-`Debug` signing key type used across the
  engine's public API. Migrate: wrap downstream uses that previously took
  `Vec<u8>` in `key.as_bytes()` to recover the raw slice.

## [0.1.0] — Initial release

- `JobRequest` / `JobResult` — single-node dispatch wire format with
  HMAC-SHA256 signing over the canonical byte form.
- `PipelineJobRequest` / `PipelineJobResult` / `PipelineStep` —
  batched chain dispatch.
- `EncryptedSecrets` — AES-256-GCM envelope for plaintext secret
  transport (fresh key + nonce per dispatch).
- `job_nonce` anti-replay token (ms timestamp + 16 random hex chars)
  with a ±5 s future-skew tolerance.
- Reserved vault-path registry (`LLM_PROVIDER_VAULT_PATHS`,
  `is_llm_provider_vault_path`, `vault_path_permitted`) — canonical
  list of host-reserved secret paths used for deny-listing and
  pre-injection.
- Integration-scoping field (`integration_name`) for gating
  integration-specific host functions.
- `capability_world` hint for worker-linker selection (not signed; a
  performance hint, not a capability grant).
