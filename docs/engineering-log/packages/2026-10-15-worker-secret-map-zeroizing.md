# The worker's secret map is a `SecretMap` end to end; the unwired claim lease is gone; the worker is non-dumpable (2026-10-15)

Security review 2026-10-15 round 2, C-10 carried ("one undocumented hop"),
plus three findings from a read of the worker's secret path on the same day.

## The defects, as verified

- **A plain map on the worker side.** The controller resolved secrets into
  `talos_workflow_engine_core::SecretMap` (`HashMap<String, Zeroizing<String>>`,
  2026-10-14) and sealed from it, but the worker opened every envelope
  (`EncryptedSecrets::decrypt*`) and every sealed claim
  (`secret_claim::process_reply` / `claim_secrets`) into a
  `HashMap<String, String>`, carried it through `TalosContext::new` and the
  six `execute_*` signatures, and wrapped each value in `Zeroizing` only in
  `TalosVaultProvider::from_resolved` — after the plain map had lived as long
  as the job. The pipeline path kept a plain copy on `PipelineStepSpec.secrets`
  for the whole run and cloned it on every attempt; a hand-written `Drop` on a
  `ZeroizingSecretMaps` newtype wiped what was not taken, and nothing wiped the
  copies. A standalone run (sandbox, `test_module`, replay, GraphQL
  `testModule`) had a declared plaintext exit, `into_runtime_secrets`, for the
  same reason: the runtime's parameter was plain.
- **A lease that gated nothing.** `talos_envelope_seal::RedisLease` (Lua CAS
  `dispatched → claimed:<worker>`, a live-Redis test, a documented fail-open
  `Unavailable` arm) had no caller: no `record_dispatch` where a seal context
  is registered, no `try_claim` in the responder, no re-dispatch on expiry.
  The RFC's own text says why it was never needed for single-claim — a
  `claim_inbox` is `nc.new_inbox()`, a NATS inbox of the dispatching
  replica's connection, so a claim can only reach the replica that holds the
  context and `InFlightSeals::take` is atomic there.
- **Only the controller was non-dumpable.** `prctl(PR_SET_DUMPABLE, 0)` was a
  private function in the controller's `main.rs`, written for the host-compile
  fallback. The worker, which holds every in-flight job's opened secrets and
  the fleet key, took no such posture; its container dropped no capability in
  the prod compose file (the Helm chart already dropped ALL).

## Decided

- **One type, from the store to the slot table.** `SecretMap` is re-exported
  by `talos_workflow_job_protocol` (worker-side crates reach core only through
  it). `EncryptedSecrets::{decrypt, decrypt_with_aad, decrypt_with_ring}`
  return it (the `zeroize` `serde` feature parses `Zeroizing<String>`
  directly); `process_reply` / `claim_secrets` return it and the pipeline
  claim parses `Vec<SecretMap>`; `TalosContext::new`, the six `execute_*`
  entry points and `PipelineStepSpec.secrets` take it;
  `TalosVaultProvider::from_resolved` and `build_provider` take it by move
  with no re-wrap; the sandbox merges the LLM-key cache's `Zeroizing` values
  in by move instead of cloning them plain. `into_runtime_secrets` and
  `ZeroizingSecretMaps` are deleted (`take_step_secrets` is the one-line
  `mem::take` that remains; the type does the wiping).
  `check_vault_refs_resolvable` is generic over the value type — it reads
  keys. The per-attempt clone in `execute_pipeline_step_attempt` stays: a
  retry needs the step's map again, and a clone of `Zeroizing` values is
  wiped with its context.
- **The lease is deleted, not relabelled.** Making its `Unavailable` arm
  fail-closed would have changed the posture of a check that never ran.
  `lease.rs`, its re-exports and the crate's `redis` / `talos-redis`
  dependencies are removed; the crate header, the RFC (a status note above
  the lease section, design text kept as the record), `THREAT_MODEL.md` and
  the extraction history (a correction line; the bullet stays byte-identical)
  say so.
- **One home for process posture.** `talos_config::process_posture::
  {make_process_non_dumpable, log_non_dumpable_outcome}`; the controller
  calls it where its private function was, the worker calls it before the
  fleet key is read and logs the outcome once tracing is up. The prod compose
  worker service drops ALL capabilities, as the chart does.
- **Check 107** (`scripts/lint-plain-secret-map.py`): a production line that
  names a secret and types `HashMap<String, String>` fails, in the fifteen
  crates a secret value passes through. Opt-out `// plain-secret-map:`, none
  today. CLAUDE.md's secret-handling rule names the type and the check.

## Deliberately NOT done

- **Wiring the lease** (record at registration, CAS in the responder, a
  sweeper that re-dispatches on expiry). Single-claim does not need it, and
  the crash case it was drawn for — a dispatched job whose replica dies before
  the claim — already resolves through the worker's claim timeout (fail-closed,
  no secretless run) and the existing `resuming` path, which issues a NEW
  dispatch with a new ephemeral. A Redis round trip per dispatch and per claim
  would have bought a second copy of a guarantee the inbox already gives.
- **`mlock` of the slot table.** Needs `IPC_LOCK`, which the chart drops with
  ALL; swap is off on the reference nodes. Not pursued without a measured need.
- **Per-path on-demand resolution over signed RPC** (the "v2" the provider's
  comment names) and an **egress proxy** that keeps plaintext out of the worker
  process entirely. Both reduce residency further at real cost (a round trip
  per secret; a TLS-terminating hop for all egress). Recorded as the next
  steps if the threat model asks for them; not this package.
- **A seccomp change.** The pod-level `seccompProfile: RuntimeDefault` already
  covers the worker container.

## Measured

- Check 107 on main @ `4424103c`: 16 lines in 10 files, all of the class, 0
  false positives; on this tree 0 (313 files read). Three more lines of the
  same defect sat on return-type lines without the word `secret` and were
  fixed by the type change but are outside the check's sight (stated in its
  limits).
- `TalosContext::new` has 98 call sites; all but the fixtures that insert a
  literal value compile unchanged (`HashMap::new()` infers the new type).
- `RedisLease`, `record_dispatch`, `try_claim`, `ClaimLeaseOutcome`: 0
  callers outside `lease.rs` across `talos-*/src`, `controller/src`,
  `worker/src`.

## Latent vs live

The plain map was live on every job the reference worker ran: under
`TALOS_ENVELOPE_SEALING=required` the sealed claim opened into a plain
`HashMap<String, String>` that lived until the context dropped (single node)
or the pipeline finished (chain; plus one plain copy per attempt). A process
memory dump during a run recovered that job's values; the type change does
not alter that window, it ensures the values are overwritten when their
owner drops and that no copy outlives its owner.

## Stated limits

- Plaintext still exists in the worker process for the life of a job — that
  is the design (a broker with opaque handles), and the README says so. What
  this package removes is the un-wiped copies and the per-attempt clones.
- `serde_json` reuses an internal scratch buffer when it unescapes a string;
  that buffer is not zeroized. Both the old and the new path share it.
- Tier-2 `expose-secret` still moves a value into guest memory the host
  cannot zero; unchanged, gated off at every dispatch site.

## Tests

- `worker::secret_claim::a_taken_step_map_leaves_nothing_behind` (the
  `mem::take`), `a_parsed_reply_holds_zeroizing_values` (pins the value type
  at the one place a sealed reply is parsed).
- `talos_config::process_posture::the_process_is_non_dumpable_afterwards`
  (Linux; moved from the controller).
- `scripts/lint-plain-secret-map.py --self-test` (a param, a return with
  spacing and path, a field, a line after a `#[cfg(test)]` module flagged; a
  doc line, a header map, a marked line, a test item, a `_tests.rs` file and
  an unlisted crate not).
- The envelope, provider, claim and vault-resolver test suites, re-typed to
  the new parameter where they inserted a literal value.

No mutation table: the guard here is a type. A `SecretMap` cannot be assigned
from a plain map, so the mutation (a plain parameter) is the compile error the
type exists to produce, and check 107 refuses the textual form.
