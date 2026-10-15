# Worker residue: the send goes where the gate judged, the preopen is counted, a hint is a world (2026-10-15)

Security review 2026-10-15 (round 2), findings **E2-1**, **E2-2** (with the
carried **E-8**), **E2-3**, **E2-5**, **E2-7** (Low/Info), **E2-6** (decision),
**E2-4** (record correction). Package R7 of the round-2 remediation.

## The defects, as verified

- **E2-1.** `wasi:http`'s gate admits the guest's `authority`; upstream builds
  the URI it sends from scheme + authority + path, and Talos never compared the
  two (RUSTSEC-2026-0350 was that builder sending to another host).
- **E2-2 / E-8.** A `filesystem` / `automation` world gets a read-write WASI
  preopen of the sandbox directory; writes through `wasi:filesystem` bypassed
  both the per-execution cap (64 MiB) and the process budget (768 MiB), which
  are counted only by `talos:core/files` — bounded only by the pod's `/tmp`
  `sizeLimit`, whose breach evicts the worker and every job on it.
- **E2-3.** `req.capability_world.as_deref().and_then(|s| s.parse().ok())` —
  and the parser maps any unknown string to `Unknown`, which the runtime reads
  as "no hint" — so a signed hint naming no world this worker knows fell back
  to the binary's inspected world.
- **E2-5.** A sealed result-cache entry's freshness lived only in Redis's
  `SETEX`; a Redis writer could re-`SET` a captured genuine entry with a longer
  TTL and pin a stale output.
- **E2-7.** When a component has imports, the inspector's whole-binary sentinel
  scan OVERRODE the import-derived world: a binary importing `secrets` with the
  minimal sentinel embedded inspected as `Minimal`.

## Decided

- **E2-1:** the admission computes the destination as `host:port`
  (`destination_key`, WHATWG-normalised, the scheme's port when none is
  written); `gated_handle` records it in the execution's
  `HardenedWasiHttpHooks`; `send_request` refuses (`HttpRequestDenied`, before
  any connection) a request whose URI names a `host:port` not admitted. The set
  is bounded by the per-execution call budget, charged before a destination is
  added. Talos's own comparison, not a trust in upstream's builder.
- **E2-2:** the epoch-deadline callback (`epoch_budget::arm_epoch_deadline`,
  which already runs every tick of guest execution for cancellation) measures
  a preopen world's sandbox every `FS_PREOPEN_CHECK_EVERY_TICKS` (5 ticks,
  500 ms): its apparent size past `MAX_FS_BYTES_PER_EXECUTION` stops the guest;
  what it holds beyond the bytes `talos:core/files` already reserved is reserved
  against the process budget (returned when the store drops), and a growth
  that does not fit stops it too. The stop carries `FS_PREOPEN_OVER_CAP_MESSAGE`
  (`talos:fs-cap`), recognised by all four trap arms as the cancel marker is.
  A walk stops early past the cap or past 50 000 entries (a guest cannot make
  the check expensive; more entries is treated as over quota). Chosen over a
  byte-counting `wasi:filesystem` wrapper: wasmtime's filesystem host has no
  quota hook, and the callback is the one place every preopen guest re-enters
  host code.
- **E2-3:** `job_world_hint` — `Ok(None)` for no hint, a known world, or a
  REFUSAL (`capability-world-unrecognised`, a signed `Failed` before anything
  is instantiated, audit WARN) for an unknown string or `Unknown`.
- **E2-5:** a sealed entry is `{"v": output, "exp": unix seconds}`, sealed
  with `WASM_RESULT_CACHE_TTL_SECS`; `open` refuses `exp < now` whatever Redis
  holds. Format `talos-rc2:`; `rc1` entries are misses (one execution each).
  The cache key (`module_hash ‖ context_hash`) was already the AAD.
- **E2-7:** with imports present, the sentinel may RAISE the world to one that
  covers the imports (`sentinel_never_narrows`), never lower it. The sentinel
  is a `#[used]` data-segment static the SDK macro emits, not a custom section;
  moving it would change every compiled module and the recorded macro
  expansions, so the scan stays whole-binary and the import-derived world wins
  on disagreement. The DCE fallback (no imports) is unchanged.
- **E2-6 — operator decision, not built.** Worker and controller share one
  Redis credential. Everything the WORKER reads back is sealed or re-verified,
  but a compromised worker can write keys the CONTROLLER reads. The fix is a
  per-role Redis ACL (or a separate instance) in the chart and both compose
  files. It is not built here: the worker's key families, measured —
  `wasm:result:*`, `oci_cache:*`, `talos:jobnonce:*`, `talos:idem:job:*`,
  `talos:idem:pipe:*`, `talos_cache:*`, `talos:tier2_expose:*`, plus the
  local-inference fleet queue's keys (`worker::local_llm_fleet`) — must all be
  in the ACL, and one missed prefix stops every dispatch (the replay guard
  fails closed). It needs a deploy test this session cannot run. Recommended:
  an ACL user per role, the list above as the worker's key patterns, and a
  chart test that the two credentials differ.
- **E2-4:** the 2026-10-14 record's "`capability_world` is not HMAC-bound" is
  corrected there (it is bound since H-3).

## Tests

- `host::wasi_http::tests::a_request_sent_to_another_destination_than_the_admitted_one_is_refused`
  (a counting loopback listener under the loopback opt-in: refused, zero
  connections; reached once admitted). The existing hooks tests now admit
  their destination.
- `epoch_budget::tests::a_preopen_sandbox_past_the_cap_is_refused` (a 65 MiB
  sparse file stands in for a guest's write; host-reserved bytes are not
  reserved twice).
- `result_publish_tests::an_unrecognised_world_hint_is_refused_not_dropped`
  (`worker`).
- `result_cache_seal::tests::an_entry_past_its_sealed_expiry_is_ignored`.
- `talos-wit-inspector`: `a_sentinel_never_narrows_the_world_the_imports_need`,
  `a_secrets_importing_component_with_the_minimal_sentinel_inspects_as_secrets`
  (a real component built with `wat`).

## Mutation proof

| Gate | Mutation | Test | Verdict |
|---|---|---|---|
| send only where admitted (egress) | `sends_where_admitted(…) \|\| true` | `a_request_sent_to_another_destination_than_the_admitted_one_is_refused` | FAIL / PASS restored |
| sentinel never narrows (capability world) | the sentinel always wins | both inspector tests | FAIL ×2 / PASS restored |

## Stated limits

- E2-2 measures every 500 ms of guest execution: a guest can write up to that
  interval's worth past the cap before it is stopped (the host functions
  refuse up front). A guest blocked in a host call is measured on its next tick.
- E2-6 above.

## Correction, 2026-10-15 (R11)

The E2-6 key-family list above is incomplete: the worker also READS
`wasm:{user}:{module}` (the module bytes the controller caches for a
`redis:wasm:` URI) and WRITES `approval:{id}` (an approval's reply topic, which
the controller reads). The per-role Redis user was then built
(`2026-10-15-worker-redis-user.md`), from an inventory that covers both and
pinned to the code by `worker/src/redis_acl_contract.rs`.
