# Rotating `WORKER_SHARED_KEY` (rolling, zero-downtime)

How to rotate the worker shared key without a simultaneous fleet restart,
without rejecting in-flight jobs, and without stranding encrypted checkpoints
or secrets.

This procedure depends on the **key-ring** support (`WorkerKeyRing`): every
verifier/decryptor accepts a set of keys while every signer/encryptor uses
exactly one current key. It mirrors the worker's `AotKeyRing` for AOT blobs.
If your build predates the ring, you must use the old coordinated-restart
method (stop all controllers and workers, swap the key, start them) — a hard
outage window. Check for the ring by confirming `WORKER_SHARED_KEY_PREVIOUS`
is read at startup (grep the worker/controller logs for `verify_key_count`).

## What the key protects

`WORKER_SHARED_KEY` is the 32-byte root behind five primitives. Each is either
a **signature** (HMAC) or an **encryption** (AES-256-GCM HKDF subkey):

| Primitive | Type | Signs/encrypts | Verifies/decrypts |
|---|---|---|---|
| memory/graph/database/state/integration RPC | HMAC | worker | controller |
| `JobRequest` / `PipelineJobRequest` | HMAC | controller | worker |
| `JobResult` / `PipelineJobResult` | HMAC | worker | controller |
| `encrypted_secrets` (per-job secret envelope) | AES-GCM | controller | worker |
| execution checkpoints (durable resume state) | AES-GCM | controller | controller (at rest) |

The ring is read from two environment variables on **both** the controller and
every worker:

* `WORKER_SHARED_KEY` — the current key. Used to sign and encrypt. (64 hex
  chars = 32 bytes. `WORKER_SHARED_KEY_FILE` is also honored for Docker/K8s
  secrets.)
* `WORKER_SHARED_KEY_PREVIOUS` — optional, comma-separated list of previous
  keys accepted **for verification and decryption only**. Empty/unset off
  rotation.

## Why it's two phases, not one

The encryptor and decryptor of a given primitive are **different processes**
(controller encrypts secrets → worker decrypts; controller signs jobs → worker
verifies; worker signs results → controller verifies). A ring only rescues
material produced under a key the *other* side already accepts. So you must
make the new key **accepted everywhere before it is used anywhere**:

* **Phase 1 (accept-new):** add the new key as a *previous* (accepted) key on
  every process, while still signing/encrypting with the old key.
* **Phase 2 (seal-new):** flip the current key to new on every process, keeping
  the old key accepted for in-flight/at-rest material.
* **Phase 3 (drop-old):** remove the old key once nothing signed/encrypted
  under it is still in flight or at rest.

Doing Phase 2 before Phase 1 has fully rolled out is the one dangerous mistake:
a process signing/encrypting with `new` while another process only accepts
`old` will reject those messages (HMAC) or fail to decrypt (AES-GCM). For the
HMAC paths the blast radius is bounded (rejected requests retry; freshness
window is ~60 s). For the **AEAD paths it is not** — an `encrypted_secrets`
payload or a checkpoint sealed under a key the reader doesn't hold fails
closed permanently. Order matters most for secrets and checkpoints.

## Procedure

Let `OLD` = the current key, `NEW` = a freshly generated key
(`openssl rand -hex 32`).

### Phase 1 — accept the new key everywhere

On the controller **and** every worker, set:

```
WORKER_SHARED_KEY=<OLD>
WORKER_SHARED_KEY_PREVIOUS=<NEW>
```

Roll the fleet (any order; workers-first or controller-first are both safe —
nothing is signed/encrypted under `NEW` yet). After the roll, every process
*accepts* both keys but still *produces* under `OLD`.

**Verify before proceeding:** in the startup logs of every controller and
worker, confirm:

* `worker_shared_key_fp=<fp(OLD)>` matches across the whole fleet (the current
  signing key is still `OLD` and consistent), and
* `verify_key_count=2` with a `previous_worker_shared_key_fp=<fp(NEW)>` line
  (the new key is staged).

The fingerprint is `worker_key_fingerprint()` — the first 8 hex chars of an
HMAC of the key; it never reveals the key bytes. `fp(OLD)`/`fp(NEW)` below
mean those computed fingerprints. Do **not** advance to Phase 2 until every
node reports `NEW` staged. (If even one worker still has `verify_key_count=1`,
a job sealed under `NEW` in Phase 2 could reach it and fail.)

### Phase 2 — seal under the new key everywhere

On the controller **and** every worker, swap:

```
WORKER_SHARED_KEY=<NEW>
WORKER_SHARED_KEY_PREVIOUS=<OLD>
```

Roll the fleet. Now everything is signed/encrypted under `NEW`; `OLD` stays
accepted so in-flight jobs and at-rest checkpoints/secrets produced in Phase 1
still verify/decrypt.

**Verify:** `worker_shared_key_fp=<fp(NEW)>` fleet-wide, `verify_key_count=2`,
`previous_worker_shared_key_fp=<fp(OLD)>`.

### Phase 3 — drop the old key

Wait until nothing produced under `OLD` is still live:

* In-flight HMAC messages drain within the freshness window (~60 s after the
  last `OLD`-signed dispatch).
* `encrypted_secrets` live only for a job's duration — drained once all jobs
  dispatched in Phase 1 complete.
* **Checkpoints are the long pole.** A `waiting` (approval-gate) or `resuming`
  execution may hold an `OLD`-sealed checkpoint indefinitely. Drain or
  complete all `waiting`/`resuming` executions, or accept that any still
  holding an `OLD` checkpoint will resume from scratch (re-running
  already-completed, possibly side-effecting nodes — at-least-once) once `OLD`
  is removed.

Then set on every process:

```
WORKER_SHARED_KEY=<NEW>
# WORKER_SHARED_KEY_PREVIOUS unset
```

Roll the fleet. **Verify:** `verify_key_count=1` fleet-wide. Rotation complete.

## Verification cheatsheet

Grep both controller and worker logs at startup:

```
worker_shared_key_fp=        # current signing-key fingerprint — must match fleet-wide
verify_key_count=            # 1 off-rotation, 2 mid-rotation
previous_worker_shared_key_fp=  # one line per staged previous key
```

A fleet-wide `worker_shared_key_fp` **mismatch** at any time means two
processes disagree on the current key — every signed RPC/job between them will
fail until corrected. This is the single most important signal; it surfaces a
config-drift bug that otherwise appears only as opaque "signature verification
failed".

## Failure modes & recovery

* **A worker rejects jobs with "signature verification failed" after Phase 2.**
  That worker didn't get `NEW` staged in Phase 1 (or wasn't rolled). Add `NEW`
  to its `WORKER_SHARED_KEY_PREVIOUS` and restart it; re-run Phase 1 verify.
* **`CRASH-RECOVERY: checkpoint present but failed to decrypt …` in controller
  logs.** A checkpoint sealed under a key the controller no longer holds —
  almost always `OLD` removed too early in Phase 3 while a `waiting`/`resuming`
  execution still held an `OLD` checkpoint. Recovery: re-add `OLD` to
  `WORKER_SHARED_KEY_PREVIOUS` and restart the controller; the execution will
  decrypt and resume. If `OLD` is unrecoverable, that execution resumes from
  scratch (at-least-once).
* **Botched single-phase swap (skipped Phase 1).** Symptoms: mass job rejection
  and/or secret-decrypt failures during the roll. Recovery: re-add the other
  key to `WORKER_SHARED_KEY_PREVIOUS` everywhere (effectively retrofitting
  Phase 1), restart, then resume the procedure in order.

## Notes

* `WORKER_SHARED_KEY_PREVIOUS` may list more than one key (comma-separated) if a
  prior rotation didn't fully complete — verification/decryption tries each.
  Keep the list short; each entry is one extra HMAC/GCM attempt per message and
  one more key whose compromise would be accepted.
* Signing/encryption **never** uses a previous key — only the current
  `WORKER_SHARED_KEY`. A staged previous key cannot be used to forge new
  traffic; it only widens what is *accepted*, bounded by your removal of it in
  Phase 3.
* The same env-var convention drives the in-cluster Postgres / Neo4j / bootstrap
  secret rotation auto-bounce (MCP-1231): a `helm upgrade` that changes the
  secret content rolls the dependent pods automatically. Stage the key values
  in those secrets and let the checksum-annotation bounce roll the fleet.
* This rotates the *shared key* only. The AOT-blob integrity key
  (`TALOS_AOT_HMAC_KEY` / `TALOS_AOT_HMAC_KEY_PREVIOUS`) rotates by the same
  two-phase ring pattern, independently — see the `AotKeyRing` rotation note in
  `worker/src/runtime.rs`.
