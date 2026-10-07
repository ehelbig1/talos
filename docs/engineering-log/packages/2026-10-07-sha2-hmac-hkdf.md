# `sha2` 0.11, `hmac` 0.13, `hkdf` 0.13 (2026-10-07)

Backlog item, first of the encryption family
(`2026-10-06-major-version-backlog.md`). The three move together: HMAC and
HKDF are built over the hash, and the versions have to agree. Between them
they sign every job, result and worker-to-controller RPC, derive every
per-row and per-job encryption key, and hash every content digest and
lookup key in the workspace.

Nothing about SHA-256, HMAC or HKDF changed. What had to be shown is that
the bytes Talos produces did not.

## Pinned before the bump

Four known-answer tests for the HKDF derivations stored data depends on,
written and passing on the OLD versions first:

* the checkpoint key, v1 and v2 (`talos-engine`);
* the envelope key, v1 and v2 (`talos-workflow-job-protocol`);
* the per-context subkey of row formats v3 and v4 (`talos-secrets-manager`);
* the environment KEK's purpose key (`talos-secrets-manager`).

The expected values were not taken from the code under test. They were
computed by Python's standard `hmac` and `hashlib`, implementing RFC 5869
directly, over made-up inputs — so each test says "this is HKDF-SHA256",
not only "this is what it was yesterday". A derivation that drifted would
make every checkpoint and every sealed row unreadable, and no other test
would say so.

The signatures were already pinned: the job-protocol and memory-RPC
wire-format snapshots carry exact MAC bytes.

## Changed

* The three versions in the workspace table.
* Two API moves, applied at about 60 sites in 37 files:
  * `new_from_slice` comes from `KeyInit`, no longer from `Mac`;
  * a digest no longer implements `LowerHex`, so `format!("{:x}", …)` is
    `hex::encode(…)` (or the same loop where a crate has no `hex`
    dependency). Both render lowercase hex of the same bytes.
* The lockfile gains `hkdf` 0.13. `sha2` 0.11 and `hmac` 0.13 were already
  there for other crates; the 0.10 and 0.12 copies stay for third-party
  crates that still use them.

## Checked

On the new versions: the four known-answer tests; both wire-format snapshot
suites (22 tests); the audit-event suite, whose hash chain renders through
the changed formatting (45); the whole unit suite; the DB-free binaries;
lint; clippy.

## Not done

* The envelope-seal key (derived from an X25519 shared secret) has no
  known-answer test here: its input cannot be built from bytes. It belongs
  with the `x25519-dalek` change, which can pin the exchange end to end.
* `aes-gcm`, `ed25519-dalek` and `x25519-dalek` are the next two changes.
