# A memory writer can confirm a value without rewriting it (2026-10-03)

**The problem.** A freshness contract (`requires_fresh`) measured the time
since a memory key was last WRITTEN. A full write costs an embedding and a
graph extraction, so a store that is read often and changes rarely — the
personal list behind the morning message, rewritten only on change by a
capture loop that runs every 30 minutes — was written only when it changed.
On a quiet day it read as stale, so it could not carry a contract, and the
morning message could not tell "nothing changed" from "the capture loop has
stopped". Recorded as workflow-building pain point 37.

**Decision: the platform decides "unchanged", not the module.** A new
`__memory_write__` field, `skip_if_unchanged: true`. The writer sends its full
value every run; the platform compares it with the live row (decrypted value,
memory type and metadata). Equal: nothing is rewritten — same ciphertext, no
embedding, no graph extraction, `updated_at` untouched — and the row gets
`checked_at = now()` and a renewed expiry. Not equal, absent, unreadable, or
expired between the read and the mark: an ordinary write.

**Rejected alternatives.**
* A separate "touch" protocol key (`__memory_checked__`): a new module output
  protocol would need its own write-ceiling gating at both engine sites, the
  hook and the audit probe — the #750 class. The envelope field inherits the
  existing gates unchanged.
* An envelope that says "unchanged" WITHOUT the value: on a controller that
  does not know the field (a rollback), it would write `null` over the store.
  Sending the value means an old controller just writes it again.
* A heartbeat key: an embedding and a graph extraction per run, which is the
  cost being avoided.

**Freshness.** `talos_memory::key_freshness` reads
`GREATEST(updated_at, checked_at)`. `updated_at` keeps meaning "when the value
last changed"; ranking, consolidation and every other reader are unaffected.

**Schema.** Migration `20261003100000`: nullable `actor_memory.checked_at`, no
default (catalog-only change). NULL means never confirmed this way; readers
fall back to `updated_at`.

**Refusal.** A non-boolean `skip_if_unchanged` drops the write with a WARN and
`talos_memory_write_failures_total{reason="validation"}` rather than being read
as `false`.

**Tests.** Two added to `talos-memory/tests/integration.rs` against a real
database: an unchanged value keeps its ciphertext and `updated_at`, gains
`checked_at`, renews its expiry, and `key_freshness` reports the check; a new
value, new or removed metadata, another memory type and an absent key are each
written. Breaking the equality check fails the first. Unit test for the flag
parsing.

**Stated limits.** The comparison costs one read and one decrypt per write on
the flagged path. Two writers racing between the read and the mark can mark a
just-changed row as checked; the value itself is never lost. The hook branch
is not driven end to end by a test.

**Adoption.** No module uses the flag yet. The personal list's capture step
will, after this deploys — not before: on a controller without the field the
flag is ignored and the write simply happens, which is safe but pointless.
