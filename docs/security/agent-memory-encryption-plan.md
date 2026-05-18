# `actor_memory` at-rest encryption — implementation plan

**Status:** ✅ **COMPLETE** (Phase A shipped 2026-04-23; Phase B shipped 2026-04-24)
**Last updated:** 2026-04-24

> **This document is now historical.** The plan it describes has been
> fully implemented. Kept in the repo because it records the design
> rationale + the two-phase migration sequence we used — useful for
> operators reading the `20260423235406` + `20260424010000` migrations
> and for anyone repeating the pattern for another plaintext column.
>
> **Current state:** the `actor_memory.value` column is DROPPED. Every
> row carries `value_enc BYTEA NOT NULL` + `value_key_id UUID NOT NULL`
> (FK to `encryption_keys`). Writes flow through
> `talos_memory::register_memory_crypto_hook` — a worker / test harness
> without the hook registered will PANIC on any write, by design.
>
> Verification: `cargo run --example verify_phase_b -p controller`.
> Operational runbook §1 lists this row as ✅ in the protection matrix.

---

## 1. Why this mattered (background)

`actor_memory.value` was plaintext JSONB. Every actor's stored memories
— including semantic memories that carry PII, internal facts, recall
histories of sensitive conversations — sat decryptable in any Postgres
dump.

Threat scenario: attacker with read-only access to Postgres (leaked
backup, compromised replica, malicious DBA) extracts every memory
without needing the KEK.

Goal (achieved): bring `actor_memory.value` to the same encryption
posture as user secrets and OAuth tokens — envelope encryption via
`SecretsManager.encrypt_value` / `decrypt_value_by_key`.

---

## 2. Design

### 2.1 Schema change

New columns on `actor_memory`:

```sql
ALTER TABLE actor_memory
    ADD COLUMN value_enc       BYTEA,           -- AES-GCM ciphertext
    ADD COLUMN value_key_id    UUID;            -- FK to encryption_keys.id
-- `value` JSONB stays for the migration window; see §2.5 for cleanup.
```

The existing `embedding vector(768)` column is unaffected — embeddings
are computed from the plaintext at write time, then the plaintext is
discarded. Embeddings DO leak some signal about the underlying text
(via similarity search) but that's an inherent property of vector
search and out of scope for this plan.

### 2.2 Wire format

`value_enc` is the raw bytes returned by
`SecretsManager.encrypt_value(plaintext_str)` — the same envelope
format used for `webhook_triggers.signing_secret_enc` and
`oauth_tokens.token_enc`. The plaintext input is the JSON
serialization of the user-supplied value (so a `serde_json::Value`
becomes a `String` then encrypts as bytes).

### 2.3 Read path

```rust
pub async fn read_memory_value(
    secrets: &SecretsManager,
    row: &MemoryRow,
) -> Result<serde_json::Value> {
    if let (Some(enc), Some(key_id)) = (&row.value_enc, row.value_key_id) {
        let plaintext = secrets.decrypt_value_by_key(key_id, enc).await?;
        return Ok(serde_json::from_str(&plaintext).context("memory value JSON")?);
    }
    // Backward-compat: pre-migration rows still carry plaintext in `value`.
    Ok(row.value.clone().unwrap_or(serde_json::Value::Null))
}
```

**Invariant:** at least one of (`value_enc`+`value_key_id`) or `value`
must be non-null on every row. Migration enforces this; new writes
populate `value_enc`+`value_key_id` and leave `value` NULL.

### 2.4 Write path

```rust
pub async fn write_memory_value(
    secrets: &SecretsManager,
    plaintext: &serde_json::Value,
) -> Result<(Vec<u8>, Uuid)> {
    let json = serde_json::to_string(plaintext).context("serialize memory value")?;
    let (key_id, ciphertext) = secrets.encrypt_value(&json).await?;
    Ok((ciphertext, key_id))
}
```

Every write site (`set`, `store_with_embedding`, INSERT in repos)
calls this and binds the ciphertext + key_id, leaving `value` NULL.

### 2.5 Migration cleanup

After the dual-write window (suggest 2 deploys / 1 week to be safe),
backfill any remaining plaintext rows then drop the column:

```sql
-- Backfill (one-time, written as a Rust binary because per-row crypto):
--   for each row WHERE value_enc IS NULL:
--     fetch row.value
--     encrypt → (key_id, ciphertext)
--     UPDATE actor_memory SET value_enc=$1, value_key_id=$2, value=NULL WHERE id=$3

-- Then in a follow-up migration (after backfill verified):
ALTER TABLE actor_memory
    ALTER COLUMN value_enc SET NOT NULL,
    ALTER COLUMN value_key_id SET NOT NULL,
    DROP COLUMN value;
```

### 2.6 Performance considerations

- **DEK cache.** Every read calls `decrypt_value_by_key(key_id, ...)`
  which hits Postgres for the DEK ciphertext, decrypts via KEK, then
  decrypts the value. `SecretsManager` already has a DEK cache (5min
  TTL per memory — see `controller/src/secrets/mod.rs`); the per-DEK
  cost amortizes near-zero.
- **Per-row crypto.** Each value decrypt is one AES-GCM call —
  microseconds. Negligible vs the ~10-50ms a memory query takes for
  embedding similarity.
- **Bulk read paths** (e.g. `list_actor_memories` with no prefix)
  decrypt every row. Cap with the existing `limit` arg; consider
  decrypt-on-demand (decrypt the value only when the caller actually
  asks for it, return an empty preview otherwise).

### 2.7 Security properties

After migration:
- DB dump alone → memory values are sealed
- DB dump + KEK → memory values recoverable (same posture as secrets)
- Compromised controller process → can decrypt (necessary for the
  platform to function; mitigation is process isolation + KMS auth)

---

## 3. Code touch points (exhaustive list)

### 3.1 `talos-memory/src/lib.rs` (canonical surface)

Per `CLAUDE.md`: "Anything that needs to read or write `actor_memory`
MUST go through `talos_memory::*` functions." This is where the
encryption helper lives.

| Function | Action |
|---|---|
| `set` (line ~251) | INSERT `value_enc` + `value_key_id`, `value` NULL |
| `store_with_embedding` (line ~338) | Same as `set` |
| `get` (line ~381) | SELECT `value_enc`, `value_key_id` (and `value` for back-compat); decrypt |
| `recall` / `search` (line ~563+) | Decrypt each row's value before returning |
| `recall_semantic` / `recall_semantic_filtered` | Same |
| `forget*` | No change (only touches keys, not values) |

The helper should be a `pub(crate)` fn `encrypt_value` / `decrypt_value`
in `talos-memory/src/lib.rs` so all writers + readers in the crate
share one implementation.

### 3.2 `controller/src/actor_repository.rs`

| Function | Action |
|---|---|
| `clone_actor_memories` (line ~1454) | Bulk decrypt source + re-encrypt target. The current `INSERT ... SELECT` shortcut won't work post-migration — must round-trip through Rust. |
| Anything else that bypasses talos-memory | **Refactor to call talos-memory.** Per architectural mandate. |

### 3.3 `controller/src/api/schema/actors/{mutations,queries}.rs`

GraphQL handlers that read/write memory. Same pattern: route through
talos-memory or use the new helper.

### 3.4 `controller/src/scheduler.rs:516`

The reads are for context-injection at trigger time. Decrypt before
injection.

### 3.5 `controller/src/workflow_repository.rs:{1123,1210}`

Both are reads for `__actor_context__` injection. Decrypt before
returning.

### 3.6 `controller/src/{advanced,analytics}_repository.rs`

Two analytics queries that COUNT or aggregate memory. They don't
read `value`, only the `key` column → no change.

### 3.7 NEW: lint to prevent future drift

Add a build-time check (clippy lint or grep-based CI guard) that
flags any `INSERT INTO actor_memory` or `SELECT ... value ... FROM
actor_memory` outside the allowlisted helper functions. Same pattern
as the dynamic-SQL guard at `AdvancedRepository::execute_paginated_select`.

---

## 4. Migration sequence

Strict ordering matters — out-of-order steps will either lose data
or break the migration.

1. **Migration A (additive, backwards-compat):**
   ```sql
   ALTER TABLE actor_memory
       ADD COLUMN value_enc BYTEA,
       ADD COLUMN value_key_id UUID
       REFERENCES encryption_keys(id) ON DELETE RESTRICT;
   ```
2. **Code change A (dual-write, encrypted-preferred read):**
   - Writes populate `value_enc` + `value_key_id`, leave `value` NULL
   - Reads prefer `value_enc`, fall back to `value` for legacy rows
3. **Deploy A.** Verify new memories show NULL `value` + non-null
   `value_enc` in the DB; old memories still readable.
4. **Backfill binary** (Rust):
   - Iterate `WHERE value_enc IS NULL AND value IS NOT NULL`
   - Decrypt-equivalent (just JSON serialize), encrypt, UPDATE
   - Run in batches of ~1000 with explicit transactions; resume-safe
   - Log + verify counts before/after
5. **Verify post-backfill:**
   ```sql
   SELECT COUNT(*) FROM actor_memory WHERE value_enc IS NULL;  -- should be 0
   SELECT COUNT(*) FROM actor_memory WHERE value IS NOT NULL;  -- legacy plaintext residue
   ```
6. **Migration B (terminal, non-reversible):**
   ```sql
   ALTER TABLE actor_memory
       ALTER COLUMN value_enc SET NOT NULL,
       ALTER COLUMN value_key_id SET NOT NULL,
       DROP COLUMN value;
   ```
7. **Code change B (drop fallback):** remove the `value`-column
   read path. All reads now require ciphertext.
8. **Deploy B.** Final state.

### Rollback

- After step 3 (code change A deployed): revert the deploy. Both
  columns coexist; reads still work because legacy rows still carry
  `value`. New rows have NULL `value` but their `value_enc` is
  ignored by reverted code → those new rows become unreadable.
  **Mitigation:** before reverting, dump the affected `value_enc`
  rows to a side table and decrypt them back into `value`.
- After step 6 (terminal migration): no clean rollback. The column
  is gone. Restore-from-backup is the only option. Run the backup
  verification drill (`operational-runbook.md` §2.6) immediately
  before this migration.

---

## 5. Test plan

### 5.1 Unit tests (talos-memory)

- `set` → `get` round-trip: arbitrary JSON value comes back equal
- `set` → DB inspection: row has `value_enc` non-null, `value` NULL
- `get` on a legacy-plaintext row (manually inserted via raw SQL with
  `value` set): returns the plaintext via fallback path
- `decrypt_value_by_key` failure (DEK rotated away, ciphertext
  unreadable): returns clear error, doesn't crash

### 5.2 Integration tests

- Full workflow with `inject_memory_context: true` — context appears
  un-redacted in `__actor_context__` (post-decrypt)
- `agent_memory::search` from inside a WASM module — receives
  un-redacted hits
- `clone_actor` copies memories AND they remain decryptable on the
  clone (verifies `value_key_id` is preserved through the bulk path)

### 5.3 Migration tests

- Run migration A on a snapshot of staging data; verify schema only
- Run backfill on a snapshot of staging; verify zero rows left with
  NULL `value_enc` AND non-null `value`
- Spot-check 10 random rows post-backfill: decrypt + JSON-parse
  matches the pre-backfill plaintext

### 5.4 Performance regression

- Measure `recall_semantic` p50 + p99 latency before + after
- Acceptance: ≤ 5% slowdown (per-row AES-GCM is microseconds; the DEK
  cache should make this nearly free)

---

## 6. Acceptance criteria

Done when:
- [ ] All 7 migration steps deployed
- [ ] `actor_memory.value` column dropped
- [ ] `actor_memory.value_enc` and `value_key_id` are NOT NULL on all rows
- [ ] No `INSERT INTO actor_memory` or `SELECT ... value ... FROM
      actor_memory` exists in the codebase outside talos-memory's
      allowlisted helpers (verified by grep + CI lint)
- [ ] All integration tests pass
- [ ] Performance regression ≤ 5%
- [ ] `operational-runbook.md` §1 matrix updated to ✅ for actor memory
- [ ] Backup verification drill (§2.6 of runbook) re-run with new schema

---

## 7. Out of scope for this work

Things that COULD be improved but are not required for this milestone:

- **Embedding privacy.** Vectors leak signal. Not addressed here.
- **Per-actor encryption keys.** Currently all DEKs are user-scoped;
  per-actor scoping would limit blast radius further but adds
  significant complexity. Defer.
- **Searchable encryption.** Current scheme requires plaintext for
  semantic search (we have it because we did the embedding at write
  time). True encrypted search needs homomorphic / OPE schemes — far
  out of scope.
- **GDPR right-to-erasure.** Currently `delete_actor_memory` removes
  rows but the DEK that encrypted them stays alive. For irreversible
  erasure, you'd want to prove the DEK has been destroyed (key
  shredding) — out of scope.

---

## 8. References

- `docs/SECRETS_MANAGEMENT.md` — envelope encryption architecture
- `docs/security/architecture.md` — overall security architecture
- `docs/security/operational-runbook.md` §1 — current at-rest matrix
- `controller/src/secrets/mod.rs` — `SecretsManager.encrypt_value`,
  `decrypt_value_by_key`, DEK cache
- `controller/src/api/schema/webhooks/mutations.rs:97-105` — reference
  pattern for using `SecretsManager.encrypt_value`
- `talos-memory/src/lib.rs` — canonical R/W surface for memories
