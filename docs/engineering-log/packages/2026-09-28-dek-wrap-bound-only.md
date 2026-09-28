# 2026-09-28 — only bound DEK wraps exist (RFC 0013, P3)

**Why.** Phase 1+2 (#967) bound every new DEK wrap to its `encryption_keys`
row and added `rebindDekWraps` for older rows. While an unbound row could still
be read, a writer able to change `encryption_keys` could mark a row
`wrap_format = 1` and plant an unbound blob copied from another row, which is
the swap RFC 0013 exists to stop. Phase 3 removes that path.

**Measured.** On the reference fleet, `rebindDekWraps` ran 2026-09-28 02:05 UTC:
`reboundCount: 2, remainingUnbound: 0`, both rows `wrap_format = 2`, two
`DEK_WRAP_REBOUND` audit rows (the global DEK's without an org, the org DEK's
naming it), both attributed to the operator. 0 unbound rows remain, so the
migration's guard passes here.

**Decided.**
- **Migration `20260928100000`**: a guard that counts non-bound rows and
  RAISEs, naming the fix (deploy phase 2, run `rebindDekWraps` until
  `remainingUnbound` is 0). Without it, a deployment that skipped the rebind
  would fail on a bare CHECK violation, or boot a controller unable to read its
  own keys. Then `CHECK (wrap_format = 2)` and `DEFAULT 2`.
- **Reader guard**: `dek_wrap::ensure_bound` refuses any stored format but 2
  at every read (`get_active_dek`, `get_dek`, `get_active_dek_for_org`) and in
  the rotation walk. It sits behind the CHECK on purpose, so a dropped
  constraint cannot quietly bring back an unbound read. `WrapFormat` and
  `aad_for` are deleted; `decrypt_dek` always uses `bound_aad()`.
- **Deleted, not kept around**: `rebindDekWraps`, `DekRebindResult`,
  `rebind_dek_wraps`, `count_unbound_dek_wraps`, the `encryption_keys.wrap` row
  of `dekMigrationStatus`, and the unbound-only walk. With the CHECK in place
  each could only ever answer 0. The GraphQL snapshot and codegen lose exactly
  what phase 2 added (30 SDL lines / 25 type lines).
- **Rotation** keeps the shared walk, renamed `rewrap_deks_under_active`,
  which rewraps bound-to-bound onto the new master key.
- **Provider level unchanged**: `KekProvider` still takes the AAD as a required
  argument, and an empty AAD is still a well-formed request. No
  `encryption_keys` path sends one.

**Deploy ordering.** Any order is safe: phase-2 controllers already write only
bound rows, and the migration only tightens the CHECK.

**Proof.**
- DB (`secrets_tests`, 24/24 single-threaded as CI runs it): the schema
  refuses `UPDATE … wrap_format = 1` and an unbound INSERT (23514), with an
  untouched row that still reads as the control. The migration, replayed on a
  recreated phase-2 database with one unbound row, stops with an error naming
  `rebindDekWraps`; after the row is bound it applies, and `CHECK
  (wrap_format = 2)` and `DEFAULT 2` are asserted from the catalog.
- Unit: `ensure_bound` refuses 0/1/3. A rotated wrap opens only under its own
  row's AAD (not another row's, not unbound). The interrupted-then-resumed
  rotation ends with every row under the new key.
- Mutations (crypto gate), 5 of 5 caught:

| Mutation | Caught by |
|---|---|
| reader accepts format 1 | `only_a_bound_wrap_is_accepted` |
| CHECK still admits 1 | both phase-3 DB tests |
| migration guard removed | migration test (the bare CHECK error does not name the fix) |
| `SET DEFAULT 2` removed | migration test |
| rotation rewraps with an empty AAD | two rotation unit tests |

**Stated limits.**
- **Measured survivor:** the reader guard is unobservable in a test while
  the CHECK holds. A format-1 row cannot be written, so deleting
  `get_dek`'s `ensure_bound` call passes the whole `talos-secrets-manager`
  suite and all 24 `secrets_tests`. It is defence in depth behind the schema, and
  the CHECK is what the DB tests pin.
- A superuser can drop the constraint and plant a row; the reader guard then
  refuses it at read time. That is the stated purpose of keeping both.
