# RFC 0013 — Bind each wrapped DEK to its own row

**Status:** In progress — P1 + P2 implemented (2026-09-27); P3 waits for the rebind to run
**Author:** Platform
**Date:** 2026-09-26

## Motivation

`encryption_keys.encrypted_key` holds each data-encryption key (DEK) wrapped by
the KEK: AES-256-GCM over the 32 key bytes (`EnvKekProvider`), or Vault transit
encrypt (`VaultTransitProvider`). **The wrap carries no associated data.** A
wrapped blob therefore unwraps successfully under the KEK whatever row it is
stored in: nothing ties the ciphertext to the `id` and `org_id` beside it.

#960 added the read-side check `secret_dek_scope_mismatch`: a v3 secret must name
a global DEK and a v4 secret its own org's. That check trusts the row's
`org_id` LABEL. It cannot see a row whose label is right and whose blob came from
another row.

**The attack this closes.** An attacker who can write `encryption_keys` but does
not hold the KEK (a compromised database credential, a SQL injection, a
restored-from-elsewhere backup) copies org A's wrapped DEK into org B's active
row. Every later v4 write for org B is then sealed under org A's key, and anyone
holding org A's key material can read it. Swapping the global DEK into an org row
(or the reverse) does the same across the global/org boundary. Today every such
swap unwraps cleanly and is silent. With the row's identity bound as AAD, it
fails to unwrap, loudly, on first use.

**What it does not buy, stated.** Nothing against a KEK compromise, and nothing
against an attacker who can already run code in the controller. It is integrity
of the key-to-row binding, not confidentiality.

**Measured on the reference fleet, 2026-09-26.** Two DEK rows, both active: one
global, one org, both created 2026-07-08, each 60 bytes (12-byte nonce + 32 + 16
tag). The migration population is two rows. Latent: no swap has been observed,
and it could not have been, because nothing would detect one.

## Design

### AAD

```
aad = "talos-dek-wrap/v2" || key_id (16 bytes, big-endian UUID)
      || 0x00                        (global DEK)
      || 0x01 || org_id (16 bytes)   (org DEK)
```

Fixed-length fields and an explicit scope tag, so no two `(key_id, org_id)`
pairs share an encoding. `algorithm` is deliberately NOT bound: it has one value
(`AES-256-GCM`) and binding it would force a rewrap on any future algorithm
migration for no gain.

### Provider surface

`KekProvider::{wrap_dek, unwrap_dek}` gain an `aad: &[u8]` parameter. They are
not given parallel `_bound` methods, because a second method pair would let a
new call site pick the unbound one by accident.

- `EnvKekProvider`: `aes_gcm::aead::Payload { msg, aad }`. The wire layout
  (`nonce || ciphertext`) is unchanged.
- `VaultTransitProvider`: base64 `associated_data` on transit encrypt and
  decrypt. It is supported for AEAD key types; the deployment creates
  `transit/keys/<name>` with the default type, `aes256-gcm96` (compose,
  `vault-init.sh`, `manual-vault-init.sh`). To be verified against Vault 1.18
  in phase 1 with the live-Vault test.

Legacy rows are read with an empty `aad`, which is what AES-GCM and transit do
today. So an empty AAD is byte-compatible with every existing blob.

### Schema

`encryption_keys.wrap_format smallint NOT NULL DEFAULT 1` with
`CHECK (wrap_format IN (1, 2))`. `1` = unbound (legacy), `2` = AAD-bound.

- Every writer stamps `2`, and all four (`create_new_dek`,
  `create_new_dek_for_org`, `rotate_dek`, `rotate_dek_for_org`) must generate
  the `id` BEFORE wrapping, because the id is part of the AAD. Today
  `create_new_dek` takes it from `RETURNING id`, and the other three call
  `Uuid::new_v4()` only after the wrap.
- `decrypt_dek(key_id, org_id, encrypted_key)` already receives both inputs. It
  gains `wrap_format`, one `SELECT` column added to the existing reads.

### Migrating existing rows

Proposed: an explicit, idempotent **rebind** under the existing master-key
rotation lock. For each `wrap_format = 1` row: unwrap with the empty AAD, rewrap
under the same KEK with the row's AAD, `UPDATE … SET encrypted_key, wrap_format
= 2 WHERE id = $1 AND wrap_format = 1`. The DEK bytes do not change, so no data
row is re-encrypted and the DEK cache stays valid. `rewrap_under_active`
(master-key rotation) always writes format 2, so a rotation also migrates.

The #960 record suggested waiting for the next master-key rotation instead. On
this fleet that has never happened and has no schedule, so the binding would
stay off indefinitely. Hence the explicit rebind.

### Closing the downgrade

While any format-1 row exists, a writer can set `wrap_format = 1` and plant an
unbound blob copied from another row. The protection is complete only when
format 1 is refused:

1. `dekMigrationStatus` gains a `dek_wraps_unbound` count.
2. A migration `CHECK (wrap_format = 2)` refuses new format-1 rows. It fails
   loudly on any deployment that still has one.
3. The code deletes the format-1 unwrap arm in the same release.

## Phases

| Phase | Ships | Reversible? |
|---|---|---|
| P1 | column + dual-format read + every writer stamps 2 + AAD in both providers | yes: format-1 rows untouched, format-2 rows readable only by P1+ code (**roll controllers together**) |
| P2 | rebind operation (platform-admin, 2FA, recorded in `admin_event_log` in its transaction) + status count | yes (rows stay readable by P1+) |
| P3 | `CHECK (wrap_format = 2)` + format-1 unwrap removed | no: requires every deployment to have rebound |

## Tests

- Swap tests, the reason this exists: org A's format-2 blob in org B's row,
  global's blob in an org row, and an org blob in the global row must each fail
  to unwrap. Each must be shown passing on pre-P1 code, i.e. undetected today.
- Mutation proof (crypto gate): drop `org_id` from the AAD, drop `key_id`, use an
  empty AAD for format 2, and have the rebind skip its `WHERE wrap_format = 1`
  guard.
- Round trips for both providers; the Vault one in the live-Vault test binary.

## Decisions (operator, 2026-09-27)

1. **An explicit, audited rebind**, not waiting for a master-key rotation.
   `rebindDekWraps` rewraps under the exclusive rotation lock and writes one
   `DEK_WRAP_REBOUND` `secret_audit_log` row per DEK (naming its org) in the
   transaction that rewraps it. A master-key rotation binds too: it shares the
   same rewrap routine.
2. **P3 follows one release after the rebind has run**: `CHECK (wrap_format = 2)`
   and the format-1 unwrap arm removed.
3. **Platform admin with a verified second factor, API keys refused**
   (`require_second_factor` + `require_scope(Admin)` + `require_platform_admin`),
   the same authority as every other key operation.

## Open questions for the operator (answered above)

1. **Rebind operation, or piggyback on the next master-key rotation only?**
   The recommendation is the explicit rebind (above).
2. **P3 timing.** P3 needs every deployment rebound. With one deployment it can
   follow P2 by one release.
3. **Scope of P2's caller:** platform admin with a 2FA-verified session, like
   `rotateOrgDek` (package CE's authority model). Recommended as is.
