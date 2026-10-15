# One rule for managing a secret, one for reading it; nonces from one source (2026-10-14)

Security review 2026-10-14, findings **C-2**, **C-3**, **C-4** (Medium) and
**C-5**, **C-6**, **C-7**, **C-9**, **C-10**, **C-11**, **C-12** (Low).
Package 10 of the review's remediation.

## Measured on the reference deployment (read-only)

- `secrets`: 36 rows; 0 with no owner; 0 whose creator differs from its owner;
  6 org-scoped, all in personal orgs whose owner is the only member. Row
  security is enforced (`TALOS_RLS_SET_ROLE=true`).
- `actors.secret_grants`: 0 entries across 13 actors.
- Format label vs DEK kind, every AEAD table: 0 mismatches except
  `module_executions`, where **2 of 103 028** rows (2026-09-10) are labelled
  v4 under the GLOBAL DEK — the C-6 mislabel had already happened, which the
  review called "consistent by construction today".

## Decided

- **C-2.** Two SQL fragments, built by macros so each statement stays a
  `&'static str` literal (`talos_secrets_manager::secret_predicates`):
  `may_manage_secret!` — a personal row is its owner's (a legacy row with no
  owner, its creator's); an org row is any CURRENT member's, membership read in
  the statement or from the caller's call-time list — and
  `may_dispatch_read_secret!` — global rows, and the user's own rows, an org
  row only while the user is still a member of its org. Applied to the dispatch
  reads (module grant, path grant, the readable-path listing and existence
  check), get/update/delete by path, the by-id rotate/expiry/namespace/delete,
  the listings, the metadata reads and the audit read. Name and key-path
  identity lookups (`resolve_to_id`'s name variants, upsert, collision
  checks) stay creator-scoped; every by-id operation they lead to applies the
  manage rule again.
  Migration `20261014190000` narrows the row-security policy's creator arm to
  ownerless rows. **The policy's owner arm is NOT narrowed for org rows**: the
  by-id statements open a session scoped to the user alone (no org GUC), and
  without that arm an owner could not rotate a secret in their own personal
  org. The app rule refuses a departed member; the backstop does not yet.
- **D-4 (operator decision, not built):** another member's org secret is not
  read into a member's dispatch. Pinned by
  `another_members_org_secret_is_not_read_into_a_dispatch`, so changing it is
  a decision. Recommendation: keep it so until a member-visible "org secret"
  concept exists in the UI; an org arm on reads would hand every member's
  modules every org credential.
- **C-3.** Deleted, not wired: the MCP tool `grant_secret_access`, its
  repository write, the summary field, the clone copy (`secret_grants_copied`)
  and the column (migration `20261014190500`). Nothing consulted it. The
  review's proposed lint ("every column a `*_grant*` tool writes has a reader")
  was not built: with the tool gone it has no subject.
- **C-4 / C-11.** Every audit insert stores `key_hash` (hex SHA-256 of the
  path, read from the row at insert time; migration `20261014191000` adds and
  backfills it), and every secret a dispatch is handed — by module grant or by
  path — gets one `dispatch_read` row (`actor_type = 'dispatch'`, the user,
  the module) in the same statement as the access counter. The audit read uses
  the manage rule, so its visibility is the secret's. CLAUDE.md's sentence
  "Audit logs record `key_hash`" is now true.
- **C-5.** The four replay-nonce sites use `talos_random::bytes::<16>()`;
  `talos-workflow-job-protocol` no longer depends on `rand`. **Lint check 100**
  (clippy `disallowed-methods`: `rand::rng`, `rand::random`), sanctioned for
  tests and the one marked retry-jitter use.
- **C-6.** The payload bundle records the version the encryption RETURNED,
  and refuses a write whose returned version differs from the one the slot AAD
  was built for (relabelling cannot fix an AAD that names the other version).
- **C-7.** `decrypt_versioned` refuses a v3 row naming an org DEK (a row
  claiming the global scope); `decrypt_versioned_scoped(.., row_org_id)` runs
  the full `dek_scope_matches_row` check. A v4 row under the GLOBAL DEK is not
  refused by the unscoped form: it crosses no tenant, and the 2 measured rows
  would become unreadable.
- **C-9.** OAuth state, login binding and connect binding nonces are 32 bytes
  of `talos_random`, hex (the same 64-character shape). `oauth_state_tokens`
  has row security (migration `20261014191500`): a session scoped to a user
  sees that user's rows only.
- **C-10.** `talos_workflow_engine_core::SecretMap` (values `Zeroizing`) from
  `SecretsManager` through `SecretsResolver`, `DispatchSecrets`, the job's
  `plaintext_secrets`, `SecretEnvelope` and the two encrypt points
  (`EncryptedSecrets::encrypt_with_aad`, `SealContext::new`, now generic over
  the value type and serialising borrowed views). A standalone run's map
  leaves it at one place, `talos_oauth::resolver::into_runtime_secrets`.
- **C-12.** `security_audit` reports `kek_posture` (weight 0): `Warn` "two
  KEKs live" under `KEK_PROVIDER=vault` without `KEK_DISABLE_LEGACY`.
  Recommendation: flip `KEK_DISABLE_LEGACY=true` once `dekMigrationStatus` is
  clean — the operator's call.

## Mutation proof

| Gate | Mutation | Test | Verdict |
|---|---|---|---|
| manage rule | org arm → `created_by` | `a_member_who_left_the_org_cannot_manage_or_read_the_secrets_they_created` | FAIL / PASS restored |
| dispatch-read rule | membership dropped, `created_by` added | same | FAIL / PASS restored |
| C-7 unscoped | v3-on-org refusal off | `a_row_naming_a_dek_outside_its_scope_does_not_open` | FAIL / PASS restored |
| C-7 scoped | scope check off | same | FAIL / PASS restored |
| `oauth_state_tokens` policy | `USING (TRUE OR …)` (template rebuilt) | `a_scoped_session_sees_only_its_own_pending_oauth_states` | FAIL / PASS restored |
| check 100 | one `rand::rng()` reintroduced | clippy `disallowed method rand::rng` | FAIL / PASS restored |

A migration mutation needs `scripts/dev-test-db.sh rebuild`: the template is
checked by migration VERSION, so an edited migration is otherwise never
re-applied (the first run of this mutation passed for that reason).

## Deliberately NOT done / stated limits

- The policy backstop on org rows (above).
- `get_llm_vault_keys`' cache already held `Zeroizing` values; unchanged. The
  in-process runtime's secret provider holds plain `String`s.
- `decrypt_versioned_scoped` is not yet called by the memory, payload and
  integration-state adapters: none of them carries the row's org at decrypt
  time, and threading it is a cross-crate signature change.
- The 2 mislabelled module-payload rows are left as they are (readable).
