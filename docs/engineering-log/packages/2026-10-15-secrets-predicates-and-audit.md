# Secrets: the manage rule on upsert, an honest audit label, one module-visibility rule (2026-10-15)

Security review 2026-10-15 (round 2), findings **C2-1** … **C2-6** (Low).
Package R5 of the round-2 remediation.

## The defects, as verified

- **C2-1.** `upsert_secret` looks the row up by `(namespace, key_path,
  created_by)` and updated it `WHERE id = $7` alone: a member who created an
  org secret and then left the org could still overwrite its value through any
  `upsert_secret` caller (the operator CLI, the OAuth, Slack and Plaid
  credential stores) — the C-2 "rotate to an attacker-controlled credential"
  scenario by another door.
- **C2-2.** Every bulk read by path (`get_secrets_by_paths`) was recorded as a
  `dispatch_read` by a `dispatch` actor — including the Gmail, Google Cloud,
  Slack and Google Calendar integrations reading their own tokens, and the
  LLM-key cache fill.
- **C2-3.** `secret_audit_log` is append-only and gains one row per secret a
  dispatch is handed; no retention position was stated, nothing reported its
  size, and there was no `(secret_id, timestamp)` index for the per-secret
  history read (measured: indexes on `(secret_id)`, `(timestamp)` and
  `(key_hash, timestamp)` only).
- **C2-4.** `SecretsResolver::resolve_llm_keys` returned a plain
  `HashMap<String, String>`, so every tier-2 dispatch copied the provider keys
  out of the cache's `Zeroizing` map, and `secrets_pipeline` re-wrapped them;
  the comment justifying it ("the engine crate cannot depend on zeroize") was
  stale — the trait file defines `SecretMap` with `zeroize`.
- **C2-6.** `SecretsManager::refuse_unreachable_allowed_modules` and
  `ModuleRepository::get_modules_by_ids_for_reader` each hand-wrote "which
  modules may this user use".

## Refuted: C2-5's leak

The review: "under `talos_app`, any user-scoped session may read every audit
row whose secret still exists". The policy's arm is `EXISTS (SELECT 1 FROM
secrets s WHERE s.id = secret_audit_log.secret_id)`, and under `talos_app` the
`secrets` table's OWN policy filters that subquery — so a user sees the audit
rows of the secrets they can see, not every secret's. Measured on a migrated
clone, in a rolled-back transaction: two users each with a secret and an audit
row; as `talos_app` with `app.current_user_id` = A, `secret_audit_log` showed
1 row, 0 of B's. No policy change was made. What remains true and
informational: the writers leave `org_id` NULL, and a deleted secret's history
is readable through the backstop by no one (C-11's second half) — no read
surface needs it today.

## Decided

- **C2-1:** the UPDATE carries `may_manage_secret!("", "$8")` (the creator)
  and a zero-row result is an error with nothing written; the INSERT path is
  unchanged (a new row is the creator's).
- **C2-2:** `get_secrets_by_paths` takes `PathReadAudit`: `Dispatch`
  (`dispatch_read` / `dispatch`) from `talos_oauth`'s dispatch resolver;
  `Controller` (`controller_read` / `system`) from the four integration
  crates; `NotRecorded` from the LLM-key cache fill, whose later hits are not
  reads. `RECORD_DISPATCH_READS_SQL` takes the two labels as parameters; the
  module-grant path (`get_module_secrets_for`) stays `Dispatch`.
- **C2-3 — retention position:** the table stays append-only; archival is the
  operator's act, by the runbook `docs/secret-audit-log-retention-runbook.md`
  (export, then delete with the immutability trigger lifted for one
  statement inside a transaction, then record it). No default period: an
  audit trail is kept as long as the obligations it serves require.
  `security_audit` gains `secret_audit_log_extent` (info): the planner's row
  estimate — not a `count(*)` over a table that only grows — and the oldest
  row's age. Migration `20261015140000` adds `(secret_id, timestamp DESC)`.
- **C2-4:** `resolve_llm_keys` returns `SecretMap`; the impl hands on the
  cache's `Zeroizing` values unchanged; the re-wrap in `secrets_pipeline` is
  gone. The type is the test.
- **C2-6:** one fragment, `talos_tenancy::module_visible_to!` (owned, a
  current org's, or catalog), in a two-argument form (membership read
  in-statement) and a three-argument form (the caller's org ids); both
  statements use it. `talos-tenancy` is the leaf both crates can reach
  (`talos-module-repository` depends on `talos-secrets-manager`).

## Tests

- `secret_manage_predicate_tests::a_member_who_left_the_org_cannot_manage_or_read_the_secrets_they_created`
  extended: an `upsert_secret` of the org secret works while a member, is
  refused after leaving, and the stored ciphertext is unchanged.
- `…::a_dispatch_records_one_audit_row_per_delivered_secret` extended: a
  `Controller` read records one `controller_read` / `system` row; a
  `NotRecorded` read records nothing.
- `…::the_two_module_visibility_readers_agree`: own, catalog, org, a
  stranger's, a missing id — the `allowed_modules` check grants exactly what
  the reader returns.
- `talos_tenancy::tests::module_visibility_is_one_fragment_in_both_forms`.
- `talos-security-audit`: `the_secret_audit_log_extent_is_reported`.

## Mutation proof

| Gate | Mutation | Test | Verdict |
|---|---|---|---|
| upsert applies the manage rule | the predicate replaced by `TRUE` | `a_member_who_left_the_org_cannot_manage_or_read_the_secrets_they_created` | FAIL / PASS restored |

## Deliberately NOT done

- The C2-5 policy migration and `owner_user_id` column (refuted above).
- A `talos_secret_audit_rows` gauge: the `security_audit` entry was chosen,
  since the number is read when someone looks at posture, not alerted on.
