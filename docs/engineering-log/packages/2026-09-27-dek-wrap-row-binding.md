# 2026-09-27 — every wrapped DEK is bound to its own row (RFC 0013, P1 + P2)

**Why.** The KEK wrap of `encryption_keys.encrypted_key` carried no associated
data, so a wrapped DEK copied into another row unwrapped cleanly. With write
access to `encryption_keys` but not the KEK, org A's DEK could be planted in
org B's active row, and every later v4 write for org B would be sealed under
org A's key. #960's `secret_dek_scope_mismatch` check trusts the row's `org_id`
label and cannot see a swapped blob. This was backlog from #960; the design is
RFC 0013, and the operator's decisions are recorded there.

**Measured.** Two DEK rows on the reference fleet (one global, one org), both
unbound, both from 2026-07-08. Latent: nothing could have detected a swap.

**Decided.**
- **One home for the encoding**, `talos_secrets_manager::dek_wrap`:
  `DekRowIdentity::bound_aad()` is `"talos-dek-wrap/v2" || key_id ||
  0x00` (global) or `|| 0x01 || org_id` (org), fixed-width, with the encoding
  pinned by test. `WrapFormat::from_db` refuses an unknown column value rather
  than guessing an AAD.
- **The AAD is a REQUIRED argument** of `KekProvider::{wrap_dek, unwrap_dek}`,
  not a second method pair: a new call site cannot pick the unbound path by
  omission. An empty AAD is byte-identical to the old wrap for both providers
  (AES-GCM with no associated data; transit with `associated_data` omitted from
  the JSON), pinned by `an_empty_aad_is_the_pre_rfc_wrap` and the transit wire
  tests.
- **Every writer binds**: `create_new_dek`, `create_new_dek_for_org`,
  `rotate_dek` and `rotate_dek_for_org` generate the id BEFORE wrapping and
  stamp `wrap_format = 2`. `create_new_dek` used `RETURNING id`; the other
  three generated it after the wrap.
- **Every reader reads the format**: `get_active_dek`, `get_dek` and
  `get_active_dek_for_org` select `wrap_format` and pass `aad_for(format)`.
  The KEK self-test and Vault's boot probe wrap bound, so they exercise the
  path every new DEK takes.
- **One rewrap routine**, `rewrap_deks_bound` / `rewrap_bound_under_active`,
  shared by `rotate_master_key` and the new `rebind_dek_wraps`. A rotation
  therefore also binds. The session-lock dance (acquire, release, and on a
  failed unlock detach — MCP-701) moved verbatim into
  `with_exclusive_rotation_lock`, instead of being copied.
- **`rebindDekWraps`** (GraphQL): `require_second_factor` +
  `require_scope(Admin)` + `require_platform_admin`, in the privileged tier.
  It is idempotent (walks only `wrap_format = 1`) and resumable (50-row batch
  transactions). It does not change the DEK bytes, so there is no data
  re-encryption and no cache invalidation. It writes one `DEK_WRAP_REBOUND`
  `secret_audit_log` row per DEK, naming the org, in the transaction that
  rewraps it. It returns `remainingUnbound` read back from the database.
  `dekMigrationStatus` gains `encryption_keys.wrap`.
- **Migration** `20260927100000`: `wrap_format smallint NOT NULL DEFAULT 1`
  plus `CHECK (wrap_format IN (1, 2))`. A constant default, so no table
  rewrite.

**Deliberately NOT done.**
- P3 (`CHECK (wrap_format = 2)` and removing the format-1 unwrap arm). Until it
  ships, a writer can mark a row 1 and plant an unbound blob; the protection is
  complete only after it. It follows one release after the rebind has run.
- Binding `algorithm` into the AAD (one value; binding it forces a rewrap on any
  algorithm migration for no gain).
- Fixing the `initialize()` global-DEK race found while testing (see Stated
  limits).

**Proof.**
- Unit: encoding pin, format round trip, swap refusal across orgs, across the
  global/org boundary in both directions, between two keys of one org, and on
  an `org_id` relabel. Also rebind of an unbound row and skip of a bound one,
  and an interrupted-then-resumed rewrap ending all-bound.
- DB (`controller/tests/secrets_tests.rs`, 23/23 single-threaded as CI runs
  it):
  - a new org DEK and a rotated one are stored bound;
  - org A's blob copied into org B's row makes B's read FAIL, with A's own row
    as the control;
  - a legacy unbound row reads, the rebind binds it with the old ciphertext
    still decrypting, one audit row is written, and a second run leaves `xmin`
    unchanged.
- Live Vault 1.18.5 (`aes256-gcm96`, the deployed default) in a disposable dev
  container: a bound wrap opens under its own row, and is refused under another
  row's `associated_data` and under none; an unbound wrap still opens.
- Mutations (crypto gate): 11 distinct, 13 runs (M3 also behaviourally, M6 also against live Vault), all caught:

| Mutation | Caught by |
|---|---|
| env provider ignores the AAD | 5 unit tests incl. the swap test |
| AAD omits `org_id` | encoding pin, swap test |
| AAD omits `key_id` | encoding pin, same-org swap case |
| bound rows read with an empty AAD | 3 unit tests |
| rewrap skips unbound rows the active key opens | rebind unit test |
| transit never sends `associated_data` | wire test; the LIVE Vault test |
| rebind writes no audit row | DB rebind test |
| rebind leaves `wrap_format` unbound | DB rebind test |
| new org DEK stamped unbound | 16 DB tests |
| rebind drops `require_platform_admin` | gate pin |
| rebind drops `require_second_factor` | gate pin, privileged-tier test |

  The first mutation run reported all six library mutations SURVIVED. The
  harness passed the test command as one zsh word, so every "run" was a
  command-not-found with no test output. The harness now reports "NO TEST RAN"
  separately.
- The GraphQL snapshot is regenerated. The first codegen run used a symlinked
  `node_modules` holding codegen 6.x against a lockfile pinning 7.x, and
  rewrote 1 482 lines of `graphql.ts`. After `npm ci`, codegen on the unchanged
  schema reproduced the committed files exactly (the control), and the real
  diff is +30 SDL / +25 types.

**Stated limits.**
- **Deploy ordering:** every controller must run this release before
  `rebindDekWraps` is called, and during a rolling deploy a new controller's
  new DEKs are bound, so an older replica cannot read them. Roll controllers
  together (one replica here).
- The rebind and the audit path are exercised on the env provider in the DB
  tests; Vault's AAD is proven at the provider level, not through a Vault-backed
  `SecretsManager`.
- **Found, NOT fixed:** `SecretsManager::initialize()` checks for an active
  global DEK and then inserts one without a lock, so concurrent initializers on
  an empty database race, and `idx_one_active_global_dek` rejects the loser.
  The same `secrets_tests` binary fails 12/20 run in parallel on `origin/main`;
  CI runs it single-threaded, by design. In production this is two controllers
  booting simultaneously on a brand-new database: one crashes once, then
  restarts cleanly.
