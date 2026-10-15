# An inbound credential is hashed at rest and scoped to one party (2026-10-14)

Security review 2026-10-14, findings **F-3** and **G-25** (Medium/Low, the
generic webhook token), **F-6** (Low, the Google Calendar channel token),
**F-5** (Low, the GCP push refusal) and **F-7** (Low, push-channel workflow
bindings). Package 8 of the review's remediation.

## The defects, as verified

All five held at `main` @ `a8ede4a9`.

- **F-3.** `webhook_triggers.verification_token` was `TEXT NOT NULL` in the
  clear (`migrations/001_initial_schema.sql:151`), written verbatim by both
  repository inserts (`talos-webhook-repository` `try_create_under_cap` and
  `insert_trigger`) and compared raw by the router's static-token branch,
  while `signing_secret_enc` beside it is envelope-encrypted. The token alone
  starts the owning workflow with a caller-chosen body.
- **G-25.** The MCP `create_webhook` minted that token as
  `Uuid::new_v4().to_string()` (`talos-mcp-handlers/src/webhooks.rs:412`).
  The GraphQL lane already used `talos_random::fill` + hex.
- **F-6.** `webhook_token::sign_channel_token` derived the
  `X-Goog-Channel-Token` as an HMAC under `WORKER_SHARED_KEY`, which every
  worker holds; `verify_channel_token` accepted it with no other state.
- **F-5.** `pubsub_push_handler` answered an unknown watch token 200 and a
  known watch with the wrong service account 401, and wrote a
  `gcp_channel_push_rejected` audit row for every such refusal.
- **F-7.** Only Gmail asked `workflow_is_bindable` (private to `talos-gmail`,
  ownership only); Google Calendar, Google Cloud and Jira each read
  `get_workflow(user)` themselves. None asked whether the workflow was
  archived or disabled.

## Decided

- **F-3: hash at rest.** New column `verification_token_hash` = hex SHA-256 of
  the token (`talos_webhook_repository::verification_token_hash`, which is
  `talos_text_util::sha256_hex`). Both inserts store only the hash; the token
  is returned once, in the create response. The router hashes the delivered
  `X-Verification-Token` and compares the digests in constant time
  (`talos_webhooks::types::verification_token_matches`, the
  `approval_token_matches` shape). The lookup stays by trigger id (the URL);
  no token predicate is added, so no index. The MCP-629 empty guard is kept in
  the router and repeated in the matcher (the SHA-256 of an empty header is a
  real digest).
- **Migrations.** `20261014220000` adds the column and backfills it per row
  (`encode(sha256(convert_to(token,'UTF8')),'hex')`, nested `BEGIN/EXCEPTION`;
  a failed row is left NULL with a WARNING), with the `updated_at` trigger
  disabled for that transaction so the backfill does not date every webhook.
  `20261014220100` drops the plaintext column. A DB test pins that the SQL
  digest equals the Rust one for a minted token, a UUID-shaped legacy token
  and a non-ASCII one, so every existing token keeps authenticating.
- **A NULL hash refuses.** The router's "neither a signing secret nor a token"
  arm returned `Open`; it was unreachable while the plaintext column was
  `NOT NULL`. It now answers 401: the only way to reach it is a failed
  backfill, and an unreadable rule refuses.
- **G-25: one minting.** `talos_webhook_repository::mint_verification_token`
  (32 bytes of `talos_random`, hex) is called by both create paths. Lint
  **check 101** refuses a binding named `*token*` (not `*_id`) whose value is
  a `Uuid::new_v4()`.
- **F-6: a random per-channel token, hashed in the row** — the GCP pattern,
  not a controller key. `TALOS_CONTROLLER_SIGNING_KEY` is optional (only
  envelope sealing needs it), so deriving from it would have made Calendar
  depend on a setting most deployments lack, and a key needs a rotation story;
  a per-channel random needs neither. Token = base64url(user id ‖ 32 random
  bytes), 64 chars; `WatchChannelRow.token_hash` (optional, absent from old
  rows so they keep their bytes). The user id stays in the token only so the
  handler can scope its read to one user (integration_state is per-user); the
  authenticator is the row's hash (`webhook_token::channel_token_admits`).
  The Calendar service no longer holds the worker key at all
  (`with_worker_shared_key` deleted); the handler still receives it as an
  Extension for the window below.
- **The dual-verify window.** A row with no hash (created before this change)
  is admitted only by a legacy token whose HMAC verifies, and only before
  **2026-12-01T00:00:00Z** (`LEGACY_WSK_TOKENS_ACCEPTED_UNTIL_UNIX`). A row
  with a hash never admits a worker-key token. Channels live 7 days and renew
  at < 24 h remaining through `create_fresh_watch_channel_locked`, which mints
  a new token, so every live channel moves over within a week of the deploy.
  The date leaves a margin for a deploy up to ~3 weeks out. **After
  2026-12-01, delete the legacy arm, `verify_channel_token`, and the
  handler's worker-key Extension** (CLAUDE.md says so).
- **F-5: one answer.** `PushWatchLookup::WrongSender` answers exactly as
  `Absent` (200, no body). The refusal is still counted on the closed-label
  `talos_google_push_refusals_total` (`record_push_refusal`), and the
  owner-facing audit row is written at most once a day per channel
  (`talos_integration_helpers::audit::insert_channel_audit_once_per_day`, one
  `INSERT … WHERE NOT EXISTS` statement keyed on user, event type and
  `metadata.channel_uuid`), which is what the 25-hour `recent_failure` view
  needs.
- **F-7: one question.** `talos_integration_helpers::watch_binding::
  workflow_is_bindable` asks the read the trigger uses (`get_workflow(user)`)
  and the trigger's own gate (`not_dispatchable_reason`, whose decision is
  `talos_workflow_liveness::is_dispatchable`). A draft is bindable, as the
  trigger dispatches a draft. All four binders and Gmail's create call it;
  lint **check 102** refuses a `bind_channel_workflow` /
  `bind_registration_workflow` that does not, or that reads `get_workflow`
  itself. The caller sees one sentence for absent, not-yours, archived and
  disabled (`WORKFLOW_NOT_BINDABLE_MESSAGE`); the operator's `event_kind`
  tells them apart (`watch_workflow_binding_{absent,archived,disabled}`, with
  `integration`). The four `talos-workflow-repository` edges in the
  integration crates went with the hand-rolled reads.

## Deliberately NOT done

- **Moving the GCP watch token out of the URL path** (the review's "consider")
  — it changes the Pub/Sub subscription config an operator wrote; not a
  code-only change.
- **A time-bomb test on the window end date.** It would fail CI on an
  arbitrary day; the date is in CLAUDE.md, this record and the constant's doc.
- **Re-checking bindability at renewal.** A renewal carries the binding it
  found; the trigger refuses at every push (the Gmail decision of 2026-10-12).
- **Rejecting an unknown Calendar channel with 403** to remove the
  "row exists" signal for a hashed-form token: Calendar's absent arm must keep
  acking (pinned in `push_ack`), and probing it needs a user id and a random
  channel UUID.

## Stated limits

- A Calendar push with a hashed-form token is now authenticated AFTER one
  indexed `integration_state` read (by the user id the token names and the
  channel id), where the HMAC was checked with no I/O. A forged hashed-form
  token therefore costs one read; a legacy-form token is still checked before
  any read. The per-channel limiter still runs only on a verified pair (F8).
- Check 101 is textual and one-line; check 102 checks bind functions by name,
  not every create that names a workflow (Gmail's create is pinned by its DB
  test).
- `WebhookAuthOutcome::Open` is no longer constructed; it is a public variant
  and was left in place.

## Operator-visible behaviour

- **Existing webhook URLs and static tokens keep working** (their hashes were
  backfilled). Tokens cannot be shown again; a lost one means recreating the
  webhook.
- **Deploy order.** The migrate job drops the plaintext column; an old
  controller pod answers a webhook delivery 500 until it is replaced (senders
  retry 5xx). Rolling back to a pre-package image needs the column back and
  every static-token webhook recreated.
- **Calendar channels** keep verifying until renewed (≤ 7 days), and until
  2026-12-01 at the latest. A channel whose renewal is failing past that date
  stops being accepted; renew or recreate it.
- **GCP:** a push from the wrong service account is now acked 200, so Pub/Sub
  no longer retries it for 7 days; it shows as a refusal metric and one audit
  row a day per channel.
- **Binding** an archived or disabled workflow to any push channel is refused
  ("No such workflow, or it is archived or disabled.").

## One home

- Webhook token minting and stored form: `talos_webhook_repository::{mint_verification_token, verification_token_hash}`; the compare: `talos_webhooks::types::verification_token_matches`.
- Calendar channel token: `talos_google_calendar::webhook_token::{mint_channel_token, channel_token_admits, LEGACY_WSK_TOKENS_ACCEPTED_UNTIL_UNIX}`.
- Wrong-sender answer: `talos_integration_helpers::push_ack::PushWatchLookup::WrongSender`; capped row: `audit::insert_channel_audit_once_per_day`.
- Workflow bindability: `talos_integration_helpers::watch_binding::workflow_is_bindable`.
- CLAUDE.md: a Security Rules bullet (inbound credentials hashed, never from a worker-held key; the window's end) and a push-integration paragraph (bindability, wrong sender); the lint count 99 → 101.

## Lint checks

- **100** — a token is not minted from `Uuid::new_v4()`. Measured on `main` @
  `a8ede4a9`: 1 hit outside test paths (the G-25 site), 6 in test paths
  (skipped); 0 after; 0 false positives.
- **101** — every push-channel workflow binding asks `workflow_is_bindable`.
  Measured: 4 definitions, 3 hits before (Calendar, GCP, Jira); 0 after.
- Numbers 100 and 101 were taken in this package; another open package adding
  a check would renumber on rebase.

## Mutation proof (authentication / authorization)

Each mutation applied to the file, the whole crate's tests (or the named DB
binaries) run, the file restored from a backup and `touch`ed, and re-run green.

| Gate | Mutation | Test | Verdict |
|---|---|---|---|
| F-3 compare | `… == 1 \|\| true` | `the_hash_path_refuses_a_wrong_token` | FAIL / PASS restored |
| F-3 compare | compare the raw token, not its hash | `the_hash_path_accepts_the_right_token`, `the_hash_path_refuses_a_wrong_token` | FAIL / PASS restored |
| F-3 empty guard | guard removed | `the_hash_path_refuses_an_empty_token` | FAIL / PASS restored |
| F-6 key scope | a hashed row admits a legacy (worker-key) token | `a_token_minted_under_the_worker_key_is_refused_by_a_hashed_channel` | FAIL / PASS restored |
| F-6 window | end date ignored | `a_legacy_channel_verifies_its_legacy_token_only_inside_the_window` | FAIL / PASS restored |
| F-7 bindable | dispatch gate skipped in `workflow_binding_verdict` | unit `an_archived_or_disabled_workflow_is_not_bindable`; DB `an_archived_workflow_cannot_be_bound` ×4 (gcal, gcp, gmail, jira) | FAIL / PASS restored |
| F-5 answer | `WrongSender` → 401 | `a_wrong_sender_is_answered_as_an_absent_watch` | FAIL / PASS restored |
| F-5 call site | handler returns 401 again | `the_gcp_push_handler_answers_a_wrong_sender_as_an_absent_watch` | FAIL / PASS restored |

## Tests added

- `talos-webhooks`: `verification_token_hash_tests::{the_hash_path_accepts_the_right_token, the_hash_path_refuses_a_wrong_token, the_hash_path_refuses_an_empty_token}`.
- `talos-webhook-repository`: `token_tests::{a_minted_token_is_64_hex_chars_and_fresh_each_time, the_stored_form_is_the_sha256_hex_and_never_the_token}`.
- controller DB `webhook_verification_token_hash_tests`: `the_stored_row_never_contains_the_returned_token`, `the_backfill_digest_is_the_one_the_router_compares`.
- `talos-google-calendar`: `webhook_token::hashed_token_tests::*` (5).
- `talos-integration-helpers`: `push_ack::tests::a_wrong_sender_is_answered_as_an_absent_watch`, `push_ack::call_site_pins::the_gcp_push_handler_answers_a_wrong_sender_as_an_absent_watch`, `watch_binding::tests::{an_archived_or_disabled_workflow_is_not_bindable, the_workflow_refusal_does_not_say_whose_the_workflow_is}`.
- controller DB: `an_archived_workflow_cannot_be_bound` in the gmail, gcal, gcp and Jira binding suites; `a_rejected_push_writes_at_most_one_row_a_day_per_channel` (gcp).
- `talos-atlassian`: `the_inventory_says_the_shared_workflow_refusal`.
