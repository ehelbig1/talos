# A Jira delivery is attributed to one site, and its token is used once (2026-10-14)

Security review 2026-10-14, findings **F-1** (High), **F-2**, **F-4**
(Medium) and **F-10** (Low). Package 3 of the review's remediation.

## The defects, as verified

- **F-1.** `push_receiver::receive_push` mapped a delivery to its owner with
  `WHERE webhook_id = ANY($1)` and read no site from the delivery. A Jira
  webhook id is a small per-site integer, so a webhook another Talos user
  created on their own site (unrecorded — e.g. through a module holding their
  own Atlassian token) and that happened to carry a victim's recorded id
  started the victim's bound workflow as the victim. `split_ambiguous` saw only
  Talos's own table.
- **F-2.** The delivery JWT's `exp` was optional, and nothing remembered a
  token, so one captured token verified with any body for as long as its
  `exp` allowed (forever without one).
- **F-10.** The dedup key is `X-Atlassian-Webhook-Identifier`, which the
  sender chooses; a missing header meant "new".
- **F-4.** Dedup rows grew one per registration per delivery with no count
  bound, under a sender-chosen key.

## Measured

- The dev stack's controller log (2026-10-14) has the receiver's one-time
  shape line from a real delivery: `alg=HS256`,
  `claim_names=context,exp,iat,iss,jti,sub`. `exp` is sent, so it is now
  required; there is no `qsh`.

## Decided

- **Site binding (F-1)**, the reviewer's fallback (operator decision D-9).
  The preferred per-registration URL with a token in the path was not built:
  `docs/jira-push-setup.md` records Atlassian's rule as one webhook URL per
  app on the app's base address, and checking whether REST-registered dynamic
  webhooks may use another URL needs a live Atlassian app — an outward action
  this session did not take. The receiver reads `issue.self` (≤ 512 bytes),
  keeps only its site — the host, or the cloud id on the API gateway form
  `https://api.atlassian.com/ex/jira/<cloud>/…` — and the owner query joins
  each registration's own connection (`atlassian_integrations.site_url` for
  its user and cloud id). A registration acts only on a delivery about its
  own site (`split_by_site` / `owner_is_on_site`, fail closed when either
  side has no site). Off-site registrations start nothing; if nothing is
  left, the answer is **202** (Atlassian does not retry) and a
  `site_mismatch` refusal row is written for each bound registration. Side
  effect: two sites issuing the same webhook id are no longer ambiguous to a
  delivery that names its site — only the delivering site's registration acts.
- **Single-use token (F-2, F-10).** `push_replay::DeliveryReplayCache`: the
  SHA-256 of each admitted token, two-generation `ArcSwap<DashMap>`, rotation
  interval = the longest a token can verify (`MAX_TOKEN_LIFETIME_SECS` +
  leeway = 61 min), at most 100 000 hashes per generation and REFUSING when
  full. Checked after the signature and before the body or any database read;
  when a shared replay guard is registered (Redis), checked there too with a
  TTL to the token's `exp`. A delivery answered **5xx** releases its token
  (locally and in the shared guard — `ReplayGuard::release`, added with a
  no-op default) so Atlassian's retry, which may reuse the token, is read
  again. `exp` is required; one more than an hour away is refused.
- **Bounded dedup (F-4).** Each registration remembers at most 10 000
  deliveries: the insert is one statement that counts the registration's rows
  and inserts only below the cap; above it nothing is inserted or started and
  a `dedup_cap` row is recorded. Each registration also acts on at most 60
  deliveries a minute per replica (`RegistrationBudget`, the gcal per-channel
  fixed-window shape, self-pruning above 4 096 keys). Refusal rows (site
  mismatch, dedup cap) are themselves budgeted at 10 per registration per
  hour, so a flood of refusals does not become a flood of rows.

## One home

- Site rule: `talos_atlassian::push_receiver::{delivery_site, owner_is_on_site, split_by_site}`.
- Token memory: `talos_atlassian::push_replay`.
- Token claims: `talos_atlassian::push_jwt::verify_delivery_jwt` (`MissingExpiry`, `ExpiryTooFar`).
- CLAUDE.md's Jira rule sentence now names the site binding and the
  single-use token.

## Mutation proof (tenancy / authentication)

| Gate | Mutation | Test | Verdict |
|---|---|---|---|
| site binding | `owner_is_on_site(..) \|\| true` | DB: `a_delivery_whose_site_is_not_the_registrations_starts_nothing`, `a_delivery_without_a_site_starts_nothing`, `the_same_webhook_id_on_two_sites_starts_only_the_delivering_sites_registration`; unit: `a_registration_acts_only_on_a_delivery_about_its_own_site` | FAIL / PASS restored |
| single-use token | the local check made always-Fresh | unit `a_replayed_token_is_refused_before_any_database_read`; DB `a_replayed_token_starts_nothing_and_records_nothing` | FAIL / PASS restored |
| release on 5xx | release skipped | `a_token_whose_delivery_was_answered_with_a_5xx_can_be_retried` | FAIL / PASS restored |
| `exp` required | `required_spec_claims.clear()` restored | `a_token_without_exp_is_refused` | FAIL / PASS restored |
| `exp` cap | cap raised 1000× | `a_token_with_a_far_future_exp_is_refused` | FAIL / PASS restored |
| dedup cap | cap raised by 10⁶ | `a_registration_at_its_dedup_cap_starts_nothing_and_inserts_nothing` | FAIL / PASS restored |

## Deliberately NOT done

- `iss` / `sub` are not checked: the live token carries them, but their
  VALUES for an OAuth 2.0 app's delivery are not documented, and a guessed
  value would refuse every real delivery. The shape log now also records the
  token's lifetime. Requiring `iss` needs its expected value, which no log
  line records today; a follow-up could log whether `iss` equals the app's
  client id (a boolean, never the value) and then require it.
- No per-registration URL token (see above). If Atlassian is confirmed to
  accept a per-registration dynamic-webhook URL, the URL token is the stronger
  binding and this site check stays as a second layer.
- No migration: the binding needs `atlassian_integrations.site_url`, which
  exists, joined through the existing `UNIQUE (user_id, cloud_id)`.

## Stated limits

- Same-site case: a second Talos user on the SAME Jira site cannot be
  separated from the victim by site. There, the binding rests on Atlassian
  building the body: a delivery names a webhook id only when that webhook
  matched the event, and an unrecorded webhook on the same site has its own,
  different id. A forged body needs a fresh signed token, which the
  single-use rule bounds to one body per token.
- The per-minute budget is per replica; the dedup cap and the token memory
  are fleet-wide only through the database and the shared replay guard.
- `exp` more than an hour away is refused. The live token's lifetime is not
  yet known (the shape line now records it); if Atlassian's is longer, every
  delivery is refused with `expiry_too_far` on the `talos_audit` target —
  visible, not silent — and `MAX_TOKEN_LIFETIME_SECS` is the one constant to
  move.
