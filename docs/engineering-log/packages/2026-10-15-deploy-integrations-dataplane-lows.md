# Deploy, integrations and data-plane Lows (2026-10-15)

Security review 2026-10-15 (round 2), package **R8**: H2-2, H2-3, H2-4,
H2-6, F2-1, F2-2, F2-3, F2-6, F-9, F-11, I2-2, I2-4, D2-8 / A-16, and the
F2-5 record correction. Every finding was re-read against the tree before it
was fixed; none was refuted.

## Decided

- **H2-2 — the nginx body limit EQUALS the controller's.**
  `check-deploy-posture.py` rule 3 now reads the controller's limits from
  `controller/src/bootstrap/router.rs`: each `Router::new()` builder's
  `.route(…)` / `.nest(…)` paths take its `DefaultBodyLimit::max(…)` (a
  literal product, or a `module::CONST` read from the `talos-<module>` crate),
  or axum's 2 MiB default when it names none; a path constant
  (`atlassian::push::WEBHOOK_PATH`) is read the same way; `#[cfg(test)]`
  modules are skipped. Each route is sent to the location nginx would pick
  (exact, then longest prefix), and every proxied location's
  `client_max_body_size` must equal the LARGEST limit under it — smaller and
  the proxy answers 413 first (H-3), larger and it is no cap. An unreadable
  limit or path is a failure, not a pass. Measured on the tree: 101 routes,
  both nginx files, 0 failures; flipping `/webhooks/` to `2m` fails.
- **H2-3** — the id-token rule also matches `permissions: write-all`
  (workflow- or job-level). 0 hits on the tree.
- **H2-4** — `publish-images.sh`: with `--skip-ci-check` and the audit switch
  off (`TALOS_PUBLISH_REQUIRE_AUDIT=0`) the tags carry `-unaudited`, as a dirty
  tree's carry `-dirty`; every signature carries the cosign annotation
  `org.talos.publish.gates=ci:<green|skipped|not-checked>,audit:<clean|vulnerable|not-run>`,
  which Rekor records publicly (the durable record), and the summary prints
  it. `install.sh` pins by digest, so it cannot see a tag; the annotation is
  what `cosign verify` prints for that digest. Not done: a refusal in
  `install.sh` (it would have to run `cosign verify` and parse annotations on
  every install; recorded as a stated limit).
- **H2-6** — `scripts/ngrok.sh`: one `mktemp -d` directory (0700) holds the
  ngrok config and both tunnels' logs, each created 0600, removed on exit. The
  cloudflared log had the same fixed `/tmp` name and is fixed with it.
- **F2-1** — the Jira replay memory is held for
  `LONGEST_VERIFIABLE_AFTER_ADMISSION_SECS` = `MAX_EXP_AHEAD_SECS + LEEWAY_SECS`
  (an `exp` up to `MAX_TOKEN_LIFETIME_SECS + LEEWAY_SECS` ahead is honoured for
  another `LEEWAY_SECS`). The interval grew by one leeway (60 s); acceptance is
  unchanged.
- **F2-3** — the verifier accepts HS256 only, the algorithm the shape log
  measured; HS384 / HS512 are refused by name. `docs/jira-push-setup.md` says so.
- **F2-2** — `record_ambiguous` writes its refusal row through
  `record_refusal`, within the same per-registration budget.
- **F2-6** — one spelling of a site's host on both sides (`site_host`:
  lowercased, IDNA by the URL parser, no trailing root dot). A delivery that is
  not about a registration's site is still withheld; the audit line now says
  which kind (`why_off_site` → `OffSite`: `delivery_names_no_site`,
  `connection_has_no_site`, `cloud_id_differs`, `host_differs`,
  `host_differs_custom_domain`), never the host. The refusal ROW keeps its one
  reason word (`site_mismatch`); the class is the audit line's. Not done:
  accepting a custom domain as its `atlassian.net` site — nothing proves the
  two are one site, and the review asked for a live datum first.
- **F-9 — not gated to platform-admin, by decision.** Slack `create_app`
  creates an app in the CALLER's Slack workspace with the caller's own
  `apps:write` user token, and stores its three credentials in the caller's
  own vault (`slack/app/<id>/…`, `upsert_secret` under the caller); the answer
  names paths only. No platform credential is used or reachable, so a
  platform-admin gate would only stop a user connecting their own Slack. The
  route stays session-authenticated with CSRF and an 8 KiB body limit. The
  error path logs Slack's error CODE only (`talos-slack/src/lib.rs`).
- **F-11 — one base-address rule.** Its home is
  `talos_integration_helpers::base_address::https_base(raw, name,
  path_allowed)`: `https://`, a non-empty authority with no userinfo,
  printable ASCII, ≤ 2000 bytes, no query, no fragment, a path only where the
  adapter takes one; the error names the setting, never the value. The five
  adapters compile on their own and cannot link the crate, so each carries the
  marked block byte for byte (`notify-*` through `usable_base`, inside their
  notification block; `control-home-assistant` likewise; the `capture-*`
  wrappers with `path_allowed = false`). `talos-catalog-tests/tests/base_address_contract.rs`
  holds every copy equal to the home and refuses a template that reads
  `BASE_URL` / `SERVER_URL` without being on the list. Behaviour changes: none
  for a valid address; `notify-*` now say "must start with https://" for an
  `http://` address (was the general sentence).
- **I2-2** — the platform ceiling has one home,
  `talos_actor_budget_refusal::platform_llm_ceiling_refuses` (fails closed,
  counted), and `LlmClient`'s vault-sourced key resolution asks it before a key
  is handed out, so every caller is gated: the shared controller client (MCP /
  GraphQL generation), the evaluation judge, consolidation. The refusal is
  `talos_llm::PlatformCeilingReached` (`is_platform_ceiling`). The actor
  repository's `external_llm_spend_refused` asks the same function, and its own
  copy of the SQL is gone. The evaluation judge maps the refusal to a new
  `EvaluationError::JudgeBudgetSkip` — the prompt said `TierSkip`, whose message
  is "cannot evaluate tier-1 actor", which would have been false; the new
  variant carries the same code (-32004), so a client reads the same skip
  class. Stated limit: the ceiling is read-then-act (I2-3), and a
  vault-sourced client now does one indexed `SUM` per call.
- **I2-4** — `DatasetService::prepare_examples` asks the per-user ceiling
  under the user's own row-security scope BEFORE it embeds, so every append
  path (distill, correction, bootstrap) is covered; `insert_prepared` still
  asks under its write transaction, which remains the gate. The concurrent
  overshoot (≤ (N−1) × batch) is unchanged, as the review accepted.
- **D2-8 / A-16** — a module replay runs as the caller (`run_replays` takes
  the user whose secrets `prefetch_secrets` resolved); GraphQL `testModule`
  resolves the module's grant through `resolve_for_standalone_run` for the
  caller (the grant is the module's `allowed_secrets`; a `vault://` reference
  in the input is fetched when stored for the caller, minted only when the
  grant covers it, and an unresolvable one is refused before the run) and runs
  as the caller. Until now it carried no secrets and the nil user. Not
  changed: `testModule`'s tier (`LlmTier::default()`) and permissive write
  ceiling — it has no actor; recorded, as A-16's remaining half.
- **F2-5** — correction appended to
  `2026-10-14-inbound-credentials-hashed-and-scoped.md` (checks 101 / 102, not
  100 / 101); `docs/rfcs/0008-github-app-authentication.md` no longer lists
  `GITHUB_APP_WEBHOOK_SECRET`.

## Tests

- `scripts/check-deploy-posture.py --self-test`: equality cases (smaller,
  larger, unreadable constant, no route), `write-all` at workflow and job level.
- `scripts/tests/publish-gates-test.sh` (stand-in docker / cargo / cosign; a
  throwaway git repository): `-unaudited` with the switch off whatever the
  audit says, none with a required clean audit, a failed required audit still
  stops the publish, the annotation on every signature.
- `scripts/tests/ngrok-private-files-test.sh` (the real script, a stand-in
  `ngrok`): 0700 directory, 0600 config and log, removed on exit.
- `talos-atlassian`: `a_token_signed_with_another_hmac_is_refused_by_name`,
  `a_token_at_the_lifetime_cap_is_remembered_until_it_cannot_verify`,
  `a_site_is_compared_in_one_spelling_and_a_mismatch_says_which_kind`; DB
  `an_ambiguous_refusal_is_budgeted_like_the_others`.
- `talos-integration-helpers::base_address` tests; `base_address_contract.rs`.
- `talos-evaluation`: `a_budget_exhausted_external_judge_yields_a_skip`; DB
  `a_vault_sourced_llm_client_refuses_at_the_platform_ceiling`.
- DB `ml_example_ceiling_embedding_tests` (new binary, the counting embedder
  stand-in): a user under the ceiling is embedded, a user at it is refused with
  zero embedding calls.
- DB `test_module_caller_identity_tests` (new binary): the caller's stored
  secret resolves for their own module; another user's does not; a module the
  caller does not own is refused before anything resolves.

## Mutation proof

| Gate | Mutation | Test | Verdict |
|---|---|---|---|
| Jira algorithm (authn) | HS384 re-admitted | `a_token_signed_with_another_hmac_is_refused_by_name` | FAIL / PASS restored |
| Jira replay horizon (authn) | interval one leeway shorter | `a_token_at_the_lifetime_cap_is_remembered_until_it_cannot_verify` | FAIL / PASS restored |
| platform ceiling in `LlmClient` | the check removed | `a_vault_sourced_llm_client_refuses_at_the_platform_ceiling` | FAIL / PASS restored |
| `testModule` resolves for the caller (tenancy) | `Some(Uuid::nil())` | `test_module_resolves_the_callers_secrets_…` | FAIL / PASS restored |

Shown to fail on the pre-fix code (not security gates): the ambiguous refusal
budget (12 rows, budget 10), the example ceiling before embedding, the
publish and ngrok script tests (run against the previous scripts).

## New lint legs and their measured false positives

- Posture rule 3 equality: 101 routes read, 0 failures on the tree, 0 false
  positives.
- Posture rule 5 `write-all`: 0 hits.
- `base_address_contract` listing: 1 hit, `briefing-html-generator`, which
  writes `BASE_URL` into HTML links and makes no request (minimal-node, no
  hosts) — exempted by name with that reason.

## Stated limits

- Rule 3 parses one file: a router built elsewhere and `.nest`ed (`/mcp`) is
  taken at axum's default; a limit applied by an outer layer is not seen.
- H2-4's record is an annotation, not an `install.sh` refusal.
- F2-6's custom-domain case is classified, not resolved.
