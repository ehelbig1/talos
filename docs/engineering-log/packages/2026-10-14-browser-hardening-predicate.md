# One predicate for "this deployment faces real users" (2026-10-14)

Package 14 of the 2026-10-14 security review (`docs/security-review/2026-10-14/`):
A-3, A-4, A-5, A-6, A-11, A-12, A-14, A-15, A-17 and H-2..H-9. Every finding was
re-located at its lines in this tree before it was changed.

## Decided

* **A-5 / A-6 — `browser_hardening_required()` for everything a browser or a
  tenant meets; `is_production()` for build and infrastructure posture only.**
  `docker-compose.prod.yml` runs `RUST_ENV=staging` deliberately (its plaintext
  backends cannot pass the production TLS gates) and faces real users. Before
  this change 36 files read `is_production()` / `is_development()` (84 lines,
  comments excluded); every site was classified:
  * **Moved (24 call sites, 13 files)** — `/mcp/local` mount
    (`talos_mcp_handlers::mount_routes`, extracted so a test drives the
    decision as served); WebSocket absent-Origin refusal
    (`talos_ws_auth::origin_verdict`); CSP selection and the HSTS default
    (`talos-security-headers`); per-IP limiter, global limiter, governor
    (`talos_rate_limit::ip_rate_limits_enforced`, one predicate for all three)
    and the auth limiters' Redis fail-closed policy
    (`talos_rate_limit::auto_fallback_policy`, also the boot log line); GraphQL
    introspection; GraphQL error scrubbing on both lanes (router HTTP handler
    and `talos_api::schema::scrub_response_errors`, which used
    `is_development()` — true for staging); the GraphQL playground and docs
    page (`talos-api-docs`); the OAuth connect-binding cookie's `Secure`
    (`talos-oauth`, the login binding cookie already followed the predicate);
    the three 2FA fail-closed gates (`talos-totp-2fa`); the API-key
    unknown-scope fail-closed; the `ALLOWED_ORIGIN` rule set and its
    multiple-origin warning (`talos-config`); the dev-CSRF-bypass boot refusal
    (`controller/src/main.rs`).
  * **Found by the classification, not in the review:** `/api/registry/publish`
    with no `REGISTRY_PUBLISH_TOKEN` was OPEN outside `production`
    (`talos-registry/src/api.rs`). It writes `kind='catalog', user_id=NULL`
    rows every user can install, and the compose frontend proxies `/api/` —
    so the compose deployment accepted an unauthenticated catalog publish.
    Moved; test `no_token_is_open_only_in_development`.
  * **Stayed (59 lines, 25 files)** — boot/infra posture: backend TLS gates,
    env-KEK guard, worker key requirement, RLS / DB-sandbox / dispatch-scheme
    posture, admin-query login, non-dumpable process, config validator,
    replay-guard fail-closed default (signed RPC between our own processes),
    audit sink, DLP endpoint TLS, the posture report, Sigstore policy, registry
    TLS downgrade, compilation sandbox and advisory DB, the API-key bcrypt cost
    floor (operator config), and the worker process.
* **Structural check 103** lists the 25 files where an `is_production()` /
  `is_development()` call or qualified reference may appear, each with its
  reason; a file not on the list fails, a listed file that no longer reads it
  fails (the list only shrinks). **Measured:** run on main @ 176a8b56 it flags
  19 lines in 11 files, every one a site this change moved — 0 false
  positives. The 6 other moved sites sit in files that keep a build-posture
  read, below the check's resolution (the file). After: 0 hits.
  **Renumber note:** this tree had checks 1..99, so the check is 100; stacked
  on packages that add 100..102 it becomes 103 (the comment block, the
  `bold "▶ check N"` line, the DECISIONS.md index line and the CLAUDE.md count
  move together).
* **A-3** — `docker-compose.prod.yml` gives `talos-network` a fixed `ipam`
  subnet (`${TALOS_COMPOSE_SUBNET:-172.29.0.0/24}`) and sets the controller's
  `TRUSTED_PROXY_CIDRS` from the same variable, so the XFF walk trusts the
  frontend nginx and the host gateway and finds the real client.
  `TrustedProxies::from_env` WARNs at boot when no CIDR is trusted and
  `ALLOWED_ORIGIN` names a non-loopback origin
  (`talos_rate_limit::proxy_trust_looks_missing`, unit-tested).
  `ENFORCE_RATE_LIMITS_IN_DEV=true` was NOT added: A-6 makes the limiters
  follow `browser_hardening_required()`, which is true for staging, so the
  variable would be inert there.
* **A-4** — a `?token=` is read only on `GET /mcp/sse`
  (`auth::query_token_permitted`; the path inside the `/mcp` nest is `/sse`,
  the unnested spelling is accepted too). Elsewhere it is not read at all: the
  request answers as `missing_credentials`, the same 401 as no credential.
* **A-17** — `aud` is required and must be `"talos"`; the aud-less branch, the
  `JWT_REQUIRE_AUD` reader and the variable (compose, chart, configuration
  reference, security docs) are gone. Compose and the chart already set it to
  `true`; only the code default was `false`. Every token minted since 2026-05
  carries `aud`.
* **A-12** — the API-key failed-validation budget is per
  `(prefix, caller address)` (`talos_api_keys::failure_budget_key`; the
  GraphQL handler passes the trusted-proxy-resolved IP bucketed by
  `rate_limit_key`). `validate_key` takes the caller.
* **A-14** — `call_a2a_agent` takes `user_id`; is admitted from the ONE
  heavy-operation bucket, moved from `talos-api` to
  `talos_rate_limit::heavy_operations()` so GraphQL `HeavyMutation` and the MCP
  tool share it (a refusal counts on `graphql_heavy_mutation`, the bucket's
  label); writes a `talos_audit` line (`event_kind = "a2a_call"`, user, HOST
  only, outcome, status or failure kind); a transport failure reports its kind
  only (`timeout` / `connect` / `redirect` / `body` / `request` / `other`).
* **A-15 (operator decision D-7)** — the narrow option: the 15-minute
  access-token revocation window is documented as accepted in
  `docs/security/architecture.md` §3.2. **The alternative, not built:** a `jti`
  on each access token and a Redis `user_id → not_before` entry written by
  every revocation path (sign-out-everywhere, password change, 2FA disable,
  refresh-token reuse) and read by `verify_token` — one Redis `GET` per
  authenticated request, failing open to the 15-minute window on a Redis
  outage. **Recommendation:** accept the window now. It is bounded, the
  refresh path is already revoked at once, and the denylist puts a Redis read
  on every request for a 15-minute gain. Build the denylist if the access-token
  TTL is ever raised, or if incident response needs revocation to take effect
  immediately.
* **H-2** — `100.64.0.0/10` added to the controller's external-egress `except`
  list; parity with the worker's is checked (below).
* **H-3** — every proxied `location` in `frontend/nginx.conf` and the chart's
  frontend ConfigMap names `client_max_body_size` equal to the controller's
  own cap for its routes (5m `/graphql` `/ws`, 2m axum default for `/api/`
  `/auth/*` `/memory-grants/` `/mcp` `/health`, 1m `/webhooks/`, 4k for the
  four capability-link routes). The nginx-ingress annotations stay in
  `values.yaml` (live under `className: nginx`, the chart default) with a
  comment; `install.sh`'s Traefik overlay nulls them. No Traefik `Middleware`:
  the buffering middleware holds whole bodies and would sit in front of SSE
  and WebSocket routes; the controller's per-route limit is already the cap.
* **H-4** — `talos.secretChecksum` hashes `metadata.uid/resourceVersion`, not
  `.data`.
* **H-5** — the image-admission identity regexp names
  `(main-publish\.yml|release\.yml)` in `install.sh` and the chart default. The
  review missed that `template-publish.yml` also holds `id-token: write`; it
  now carries a `# signing-identity:` marker saying it signs templates only.
* **H-6** — `--skip-ci-check` makes the RustSec audit required (a missing
  `cargo-audit` aborts too); `TALOS_PUBLISH_REQUIRE_AUDIT` overrides either way.
  `lint-frontend` / `lint-frontend-full` print SKIPPED without
  `node_modules`, and exit 3 under CI or `TALOS_SKIP_IS_FAILURE=1`, which the
  pre-push hook sets for its frontend gate.
* **H-7** — `frontend/.dockerignore` excludes `.env*`.
* **H-8** — the `frontend/nginx.conf` HTTP→HTTPS redirect is REMOVED, not
  pointed at `$server_name`: in this shared image `server_name` is
  `localhost`, so `$server_name` would send every user to
  `https://localhost/…`. The TLS proxy in front owns the scheme; HSTS stays.
  The chart ConfigMap never had the redirect.
* **H-9** — `scripts/ngrok.sh` writes the token to a `umask 077` temp config
  (`printf`, a builtin) and passes `--config`; removed on exit.
* **One checker for the deploy artefacts:** `scripts/check-deploy-posture.py`
  (A-3 compose CIDRs = subnet, H-2 except-list parity, H-3 body limits, H-4
  no `.data`, H-5 markers and regexps, H-7 `.env*`). In `make lint`; its
  `--self-test` and a tree run (`scripts/tests/deploy-posture-test.sh`) under
  `make test-scripts`. Run against main @ 176a8b56 it reports all six rules.

## Did not hold

* **A-11** — `/api/slack/channels` and `/api/slack/users` are already behind
  `rest_cookie_csrf_gate`: they sit in `slack_api_routes`
  (`controller/src/bootstrap/router.rs`, the `.layer(from_fn(rest_cookie_csrf_gate))`
  under the two routes), since `builder/SlackBrowser.tsx` was deleted on
  2026-09-10. The review read the gate's doc comment, which was stale; the
  comment is corrected, nothing else changed.

## Deliberately NOT done

* The worker's two tenant-facing `is_production()` reads —
  `host/limits.rs` (dev egress opt-ins refused in production) and
  `host/secrets.rs` (tier-2 expose cap fail-closed) — stay, listed in check
  100 with that reason: they are the worker crate's (package E's, landed in
  #1300), the worker serves no browser, the compose file sets neither opt-in,
  and `expose_secret` is hardcoded off at every dispatch path. A follow-up
  moves them if the worker is to share the predicate.
* No new `RateLimitKind` for the MCP side of the heavy-operation bucket: the
  label names the bucket, and a new label needs pre-seeding (check 58 class).
* The API-key budget per `(prefix, address)` raises the bcrypt-work bound for
  a caller with many addresses; accepted (the review's own fix), and only rows
  never used since the digest migration take the bcrypt path.

## Operator-facing changes

* **compose (`docker-compose.prod.yml`)** — `talos-network` now has a fixed
  subnet; an operator with a colliding Docker network sets
  `TALOS_COMPOSE_SUBNET`. Under `staging` the deployment now has: strict CSP,
  HSTS by default, Origin required on WS, scrubbed GraphQL errors, no
  introspection or playground, all rate limiters on, auth limiters and 2FA
  fail CLOSED when Redis is unreachable, `ALLOWED_ORIGIN` rules enforced, no
  `/mcp/local`, and `/api/registry/publish` refused without
  `REGISTRY_PUBLISH_TOKEN`. A staging deployment with
  `ALLOW_DEV_UNSAFE_CSRF_BYPASS=true` now refuses to boot.
* **Removed env var:** `JWT_REQUIRE_AUD` (no reader).
* **chart** — controller egress can no longer reach `100.64.0.0/10`; the
  checksum annotations change value once on the next upgrade (new hash input),
  rolling the dependent pods once; the default image identity regexp is
  narrower (an image signed by any other workflow is refused at admission).
* **install.sh** — the same regexp; the Traefik ingress no longer carries the
  inert nginx annotations.
* **publish-images.sh** — `--skip-ci-check` requires a clean `cargo audit`.
* **pre-push** — a push carrying frontend files fails when
  `frontend/node_modules` is absent.

## Mutation verdicts

Each: mutate, run the whole crate / binary (FAIL), restore from a copy,
`touch`, re-run (PASS).

| Gate | Mutation | Guarding test(s) | Verdict |
|---|---|---|---|
| A-4 token in query | `query_token_permitted` → `true` | `talos-mcp-handlers` lib: `a_query_token_off_the_event_stream_is_not_read`, `only_the_event_stream_get_may_carry_its_token_in_the_query`; controller `mcp_auth_metrics_tests::a_query_token_is_read_only_on_the_event_stream` | FAIL / PASS |
| A-5 `/mcp/local` mount | `mount_routes` on `talos_config::is_production()` | `mcp_local_route_caller_tests::the_route_is_not_mounted_outside_development` | FAIL / PASS |
| A-6 WS Origin | `origin_verdict` on `config::is_production()` | `talos-ws-auth/tests/origin_rust_env.rs` | FAIL / PASS |
| A-17 aud | `None => Ok(())` | `jwt_security_tests::a_token_without_an_audience_is_refused`; `talos-auth` `test_jwt_missing_audience_is_refused`, `the_session_verifier_accepts_and_refuses_what_it_is_recorded_to` | FAIL / PASS |
| A-12 budget | `failure_budget_key` → prefix only | `talos-api-keys` `one_callers_failures_do_not_lock_out_another` | FAIL / PASS |
| registry publish | `check_publish_authorized` on `is_production()` | `talos-registry` `no_token_is_open_only_in_development` | FAIL / PASS |

## One home

* the deployment predicate: `talos_auth_types::browser_hardening_required`;
  the list of build-posture readers: structural check 103;
* the `/mcp` route set and its local mount: `talos_mcp_handlers::mount_routes`;
* the WS Origin verdict: `talos_ws_auth::origin_verdict`;
* which MCP request may carry `?token=`: `talos_mcp_handlers::auth::query_token_permitted`;
* rate-limit enforcement and the auth fallback policy:
  `talos_rate_limit::{ip_rate_limits_enforced, auto_fallback_policy}`;
* the heavy-operation per-user bucket: `talos_rate_limit::heavy_operations`;
* the API-key failure budget key: `talos_api_keys::failure_budget_key`;
* the deploy-artefact rules: `scripts/check-deploy-posture.py`.

CLAUDE.md gained one rule sentence (Security Rules: which predicate a control
follows) and the check count.
