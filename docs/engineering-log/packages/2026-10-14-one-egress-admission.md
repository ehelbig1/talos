# Every byte a module sends leaves through one admission (2026-10-14)

Security review 2026-10-14, domain E (worker sandbox and module egress),
package 6: findings E-1, E-2, E-3, E-6, E-9, E-10. Each was verified at its
lines on this tree before it was changed.

## Verified

| Finding | Held? | Evidence on this tree |
|---|---|---|
| E-1 `email::send` outside the admission | **Held** (worker half) | `host/email.rs`: the URL from `get_host_secret("EMAIL_API_URL")` or the `EMAIL_API_URL` env var went straight to `client.post(&url)`; no scheme, IP-literal, allowlist or posture check. A private literal is never seen by the connect-time resolver. Measured by the new env test before the fix: the listener on `https://127.0.0.1:<port>/` was dialled (1 accept) under `allowed_hosts: ["*"]`. |
| E-1 `create_secret` should validate key paths | **Did not hold as specified** | `talos-oauth/src/credentials.rs` stores every OAuth token through `SecretsManager::create_secret` at `oauth/<provider>/<uuid>/<provider_key>/…`, and `provider_key` is the account address (`@`, `.`), which `validate_vault_key_path` refuses — the change would refuse every OAuth token write. The three non-API writers (talos-oauth `oauth/…`, talos-plaid-connect `plaid/…` via `upsert_secret`, the operator CLI) all write fixed lowercase prefixes, so none can create `EMAIL_API_URL` / `EMAIL_API_KEY`. Not changed. |
| E-2 raw sockets for `Database` | **Held in code; partly inert at runtime** | `runtime.rs::socket_grant` granted `Network | Database | Trusted`; `context.rs` set `inherit_network()` + `allow_ip_name_lookup(true)`. Measured: since the wasmtime 48 bump (2026-09-29) `WasiCtxBuilder` defaults **TCP to off** (`AllowedNetworkUses` derives `Default`; wasmtime 47 defaulted tcp/udp on) and nothing calls `allow_tcp(true)`, so on this tree NO store can create a TCP socket. Guest DNS lookup WAS live for every granted store, `database-node` included — the side channel the review named. |
| E-3 no secret→destination binding | **Held** | `host/vault.rs::resolve_vault_placed` gated on `allowed_secrets` and the tier-1 LLM path only; a `"*"` module could substitute a granted token into a request to any admitted host, and `messaging.rs` substituted into NATS headers. |
| E-6 `WASM_ALLOW_INSECURE_HTTP` in production | **Held** | `host/egress.rs::insecure_http_opt_in` was a bare env read; its sibling folded `!is_production()`. |
| E-9 `wasi:http` parity caps | **Held** | `send_via_hardened_client`: unset timeouts 600 s and set ones unbounded, request body streamed uncapped, no outbound header cap, no inbound header caps, no breaker permit. |
| E-10 host-only allowlist | **Held** | `egress.rs::host_allowlist_match_kind` compared the host only; port entered only the rate-limit key. |

## Decided

* **E-1.** `TalosContext::admit_email_api_url` (`host/email.rs`) runs the
  shared `egress_admission::admit_url` and then, for a hostname,
  `validate_no_dns_rebinding` — `webhook::send`'s order — and `send` POSTs the
  URL that was judged. A refusal is recorded under `email-send` with the
  admission's policy token; the target is a host or IP, never the URL (a
  configured secret); an unparseable URL is recorded as
  `invalid-email-api-url` with an empty target.
* **E-2.** `socket_grant` takes `allowed_hosts` and grants only
  `Network | Trusted`, Tier-2, public egress, **and `"*"` in `allowed_hosts`**.
  `Database` is out (recommended option of D-2, below). A module whose
  operator named its hosts gets no network at all — no guest DNS, no address
  check to pass — because raw sockets dial addresses and cannot honour a
  name list. `allow_ip_name_lookup(true)` is kept for a granted store: it can
  already reach any public host over `talos:core/http`, so a lookup adds no
  channel. TCP stays as it is today (off — see Stated limits).
* **E-3.** `host::vault::secret_destination_refusal` (pure) and its call in
  `resolve_vault_placed`, after the `allowed_secrets` and tier-1 gates and
  before the provider is touched: a credential is substituted only when the
  destination host is NAMED in `allowed_hosts` (exact or suffix entry,
  `egress::host_named_in_allowlist`; ports on entries ignored), and never on
  `MessagingHeader`. Audit policy `secret-destination`; the surfaces latch
  `secret-lookup` as for every other resolve refusal. The remedy the guest
  error names: add the destination to `allowed_hosts` beside `"*"` (a named
  entry is credited even with `"*"` present).
* **E-6.** `host::limits::dev_only_egress_toggle(var, once, relaxed)` is the
  one rule for a dev-only egress toggle (env read, refused under
  `is_production()`, WARN once per process); both opt-ins in
  `DevEgressOptIns` call it.
* **E-9.** `send_via_hardened_client`: both guest timeouts through
  `clamp_guest_timeout_ms` (unset → `fetch`'s 30 s default, max 120 s); more
  than `MAX_OUTBOUND_HEADERS` → `HttpRequestHeaderSectionSize`; the request
  body wrapped in `http_body_util::Limited(MAX_OUTBOUND_HTTP_BODY_BYTES)` →
  `HttpRequestBodySize`, settled as no breaker evidence; a `RequestPermit`
  from the global breaker keyed by `BreakerTarget::from_url` and settled as
  `fetch` settles it (open → `DestinationUnavailable`); inbound
  `MAX_INBOUND_HEADERS` / `MAX_INBOUND_HEADER_VALUE_BYTES` →
  `HttpResponseHeaderSectionSize` / `HttpResponseHeaderSize`.
* **E-10.** `egress::split_allowlist_entry` reads `host:port`; an entry with a
  port admits that host on `port_or_known_default()` only; an entry without
  one admits every port, as before; a malformed port (`host:`, `host:0`,
  `host:99999`) keeps the whole string as the pattern and matches nothing.
  `admit_url` (fetch, fetch_all, wasi:http, email), `webhook::send`,
  `graphql::execute` and `http_stream::connect` pass the request's port.

## One home

* URL admission: `host::egress_admission::admit_url` — now also the email
  surface's.
* Allowlist matching: `host::egress::match_allowlist` behind
  `host_allowlist_match_kind` (port-aware) and `host_named_in_allowlist`
  (named-ness, ports ignored).
* Raw-socket grant: `runtime::socket_grant`.
* Secret→destination: `host::vault::secret_destination_refusal`.
* Dev-only egress toggles: `host::limits::dev_only_egress_toggle`.

CLAUDE.md gained one bullet under "Worker-side secret isolation" (the
destination rule and the admission rule for any URL a host function sends to).

## Mutations (egress controls)

Each applied to the final tree, the whole crate run (`cargo test -p
talos-worker-runtime --no-fail-fast`, no name filter), the file restored from
its backup with `cp`, `cmp`-checked and `touch`ed, and the whole crate run
again: 958 lib + 2 + 1 + 3 + doc, all pass after every restore.

| # | Mutation | Verdict | Caught by |
|---|---|---|---|
| 1a | `send` parses the URL itself instead of calling `admit_email_api_url` | FAIL (caught) | `email_admission_tests::send_records_a_refusal_from_the_gate_before_any_post`; `dev_egress_env::the_email_api_url_from_the_environment_passes_the_egress_admission` ("the refused URL must never be dialled", left 1) |
| 1b | `admit_email_api_url` returns any parseable URL | FAIL (caught) | 3 `email_admission_tests` (private literal, plaintext, allowlist); the env test |
| 2a | `Database` back in `socket_grant` | FAIL (caught) | `socket_grant_tests::only_network_and_trusted_get_sockets_at_tier2`, `::a_database_guest_has_no_network` |
| 2b | the `"*"` condition removed from `socket_grant` | FAIL (caught) | `socket_grant_tests::a_named_host_list_gets_no_sockets`, `::a_named_host_list_has_no_network` |
| 3a | the destination gate's result ignored in `resolve_vault_placed` | FAIL (caught) | 4 `vault_destination_tests` (fetch, webhook, body, message bus) |
| 3b | `secret_destination_refusal` admits wildcard-only hosts | FAIL (caught) | `secret_destination_tests::a_named_destination_passes_and_a_wildcard_only_one_does_not` + 3 `vault_destination_tests` |
| 6 | `insecure_http_opt_in` back to a bare env read | FAIL (caught) | `dev_egress_env::the_environment_reaches_a_context_and_production_refuses_the_private_target_toggle` |
| 10 | entry ports ignored in `match_allowlist` | FAIL (caught) | `host_allowlist_match_kind_tests::an_entry_with_a_port_admits_only_that_port`, `egress_admission::tests::an_entry_with_a_port_admits_that_port_only` |

No mutation survived.

## Behaviour changes an operator will see

* **`webhook-fanout`** (catalog, `http-node`, `allowed_hosts: ["*"]`, requires a
  `vault://` auth header): its sends are refused with `secret-destination`
  until the copy's owner names the destination host(s) in `allowed_hosts`.
  Same for an installed `http-request` / `http-retry` copy to which the owner
  granted secrets. Fleet population not measured (no database access in this
  package).
* A module that calls `email::send` must list the email API's host in
  `allowed_hosts`. No catalog template calls `email::send`.
* `wasi:http`: an unset timeout is now 30 s (was 600 s); every timeout is at
  most 120 s.
* `run_sandbox` / `test_module` of a `network-node` module (actor-less path,
  `allowed_hosts` empty) no longer gets guest DNS.

## Operator decision D-2 — does any `database-node` module rely on raw sockets?

**Built: the recommended, reversible option** — `Database` dropped from
`socket_grant` (one line to restore; mutation 2a is that line). The catalog's
`database-node` templates, each searched (`template.rs` and `src/`) for
`std::net`, `TcpStream`, `UdpSocket`, `TcpListener`, `ToSocketAddrs`,
`lookup_host`, `wasi::sockets` / `wasi:sockets`:

| Template | `allowed_hosts` | Raw sockets / guest DNS in source |
|---|---|---|
| `data-pipeline-etl` | `["*"]` | none (HTTP through `talos:core/http`, SQL through `database`) |
| `database-query` | `[]` | none |

And measured on this tree: since the wasmtime 48 bump no store can create a
TCP socket at all, so no deployed `database-node` module can have depended on
raw TCP since 2026-09-29; what the grant still gave them was guest DNS.
**Recommendation: keep `Database` out.** Users' own `database-node` modules
were not inspected (no database access).

## Deliberately NOT done

* **The `allow_vault_to_wildcard_hosts` module flag** (E-3's "unless" clause).
  It needs a new HMAC-bound wire field (`JobRequest` + `PipelineStep`, both
  snapshots), a `modules` column and migration, the manifest parser,
  `get_module_info`, and every dispatch path — five-plus crates — and its only
  effect is to re-open the wildcard case the rule closes. The opt-out that
  exists without it is the narrower one: name the destination beside `"*"`.
  If the operator wants the flag, it is its own package.
* **Per-secret `allowed_destinations`** — recorded as the longer-term shape
  (OAuth integrations know their provider hosts); not built.
* **`allow_tcp(true)` for granted stores.** Raw TCP has been off since the
  wasmtime 48 bump; turning it back on WIDENS egress and is an operator
  decision (the catalog's `network-scanner`, `network-node` with `"*"`, uses
  `std::net::TcpStream` and cannot work today). Pinned by
  `socket_grant_tests::tcp_is_off_even_for_a_granted_store`.
* **Making the vault route for `EMAIL_API_URL` work.** `get_host_secret` reads
  through `into_auth_header("Authorization")`, which prefixes `Bearer ` to the
  URL, so a vault-sourced URL has never parsed; fixing it would widen a route,
  and the gate now covers it if someone does.
* **`create_secret` key-path validation** — see Verified; it would refuse
  OAuth token writes.
* **Loosening `talos-registry::validate_allowed_hosts`** to accept
  `host:port`. The catalog/publish path still refuses port entries (and its
  message, "outbound URL matching ignores port", is now stale); a port entry
  reaches a job only through `update_module_hosts`, which never checked `:`.
* **Default-deny of non-443/80 ports** for port-less entries (E-10's stronger
  form): it would break every module that calls a non-default port today.
* **Refactoring `fetch`'s inline inbound-header checks** onto
  `wasi_http::response_header_violation`.

## Stated limits

* The dev-bypass explicit-host check (`host_explicitly_allowed`) and the
  connect-time resolver compare entries whole, so `localhost:8080` does not
  count as naming `localhost` for `WORKER_ALLOW_PRIVATE_HOST_TARGETS`. Both
  layers agree, so it fails closed.
* Over HTTP/1, hyper refuses more than 100 response headers before the
  `MAX_INBOUND_HEADERS` (128) check can; the count cap is unit-tested on
  `response_header_violation`, the wire leg only asserts a refusal.
* The secret-destination rule ignores ports: a credential may go to a named
  host on any port the admission admitted (a `"*"` entry admits every port).
* An email-API refusal is charged against the per-execution email budget (the
  admission runs after the credential lookup, which is after the charge);
  the URL is operator configuration, so a refused URL refuses every call.

## Commands

* `cargo test -p talos-worker-runtime` — 958 lib, 2 `dev_egress_env`,
  1 `metrics_shape`, 3 `sql_corpus`, 1 doc; run twice, green both times.
* `cargo clippy -p talos-worker-runtime --all-targets -- -D warnings` — clean.

## Measured on the reference deployment (2026-10-14, read-only, by the orchestrating session)

- Modules with `"*"` in `allowed_hosts` AND a non-empty `allowed_secrets`: **1**,
  a catalog row (`RAG Pipeline`) referenced by **0** live workflows. E-3 refuses
  nothing any live workflow sends today.
- `database-node` modules: 2, neither holding a secret grant (D-2). Every
  `network-node` module holding secrets (8 of 9) names its hosts, so E-3 and
  E-2's named-list rule leave their HTTP paths unchanged; they lose guest DNS,
  which no host-function HTTP path uses.
- `messaging-node` modules holding secrets: 0 (the message-bus header refusal
  changes nothing live).
