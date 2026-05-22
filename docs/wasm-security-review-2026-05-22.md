# Talos WASM Security Review — 2026-05-22

Branch: `claude/talos-wasm-security-XqZn1`
Scope: end-to-end review of Talos's use of WebAssembly — wasmtime sandbox configuration, host-function trust boundary (`worker/src/host_impl.rs`, 12,256 LoC), compilation pipeline (`talos-compilation/`), OCI distribution + Sigstore verification, SSRF gate, SQL validator, and the WIT capability-world model (`wit/talos.wit`).

This document is a snapshot. Each finding cites file + line so it can be confirmed and acted on independently.

---

## 1. Architecture in one paragraph

Untrusted user code is shipped to the platform as Rust (or JS/Python) source, compiled to a wasm32-wasip2 component inside a network-disconnected, read-only-rootfs container, signed (Sigstore keyless via GHA OIDC) into an OCI registry, then pulled by a credential-free worker, layer-digest-verified, cosign-verified (in `Required` policy), and executed inside wasmtime against one of twelve tiered linkers (capability worlds: `minimal-node` … `automation-node`). The worker has no Postgres / Neo4j / LLM-provider credentials — every privileged read/write is signed-NATS-RPC back to the controller. There are three independent stop conditions per job (fuel, epoch interruption, tokio timeout), an AES-256-GCM-with-AAD envelope for per-job secrets, an HMAC-signed `JobRequest` per execution, and an HMAC-signed AOT artifact cache (gates the one `unsafe Component::deserialize` site).

This is a strong baseline. The findings below are mostly defense-in-depth gaps; one (#1) is an unsigned-field downgrade window that should be closed.

---

## 2. Strong properties confirmed

| Property | Evidence |
|---|---|
| Wasmtime proposals locked down (no SIMD, threads, GC, function-references, tail-call, multi-memory, memory64, relaxed-SIMD) | `worker/src/runtime.rs:1374-1383` |
| Three independent kill switches: fuel + epoch interruption + tokio timeout | `runtime.rs:1342,1423,2216,2588` |
| Per-job fresh `Store`; no state leak across jobs sharing the `Engine` | `runtime.rs:2203,2582,2852,3402` |
| `unsafe { Component::deserialize }` gated by HMAC-SHA256 over `(version‖cap‖bytes)` with constant-time compare | `runtime.rs:3266-3306` |
| Per-job secret blob = AES-256-GCM with `workflow_execution_id` as AAD (rebinds ciphertext to the signed request) | `main.rs:1433` |
| `JobRequest` HMAC-SHA256 signed, length-prefixed canonical encoding, 300 s nonce window, replay cache (`JOB_NONCE_CACHE`) | `talos-workflow-job-protocol/src/lib.rs:1300-1400` |
| SSRF: custom `reqwest::dns::Resolve` re-applies private-IP filtering at resolution time → DNS-rebind TOCTOU window collapsed to zero | `worker/src/ssrf_resolver.rs:127-199` |
| Private-IP block-list covers RFC1918, loopback, link-local, multicast, broadcast, CGNAT (100.64/10), IPv6 ULA, IPv4-mapped IPv6, fe80::/10, ::1, the full 0.0.0.0/8 | `host_impl.rs:661-749` |
| Tier-1 LLM-egress enforced at five host-function surfaces; centralised in `decide_llm_tier_access` | `host_impl.rs:2430,2601,3152,6105,6461,11496` |
| `fetch_with_bearer` / `fetch_with_header` delegate through `self.fetch()` so the full allowlist + SSRF + Tier-1 chain applies (one path, not parallel paths) | `host_impl.rs:3547,3574` |
| SQL validator uses `sqlparser-rs` AST walk (not regex), rejects multi-statement, walks CTEs + FROM-subqueries, function deny-list catches set-returning funcs in FROM, fail-closed on unknown statement types (MCP-519) | `worker/src/sql_validator.rs` |
| OCI cache key is **digest-keyed** (not tag-keyed); layer digest re-verified on every cache hit; cache writes only after Sigstore + digest both pass | `worker/src/main.rs:1492-1505,1860-1978` |
| Production Sigstore policy must be explicitly chosen at startup (Disabled allowed but logged); deferring fail-closed in `Required` mode | `worker/src/main.rs:162-179,221-241,1692-1728` |
| File sandbox uses `cap_std::fs::Dir` over a per-execution `TempDir` (capability-secure: rejects `..` and out-of-sandbox symlinks at the OS layer) | `worker/src/context.rs:130,534-539; host_impl.rs:7194-7480` |
| Three-tier secret model — Tier-1 ops (`hmac-sign`, `fetch-with-bearer`, `fetch-with-header`) keep plaintext on the host side; `Zeroizing<String>` discipline on resolved values; opaque `u64` slot handles to guest | `wit/talos.wit:97-177; host_impl.rs:3521-3575,4030+` |
| Lint-enforced: `make lint` fails on raw `actor_memory` SQL outside `talos-memory/` and on raw sqlx inside `talos-mcp-handlers/` | `CLAUDE.md`; `scripts/lint-structural.sh` |

---

## 3. Findings

Severity bands: **Critical** = exploitable today against the documented threat model; **High** = exploitable contingent on one other compromise (insider / NATS MITM / operator misconfig); **Medium** = real but bounded, or defense-in-depth gap; **Low** = hardening / hygiene.

### 3.1 [High — defense-in-depth] `capability_world` hint is NOT in the `JobRequest` HMAC signing payload

**Location:** `talos-workflow-job-protocol/src/lib.rs:1230-1350` (`signing_payload`), `worker/src/main.rs:2391-2392`, `worker/src/runtime.rs:1855-1858,2120-2128`.

**Observation.** The `JobRequest` HMAC includes `module_uri`, `wasm_hash`, `actor_id`, `user_id`, `max_llm_tier`, `allowed_secrets`, `allowed_sql_operations`, `allow_tier2_exposure`, `integration_name`, and `reply_topic`. It does **not** include `capability_world`.

The worker honours the hint without re-validation when it is present and non-`Unknown` (runtime.rs:1855-1858):

```rust
let cap = match capability_world_hint {
    Some(hint) if !matches!(hint, CapabilityWorld::Unknown) => hint,
    _ => crate::wit_inspector::inspect_component(wasm_bytes).capability_world,
};
```

The hint drives three runtime decisions that have security consequences:

1. **`allow_wasi_network`** — granted for `Network | Database | Trusted` (runtime.rs:2125-2128). This calls `WasiCtxBuilder::inherit_network()` (context.rs:650), unlocking `wasi:sockets` raw TCP/UDP that bypass the HTTP allowlist + SSRF gate.
2. **Result cache TTL** — forced to `None` only when `cap == Governance` (runtime.rs:1860-1862). An attacker downgrading `Governance` → anything else lets human-approval verdicts be served from cache.
3. **Linker selection** — `select_tier(&cap)` (runtime.rs:2131) — determines which host functions are wired in.

**Exploit window.** An attacker with NATS-channel write (insider, MITM on an unencrypted bus, a compromised non-worker subscriber that can republish) can flip `capability_world` in a signed-but-replayable JobRequest while keeping every other field intact and HMAC-valid. The `wasm_hash` binding means the binary cannot be swapped, but the linker tier and WASI-socket flag can.

The Wizer-snapshot rationale in the comment is real (post-snapshot binaries can lose embedded WIT world-name strings), so simply removing the hint isn't an option. Two non-mutually-exclusive fixes:

- **Sign the hint.** Append `capability_world` to the `signing_payload` at the end, per the "wire-format stability rule" already used for `actor_id` / `max_llm_tier` / `reply_topic`. Cost: one coordinated controller+worker restart, no migration.
- **Take `max(hint, inspect(binary))`.** If the binary is re-inspectable (most cases), use whichever world is more restrictive. The Wizer-snapshot edge case falls back to the signed hint. This requires the hint to be signed (the snapshot path has no other anchor).

**Severity reasoning.** Tagged High not because the exploit is obvious (the wasm_hash binding does most of the work) but because every other policy field in `JobRequest` is signed, and the lone unsigned field is the one that drives WASI-network gating. The class of bug ("we forgot to add the new field to the signing payload") has already bitten the codebase — see the `actor_id` / `max_llm_tier` / `reply_topic` comments at lines 1276-1300, each a retro fix.

---

### 3.2 [Medium] Database RPC error text passed verbatim to guest

**Location:** `worker/src/host_impl.rs:7155-7173`; `talos-rpc-subscribers/src/lib.rs:289,292,330` (`.map_err(|e| DatabaseRpcError::QueryError(e.to_string()))`).

**Observation.** The controller wraps raw `sqlx::Error` text (which includes Postgres error detail: column names, table names, RLS-policy names, constraint names) into `DatabaseRpcError::{QueryError, InvalidQuery, ConnectionFailed}`. The worker forwards that text verbatim into `self.last_db_error` (lines 7156, 7160, 7164, 7172), readable by the guest via `database::get_last_error()`.

CLAUDE.md is explicit on this:

> NEVER return internal error details to API clients. Log full errors server-side, return generic messages.

The SQL validator already rejects access to `pg_catalog` introspection functions, but it does not blocklist `SELECT FROM pg_catalog.*` tables in general (see 3.4). Combined with verbose PG errors, a guest can enumerate the schema reachable from its role: column names appear in "column X does not exist" errors, constraint names appear in foreign-key violations, RLS-policy names appear in "row violates row-level security policy" errors.

**Mitigation.** Replace pass-through `e.to_string()` with a generic message at the controller boundary, log the detail server-side. The `wit_database::Error` enum already has the four-way classification (`Connectionfailed`, `Queryerror`, `Unauthorized`, `Invalidquery`) — that should be the full surface area visible to guests.

**Severity reasoning.** Mitigated by: (a) the role-wrap via `TALOS_RPC_GUEST_ROLE` if configured, (b) the validator's strict allowlist of statements + functions. But the gap is on a documented security invariant (CLAUDE.md), and the fix is one line per arm.

---

### 3.3 [Medium] Transitive-dependency allowlist gap

**Location:** `talos-compilation/src/dependency_allowlist.rs:64-179`, `talos-compilation/src/lib.rs:1586-1592`.

**Observation.** `validate_dependencies(deps_obj)` walks the user-declared dependency map and checks each crate name against the allowlist. It does not walk `Cargo.lock`. So `tokio = "1"` (allowed) pulls in `mio`, `parking_lot`, `socket2`, etc. transitively — none of which are checked. The risk surface is:

- A future RustSec advisory on a transitive crate is caught by `cargo audit` post-compile (lib.rs:50-197), but only if the advisory DB is fresh.
- A transitive proc-macro crate ships compile-time code that runs inside the build container.

Compensating controls (these are why this is Medium not High):

- The build container is `--network=none` (`talos-compilation/src/container.rs:79-90`) — proc-macros and `build.rs` cannot exfiltrate.
- The rootfs is read-only.
- `cargo audit --db /opt/talos-advisory-db --no-fetch` runs against the baked-in RustSec DB; fails closed in production (90-day staleness gate).
- The dependency-allowlist fingerprint is folded into the WASM provenance hash (lib.rs:1369-1390) — auditors can replay the build with the same allowlist and check the digest.

**Recommendation.** Add a post-lockfile sweep: parse `Cargo.lock` after `cargo generate-lockfile --offline`, fail compilation if any resolved crate is not in the union of (default allowlist) + (well-known transitives whitelist). The well-known transitives whitelist can be auto-derived once from a clean `cargo tree` of the default allowlist and committed alongside.

---

### 3.4 [Medium] SQL validator does not blocklist `pg_catalog` / `information_schema` reads

**Location:** `worker/src/sql_validator.rs` (no explicit block on these schemas).

**Observation.** The validator rejects ~35 dangerous functions (`pg_read_file`, `dblink`, `pg_sleep`, etc.) and walks CTEs and FROM-subqueries for nested mutations. It does not, however, reject `SELECT … FROM pg_catalog.pg_roles`, `SELECT … FROM pg_catalog.pg_class`, `SELECT … FROM information_schema.columns`, etc. A guest with SELECT permission can map the database's roles, tables, columns, and constraints.

**Compensating control.** `TALOS_RPC_GUEST_ROLE` (talos-rpc-subscribers/src/lib.rs:1543-1565) is meant to constrain what privileges the guest's session role has. Postgres's `pg_catalog` views are filtered by role, so a guest role with no SELECT on user tables also gets a thinned `pg_class`. But the role-wrap is operator-opt-in and the default behaviour is to run as the app user.

**Recommendation.** Either (a) deny references to `pg_catalog.*` and `information_schema.*` in the validator's table-name walk, or (b) require `TALOS_RPC_GUEST_ROLE` at startup in production. The latter is the durable fix.

---

### 3.5 [Medium] `proc-macro` and `build.rs` execute on the build host (inside the container)

**Location:** `talos-compilation/src/container.rs:79-90`, `lib.rs:926-931,1157`.

**Observation.** Standard cargo behaviour: user-declared crates may bring in proc-macro deps that execute Rust code at compile time, and the user's `build.rs` runs natively before WASM emission. Both are sandboxed by the build container (`--network=none`, read-only rootfs, tmpfs `/tmp:1g`, `--memory 2g`, `--cpus 2`, seccomp profile at `security/seccomp-controller.json`).

The container is good, but the threat is real: a malicious transitive proc-macro can rewrite the WASM source before compilation, planting a logic bomb that the WIT-import scan won't see (the bomb is in legitimately-permitted code paths). The advisory-DB check catches *known* vulnerable proc-macros, not future-malicious ones.

**Recommendation.** Two cheap hardenings:

1. Run `cargo metadata --format-version 1` after lockfile generation and refuse compilation if any resolved crate has `proc-macro = true` in its `Cargo.toml` *and* is not on a small audited proc-macro allowlist (`serde_derive`, `thiserror-impl`, `tokio-macros`, …).
2. Drop `CAP_NET_RAW` and inspect the seccomp profile against the actual syscalls cargo+rustc need (kbd `strace -c`); compile failures on additional syscalls are loud, which is the goal.

---

### 3.6 [Medium] Compilation hint trusted over re-inspection in the snapshot path

**Location:** `worker/src/runtime.rs:1855-1858`, `runtime.rs:2120-2128`.

This is the read-side companion to 3.1 — the worker takes the controller's word on `capability_world` in the main `execute_job_with_full_features` path. The `run_sandbox` path re-inspects (runtime.rs:2547), as do `compile_module_steps` (runtime.rs:2776), `precompile_aot` (runtime.rs:3039), and the OCI-pull path (runtime.rs:3494). The inconsistency itself is a finding: the main path is the highest-volume, most-attacker-reachable path.

**Recommendation.** Once 3.1 is fixed (hint signed), additionally re-inspect when the binary is not snapshotted (most cases) and bail if `inspect ≠ hint`. The signed hint becomes the trust root only for snapshot binaries.

---

### 3.7 [Low] Sigstore identity-regexp is operator-supplied and unvalidated at startup

**Location:** `worker/src/main.rs:444-462,473`.

The operator configures the `--certificate-identity-regexp` value via env. A permissive regexp (e.g. `.*talos.*@.*` instead of `^https://github\\.com/OWNER/talos/\\.github/workflows/template-publish\\.yml@`) accepts signatures from any fork. CLAUDE.md flags this as a known operational footgun. The fix is to validate the regexp shape at startup (must start with `^https://`, must contain `@` near the end, must not contain `.*` after the workflow filename) and fail boot in `Required` mode if it's too loose.

---

### 3.8 [Low] Cargo.toml version-string validator does not parse the string as TOML

**Location:** `talos-compilation/src/lib.rs:1615-1639`.

The version validator rejects `git=`, `path=`, `{`, `}`, quotes, brackets, but accepts `=` and `,`. A user can sneak `"1.0, features = [\"derive\"]"` into a version field and toggle features off the allowed-feature path. Standard `[dependencies.crate]` shape is the right model; the cheap fix is to parse the value as a `cargo_metadata::DependencySpec` and reject if it's anything other than a bare semver range.

---

### 3.9 [Low] Slot-handle lookup is not constant-time

**Location:** `worker/src/host_impl.rs:3979` and surrounding `provider.resolve()`.

The `u64` slot handle is looked up in a `DashMap`. Standard hash lookup, not constant-time. A timing oracle reveals slot-existence vs miss. Low-value information (the slot count is already bounded by per-execution allowlist size). Document or use a constant-time match if/when slots become longer-lived.

---

### 3.10 [Low] GraphQL introspection detection only inspects top-level selection set

**Location:** `worker/src/host_impl.rs:69-120`.

`looks_like_graphql_introspection` flags `__schema` / `__type` at the root selection set. Aliased introspection (`{ alias: __schema { … } }`) and fragment-nested introspection bypass the heuristic. The comment at line 80 acknowledges this as an intentional limitation to avoid false positives. Recommendation: parse the GraphQL document with `async-graphql-parser` and walk the AST for any `__schema` / `__type` field — false-positive rate stays low because real queries don't reference these.

---

### 3.11 [Low] Messaging publish does not enforce per-actor topic prefix

**Location:** `worker/src/host_impl.rs:5472-5592` (`wit_messaging::publish`).

The publish path rejects the reserved `talos.` and `wasm.` prefixes but lets any other subject through. Two integrations / two actors that converge on the same logical name (`mycompany.billing.events`) can read and write each other's stream. Recommendation: auto-prefix with `actor.<actor_id>.` or `integration.<integration_name>.` on publish, document the rule in the WIT.

---

### 3.12 [Informational — unfinished primitives]

- `agent-orchestration::inject_runtime_node` and `reroute_to_node` are stubbed (`worker/src/host_impl.rs:9143-9165`) — return errors today. The comments document the required capability-ceiling check; verify the check ships with the implementation, not after.
- WIT defines `email::send` and `messaging::request` interfaces — confirm at implementation time that they re-use the HTTP allowlist + SSRF gate, not a parallel client. Today they appear behind the `host_impl` path that already imports the central reqwest client, but worth a CI test.

---

## 4. Out-of-scope but worth flagging

- **Reproducibility.** The provenance log records the dependency-allowlist fingerprint + WIT-schema fingerprint + content hash (lib.rs:1369-1395), but `Cargo.lock` itself is not pinned in a source-of-truth repo before the build. A registry-cache tamper would surface as a different output hash with no upstream signal. Out of WASM-sandbox scope, but undercuts the "rebuild and verify" supply-chain story.
- **JS / Python compilation paths** (`talos-compilation/src/js_templates.rs` + `componentize-py`) run host-side without container isolation; gated behind `TALOS_COMPILATION_ALLOW_HOST_FALLBACK`. Acceptable for single-tenant deployments per the comment; for multi-tenant, this must stay off (which it does by default, with a startup-time warning).
- **Sigstore-policy default in non-production is `Disabled`** (`main.rs:162-179`). Production gate is enforced at startup. Acceptable, but the dev-vs-prod policy divergence is worth documenting in the operator-facing security checklist.

---

## 5. Recommended next steps (in priority order)

1. **Add `capability_world` to `JobRequest::signing_payload`** (closes §3.1). One line at the end of the `format!` block, one extra field comparison in `verify`. Coordinate worker + controller restart.
2. **Strip controller-supplied error text from `DatabaseRpcError::{QueryError, InvalidQuery, ConnectionFailed}`** (closes §3.2). Map to a generic message at the controller boundary; full text stays in server logs.
3. **Default-deny `pg_catalog.*` / `information_schema.*` table references in `sql_validator.rs`** (closes §3.4), OR refuse to boot the controller in production if `TALOS_RPC_GUEST_ROLE` is unset.
4. **Post-lockfile transitive-dep audit** (closes §3.3). Add a `Cargo.lock` parser + audited transitive whitelist; fail compilation on out-of-set crates.
5. **Proc-macro allowlist** (closes §3.5). Refuse compilation if any resolved crate has `proc-macro = true` and is not on a small audited list.
6. **Re-inspect WIT in the main worker path and use `max(hint, inspect)`** (closes §3.6). Depends on #1.
7. **Validate Sigstore identity-regexp shape at worker startup** (closes §3.7). Refuse boot in `Required` mode if it's not anchored.

Items 1-3 are mechanical and should ship together. Items 4-5 are a single compilation-pipeline PR. Items 6-7 are independent.
