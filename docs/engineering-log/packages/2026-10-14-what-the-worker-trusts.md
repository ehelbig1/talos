# What the worker trusts and what it holds (2026-10-14)

Security review 2026-10-14, package 7: findings E-4, E-5, E-7, E-12 (domain
E, worker sandbox), H-1 (domain H, deploy) and G-21 (domain G, compilation).
Each was verified at its lines on this tree before it was changed.

## Verified

| Finding | Held? | Evidence on this tree |
|---|---|---|
| E-4 Redis result cache unauthenticated | **Held** | `runtime.rs::get_cached_result` read `wasm:result:{module_hash}:{context_hash}` with `conn.get::<_, String>` → `serde_json::from_str` → returned as the job's output; `cache_result` wrote `serde_json::to_string(result)` with `SETEX`. No MAC, no encryption. The OCI cache beside it re-verifies its digest on a hit. |
| E-5 provider credentials by env | **Held** | `host/vault.rs::llm_key_with_use_recorded`: vault path first, then `std::env::var(env_name)` for every tier-2 tenant, in every environment. `context.rs` reads `S3_ENDPOINT` / `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY`; `host/email.rs` falls back to the `EMAIL_API_URL` / `EMAIL_API_KEY` env vars. None of these was in the configuration reference as a worker-held credential. |
| E-7 Audit + empty regexp attested and cached | **Held** | `module_fetcher.rs`: `sigstore_pass_in_this_run` started `true`; with `identity_regexp.is_empty()` the Audit arm logged and fell through, so the flag stayed `true` and the layer was `SET` into the Redis OCI cache. `talos-sigstore-policy::from_env_str` mapped any unknown value to `Disabled`, which the production gate refused but nothing else did. |
| H-1 template verification off while NOTES says ON | **Held** | `install.sh` rendered `required: "${TALOS_SIGSTORE_REQUIRED:-disabled}"` and nothing refused `disabled` with `TALOS_REGISTRY_URL` set; `NOTES.txt` printed "sigstore enforcement is ON" from `security.sigstore.enabled`, the image-admission switch, which does not cover templates. |
| E-12 log relay volume and injection | **Held** | `host/logging.rs`: 10 000 messages × 10 000 B per execution (≈100 MB) relayed to NATS and `tracing`, message text verbatim (`\n`, ESC reach a text subscriber). |
| G-21 advisory-DB age measured on the wrong copy | **Held** | `lib.rs` called `check_advisory_db_age(/opt/talos-advisory-db)` on the controller host, then ran `cargo audit --db /opt/talos-advisory-db` inside the builder container (`container::audit_command`, `--network=none`, no mount of that path) — the builder image's own copy. `advisory_db.rs` recorded this as a stated limit. |

E-1 (the email URL outside the egress admission), cited by E-5's evidence, was
already closed by package 6 (`2026-10-14-one-egress-admission.md`).

## Decided

* **E-4 — seal, keep the Redis tier.** `talos_worker_runtime::result_cache_seal`
  is the one home: AES-256-GCM under a per-cache-key subkey
  (`HMAC-SHA256(seal key, label ‖ cache key)`), the seal key
  `HMAC-SHA256(WORKER_SHARED_KEY, label)`, the cache key as AAD, the nonce from
  `talos_random`, stored as `talos-rc1:` + base64. That is both the MAC the
  package asked for and the encryption at rest it asked for if the tier is
  kept. `open` returns `None` for a flipped byte, an entry moved to another
  cache key, another fleet key, or a plaintext value; `get_cached_result`
  treats `None` as a miss (WARN `result_cache_entry_unsealed`) and the module
  runs. The worker binary sets the key (`with_result_cache_seal_key`); a
  runtime without one — the embedded rehearsal surfaces, tests — uses no Redis
  tier at all.
* **E-5 — a worker outside development refuses the env fallback for LLM
  provider keys; S3/email are documented as operator-held worker credentials
  (the narrow option).** `context::EnvProviderKeys` is the one rule
  (`permitted = !hardened || TALOS_WORKER_ALLOW_ENV_PROVIDER_KEYS`, where
  `hardened` is `talos_auth_types::browser_hardening_required()` — the
  fallback is a control a tenant meets, so structural check 103 holds it to
  that rule rather than `is_production()`, and a `RUST_ENV=staging`
  deployment refuses it too), read
  once per execution like `DevEgressOptIns`; `llm_key_with_use_recorded` asks
  it. A refused key that IS set is logged once per process. The S3 and email
  rows in `docs/configuration-reference.md` now say they are worker-held
  operator credentials used by every module with that capability.
* **E-7.** `SigstorePolicy::from_env_str` / `from_env` return
  `Result<_, UnrecognisedSigstorePolicy>` (empty is still the silent
  `Disabled` the production gates police). The worker's
  `enforce_production_sigstore_policy_explicit` refuses an unknown value in
  every environment, and the boot's two later checks read the policy it
  resolved; the controller's OCI sync declines (`PolicyNotExplicit`) on one in
  every environment, and its per-artifact verify returns `Err`. The pull's
  cache-or-not decision is the pure `module_fetcher::sigstore_verdict`:
  Verified → cacheable; `audit` with no identity or a failed verify → execute
  uncached; `required` → refuse with the two existing messages; explicit
  `disabled` → cacheable (operator intent unchanged; the cache is still
  digest-keyed and re-verified).
* **H-1.** `deploy/k3s/lib/template-signing.sh` (pure, beside
  `worker-trust.sh`): `ts_sigstore_mode` mirrors the Rust spellings,
  `ts_template_signing_refusal` refuses `disabled` with a registry unless
  `TALOS_ALLOW_UNSIGNED_TEMPLATES=yes`, and an unknown policy always.
  `install.sh` calls it in the validation block, before the root check and
  every install step. `NOTES.txt` prints "Image admission" and "Template
  verification" as two lines, each with its own state, and whether a registry
  is configured.
* **E-12.** `host/logging.rs`: `neutralise_log_text` writes every
  `char::is_control` character (C0, DEL, C1) as its escape (`\n` → `\\n`,
  ESC → `\\u{1b}`); `log-json` payloads are neutralised in every string and
  key. A per-execution byte budget `MAX_LOG_BYTES_PER_EXECUTION` = 1 MiB
  across `log` and `log-json` (one WARN, then drop), beside the unchanged
  10 000-message count and `MAX_LOG_MESSAGE_BYTES` = 10 000. Documented in
  `docs/module-authoring.md`.
* **G-21.** `container::audit_command_with_db_probe` returns, from the
  audit's own sandbox decision, an `AdvisoryDbProbe` in container mode: the
  builder image under the audit envelope with NO mount, running
  `stat -c %Y` over the three signals `advisory_db_age_days` reads on the
  host. `advisory_db::builder_advisory_db_age_days` runs it under the compile
  slot at most once an hour per image (the age is recomputed from the cached
  signal on every call) and the gate (`check_measured_advisory_db_age`) judges
  that age. Host mode still `stat`s the host copy, which is the one a host
  audit reads.

## Deliberately NOT done

* **E-4: dropping the Redis tier.** The package offered it. Sealing keeps
  the fleet-wide hit (the tier is opt-in through `WASM_RESULT_CACHE_TTL_SECS`
  and is what makes a cache shared across workers) and closes both the
  integrity and the at-rest gap. No plaintext-compatibility arm: an unsealed
  value is exactly what an attacker writes, and a miss costs one execution.
* **E-4: verifying against `WORKER_SHARED_KEY_PREVIOUS`.** A rotation turns
  old entries into misses until their TTL; a cache does not need the ring.
* **E-5: moving S3/email to controller-minted per-job secrets.** Recommended
  as the follow-up (below), not done: it needs a vault path convention for
  per-user S3/email credentials, a controller resolver and a module grant,
  i.e. a new primitive. `email.rs` already prefers a job secret
  (`EMAIL_API_URL` / `EMAIL_API_KEY` in the job's map) over the env, so the
  migration is a controller-side change.
* **E-5: an env refusal for S3/email in production.** It would break any
  deployment using them with no replacement path today.
* **H-1: a chart-level `fail`** (render refusal for `ociRegistry.url` +
  `required: disabled`). The package scoped the refusal to `install.sh`; a
  chart `fail` would also stop a raw `helm upgrade` but needs a values key
  (`allowUnsignedTemplates`) and an install.sh mapping. Left as a follow-up.
* **G-21: sampling the builder copy hourly onto `talos_advisory_db_age_days`.**
  The metric keeps its `copy="controller"` label and its alerts; a
  `builder` label would need the sampler to start a container every hour on
  every controller. Stated limit below.
* **E-12: changing the 10 000-message count or the per-message cap.**

## Latent vs live

* E-4: latent unless `WASM_RESULT_CACHE_TTL_SECS` is set (the chart and the
  compose files do not set it). After this change an entry written by an
  older worker is a miss once.
* E-5: the chart puts `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` in the
  controller-only bootstrap Secret, and both compose files set
  `ANTHROPIC_API_KEY` on the controller service only, so no shipped
  configuration hands a provider key to a worker; the production refusal
  breaks none of them. `docker-compose.prod.yml` runs `RUST_ENV=staging`,
  where the fallback stays on.
* E-7: live for any `audit` deployment with no identity regexp (install.sh
  derives one whenever the policy is not disabled, so not on installer-built
  clusters). The unknown-value refusal changes behaviour only for a value
  that was a typo.
* H-1: latent until `TALOS_REGISTRY_URL` is set; from then on an
  `install.sh` run with the default policy now stops with the reason.
* G-21: live wherever the builder image is older than the controller image.

## Stated limits

* The controller's hourly advisory-DB sampler and its alerts still read only
  the controller's copy (`copy="controller"`); the compile gate reads the
  builder's. A stale builder now refuses compiles in production before any
  alert says why.
* The builder probe costs one container start per hour per controller (cached
  in-process, one entry); an image without a database is not cached, so each
  compile probes again — and `cargo audit` fails closed there anyway.
* `EMAIL_API_*` / `S3_*` remain worker-held. Recommendation: move them to
  per-user vault paths delivered in the job's sealed envelope, the way LLM
  provider keys travel, and then refuse the env fallback in production too.
* The log byte budget counts the bytes the guest asked to log after the
  per-message cap and escaping, not the NATS envelope around them.

## One home

* `talos_worker_runtime::result_cache_seal::{ResultCacheSealKey, seal, open}`
* `talos_worker_runtime::context::EnvProviderKeys`
* `talos_sigstore_policy::SigstorePolicy::from_env_str` →
  `Result<_, UnrecognisedSigstorePolicy>`;
  `talos_worker_runtime::module_fetcher::sigstore_verdict`
* `deploy/k3s/lib/template-signing.sh::ts_template_signing_refusal`
* `talos_worker_runtime::host::logging::neutralise_log_text`,
  `MAX_LOG_BYTES_PER_EXECUTION`
* `talos_compilation::container::audit_command_with_db_probe`,
  `talos_compilation::advisory_db::builder_advisory_db_age_days`

CLAUDE.md gained four rule sentences: the sealed Redis result cache (OCI
template registry section), the env provider-key rule (LLM key resolution),
the Sigstore unknown-value / verdict / installer rule (OCI template registry)
and the advisory-DB gate's copy (Docker Build Notes).

## Mutation proofs

Each mutation was applied alone, the whole crate's tests run, the file
restored from its backup (byte-compared) and `touch`ed, and the whole crate
run again: `talos-worker-runtime` 975 / 975 lib tests and its integration
binaries, `talos-sigstore-policy` 19 / 19, the template-signing script test
green.

| Finding | Mutation | Guarding test | Mutant | Restored |
|---|---|---|---|---|
| E-4 | `open` accepts an unsealed value (`strip_prefix` miss → `serde_json::from_str(stored)`) | `result_cache_seal::tests::an_unsealed_entry_is_ignored` | FAIL (974 / 1) | PASS |
| E-4 | the entry key and AAD no longer bind the cache key | `result_cache_seal::tests::an_entry_moved_to_another_cache_key_is_ignored` | FAIL (974 / 1) | PASS |
| E-5 | `EnvProviderKeys::lookup` refuses only when the env value is absent (the production guard reverted) | `context::…::production_refuses_an_llm_provider_key_from_the_worker_env` | FAIL (974 / 1) | PASS |
| E-7 | `sigstore_verdict`: `audit` + `NoIdentity` → `Cacheable` (the pre-fix flag) | `module_fetcher::…::audit_without_an_identity_regexp_is_never_cached` | FAIL (974 / 1) | PASS |
| E-7 | `from_env_str`: unknown → `Ok(Disabled)` | `talos-sigstore-policy`: `an_unrecognised_policy_is_an_error`, `explicit_is_exactly_the_recognised_set`; `talos-worker-runtime`: `sigstore_policy_unknown_value_is_refused_by_the_boot_gate` (and three siblings on the poisoned env lock) | FAIL (17 / 2; 971 / 4) | PASS |
| H-1 | the refusal's condition made false (`&& -z "MUTATED"`) | `deploy/k3s/tests/template-signing-test.sh` | FAIL (5 checks) | PASS |
| H-1 | `install.sh` warns instead of `die` on the refusal | same | FAIL (1 check) | PASS |

The flipped-byte test (`an_entry_with_a_flipped_byte_is_ignored`, every byte
of a sealed value) is guarded by the AEAD tag itself; no plausible edit
short of removing the cipher makes it pass a tampered value.
