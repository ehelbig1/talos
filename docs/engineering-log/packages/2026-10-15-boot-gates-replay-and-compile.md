# A deployment that faces users requires the replay guard and compiles only in the sandbox (2026-10-15)

Two operator decisions from security review 2026-10-15 (round 2), taken on
the recommendations in that round's report. Package R9.

## D2-B — the distributed replay guard is required

- `talos_replay_guard::boot_requirement(hardened, distributed, redis_configured)`
  is the one rule; `boot_requirement_from_env` reads the switch and
  `REDIS_URL`. Where `talos_auth_types::browser_hardening_required()` holds
  (`RUST_ENV` production AND staging, which is how `docker-compose.prod.yml`
  runs), the controller (`bootstrap::services`, beside the fleet-identity
  gate) and the worker (beside its fleet-identity gate) refuse to boot with
  `TALOS_DISTRIBUTED_REPLAY` off or `REDIS_URL` unset. No acknowledgement
  waives it. Development is unchanged.
- Every hardened shape already satisfies it: the chart sets the switch on both
  services and takes `REDIS_URL` from the bootstrap Secret (`install.sh`
  requires `TALOS_REDIS_URL`); the prod compose file sets both on both
  services (and rule 7 of `check-deploy-posture.py` holds it to the chart).
- What R2 built stays: with the switch on, the guard registers whether or not
  Redis answers, and a fail-closed process refuses until it does.
  `TALOS_REPLAY_FAIL_CLOSED=0` remains the operator's availability trade; this
  decision requires the guard, not the fail-closed answer.
- Predicate: the hardening one, not `is_production()`, because the decision's
  point is every deployment shape that faces users (the round's second lesson).

## G-9 — container mode is the only compile mode where users are

- `talos_compilation::container::compile_sandbox_required()` (the hardening
  predicate) is the one rule. Where it holds:
  - `TALOS_COMPILATION_CONTAINER` defaults on (it defaulted to
    `is_production()`, so `RUST_ENV=staging` compiled on the host with no
    acknowledgement at all);
  - `sandbox_decision` refuses both host cases — container mode off, no
    runtime — with no override; the acknowledgement token
    `acknowledge-single-tenant-rce-risk` no longer admits a host compile;
  - the JavaScript / Python host toolchains (M-13) are refused the same way;
  - the cargo-audit fail-closed arms (tool error, tool unavailable) follow the
    same predicate, so staging no longer skips a failed audit;
  - the controller refuses to BOOT while `TALOS_COMPILATION_ALLOW_HOST_FALLBACK`
    is set, whatever its value (`refuse_retired_host_fallback`): an operator
    who relied on it learns at boot, not from the first refused compile.
- `host_fallback_allowed`, the production startup advisory and the
  non-dumpable boot refusal that existed only for the fallback are deleted
  (`enforce_non_dumpable_posture` now logs only).
- Consequence, stated in `docker-compose.prod.yml`'s header and the
  configuration reference: a hardened deployment with no container runtime
  compiles nothing. The prod compose file gives its controller none, so it runs
  registry-only (`TALOS_MODULE_COMPILATION=false` with `TALOS_REGISTRY_URL`)
  or is given podman/docker and the builder image. The chart is unchanged in
  behaviour (production already refused without the token; no artefact in the
  repository sets it). Development (`make up`, `RUST_ENV` unset) is unchanged.
- Rejected: the token-level (`syn`) scan alternative. The host path is gone
  where it mattered, so the per-line regex now guards development only.

## D2-A, D2-C

- **D2-A** — guest SQL keeps the catalog arm on `modules` (R3,
  `20261015130000`): catalog rows carry no tenant data. No change.
- **D2-C** — tapped labels are validated against the dataset's vocabulary and
  their origin recorded (R4). No change.

## Tests

- `talos-replay-guard`: `a_hardened_deployment_requires_the_distributed_guard`.
- `talos-compilation`:
  `the_retired_host_fallback_is_refused_at_boot_where_the_sandbox_is_required`,
  `the_sandbox_is_required_wherever_the_deployment_faces_users` (production,
  staging, development), `sandbox_decision_covers_every_input` (rewritten),
  `container_disabled_where_the_sandbox_is_required_is_refused` (production and
  staging, with and without the retired token, both entry points),
  `gate_refuses_the_host_path_wherever_the_sandbox_is_required` (M-13).
  The tests that pinned the token's acceptance are deleted with it.

## Mutation proof

| Gate | Mutation | Test | Verdict |
|---|---|---|---|
| replay guard required | the `!distributed` refusal disabled | `a_hardened_deployment_requires_the_distributed_guard` | FAIL / PASS restored |
| no host compile where required | `sandbox_decision` never refuses | `sandbox_decision_covers_every_input`, `container_disabled_where_the_sandbox_is_required_is_refused` | FAIL ×2 / PASS restored |
| staging requires the sandbox | `compile_sandbox_required` = `is_production()` | `the_sandbox_is_required_wherever_the_deployment_faces_users`, `container_disabled_…`, `gate_refuses_…` | FAIL ×3 / PASS restored |

## Stated limits

- The boot gates are tested as functions; no test boots a controller or a
  worker under `RUST_ENV=staging`.
- E2-6 (one Redis credential per role) is its own package.
