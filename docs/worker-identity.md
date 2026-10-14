# Per-worker identity in production (retiring the fleet-shared key)

Every worker holds `WORKER_SHARED_KEY`. On a surface that still accepts it, one
leaked key — or one compromised worker — can sign for ANY actor, user or
execution: memory and integration-state RPCs, sandbox SQL, durable state,
forged job results for other workers' jobs, forged dispatches. Each worker can
instead hold its own Ed25519 identity, and three switches retire the shared key
one surface at a time:

| Surface | Switch | Set on |
|---|---|---|
| dispatch (controller → worker) | `TALOS_DISPATCH_REQUIRE_ED25519=1` | worker |
| result (worker → controller) | `TALOS_RESULT_REQUIRE_ED25519=1` | controller |
| signed RPC (worker → controller) | `TALOS_RPC_REQUIRE_ED25519=1` | controller |

**Since 2026-10-14 a production process refuses to boot while a switch it
reads is off**, unless `TALOS_ALLOW_LEGACY_FLEET_HMAC` names that surface
(`dispatch`, `result`, `rpc`, comma-separated, or `all`). The acknowledgement
is logged at ERROR on every boot (`event_kind="legacy_fleet_hmac_in_production"`)
and `security_audit` reports it (`fleet_identity`, `warn`). Outside production
nothing changes. Security review 2026-10-14, finding B-2.

## On the k3s installer

`deploy/k3s/install.sh` already rolls workers onto their identity in four
phases (`deploy/k3s/lib/worker-trust.sh`: A, B, C, D — each needs its own
`helm upgrade`, the installer applies one per run). Each phase now also renders
`TALOS_ALLOW_LEGACY_FLEET_HMAC` for exactly the surfaces it does not yet
require:

| Phase | Controller acknowledges | Worker acknowledges |
|---|---|---|
| off, A, B, C | `result,rpc` | `dispatch` |
| D | `rpc` | — |

So an upgrade never stops a deployment from booting, and at phase D only one
surface is still on the shared key.

**Why `rpc` is still acknowledged at D.** The controller's own in-process
rehearsal runtime (`run_sandbox`, `test_module`, scratch sessions) makes
signed RPCs with the fleet key — the controller holds no worker identity. With
`TALOS_RPC_REQUIRE_ED25519=1` those rehearsals' memory and state calls would be
refused. Retiring it needs either a controller-side RPC identity or a
rehearsal path that does not go over the RPC subjects; that is operator
decision D-8 in the 2026-10-14 review.

## By hand (compose, or a chart without the installer)

1. Mint the keypairs: `controller generate-worker-trust-keypair` (prints a
   seed and a public key, 64 hex each). Give each worker
   `TALOS_WORKER_SIGNING_KEY` (seed) and `TALOS_WORKER_ID`, and give the
   controller `TALOS_WORKER_PUBLIC_KEYS=<id>=<public hex>`.
2. Give the controller `TALOS_CONTROLLER_SIGNING_KEY`, `TALOS_DISPATCH_SCHEME=ed25519`,
   and each worker `TALOS_CONTROLLER_PUBLIC_KEY`.
3. Roll the workers, then the controller, so each side can verify the other
   before either requires it.
4. Set `TALOS_DISPATCH_REQUIRE_ED25519=1` (workers) and
   `TALOS_RESULT_REQUIRE_ED25519=1` (controller), and drop those surfaces from
   `TALOS_ALLOW_LEGACY_FLEET_HMAC`.

Until step 4, a production deployment sets
`TALOS_ALLOW_LEGACY_FLEET_HMAC=result,rpc` on the controller and
`TALOS_ALLOW_LEGACY_FLEET_HMAC=dispatch` on workers.
