# The worker logs in to Redis as its own user (2026-10-15)

Security review 2026-10-15 round 2, E2-6, built on the round's recommendation
("an ACL user per role"). Package R11.

## The exposure

The controller and the worker shared one Redis credential (`default`). A
compromised worker could therefore write every key the controller reads:
- `wasm:{user}:{module}`, a module's cached bytes, which other workers then
  run;
- the controller's replay nonces (`talos:nonce:*`);
- request idempotency (`idempotency:*`) and webhook dedup
  (`webhook:processed:*`).

## The inventory (measured, not assumed)

An exhaustive sweep of the six crates in the worker binary that touch Redis
(`worker`, `talos-worker-runtime`, `talos-local-inference`,
`talos-replay-guard`, `talos-idempotency`, `talos-redis`; `cargo tree -i
redis`) found nine key families. Two of them were missing from R7's E2-6
note:
- `wasm:{user}:{module}`, read only;
- `approval:{id}`, written.

The table and the commands each family takes are in
`deploy/redis/worker.acl-rules`, one line per family, with the code beside it.
Commands sent inside Lua scripts are listed too, because Redis checks a
script's commands against the caller's ACL.

## Decided

- **`deploy/redis/worker.acl-rules` is the one home** of the worker's key
  patterns and commands:
  - `-@all` plus the 28 commands it uses;
  - `%R~wasm:*`, so module bytes are readable and not writable;
  - `~wasm:result:*` for its own sealed results.
- **Compose (dev and prod)** runs Redis through `deploy/redis/start.sh`, which
  keeps `default` (the controller) and creates `talos-worker` from the rules
  with `REDIS_WORKER_PASSWORD`. Both compose files' worker `REDIS_URL` names
  `talos-worker`. The password is required:
  - `make up` back-fills it into `.env`, as it does the NATS worker pair, and
    `make setup` mints it;
  - prod compose requires it in `.env.production`;
  - the prod healthcheck now authenticates.
- **Chart:** `worker.redisUrlSecretKey` (default `REDIS_URL`) picks the
  bootstrap-Secret key behind the worker's `REDIS_URL`. `install.sh` takes
  `TALOS_WORKER_REDIS_URL`, stores it as `WORKER_REDIS_URL` (back-filled when
  first given), selects that key, and refuses a value equal to
  `TALOS_REDIS_URL`. The chart's Redis is external, so the operator creates
  the user from the same rules (`docs/redis-worker-user.md`). Without it the
  installer warns.
- **Worker boot:** `ACL WHOAMI`. Logged in as `default` where the deployment
  faces users, it warns once (`worker_redis_shared_credential`). It does not
  refuse: a managed Redis without ACL users must keep working.

## Not separated (stated)

`talos:llm-admit:*` (the fleet queue both processes write) and `approval:*`
(the worker writes a reply topic the controller publishes the decision to)
stay shared. A compromised worker can disturb the queue or redirect one
approval's reply. Moving the approval reply topic out of Redis (into the
signed suspension record) is the follow-up that would close the second; not
built here.

## Tests

- `worker/src/redis_acl_contract.rs`:
  - every `redis.call('X'` in the worker's three Lua scripts is granted;
  - every key prefix the worker builds (three exported constants, six inline
    literals checked to still exist in their files) is granted, with module
    bytes readable and not writable;
  - the controller's keys are not writable.
- `scripts/tests/redis-worker-acl-test.sh` (`make test-scripts`; docker; fails
  in CI without it): the compose image with `start.sh` and the real rules.
  - Allowed: every family's commands as `talos-worker`, including MULTI/EXEC
    and scripts sending every scripted command.
  - Refused: writes to module bytes, the controller's nonces, idempotency and
    session keys, a script writing one, and `KEYS` / `FLUSHALL` / `CONFIG`.
  - The `default` user is unchanged.
- `worker`: `only_the_default_user_is_the_shared_one`.
- Both compose files render with every required variable given; `helm
  template` renders the worker's key from the value and the controller's
  unchanged.

## Mutation proof

| Rule | Mutation | Contract test | Script test |
|---|---|---|---|
| a family granted | `~approval:*` removed | FAIL | FAIL (NOPERM on `SET approval:w`) |
| module bytes read-only | `%R~wasm:*` → `~wasm:*` | FAIL ×2 | FAIL (`SET wasm:<uuid>:m` allowed) |
| a scripted command granted | `+zrank` removed | FAIL | FAIL (ACL failure in script) |

All restored: PASS.

## Deploy note

On the next `make up` the Redis container is recreated with the new
entrypoint. Redis is cache-only in dev (append-only file kept on its volume),
and the worker reconnects as `talos-worker`.
