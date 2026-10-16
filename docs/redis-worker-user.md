# The worker's own Redis user

The controller and the worker used to log in to Redis with one credential, so
a compromised worker could write any key the controller reads: a module's
cached bytes (which other workers then run), the controller's replay nonces,
its idempotency records (security review 2026-10-15, E2-6). The worker now
logs in as `talos-worker`, limited to its own key families and commands.

**The rules have one home: `deploy/redis/worker.acl-rules`.** Each family is
listed there with the code that uses it.
`worker/src/redis_acl_contract.rs` fails when the code uses a key prefix or a
scripted command the rules do not grant. `scripts/tests/redis-worker-acl-test.sh`
drives every family through a real Redis as that user, and checks that the
controller's keys are refused.

## Compose (dev and `docker-compose.prod.yml`)

Nothing to do. `deploy/redis/start.sh` creates the user from the rules with
`REDIS_WORKER_PASSWORD`, and the worker's `REDIS_URL` names it.
- **Dev:** `make up` back-fills the password into `.env`.
- **Prod compose:** set the password in `.env.production`.

## Helm / k3s with your own Redis

The chart deploys no Redis, so you create the user yourself, then give the
installer its URL.

1. Create the user, as an admin, on your Redis:

   ```bash
   RULES=$(grep -v '^[[:space:]]*#' deploy/redis/worker.acl-rules | grep -v '^[[:space:]]*$' | tr '\n' ' ')
   redis-cli -u "$ADMIN_REDIS_URL" ACL SETUSER talos-worker reset on ">$WORKER_PASSWORD" $RULES
   ```

   A managed Redis without ACL users cannot do this. On one, the worker
   keeps the shared credential and warns at boot
   (`worker_redis_shared_credential`).
2. Set `TALOS_WORKER_REDIS_URL=rediss://talos-worker:<password>@host:6379` in
   `/etc/talos/install.env` and re-run `install.sh`. It stores the URL as
   `WORKER_REDIS_URL` in the bootstrap Secret and sets
   `worker.redisUrlSecretKey`. For a raw `helm install`, put the key in the
   Secret and set the value yourself.

## What the worker can still reach

Two families are shared on purpose:
- `talos:llm-admit:*`, the local-LLM fleet queue, which both processes
  write;
- `approval:*`, a marker that a run awaits an approval decision.

A compromised worker can disturb that queue, or plant a marker for another
run. A planted marker changes no destination: since 2026-10-15 the controller
publishes a decision to the subject the run's own id names
(`subjects::approval_publish_subject`), and the database decision is recorded
either way. The worker cannot write a module's bytes, the controller's
nonces or its idempotency records.
