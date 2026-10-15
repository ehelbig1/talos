#!/bin/sh
# Redis for the compose stacks: the `default` user (the controller) with
# REDIS_PASSWORD, and the worker's own user `talos-worker` with
# REDIS_WORKER_PASSWORD and the rules in worker.acl-rules (security review
# 2026-10-15, E2-6: one shared credential let a compromised worker write any
# key the controller reads — a module's cached bytes, the controller's replay
# nonces, its idempotency records).
set -eu
: "${REDIS_PASSWORD:?REDIS_PASSWORD is required}"
: "${REDIS_WORKER_PASSWORD:?REDIS_WORKER_PASSWORD is required}"
rules=$(grep -v '^[[:space:]]*#' /etc/talos-redis/worker.acl-rules | grep -v '^[[:space:]]*$' | tr '\n' ' ')
# shellcheck disable=SC2086 # the rules are separate arguments by design.
exec redis-server --appendonly yes --requirepass "$REDIS_PASSWORD" \
    --user talos-worker reset on ">$REDIS_WORKER_PASSWORD" $rules "$@"
