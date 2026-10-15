#!/usr/bin/env bash
# The worker's Redis user, as deploy/redis/start.sh creates it from
# deploy/redis/worker.acl-rules, can do everything the worker does and nothing
# to the keys the controller owns (security review 2026-10-15, E2-6). A real
# Redis (the compose files' image), the worker's commands per key family —
# including scripts that send every command the worker's Lua scripts do —
# then the controller's keys, refused. The commands each family needs are
# pinned to the code by worker/src/redis_acl_contract.rs.
#
# Needs docker. Without it the test is skipped outside CI and FAILS in CI.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="$(sed -n 's|^    image: \(redis:7-alpine@sha256:[0-9a-f]*\)$|\1|p' "$root/docker-compose.yml" | head -1)"
[ -n "$image" ] || { echo "redis-worker-acl-test: no pinned redis image in docker-compose.yml" >&2; exit 1; }
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    if [ -n "${CI:-}" ]; then echo "redis-worker-acl-test: docker is required in CI" >&2; exit 1; fi
    echo "redis-worker-acl-test: SKIPPED (no docker)"; exit 0
fi

name="talos-redis-acl-test-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$name" -e REDIS_PASSWORD=admin-pw -e REDIS_WORKER_PASSWORD=worker-pw \
    -v "$root/deploy/redis:/etc/talos-redis:ro" --entrypoint /bin/sh "$image" \
    /etc/talos-redis/start.sh >/dev/null
for _ in $(seq 1 50); do
    docker exec "$name" redis-cli -a admin-pw --no-auth-warning ping 2>/dev/null | grep -q PONG && break
    sleep 0.2
done

as_worker() { docker exec "$name" redis-cli --no-auth-warning --user talos-worker --pass worker-pw "$@" 2>&1; }
fail() { echo "redis-worker-acl-test: $*" >&2; exit 1; }
allowed() { local out; out="$(as_worker "$@")"; case "$out" in *NOPERM*|*ERR*) fail "worker refused: $* → $out";; esac; }
refused() { local out; out="$(as_worker "$@")"; case "$out" in *NOPERM*) ;; *) fail "worker allowed: $* → $out";; esac; }

# The connection handshake and the boot check.
allowed PING
[ "$(as_worker ACL WHOAMI)" = "talos-worker" ] || fail "ACL WHOAMI"

# Dispatch replay guard and job idempotency.
allowed SET talos:jobnonce:job:j:n 1 NX PX 360000
allowed SET talos:idem:job:j v EX 90
allowed GET talos:idem:pipe:j
allowed DEL talos:idem:job:j
# Sealed results; a module's cached bytes are read, never written.
allowed SETEX wasm:result:h:d 60 v
allowed GET wasm:result:h:d
allowed TTL wasm:result:h:d
allowed GET wasm:00000000-0000-0000-0000-000000000000:m
refused SET wasm:00000000-0000-0000-0000-000000000000:m attacker
refused DEL wasm:00000000-0000-0000-0000-000000000000:m
# OCI layer cache.
allowed SET oci_cache:sha256:d v EX 86400
allowed DEL oci_cache:sha256:d
# The guest cache interface, its atomic multi-set and its counter script.
allowed SETEX "talos_cache:u=u:k" 60 v
allowed EXISTS "talos_cache:u=u:k"
allowed MGET "talos_cache:u=u:k" "talos_cache:u=u:j"
allowed EXPIRE "talos_cache:u=u:k" 60
[ "$(printf 'MULTI\nSETEX talos_cache:u=u:a 60 1\nSETEX talos_cache:u=u:b 60 2\nEXEC\n' \
    | docker exec -i "$name" redis-cli --no-auth-warning --user talos-worker --pass worker-pw | grep -c NOPERM || true)" = "0" ] \
    || fail "MULTI/SETEX/EXEC refused"
allowed EVAL "local v = redis.call('INCRBY', KEYS[1], ARGV[1]) if redis.call('TTL', KEYS[1]) < 0 then redis.call('EXPIRE', KEYS[1], 60) end return v" 1 "talos_cache:u=u:n" 1
# The tier-2 expose cap.
allowed EVAL "local n = redis.call('INCR', KEYS[1]) if n == 1 then redis.call('EXPIRE', KEYS[1], 86400) end return n" 1 talos:tier2_expose:u:d
# Local-LLM fleet admission: every command the admission script sends.
allowed EVAL "local t = redis.call('TIME') redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', 0) redis.call('ZRANGEBYSCORE', KEYS[3], '-inf', 0) redis.call('ZADD', KEYS[1], 1, 'w') redis.call('ZSCORE', KEYS[1], 'w') redis.call('ZRANK', KEYS[1], 'w') redis.call('ZCARD', KEYS[1]) redis.call('ZREM', KEYS[1], 'w') redis.call('INCR', KEYS[4]) redis.call('PEXPIRE', KEYS[4], 1000) redis.call('GET', KEYS[5]) redis.call('SET', KEYS[5], 'm', 'PX', 1000) return 1" 5 \
    "talos:llm-admit:{00}:holders" "talos:llm-admit:{00}:waiters" "talos:llm-admit:{00}:alive" "talos:llm-admit:{00}:ticket" "talos:llm-admit:{00}:model"
allowed SCRIPT LOAD "return 1"
# Approval reply topics.
allowed SET approval:w topic EX 86400
allowed DEL approval:w

# Keys the controller owns.
refused SET talos:nonce:rpc:x 1 NX PX 60000
refused SET idempotency:k v
refused GET webhook:processed:k
refused SET session:x v
refused EVAL "return redis.call('SET', KEYS[1], 'x')" 1 talos:nonce:rpc:y
# Commands the worker never sends.
refused KEYS '*'
refused FLUSHALL
refused CONFIG GET requirepass

# The controller (the `default` user) is unchanged.
[ "$(docker exec "$name" redis-cli -a admin-pw --no-auth-warning SET talos:nonce:rpc:x 1)" = "OK" ] \
    || fail "the default user lost a key"
echo "redis-worker-acl-test: ok"
