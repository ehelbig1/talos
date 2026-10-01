# 2026-10-01 — how to run the compose stack without the in-stack Ollama

**Context.** On the reference deployment both LLM calls and embeddings now go
to the host's own Ollama (GPU; embeddings measured ~50x faster than the
CPU-only in-stack container). After the switch the `talos-ollama` container
served no request: its log shows only its own health checks, and no running
container's environment names `ollama:11434`.

**The obstacle.** The controller and the worker declare
`depends_on: ollama: condition: service_healthy`, so the service cannot just
be omitted, and a stopped container is recreated by the next `make up`.

**Recipe (documented in `docker-compose.yml` above the `ollama` service).** In
the gitignored `docker-compose.override.yml`: put `ollama` behind a profile
and drop the two dependencies with `!reset null`. Run
`docker compose rm -sf ollama` once BEFORE adding the block (a profile-gated
service is no longer addressable by name).

**Checked.** `docker compose config`: `ollama` leaves the service list and
both `depends_on` lists; a dry-run `up` leaves the running controller and
worker untouched and creates no Ollama container. Applied on the reference
deployment the same day.

**Not changed.** The default: with no override the in-stack Ollama starts and
is waited for, as before. No `required: false` on the base dependency — that
would let a default deployment's controller start before its only embedder.

**Stated limit.** Comment and record only; nothing gates the recipe against a
future change to the `depends_on` lists.
