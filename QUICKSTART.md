# Talos Quick Start

Run the whole stack locally in Docker. No host Rust toolchain is required just
to run it — everything builds inside containers.

## 🚀 One command

```bash
make setup
```

This generates a complete `.env` with secure random secrets, then builds and
starts the stack and waits for it to report healthy. The first build compiles
the ~100-crate Rust workspace, so it takes a while; later runs are cached.

**Access:**
- Frontend (start with `docker compose up -d frontend`): http://localhost:3002
  (note: **3002**, not 3000 — the compose dev stack publishes it there)
- API: http://localhost:8000
- GraphiQL (dev only): http://localhost:8000/graphql
- Health: http://localhost:8000/health

That's it. 🎉

---

## What `make setup` writes to `.env`

`docker-compose.yml` marks a number of variables as **required** (it fails fast
if any are missing). `make setup` generates all of them. The two crypto keys
**must be 64 hex characters** (`openssl rand -hex 32`) — the controller's config
validator rejects anything else:

| Variable | Notes |
|---|---|
| `TALOS_MASTER_KEY` | 64 hex chars — root key-encryption key |
| `WORKER_SHARED_KEY` | 64 hex chars — HMAC key for signed worker RPC |
| `JWT_SECRET` | session signing |
| `POSTGRES_PASSWORD` / `REDIS_PASSWORD` | datastore creds |
| `NATS_USER` / `NATS_PASSWORD` | message bus |
| `NEO4J_PASSWORD` | graph store |
| `MINIO_ROOT_*` / `MINIO_CONTROLLER_*` / `MINIO_WORKER_*` | object store |
| `GRAFANA_PASSWORD` | observability |

To rotate everything, delete `.env` and re-run `make setup`.

---

## Day-to-day

```bash
make ps                          # service health + DB row counts
make logs SERVICE=controller     # tail one service (omit value for all)
make rebuild SERVICE=controller  # hot-rebuild one service after a code change
make down                        # stop (preserves data volumes)
make nuke                        # ⚠️ wipe everything incl. volumes (needs TALOS_NUKE=yes)
```

Run `make help` for the full target list.

---

## LLM models

- **Embeddings / semantic search work out of the box** — the small
  `nomic-embed-text` model (~274 MB) is baked into the `ollama` image.
- **Tier-2 (external) LLM** nodes need a provider key. Add to `.env`:
  ```
  ANTHROPIC_API_KEY=sk-ant-...
  ```
- **Tier-1 (on-host) LLM** — for actors that must keep data on the host — is
  **opt-in** because the models are large (~20 GB for `qwen2.5:32b`). Set the
  model in `.env`, then rebuild just the ollama image:
  ```
  TIER1_MODEL=qwen2.5:32b
  ```
  ```bash
  make rebuild SERVICE=ollama
  ```
  Comma-separate for multiple models (include `mistral` if any workflow hardcodes
  it). This is why a fresh `make up` no longer needs ~30 GB of free Docker disk.

---

## 🐛 Troubleshooting

### `make up` says "no .env found"
Run `make setup` (generates one) — or copy your own.

### `TALOS_MASTER_KEY required` / other "required in .env" errors
Your `.env` is missing a required variable. Delete it and re-run `make setup`,
or add the missing key (see the table above).

### `no space left on device` during build
Docker's disk is full. Reclaim with `docker builder prune -f` and
`docker image prune -f`, or raise Docker Desktop's disk-image size limit.
(If you opted into a large `TIER1_MODEL`, that image alone can be ~20 GB+.)

### GraphiQL not accessible
GraphiQL is disabled when `RUST_ENV=production`. The generated `.env` leaves it
unset, so it's enabled. If you set it, unset it and `make restart SERVICE=controller`.

### Port already in use
```bash
lsof -i :3002   # frontend (compose publishes it on 3002)
lsof -i :8000   # API
lsof -i :5432   # postgres (only if you exposed it)
```

### Reset the database (deletes data)
```bash
TALOS_NUKE=yes make nuke && make up
```

---

## Building on the host (contributors)

Running the stack doesn't need a host toolchain, but developing Rust does:

```bash
make check    # fast workspace type-check
make build    # release build of all binaries
make lint     # rustfmt + structural + clippy + cargo-deny (matches CI)
make test     # full test suite via cargo-nextest
```

Run `make hooks` once per clone to install the pre-commit / pre-push gates.

---

## Migrations

Migrations run automatically — the compose `migrate` service applies them before
the controller starts (you'll see `talos-migrate` exit 0 in `make ps`). New
migrations go in `migrations/` with a `YYYYMMDDHHMMSS_description.sql` prefix;
never edit an already-applied migration (see CLAUDE.md → Migration Rules).
