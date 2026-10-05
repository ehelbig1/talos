# Talos Quick Start

Run the whole stack locally in Docker. No host Rust toolchain is required just
to run it — everything builds inside containers.

## Prerequisites

- **Docker** with Compose v2 (Docker Desktop on macOS, or Docker Engine and
  the compose plugin on Linux), **git** and **make**.
- **Disk:** plan for 30 GB or more. Measured on a working development
  machine: about 9 GB of images in use, 8 GB of volumes, and a build cache
  that grows past 20 GB as the Rust workspace is rebuilt
  (`docker builder prune` reclaims it; `make up` warns before the disk fills).
- **Memory:** give Docker at least 8 GB. The running stack used 4.4 GB
  across its containers when measured; compiling the Rust workspace inside
  Docker needs more on top of that.

## 🚀 One command

```bash
git clone https://github.com/ehelbig1/talos.git
cd talos
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

## Next: a running workflow

```bash
make quickstart
```

Walks the golden path against your local stack and prints every step as a
plain `curl` you can copy: sign up (or reuse an account), mint an API key,
browse the module templates with what each needs, install one, build a
one-node workflow, run it, and read the output back.

Then:

- [docs/examples/ai-pr-review.md](docs/examples/ai-pr-review.md) — an AI
  pull-request reviewer end to end: modules, capability worlds, secrets and
  an approval gate in one worked example.
- The whole platform is drivable from an MCP client (Claude Code or any
  other) at `http://localhost:8000/mcp`, with the API key `make quickstart`
  minted.
- `make ps` shows every service's health.

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
| `MINIO_ROOT_*` / `MINIO_CONTROLLER_*` / `MINIO_VERIFIER_*` | object store (root, the audit WRITER, the audit VERIFIER — there is no worker identity) |
| `GRAFANA_PASSWORD` | observability |

To rotate everything, delete `.env` and re-run `make setup`.

---

## Day-to-day

```bash
make doctor                      # preflight: stale images vs source, disk pressure, stack health
make ps                          # service health + DB row counts
make logs SERVICE=controller     # tail one service (omit value for all)
make rebuild SERVICE=controller  # hot-rebuild one service after a code change
make down                        # stop (preserves data volumes)
make nuke                        # ⚠️ wipe everything incl. volumes (needs TALOS_NUKE=yes)
```

**Run `make doctor` before live-testing.** It catches the trap where you edit
Rust, forget to rebuild, and `make up`'s cached image runs *old* code — plus
Docker-VM disk pressure (which otherwise surfaces as confusing Redis/DB errors,
not an obvious "out of space").

Run `make help` for the full target list.

---

## LLM models

- **Embeddings / semantic search work out of the box** — the
  `mxbai-embed-large` model (~670 MB, 1024-dim) is baked into the `ollama`
  image; its dimension matches the `vector(1024)` embedding columns.
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
`make doctor` warns when the build cache is getting large *before* it bites.

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
make lint     # rustfmt + structural lints + cargo-deny (fast; lint-full adds clippy, as CI runs)
make test     # full test suite via cargo-nextest
```

Run `make hooks` once per clone to install the pre-commit / pre-push gates.

---

## Migrations

Migrations run automatically — the compose `migrate` service applies them before
the controller starts (you'll see `talos-migrate` exit 0 in `make ps`). New
migrations go in `migrations/` with a `YYYYMMDDHHMMSS_description.sql` prefix;
never edit an already-applied migration (see CLAUDE.md → Migration Rules).
