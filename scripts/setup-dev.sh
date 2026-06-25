#!/usr/bin/env bash
#
# Talos one-command dev setup.
#
# Generates a complete .env with secure random secrets (covering every variable
# docker-compose.yml marks as required), then hands off to `make up`, which
# builds + starts the stack in Docker. No host Rust toolchain is needed just to
# run Talos — everything builds inside containers.
#
# Idempotent: if .env already exists it is left untouched.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "🔧 Talos dev setup"
echo "=================="
echo ""

if [ -f .env ]; then
    echo "✅ .env already exists — leaving it untouched."
else
    echo "📝 Generating .env with secure random secrets..."

    # TALOS_MASTER_KEY and WORKER_SHARED_KEY MUST be 64 hex chars (32 bytes) —
    # the config validator rejects anything else. The rest are arbitrary strings.
    cat > .env <<EOF
# ─── Crypto keys — MUST be 64 hex chars (openssl rand -hex 32) ───────────────
TALOS_MASTER_KEY=$(openssl rand -hex 32)
WORKER_SHARED_KEY=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 32)

# ─── Datastore credentials ──────────────────────────────────────────────────
POSTGRES_PASSWORD=$(openssl rand -hex 16)
REDIS_PASSWORD=$(openssl rand -hex 16)
NATS_USER=talos
NATS_PASSWORD=$(openssl rand -hex 16)
NEO4J_PASSWORD=$(openssl rand -hex 16)

# ─── Object store (MinIO) ───────────────────────────────────────────────────
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=$(openssl rand -hex 16)
MINIO_CONTROLLER_USER=talos-controller
MINIO_CONTROLLER_PASSWORD=$(openssl rand -hex 16)
MINIO_WORKER_USER=talos-worker
MINIO_WORKER_PASSWORD=$(openssl rand -hex 16)

# ─── Observability ──────────────────────────────────────────────────────────
GRAFANA_PASSWORD=admin

# ─── App config (dev defaults) ──────────────────────────────────────────────
# DATABASE_URL host is 'postgres' (the compose service), not localhost.
DATABASE_URL=postgres://talos:__PGPW__@postgres:5432/talos
RUST_LOG=info,controller=debug
BASE_URL=http://localhost:8000
FRONTEND_URL=http://localhost:3000
ALLOWED_ORIGIN=http://localhost:3000
TRUSTED_IPS=127.0.0.1,::1

# ─── Optional ───────────────────────────────────────────────────────────────
# Tier-2 (external) LLM — uncomment + set to use Anthropic for LLM nodes:
# ANTHROPIC_API_KEY=
#
# Tier-1 (on-host) LLM via Ollama — OPT-IN, large download. Set the model then
# run \`make rebuild SERVICE=ollama\`. Embeddings already work without this.
# TIER1_MODEL=qwen2.5:32b
#
# OAuth integrations (Gmail / Google Calendar / Slack) — leave blank if unused:
# GOOGLE_CLIENT_ID=
# GOOGLE_CLIENT_SECRET=
# GOOGLE_REDIRECT_URI=http://localhost:8000/auth/oauth/google/callback
EOF

    # Stitch the generated Postgres password into DATABASE_URL (portable sed:
    # write to a temp file rather than relying on GNU/BSD -i differences).
    PGPW="$(grep '^POSTGRES_PASSWORD=' .env | cut -d= -f2)"
    sed "s|__PGPW__|${PGPW}|" .env > .env.tmp && mv .env.tmp .env

    echo "✅ Created .env"
fi

echo ""
echo "🚀 Building and starting the stack (first build compiles the Rust"
echo "   workspace — this takes a while; subsequent runs are cached)..."
echo ""
make up

cat <<'EOF'

✅ Setup complete!

  Frontend (optional):  docker compose up -d frontend   → http://localhost:3000
  API / GraphiQL:       http://localhost:8000/graphql
  Health:               http://localhost:8000/health

Day-to-day:
  make ps                       Service health + DB row counts
  make logs SERVICE=controller  Tail one service
  make rebuild SERVICE=controller   Hot-rebuild after a code change
  make down                     Stop (preserves data volumes)
  make nuke                     Wipe everything incl. volumes (needs TALOS_NUKE=yes)

LLM notes:
  • Embeddings / semantic search work out of the box (nomic-embed-text).
  • Tier-2 LLM nodes need ANTHROPIC_API_KEY in .env.
  • Tier-1 on-host LLM needs TIER1_MODEL set + `make rebuild SERVICE=ollama`.
EOF
