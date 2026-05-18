#!/bin/bash
set -e

echo "🔧 Talos Development Environment Setup"
echo "======================================"
echo ""

# Check if .env exists
if [ -f .env ]; then
    echo "✅ .env file already exists"
    source .env
else
    echo "📝 Creating .env file with secure random secrets..."

    # Generate secure random secrets
    POSTGRES_PASSWORD=$(openssl rand -hex 32)
    TALOS_MASTER_KEY=$(openssl rand -hex 32)
    JWT_SECRET=$(openssl rand -hex 32)

    # Create .env file
    cat > .env <<EOF
# Database Configuration
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
DATABASE_URL=postgres://talos:${POSTGRES_PASSWORD}@localhost:5432/talos
DB_MAX_CONNECTIONS=30

# Controller Configuration
RUST_LOG=info,controller=debug
BASE_URL=http://localhost:8000

# Frontend Configuration
VITE_API_URL=http://localhost:8000
FRONTEND_URL=http://localhost:3000

# Security Configuration
JWT_SECRET=${JWT_SECRET}
TALOS_MASTER_KEY=${TALOS_MASTER_KEY}
ALLOWED_ORIGIN=http://localhost:3000
BCRYPT_COST=12

# Rate Limiting - Whitelist localhost for development
TRUSTED_IPS=127.0.0.1,::1

# OAuth Configuration (optional - leave empty if not using)
# GOOGLE_CLIENT_ID=
# GOOGLE_CLIENT_SECRET=
# GOOGLE_REDIRECT_URI=http://localhost:8000/auth/oauth/google/callback
EOF

    echo "✅ Created .env file with secure random secrets"
    source .env
fi

echo ""
echo "🐘 Starting PostgreSQL database..."
docker-compose up -d postgres

echo ""
echo "⏳ Waiting for database to be ready..."
sleep 5

# Check if database is ready
until docker exec talos-postgres pg_isready -U talos > /dev/null 2>&1; do
    echo "   Waiting for database..."
    sleep 2
done

echo "✅ Database is ready"

echo ""
echo "🗄️  Running database migrations..."
if ! command -v sqlx &> /dev/null; then
    echo "   Installing sqlx-cli..."
    cargo install sqlx-cli --no-default-features --features postgres
fi

sqlx migrate run

echo ""
echo "📦 Preparing sqlx offline query cache..."
cargo sqlx prepare --workspace

echo ""
echo "🔨 Building workspace..."
cargo build --workspace

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Start all services:  docker-compose up -d"
echo "  2. View logs:           docker-compose logs -f"
echo "  3. Access frontend:     http://localhost:3000"
echo "  4. Access API:          http://localhost:8000"
echo "  5. GraphiQL (dev):      http://localhost:8000/graphql"
echo ""
echo "Useful commands:"
echo "  cargo test              Run tests"
echo "  make status             Show database row counts (confirm data survived a rebuild)"
echo "  make down               Stop all services (preserves data)"
echo "  make clean              Remove containers + local images (preserves data)"
echo "  make rc                 Hot-rebuild controller only (~60s, preserves data)"
echo "  make reset-db           Drop and recreate database (⚠️  deletes all data)"
echo "  make nuke               Remove everything including volumes (⚠️  deletes all data)"
echo ""
echo "Start-from-scratch recovery (without losing workflow definitions):"
echo "  1. In the MCP client, run: export_platform_state"
echo "     Save the JSON manifest to a file (e.g. talos_state.json)"
echo "  2. Run: make nuke && make up-dev"
echo "  3. Re-provision secrets: set_secret for each entry in secret_references"
echo "  4. In the MCP client, run: import_platform_state with the saved manifest"
echo "     Catalog modules (llm-inference, http-request, etc.) are auto-remapped by name."
echo "     Custom sandboxes must be recompiled: run compile_custom_sandbox for each."
echo ""
