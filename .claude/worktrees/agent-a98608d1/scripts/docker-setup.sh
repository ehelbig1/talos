#!/bin/bash

# Talos Docker Setup Script
# This script helps set up the Docker environment for local development

set -e

echo "🚀 Talos Docker Setup"
echo "===================="
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Docker and Docker Compose are installed"
echo ""

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file from .env.example..."
    cp .env.example .env
    echo "✅ .env file created"
else
    echo "ℹ️  .env file already exists"
fi

echo ""
echo "🔨 Building Docker images..."
docker-compose build

echo ""
echo "🚀 Starting services..."
docker-compose up -d

echo ""
echo "⏳ Waiting for services to be healthy..."
sleep 10

# Check service status
echo ""
echo "📊 Service Status:"
docker-compose ps

echo ""
echo "✅ Setup complete!"
echo ""
echo "🌐 Services are running at:"
echo "   Frontend:    http://localhost:3000"
echo "   GraphQL API: http://localhost:8000/graphql"
echo "   PostgreSQL:  localhost:5432"
echo ""
echo "📝 Useful commands:"
echo "   View logs:       make logs"
echo "   Stop services:   make down"
echo "   Rebuild:         make rebuild"
echo "   Database shell:  make db-shell"
echo ""
echo "For more commands, run: make help"
