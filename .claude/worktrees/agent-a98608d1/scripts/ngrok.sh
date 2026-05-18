#!/usr/bin/env bash

# ---------------------------------------------------------------------------
# Development helper: establish a public HTTPS tunnel and update the running
# controller container's BASE_URL so Google Calendar push notifications work.
#
# Tunnel preference order:
#   1. ngrok  (requires NGROK_AUTHTOKEN in env for free tier on ngrok v3)
#   2. cloudflared quick tunnel  (no account required)
#
# Usage:
#   bash scripts/ngrok.sh          # from repo root; docker-compose must be reachable
#   make ngrok                     # same, via Makefile
#   make up-dev                    # builds + starts everything, then runs this script
# ---------------------------------------------------------------------------

set -euo pipefail

# ---------------------------------------------------------------------------
# Load .env from the repo root so NGROK_AUTHTOKEN etc. are available.
# docker-compose sources .env automatically; plain bash scripts do not.
# ---------------------------------------------------------------------------
if [[ -z "${NGROK_AUTHTOKEN-}" && -f ".env" ]]; then
    NGROK_AUTHTOKEN=$(grep -E '^NGROK_AUTHTOKEN=' .env | head -n1 | cut -d= -f2- | tr -d '"' | tr -d "'") || true
    export NGROK_AUTHTOKEN
fi

PUBLIC_URL=""
TUNNEL_PID=""

# ---------------------------------------------------------------------------
# Helper: restart the controller so it picks up the new BASE_URL
# ---------------------------------------------------------------------------
restart_controller() {
    local url="$1"
    export BASE_URL="$url"
    echo "🔄 Restarting controller with BASE_URL=$BASE_URL ..."
    docker-compose up -d --no-deps --no-build controller
    echo "✅ Controller restarted. Webhook URL: $BASE_URL/api/google-calendar/webhook"
}

# ---------------------------------------------------------------------------
# Try ngrok
# ---------------------------------------------------------------------------
try_ngrok() {
    if ! command -v ngrok > /dev/null 2>&1; then
        echo "ℹ️  ngrok not found." >&2
        return 1
    fi
    if ! ngrok version > /dev/null 2>&1; then
        echo "ℹ️  ngrok binary not functional." >&2
        return 1
    fi

    # Configure auth token if provided (required for ngrok v3 free tier)
    if [[ -n "${NGROK_AUTHTOKEN-}" ]]; then
        ngrok config add-authtoken "$NGROK_AUTHTOKEN" > /dev/null
    else
        echo "ℹ️  NGROK_AUTHTOKEN not set — trying ngrok without auth token (may fail on ngrok v3)."
    fi

    rm -f /tmp/ngrok.log
    ngrok http 8000 \
        --log=stdout \
        --log-format=json \
        --region=us \
        > /tmp/ngrok.log 2>&1 &
    TUNNEL_PID=$!

    # Wait up to 10 seconds for the tunnel URL
    local timeout=10 elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if grep -q '"msg":"started tunnel"' /tmp/ngrok.log 2>/dev/null; then
            break
        fi
        # Check if ngrok already exited (auth error, etc.)
        if ! kill -0 "$TUNNEL_PID" 2>/dev/null; then
            if grep -q 'ERR_NGROK_108' /tmp/ngrok.log 2>/dev/null; then
                echo "❌ ngrok error: You already have an active ngrok session on another terminal." >&2
                echo "   Kill it at https://dashboard.ngrok.com/agents, then retry." >&2
            else
                echo "ℹ️  ngrok exited early. Log:" >&2
                cat /tmp/ngrok.log >&2
            fi
            return 1
        fi
        sleep 0.5
        elapsed=$((elapsed + 1))
    done

    PUBLIC_URL=$(grep '"msg":"started tunnel"' /tmp/ngrok.log | grep -oE 'https://[a-z0-9.-]+' | head -n1)
    if [[ -z "$PUBLIC_URL" ]]; then
        echo "ℹ️  Could not extract ngrok URL. Log:" >&2
        cat /tmp/ngrok.log >&2
        kill "$TUNNEL_PID" 2>/dev/null || true
        return 1
    fi

    echo "✅ ngrok tunnel: $PUBLIC_URL"
    return 0
}

# ---------------------------------------------------------------------------
# Try Cloudflare Quick Tunnel (no account required)
# ---------------------------------------------------------------------------
try_cloudflared() {
    if ! command -v cloudflared > /dev/null 2>&1; then
        echo "ℹ️  cloudflared not found." >&2
        return 1
    fi

    rm -f /tmp/cloudflared.log
    cloudflared tunnel --url http://localhost:8000 \
        --no-autoupdate \
        > /tmp/cloudflared.log 2>&1 &
    TUNNEL_PID=$!

    # cloudflared prints the URL to stderr; wait up to 15 seconds
    local timeout=15 elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if grep -qE 'https://[a-z0-9-]+\.trycloudflare\.com' /tmp/cloudflared.log 2>/dev/null; then
            break
        fi
        if ! kill -0 "$TUNNEL_PID" 2>/dev/null; then
            echo "ℹ️  cloudflared exited early. Log:" >&2
            cat /tmp/cloudflared.log >&2
            return 1
        fi
        sleep 0.5
        elapsed=$((elapsed + 1))
    done

    PUBLIC_URL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' /tmp/cloudflared.log | head -n1)
    if [[ -z "$PUBLIC_URL" ]]; then
        echo "ℹ️  Could not extract cloudflared URL." >&2
        kill "$TUNNEL_PID" 2>/dev/null || true
        return 1
    fi

    echo "✅ Cloudflare Quick Tunnel: $PUBLIC_URL"
    return 0
}

# ---------------------------------------------------------------------------
# Main: try tunnels in order
# ---------------------------------------------------------------------------
if try_ngrok; then
    :  # PUBLIC_URL and TUNNEL_PID set by try_ngrok
elif try_cloudflared; then
    :  # PUBLIC_URL and TUNNEL_PID set by try_cloudflared
else
    echo "" >&2
    echo "❌ No tunnel could be established. To use Google Calendar webhooks in development," >&2
    echo "   you need a public HTTPS URL. Options:" >&2
    echo "" >&2
    echo "   1. ngrok (free account):  https://dashboard.ngrok.com/signup" >&2
    echo "      Then add to your .env:  NGROK_AUTHTOKEN=<your-token>" >&2
    echo "      Run: make up-dev" >&2
    echo "" >&2
    echo "   2. Cloudflare Quick Tunnel (no account):" >&2
    echo "      brew install cloudflare/cloudflare/cloudflared   # macOS" >&2
    echo "      Then run: make up-dev" >&2
    echo "" >&2
    exit 1
fi

restart_controller "$PUBLIC_URL"
echo ""
echo "Keep this terminal open while developing. Press Ctrl+C to stop the tunnel."

wait "$TUNNEL_PID"
