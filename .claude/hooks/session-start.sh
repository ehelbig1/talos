#!/bin/bash
# SessionStart hook for Claude Code on the web.
#
# Ensures a fresh remote container can actually BUILD the workspace and run the
# gates. The one hard requirement is the mold linker: .cargo/config.toml pins
# `-fuse-ld=mold` for Linux, so without it `cargo check/build/test` fails the
# final link with a confusing "linking with `cc` failed" on trivial build
# scripts. Also primes frontend deps so the frontend lint/test gate works.
#
# Synchronous + idempotent + non-interactive. Web-only (no-op locally).
set -uo pipefail

# Only run in Claude Code on the web; local dev uses scripts/setup-dev.sh.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
    exit 0
fi

# --- mold linker (required by .cargo/config.toml on Linux) -------------------
if ! command -v mold >/dev/null 2>&1; then
    echo "session-start: installing mold linker..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -y >/dev/null 2>&1 || apt-get update -y >/dev/null 2>&1 || true
        sudo apt-get install -y mold >/dev/null 2>&1 || apt-get install -y mold >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y mold >/dev/null 2>&1 || dnf install -y mold >/dev/null 2>&1 || true
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --noconfirm mold >/dev/null 2>&1 || pacman -S --noconfirm mold >/dev/null 2>&1 || true
    fi
    if command -v mold >/dev/null 2>&1; then
        echo "session-start: mold installed ($(command -v mold))."
    else
        echo "session-start: WARNING — could not install mold; cargo builds will"
        echo "  fail at link unless you run with RUSTFLAGS=\"\" to use the default linker."
    fi
else
    echo "session-start: mold already present ($(command -v mold))."
fi

# --- frontend deps (so the frontend lint/test gate runs) --------------------
if [ -f "${CLAUDE_PROJECT_DIR:-.}/frontend/package.json" ]; then
    echo "session-start: installing frontend deps (npm install)..."
    ( cd "${CLAUDE_PROJECT_DIR:-.}/frontend" && npm install --no-audit --no-fund >/dev/null 2>&1 ) \
        && echo "session-start: frontend deps ready." \
        || echo "session-start: WARNING — frontend npm install failed (continuing)."
fi

echo "session-start: done."
