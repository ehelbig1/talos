#!/usr/bin/env bash
#
# Verify every module-templates/* compiles against the current WIT.
#
# Catches the failure mode that produced bug A3 (2026-04-22):
# `llm-inference` had drifted from the http::Request shape (added `timeout_ms`,
# changed body to Vec<u8>) and silently shipped broken — the catalog install
# only fails when a user actually tries to compile it.
#
# Run via `make check-catalog`. Returns non-zero if any template fails.
#
# Each template is checked independently with `cargo component check
# --release --target wasm32-wasip2`; bindings are regenerated fresh from the
# (synced) wit/talos.wit so we catch shape drift the same way the real
# compiler would.
#
# Optimization: bindings.rs files in templates are stale dev artifacts —
# we delete them before checking so cargo-component regenerates from the
# canonical WIT.

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

if ! command -v cargo-component >/dev/null 2>&1; then
    echo "ERROR: cargo-component not installed. Install with:"
    echo "  cargo install cargo-component --locked"
    exit 1
fi

# 1. Sync WIT first — every template references ../../wit/talos.wit OR has its
# own wit/talos.wit copy; bring both in sync to avoid spurious drift.
if [ -f "$ROOT/Makefile" ]; then
    # Direct WIT-sync check via diff. Earlier versions called
    # `make check-wit-sync` which never existed — the missing target made
    # the `||` branch fire on every run, masking real drift behind a generic
    # "WIT files have drifted" message even when the files matched. Use the
    # actual diff so the error fires only when the files actually differ.
    if ! diff -q "$ROOT/wit/talos.wit" "$ROOT/module-templates/wit/talos.wit" >/dev/null 2>&1; then
        echo "WIT files have drifted between primary and module-templates copies."
        echo "Fix: cp wit/talos.wit module-templates/wit/talos.wit"
        exit 1
    fi
fi

failures=()
checked=0
total=0

# Discover templates (every dir with talos.json + Cargo.toml is a template)
for dir in "$ROOT"/module-templates/*/; do
    if [ ! -f "$dir/talos.json" ] || [ ! -f "$dir/Cargo.toml" ]; then
        continue
    fi
    total=$((total + 1))
done

echo "📦 Catalog template check — $total templates"
echo

for dir in "$ROOT"/module-templates/*/; do
    name="$(basename "$dir")"
    if [ ! -f "$dir/talos.json" ] || [ ! -f "$dir/Cargo.toml" ]; then
        continue
    fi

    checked=$((checked + 1))
    printf "  [%2d/%2d] %-45s " "$checked" "$total" "$name"

    # Force fresh bindings so we catch WIT drift on every run.
    rm -f "$dir/src/bindings.rs"

    # Run check; suppress noisy build output, keep the error if it fails.
    log="$(mktemp)"
    if (cd "$dir" && cargo component check --release --target wasm32-wasip2 >"$log" 2>&1); then
        echo "✅"
    else
        echo "❌"
        # Trim the diagnostic to the first error block (~30 lines).
        echo "─── error from $name ───"
        head -n 40 "$log" | sed 's/^/    /'
        echo "─── end ───"
        echo
        failures+=("$name")
    fi
    rm -f "$log"
done

echo
if [ "${#failures[@]}" -gt 0 ]; then
    echo "❌ ${#failures[@]} template(s) failed: ${failures[*]}"
    exit 1
fi

echo "✅ All $checked catalog templates compile clean against current WIT."
