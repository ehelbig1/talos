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
#
# Coverage (DX #13, 2026-07-13): templates WITHOUT a Cargo.toml (the
# scaffold-at-install kind — 23 of 62 at the time of writing, including the
# whole ML set) were silently SKIPPED, so a type error in them shipped
# unnoticed until a user ran install. They are now checked too, via a
# generated temp scaffold using the same boilerplate the covered templates
# carry (world from talos.json, lib path = template.rs).

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

# One shared target dir across all templates — they share the identical dep
# graph, so per-dir targets rebuilt serde/wit-bindgen 60x for nothing.
export CARGO_TARGET_DIR="$ROOT/target/catalog-check"

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

# Discover templates: every dir with talos.json AND (Cargo.toml or
# template.rs) — the latter are scaffold-at-install templates.
for dir in "$ROOT"/module-templates/*/; do
    if [ ! -f "$dir/talos.json" ]; then
        continue
    fi
    if [ ! -f "$dir/Cargo.toml" ] && [ ! -f "$dir/template.rs" ]; then
        continue
    fi
    total=$((total + 1))
done

# Scaffold a temp crate for a Cargo.toml-less template. Mirrors the covered
# templates' boilerplate; world comes from talos.json capability_world
# (falling back to the #[talos_module(world = "...")] attribute in source).
scaffold_and_check() {
    local dir="$1" name="$2" log="$3"
    local world
    world="$(grep -o '"capability_world"[[:space:]]*:[[:space:]]*"[^"]*"' "$dir/talos.json"         | sed 's/.*"\([^"]*\)"$/\1/' | head -1)"
    if [ -z "$world" ]; then
        world="$(grep -o 'world[[:space:]]*=[[:space:]]*"[^"]*"' "$dir/template.rs"             | sed 's/.*"\([^"]*\)"$/\1/' | head -1)"
    fi
    if [ -z "$world" ]; then
        echo "no capability_world in talos.json and no world attribute in template.rs" >"$log"
        return 1
    fi
    local pkg="${name//_/-}"
    # Extra crates declared in talos.json `dependencies` — the real install
    # path passes them to the compilation service, so the scaffold must too.
    local extra_deps
    extra_deps="$(python3 - "$dir/talos.json" <<'PY'
import json, sys
meta = json.load(open(sys.argv[1]))
for name, ver in (meta.get("dependencies") or {}).items():
    print(f'{name} = "{ver}"')
PY
)"
    local tmp
    tmp="$(mktemp -d)"
    cp "$dir/template.rs" "$tmp/template.rs"
    cat > "$tmp/Cargo.toml" <<TOML
[package]
name = "$pkg"
version = "0.1.0"
edition = "2021"

[dependencies]
wit-bindgen-rt = { version = "0.44.0", features = ["bitflags"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
talos_sdk_macros = { path = "$ROOT/talos_sdk_macros" }
$extra_deps

[lib]
crate-type = ["cdylib"]
path = "template.rs"

[package.metadata.component]
package = "talos:$pkg"

[package.metadata.component.target]
path = "$ROOT/wit/talos.wit"
world = "$world"

[workspace]
TOML
    local rc=0
    (cd "$tmp" && cargo component check --release --target wasm32-wasip2 >"$log" 2>&1) || rc=1
    rm -rf "$tmp"
    return $rc
}

echo "📦 Catalog template check — $total templates"
echo

for dir in "$ROOT"/module-templates/*/; do
    name="$(basename "$dir")"
    if [ ! -f "$dir/talos.json" ]; then
        continue
    fi
    if [ ! -f "$dir/Cargo.toml" ] && [ ! -f "$dir/template.rs" ]; then
        continue
    fi

    checked=$((checked + 1))
    printf "  [%2d/%2d] %-45s " "$checked" "$total" "$name"

    # Force fresh bindings so we catch WIT drift on every run.
    rm -f "$dir/src/bindings.rs"

    # Run check; suppress noisy build output, keep the error if it fails.
    log="$(mktemp)"
    ok=0
    if [ -f "$dir/Cargo.toml" ]; then
        (cd "$dir" && cargo component check --release --target wasm32-wasip2 >"$log" 2>&1) || ok=1
    else
        scaffold_and_check "$dir" "$name" "$log" || ok=1
    fi
    if [ "$ok" -eq 0 ]; then
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
