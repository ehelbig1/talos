#!/usr/bin/env bash
#
# Verify every module-templates/* compiles THE WAY PRODUCTION COMPILES IT.
#
# ── What this gate covers, and what it does not ──────────────────────────────
#
# COVERS:
#   * Every template's source compiles against the current WIT, using the
#     SAME dependency declaration production uses — `talos.json`'s
#     `dependencies` field, and nothing else (leg 1).
#   * No template's own `Cargo.toml` declares an extra crate that
#     `talos.json` omits (leg 2) — see below for why that is the whole
#     point of this rewrite.
#
# DOES NOT COVER:
#   * Whether the RUNTIME actually forwards `talos.json.dependencies`. That
#     is a property of Rust code, not of the templates, and it is gated by
#     `talos_compilation::catalog`'s unit tests plus structural lint check
#     68. Between 2026-07 and 2026-08-11 that property was FALSE while this
#     script was green — do not read a green run here as "production can
#     build these".
#   * Runtime behaviour of any kind. This is `cargo component check`, not a
#     link, not an instantiation, not an execution.
#   * Templates with neither `talos.json` nor a source file — they are
#     skipped, and a template that is skipped is not a template that passed.
#
# ── Why leg 1 no longer uses each template's own Cargo.toml ──────────────────
#
# It used to: templates WITH a `Cargo.toml` were checked by `cd`ing into them
# and building that crate, and only Cargo.toml-LESS templates got a scaffold
# built from `talos.json`. That is two gates for one artifact, and production
# is neither of them — production generates a FIXED manifest
# (`talos_compilation::create_workspace`) whose only variable part is the
# `talos.json` `dependencies` block.
#
# The divergence was not theoretical. `create-calendar-event` declared
# `urlencoding = "2.1.3"` in its `Cargo.toml` and nothing in its
# `talos.json`. This script compiled it green via the Cargo.toml for months
# while the controller failed it at EVERY boot with
# `use of unresolved module or unlinked crate urlencoding`, leaving its
# `wasm_bytes` NULL — the template could not run at all. A gate whose green
# is compatible with a runtime failure is worse than no gate.
#
# Leg 1 therefore builds every template the way production does. The on-disk
# `Cargo.toml` files are kept (they are what makes `cd module-templates/x &&
# cargo component build` work for a human) but they are no longer authoritative
# for anything, and leg 2 pins them to `talos.json` so they cannot drift again.
#
# ── Original purpose, still served ───────────────────────────────────────────
# Catches the failure mode that produced bug A3 (2026-04-22): `llm-inference`
# had drifted from the http::Request shape and silently shipped broken — the
# catalog install only fails when a user actually tries to compile it.
#
# Historical note: this check used to delete each template's src/bindings.rs
# before checking, so cargo-component would regenerate from the canonical WIT.
# The temp-dir scaffold makes that unnecessary — and the deletion was leaving
# ~315k lines of tracked deletions in the working tree on every run.
#
# Run via `make check-catalog`. Returns non-zero if any leg fails.

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

# Crates the generated manifest already bundles. Must stay in lockstep with
# `talos_compilation::create_workspace`'s PRE_BUNDLED list — and BOTH legs
# depend on that lockstep, not just leg 2:
#
#   leg 2: a crate pre-bundled there but not here reads as an undeclared
#          Cargo.toml dep (loud false positive, not a silent miss).
#   leg 1: `create_workspace` SKIPS a pre-bundled crate when it emits the
#          `[dependencies]` block, precisely so a `talos.json` declaring e.g.
#          `serde` cannot produce a duplicate-key Cargo.toml. The scaffold
#          below must skip the same names or it emits `serde = "1.0"` twice
#          and the template fails this gate with a TOML parse error while
#          production compiles it fine — a false positive that would look
#          like a broken template.
PRE_BUNDLED="serde serde_json wit-bindgen wit-bindgen-rt talos_sdk_macros talos-sdk-macros"

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

# ── Leg 2: manifest agreement (static, cheap, runs first) ────────────────────
#
# `talos.json` is the ONLY dependency declaration production reads. Any extra
# crate a template's own Cargo.toml declares must therefore also appear
# there, or the template builds in dev and fails in production.
#
# Direction is deliberate: Cargo.toml ⊆ talos.json. The reverse (a talos.json
# dep absent from Cargo.toml) is harmless for production — production never
# reads the Cargo.toml — and forcing equality would mean every
# Cargo.toml-less template needed a Cargo.toml.
echo "🔗 Manifest agreement — talos.json must declare every Cargo.toml dep"
mismatches=()
for dir in "$ROOT"/module-templates/*/; do
    [ -f "$dir/talos.json" ] || continue
    [ -f "$dir/Cargo.toml" ] || continue
    name="$(basename "$dir")"
    while IFS= read -r crate; do
        [ -n "$crate" ] || continue
        case " $PRE_BUNDLED " in *" $crate "*) continue ;; esac
        if ! python3 - "$dir/talos.json" "$crate" <<'PY'
import json, sys
meta = json.load(open(sys.argv[1]))
deps = meta.get("dependencies") or {}
sys.exit(0 if sys.argv[2].lower() in {k.lower() for k in deps} else 1)
PY
        then
            mismatches+=("$name: Cargo.toml declares '$crate' but talos.json \`dependencies\` does not")
        fi
    done < <(awk '
        /^\[dependencies\]/ { in_deps=1; next }
        /^\[/               { in_deps=0 }
        in_deps && /^[[:space:]]*[A-Za-z0-9_-]+[[:space:]]*=/ {
            sub(/^[[:space:]]*/, "");
            split($0, a, "=");
            gsub(/[[:space:]]/, "", a[1]);
            print a[1]
        }
    ' "$dir/Cargo.toml")
done
if [ "${#mismatches[@]}" -gt 0 ]; then
    echo "❌ ${#mismatches[@]} template(s) declare a crate production will never see:"
    printf '    %s\n' "${mismatches[@]}"
    echo
    echo "  talos.json's \`dependencies\` is the only declaration the runtime reads"
    echo "  (talos_compilation::CatalogTemplate::dependencies). Add the crate there,"
    echo "  or delete it from the Cargo.toml if it is vestigial."
    exit 1
fi
echo "✅ every Cargo.toml dep is declared in its talos.json"
echo

# ── Leg 1: production-parity compile ─────────────────────────────────────────

failures=()
checked=0
total=0

# Discover templates: every dir with talos.json AND a source file the runtime
# would seed (template.rs, else src/lib.rs — same precedence as
# `talos_compilation::CatalogTemplate::load`).
template_source() {
    if [ -f "$1/template.rs" ]; then
        echo "$1/template.rs"
    elif [ -f "$1/src/lib.rs" ]; then
        echo "$1/src/lib.rs"
    fi
}

for dir in "$ROOT"/module-templates/*/; do
    [ -f "$dir/talos.json" ] || continue
    [ -n "$(template_source "$dir")" ] || continue
    total=$((total + 1))
done

# Build one template exactly the way `talos_compilation::create_workspace`
# does: fixed base manifest + the `dependencies` block from talos.json, and
# nothing from the template's own Cargo.toml. World comes from talos.json
# `capability_world`, falling back to the `#[talos_module(world = "...")]`
# attribute in the source (the same fallback `install_module_from_catalog`
# uses).
scaffold_and_check() {
    local dir="$1" name="$2" log="$3" src="$4"
    local world
    world="$(grep -o '"capability_world"[[:space:]]*:[[:space:]]*"[^"]*"' "$dir/talos.json" \
        | sed 's/.*"\([^"]*\)"$/\1/' | head -1)"
    if [ -z "$world" ]; then
        world="$(grep -o 'world[[:space:]]*=[[:space:]]*"[^"]*"' "$src" \
            | sed 's/.*"\([^"]*\)"$/\1/' | head -1)"
    fi
    if [ -z "$world" ]; then
        echo "no capability_world in talos.json and no world attribute in the source" >"$log"
        return 1
    fi
    local pkg="${name//_/-}"
    # Extra crates declared in talos.json `dependencies` — the ONLY
    # dependency source the runtime reads.
    local extra_deps
    extra_deps="$(PRE_BUNDLED="$PRE_BUNDLED" python3 - "$dir/talos.json" <<'PY'
import json, os, sys
meta = json.load(open(sys.argv[1]))
# Mirror create_workspace's PRE_BUNDLED skip. Without it a talos.json that
# legitimately declares `serde` (allowlisted, and production silently drops
# it as already-bundled) emits a second `serde = ...` line into a manifest
# that already has one, and cargo fails with `duplicate key` — this gate
# would report a template as broken that production builds fine.
pre_bundled = {c.lower() for c in os.environ.get("PRE_BUNDLED", "").split()}
for name, ver in (meta.get("dependencies") or {}).items():
    if name.lower() in pre_bundled:
        continue
    # Mirror the two feature-flag special cases in
    # talos_compilation::create_workspace — without them a template
    # declaring uuid/tokio compiles here and fails in production.
    if name == "uuid":
        print(f'uuid = {{ version = "{ver}", features = ["v4", "v7"] }}')
    elif name == "tokio":
        print(f'tokio = {{ version = "{ver}", features = ["rt", "macros", "time", "sync", "io-util"] }}')
    else:
        print(f'{name} = "{ver}"')
PY
)"
    local tmp
    tmp="$(mktemp -d)"
    cp "$src" "$tmp/template.rs"
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

echo "📦 Catalog template check — $total templates, production-parity manifests"
echo

for dir in "$ROOT"/module-templates/*/; do
    name="$(basename "$dir")"
    [ -f "$dir/talos.json" ] || continue
    src="$(template_source "$dir")"
    [ -n "$src" ] || continue

    checked=$((checked + 1))
    printf "  [%2d/%2d] %-45s " "$checked" "$total" "$name"

    # NOTE: no `rm -f "$dir/src/bindings.rs"` here any more. It existed to
    # force fresh bindings when the check built IN the template directory;
    # the production-parity scaffold builds in a temp dir and cargo-component
    # regenerates bindings there from the canonical WIT unconditionally, so
    # the deletion did nothing except leave ~315k lines of tracked-file
    # deletions in the working tree after every run — which the publish
    # gate then refuses as a dirty tree.

    log="$(mktemp)"
    ok=0
    scaffold_and_check "$dir" "$name" "$log" "$src" || ok=1
    if [ "$ok" -eq 0 ]; then
        echo "✅"
    else
        echo "❌"
        # Trim the diagnostic to the first error block (~40 lines).
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

echo "✅ All $checked catalog templates compile clean against current WIT,"
echo "   using only the dependencies their talos.json declares."
