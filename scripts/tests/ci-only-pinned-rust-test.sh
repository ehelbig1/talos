#!/usr/bin/env bash
# Tests for scripts/ci-only-pinned-rust.sh with a fake `rustup` whose
# installed toolchains are lines in a file.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../ci-only-pinned-rust.sh"

fails=0
T="$(mktemp -d)"
completed=""
on_exit() {
    local st=$?
    rm -rf "$T"
    if [[ -z "$completed" ]]; then
        echo "✗ ci-only-pinned-rust test stopped before its last check (status $st)" >&2
        exit 1
    fi
    exit "$st"
}
trap on_exit EXIT

mkdir -p "$T/bin"
cat > "$T/bin/rustup" <<'SHIM'
#!/usr/bin/env bash
# toolchain list [--quiet] | toolchain uninstall <name>
[ "$1" = "toolchain" ] || exit 2
case "$2" in
    list) cat "$RUSTUP_STATE" ;;
    uninstall) grep -vxF -- "$3" "$RUSTUP_STATE" > "$RUSTUP_STATE.new" || true; mv "$RUSTUP_STATE.new" "$RUSTUP_STATE" ;;
    *) exit 2 ;;
esac
SHIM
chmod +x "$T/bin/rustup"
export RUSTUP_STATE="$T/toolchains"

# run <expected exit> <label> <RUST_TOOLCHAIN> <installed line …> — sets OUT.
run() {
    local want="$1" label="$2" pin="$3"; shift 3
    printf '%s\n' "$@" > "$RUSTUP_STATE"
    set +e
    OUT="$(PATH="$T/bin:$PATH" RUST_TOOLCHAIN="$pin" bash "$SCRIPT" 2>&1)"
    local got=$?
    set -e
    if [ "$got" = "$want" ]; then printf '  ok   %s\n' "$label"; else printf '  FAIL %s (exit %s, want %s)\n       %s\n' "$label" "$got" "$want" "$OUT"; fails=$((fails+1)); fi
}
left() { # left <label> <expected remaining, space-separated>
    local got; got="$(tr '\n' ' ' < "$RUSTUP_STATE" | sed 's/ $//')"
    if [ "$got" = "$2" ]; then printf '  ok   %s\n' "$1"; else printf '  FAIL %s\n       want: %s\n       got:  %s\n' "$1" "$2" "$got"; fails=$((fails+1)); fi
}

echo "the image's own toolchains go, the pinned one stays"
run 0 "runs" 1.96 stable-x86_64-unknown-linux-gnu 1.96-x86_64-unknown-linux-gnu
left "only the pinned toolchain is left" "1.96-x86_64-unknown-linux-gnu"
run 0 "several others" 1.96 stable-x86_64-unknown-linux-gnu nightly-x86_64-unknown-linux-gnu 1.96-x86_64-unknown-linux-gnu 1.99.0-x86_64-unknown-linux-gnu
left "all of them removed" "1.96-x86_64-unknown-linux-gnu"

echo "a pin is a whole component, not a prefix"
run 0 "1.9 does not keep 1.96 or 1.99" 1.9 1.96-x86_64-unknown-linux-gnu 1.99.0-x86_64-unknown-linux-gnu 1.9-x86_64-unknown-linux-gnu
left "only 1.9 is left" "1.9-x86_64-unknown-linux-gnu"

echo "nothing to remove"
run 0 "only the pinned toolchain installed" 1.96 1.96-x86_64-unknown-linux-gnu
left "it is untouched" "1.96-x86_64-unknown-linux-gnu"

echo "the pinned toolchain is missing: nothing is removed"
run 1 "refused" 1.96 stable-x86_64-unknown-linux-gnu
left "the other toolchain is still there" "stable-x86_64-unknown-linux-gnu"
if grep -qF "no installed toolchain matches '1.96'" <<< "$OUT"; then printf '  ok   says why\n'; else printf '  FAIL says why\n'; fails=$((fails+1)); fi

echo "no pin given"
printf '%s\n' stable-x86_64-unknown-linux-gnu > "$RUSTUP_STATE"
set +e; OUT="$(PATH="$T/bin:$PATH" env -u RUST_TOOLCHAIN bash "$SCRIPT" 2>&1)"; rc=$?; set -e
if [ "$rc" -ne 0 ]; then printf '  ok   refused\n'; else printf '  FAIL refused\n'; fails=$((fails+1)); fi
left "nothing removed" "stable-x86_64-unknown-linux-gnu"

completed=1
if [ "$fails" -gt 0 ]; then
    echo "✗ $fails check(s) failed"
    exit 1
fi
echo "✓ ci-only-pinned-rust: all checks passed"
