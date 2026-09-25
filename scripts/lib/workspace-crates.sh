# Map changed file paths to the workspace crates that own them.
#
# Sourced by scripts/test-changed.sh and .githooks/pre-commit, so "which
# crates did this change touch" has one answer.
#
#   crate_for PATH          → the owning crate's package name; non-zero if none
#   crates_for_paths < LIST → one crate per line (sorted, unique); a line
#                             reading `*` means a workspace-wide input changed
#                             (root Cargo.toml / Cargo.lock / .cargo/ /
#                             rust-toolchain.toml / wit/), so the caller
#                             should fall back to the whole workspace.
#
# Paths are repository-relative and the caller's working directory must be
# the repository root.

crate_for() {
    local dir
    dir=$(dirname "$1")
    while [ "$dir" != "." ] && [ "$dir" != "/" ]; do
        if [ -f "$dir/Cargo.toml" ] && grep -q '^\[package\]' "$dir/Cargo.toml" 2>/dev/null; then
            grep -m1 '^name[[:space:]]*=' "$dir/Cargo.toml" \
                | sed -E 's/^name[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/'
            return 0
        fi
        dir=$(dirname "$dir")
    done
    return 1
}

crates_for_paths() {
    local path c
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        case "$path" in
            Cargo.toml|Cargo.lock|rust-toolchain.toml|.cargo/*|wit/*)
                echo '*'
                continue
                ;;
            *.rs|*/Cargo.toml|*.wit) ;;
            *) continue ;;
        esac
        if c=$(crate_for "$path"); then
            echo "$c"
        fi
    done | sort -u
}
