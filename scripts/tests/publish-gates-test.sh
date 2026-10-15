#!/usr/bin/env bash
# scripts/publish-images.sh records what vouched for a publish (security review
# 2026-10-15, H2-4): --skip-ci-check with the audit switch off tags
# `-unaudited`, and every signature carries
# `org.talos.publish.gates`. Drives the real script against stand-in docker,
# cargo and cosign; nothing is built, pushed or signed.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/repo"

cat > "$work/bin/docker" <<'STUB'
#!/usr/bin/env bash
echo "docker $*" >> "$CALLS"
case "${1:-}" in
    inspect) echo "stand-in/talos@sha256:0000000000000000000000000000000000000000000000000000000000000000" ;;
esac
exit 0
STUB
cat > "$work/bin/cosign" <<'STUB'
#!/usr/bin/env bash
echo "cosign $*" >> "$CALLS"
STUB
# `cargo audit` answers with $AUDIT_EXIT; `cargo-audit` exists for `command -v`.
cat > "$work/bin/cargo" <<'STUB'
#!/usr/bin/env bash
exit "${AUDIT_EXIT:-0}"
STUB
printf '#!/usr/bin/env bash\nexit 0\n' > "$work/bin/cargo-audit"
chmod +x "$work/bin/"*

(
    cd "$work/repo"
    git init -q
    git -c user.email=t@example.test -c user.name=t commit -q --allow-empty -m init
)

run() {
    : > "$work/calls"
    (
        cd "$work/repo"
        PATH="$work/bin:$PATH" CALLS="$work/calls" TALOS_GHCR_OWNER=stand-in "$@" \
            bash "$root/scripts/publish-images.sh" --service controller --skip-ci-check > "$work/out" 2>&1
    )
}
fail() { echo "publish-gates-test: $*" >&2; cat "$work/out" "$work/calls" >&2; exit 1; }

# Neither gate vouched: CI skipped, audit overridden and vulnerable.
run env AUDIT_EXIT=1 TALOS_PUBLISH_REQUIRE_AUDIT=0
grep -q -- '-unaudited ' "$work/calls" || grep -q -- '-unaudited$' "$work/calls" || fail "no -unaudited tag"
grep -q 'org.talos.publish.gates=ci:skipped,audit:vulnerable' "$work/calls" || fail "signature does not carry the gates"
grep -q 'Gates: ci:skipped,audit:vulnerable' "$work/out" || fail "summary does not name the gates"

# The audit switch off: tagged even when the audit happened to come back clean,
# because nothing would have stopped the publish if it had not.
run env AUDIT_EXIT=0 TALOS_PUBLISH_REQUIRE_AUDIT=0
grep -q -- '-unaudited' "$work/calls" || fail "the audit switch was off and the tag does not say so"
grep -q 'org.talos.publish.gates=ci:skipped,audit:clean' "$work/calls" || fail "the gates are not recorded"

# A required audit vouched (CI skipped, the switch on by default, clean): no
# suffix, the gates still recorded.
run env AUDIT_EXIT=0
if grep -q -- '-unaudited' "$work/calls"; then fail "a required clean audit was tagged -unaudited"; fi
grep -q 'org.talos.publish.gates=ci:skipped,audit:clean' "$work/calls" || fail "clean publish does not carry the gates"

# The default with --skip-ci-check still refuses a vulnerable audit (H-6).
if run env AUDIT_EXIT=1; then fail "a required audit that failed did not stop the publish"; fi
if grep -q '^docker push' "$work/calls"; then fail "pushed after a failed required audit"; fi

echo "publish-gates-test: ok"
