#!/usr/bin/env bash
# Tests for scripts/setup-admin-query-login.sh and the stdin path of
# scripts/patch-bootstrap-secret.sh it relies on.
#
# Fake `docker` and `kubectl` on PATH stand in for the stack: `exec …
# admin-query-login provision` prints a URL (or fails), `logs` prints the line
# the script waits for, and every call is logged. No daemon, cluster or
# database is touched, so this runs anywhere.
#
# Pinned: the URL lands in its store and NEVER in the script's output; a
# failed provision changes nothing; a re-run replaces the line rather than
# adding one; the env file stays mode 600; --remove takes the line out,
# restarts, then disables the login; and `echo -n "$V" | patch… KEY=-` (no
# trailing newline) is accepted.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

fails=0
check() { # check <label> <expected> <actual>
    if [ "$2" = "$3" ]; then printf '  ok   %s\n' "$1"; else printf '  FAIL %s\n       expected: %s\n       actual:   %s\n' "$1" "$2" "$3"; fails=$((fails+1)); fi
}
has() { if printf '%s' "$1" | grep -qF -- "$2"; then echo yes; else echo no; fi; }

T="$(mktemp -d)"
completed=""
on_exit() {
    local st=$?
    rm -rf "$T"
    if [[ -z "$completed" ]]; then
        echo "✗ setup-admin-query-login test stopped before its last check (status $st)" >&2
        exit 1
    fi
    exit "$st"
}
trap on_exit EXIT

mkdir -p "$T/repo/scripts" "$T/bin" "$T/work"
cp "$REPO/scripts/setup-admin-query-login.sh" "$REPO/scripts/patch-bootstrap-secret.sh" "$T/repo/scripts/"
SCRIPT="$T/repo/scripts/setup-admin-query-login.sh"
URL1="postgres://talos_admin_query:1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa@postgres:5432/talos"
URL2="postgres://talos_admin_query:2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb@postgres:5432/talos"

cat > "$T/bin/docker" <<'EOF'
#!/usr/bin/env bash
echo "docker $*" >> "$FAKE_LOG"
case "$*" in
    *"admin-query-login provision"*)
        [ "${FAKE_PROVISION_FAILS:-}" = 1 ] && { echo "the database refused it" >&2; exit 1; }
        printf '%s\n' "$FAKE_URL" ;;
    *"compose logs"*) echo "INFO query_paginated connects as its own login ($FAKE_VAR set)" ;;
esac
exit 0
EOF
cat > "$T/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
echo "kubectl $*" >> "$FAKE_LOG"
case "$*" in
    *"admin-query-login provision"*) printf '%s\n' "$FAKE_URL" ;;
    *" logs "*) echo "INFO query_paginated connects as its own login" ;;
    *" patch "*)
        # The helper hands the value over in a --patch-file, never on argv.
        prev=""
        for a in "$@"; do
            [ "$prev" = "--patch-file" ] && cat "$a" > "$FAKE_LOG.secret"
            prev="$a"
        done ;;
esac
exit 0
EOF
chmod +x "$T/bin/docker" "$T/bin/kubectl"
export FAKE_LOG="$T/log" FAKE_VAR=TALOS_ADMIN_QUERY_DATABASE_URL
run() { # run <args...> ; output in $out, status in $st
    set +e
    out="$(cd "$T/work" && PATH="$T/bin:$PATH" bash "$SCRIPT" "$@" 2>&1)"
    st=$?
    set -e
}
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

echo "── compose: first setup"
printf 'POSTGRES_PASSWORD=x\n# a comment\nREDIS_PASSWORD=y\n' > "$T/work/.env"
chmod 644 "$T/work/.env"
: > "$FAKE_LOG"
FAKE_URL="$URL1" run --compose
check "exit status" 0 "$st"
check "the URL is in .env" "TALOS_ADMIN_QUERY_DATABASE_URL=$URL1" "$(grep '^TALOS_ADMIN_QUERY_DATABASE_URL=' "$T/work/.env")"
check "the other lines are kept" "yes" "$(grep -q '^REDIS_PASSWORD=y$' "$T/work/.env" && grep -q '^# a comment$' "$T/work/.env" && echo yes || echo no)"
check ".env is mode 600" "600" "$(mode_of "$T/work/.env")"
check "the URL is not in the output" "no" "$(has "$out" "1111aaaa")"
check "the controller is recreated (up -d)" "yes" "$(has "$(cat "$FAKE_LOG")" "compose up -d controller")"
check "the log line is awaited" "yes" "$(has "$out" "connects as its own login")"

echo "── compose: run again (rotate)"
FAKE_URL="$URL2" run --compose
check "exit status" 0 "$st"
check "one line, the new URL" "TALOS_ADMIN_QUERY_DATABASE_URL=$URL2" "$(grep '^TALOS_ADMIN_QUERY_DATABASE_URL=' "$T/work/.env")"
check "no leftover temp file" "0" "$(find "$T/work" -name '.TALOS_ADMIN_QUERY_DATABASE_URL.*' | wc -l | tr -d ' ')"

echo "── compose: provisioning fails"
cp "$T/work/.env" "$T/before"
: > "$FAKE_LOG"
FAKE_PROVISION_FAILS=1 FAKE_URL="$URL1" run --compose
check "exit status" 1 "$st"
check ".env unchanged" "same" "$(cmp -s "$T/before" "$T/work/.env" && echo same || echo changed)"
check "no restart" "no" "$(has "$(cat "$FAKE_LOG")" "up -d")"

echo "── compose: something that is not a URL comes back"
FAKE_URL="Error: refusing" run --compose
check "exit status" 1 "$st"
check ".env unchanged" "same" "$(cmp -s "$T/before" "$T/work/.env" && echo same || echo changed)"

echo "── compose: --remove"
: > "$FAKE_LOG"
run --compose --remove
check "exit status" 0 "$st"
check "the line is gone" "0" "$(grep -c '^TALOS_ADMIN_QUERY_DATABASE_URL=' "$T/work/.env" || true)"
check "the other lines are kept" "yes" "$(grep -q '^POSTGRES_PASSWORD=x$' "$T/work/.env" && echo yes || echo no)"
log="$(cat "$FAKE_LOG")"
check "restart, then disable" "yes" "$(printf '%s\n' "$log" | grep -n 'up -d controller' | cut -d: -f1 | { read -r a; b=$(printf '%s\n' "$log" | grep -n 'admin-query-login disable' | cut -d: -f1); [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ] && echo yes || echo no; })"

echo "── compose: --env-file to a file that does not exist yet"
FAKE_URL="$URL1" run --compose --env-file "$T/work/other.env"
check "exit status" 0 "$st"
check "the file holds only the URL" "TALOS_ADMIN_QUERY_DATABASE_URL=$URL1" "$(cat "$T/work/other.env")"
check "and is mode 600" "600" "$(mode_of "$T/work/other.env")"

echo "── k3s: setup"
printf 'TALOS_HOST=example.test\n' > "$T/work/install.env"
: > "$FAKE_LOG"; rm -f "$FAKE_LOG.secret"
FAKE_URL="$URL1" TALOS_INSTALL_ENV="$T/work/install.env" run --k3s
check "exit status" 0 "$st"
check "the Secret patch carries the URL" "yes" "$(has "$(cat "$FAKE_LOG.secret" 2>/dev/null)" "$URL1")"
check "install.env carries it" "TALOS_ADMIN_QUERY_DATABASE_URL=$URL1" "$(grep '^TALOS_ADMIN_QUERY_DATABASE_URL=' "$T/work/install.env")"
check "the URL is not in the output" "no" "$(has "$out" "1111aaaa")"
check "the URL never reached a command line" "no" "$(has "$(cat "$FAKE_LOG")" "1111aaaa")"
check "the controller is restarted" "yes" "$(has "$(cat "$FAKE_LOG")" "rollout restart")"

echo "── k3s: --remove"
: > "$FAKE_LOG"; rm -f "$FAKE_LOG.secret"
TALOS_INSTALL_ENV="$T/work/install.env" run --k3s --remove
check "exit status" 0 "$st"
check "install.env loses the line" "0" "$(grep -c '^TALOS_ADMIN_QUERY_DATABASE_URL=' "$T/work/install.env" || true)"
check "the login is disabled" "yes" "$(has "$(cat "$FAKE_LOG")" "admin-query-login disable")"

echo "── patch-bootstrap-secret.sh: a value piped without a trailing newline"
: > "$FAKE_LOG"; rm -f "$FAKE_LOG.secret"
set +e
pout="$(printf '%s' "s3cret-no-newline" | PATH="$T/bin:$PATH" bash "$T/repo/scripts/patch-bootstrap-secret.sh" SOME_KEY=- 2>&1)"
pst=$?
set -e
check "accepted" 0 "$pst"
check "the value reached the Secret" "yes" "$(has "$(cat "$FAKE_LOG.secret" 2>/dev/null)" "s3cret-no-newline")"
set +e
pout="$(printf '' | PATH="$T/bin:$PATH" bash "$T/repo/scripts/patch-bootstrap-secret.sh" SOME_KEY=- 2>&1)"
pst=$?
set -e
check "an empty stdin is still refused" 1 "$pst"

completed=1
if [ "$fails" -gt 0 ]; then
    echo "✗ $fails check(s) failed"
    exit 1
fi
echo "✓ setup-admin-query-login: all checks passed"
