#!/usr/bin/env bash
# scripts/ngrok.sh keeps its tunnel log and ngrok's config in a directory only
# this user can open, and removes it on exit (security review 2026-10-15, H2-6;
# the token half is H-9). Drives the real script with a stand-in `ngrok` and
# `docker-compose` on PATH.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/tmp"

cat > "$work/bin/ngrok" <<'STUB'
#!/usr/bin/env bash
[ "${1:-}" = "version" ] && exit 0
config=""
while [ $# -gt 0 ]; do
    [ "$1" = "--config" ] && config="$2"
    shift
done
dir="$(dirname "$config")"
# Where this process's stdout goes (the script redirects it to its log).
readlink "/proc/$$/fd/1" > "$SEEN.stdout" 2>/dev/null \
    || lsof -p $$ -a -d 1 -Fn 2>/dev/null | sed -n 's/^n//p' > "$SEEN.stdout"
{
    echo "config=$config"
    echo "dir_mode=$(stat -c '%a' "$dir" 2>/dev/null || stat -f '%Lp' "$dir")"
    echo "config_mode=$(stat -c '%a' "$config" 2>/dev/null || stat -f '%Lp' "$config")"
    echo "log_mode=$(stat -c '%a' "$dir/ngrok.log" 2>/dev/null || stat -f '%Lp' "$dir/ngrok.log")"
} > "$SEEN"
echo '{"msg":"started tunnel","url":"https://stand-in.example.test"}'
STUB
printf '#!/usr/bin/env bash\nexit 0\n' > "$work/bin/docker-compose"
chmod +x "$work/bin/ngrok" "$work/bin/docker-compose"

(
    cd "$work"
    PATH="$work/bin:$PATH" TMPDIR="$work/tmp" NGROK_AUTHTOKEN="stand-in-token" SEEN="$work/seen" \
        bash "$root/scripts/ngrok.sh" > "$work/out" 2>&1
)

fail() { echo "ngrok-private-files-test: $*" >&2; cat "$work/out" >&2; exit 1; }
grep -q 'ngrok tunnel: https://stand-in.example.test' "$work/out" || fail "the stand-in tunnel was not read from the log"
config="$(sed -n 's/^config=//p' "$work/seen")"
case "$config" in "$work/tmp/talos-tunnel."*/ngrok.yml) ;; *) fail "config at $config, not in a private tunnel directory" ;; esac
[ "$(sed -n 's/^dir_mode=//p' "$work/seen")" = "700" ] || fail "tunnel directory is not 0700"
[ "$(sed -n 's/^config_mode=//p' "$work/seen")" = "600" ] || fail "config is not 0600"
[ "$(sed -n 's/^log_mode=//p' "$work/seen")" = "600" ] || fail "log is not 0600"
stdout="$(cat "$work/seen.stdout" 2>/dev/null || true)"
if [ -n "$stdout" ]; then
    case "$stdout" in "$(dirname "$config")/ngrok.log" | /private"$(dirname "$config")/ngrok.log") ;; *) fail "ngrok logged to $stdout" ;; esac
fi
[ ! -e "$(dirname "$config")" ] || fail "the tunnel directory outlived the script"
if grep -n '/tmp/[a-z]*\.log' "$root/scripts/ngrok.sh" | grep -v '^[0-9]*:#'; then fail "a fixed /tmp log path is back"; fi
echo "ngrok-private-files-test: ok"
