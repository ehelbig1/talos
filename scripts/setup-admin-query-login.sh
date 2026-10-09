#!/usr/bin/env bash
# Switch the platform-admin `query_paginated` tool onto a database login of its
# own (docs/query-paginated-login.md), or back off it.
#
#   scripts/setup-admin-query-login.sh --compose [--env-file PATH]
#   scripts/setup-admin-query-login.sh --k3s
#   scripts/setup-admin-query-login.sh --compose|--k3s --remove
#
# Set up (and, run again, rotate):
#   1. Inside the RUNNING controller container, `controller admin-query-login
#      provision` makes the login `talos_admin_query` (or gives it a new
#      password), checks it the way every query_paginated call does, and prints
#      its URL. The password is generated there, sent to Postgres only as a
#      SCRAM verifier, and comes back here on a pipe.
#   2. The URL goes straight into its store, never onto the terminal:
#        --compose  TALOS_ADMIN_QUERY_DATABASE_URL in the env file (default
#                   ./.env), replaced in place, mode 600;
#        --k3s      the bootstrap Secret, through scripts/patch-bootstrap-secret.sh
#                   (which restarts the controller), and /etc/talos/install.env
#                   when it exists, so a reinstall carries it.
#   3. The controller is restarted (compose: `up -d controller`, which re-reads
#      the env file; `restart` would not) and its log is checked for
#      "query_paginated connects as its own login".
#
# --remove takes the setting out of the same places, restarts, and then runs
# `controller admin-query-login disable` (the login keeps its membership but
# can no longer log in, so a copy of the old URL is useless).
#
# Between provisioning and the restart, a controller already configured with
# an older password refuses query_paginated calls; nothing else is affected.
#
# Environment (k3s; the same names scripts/patch-bootstrap-secret.sh reads):
#   TALOS_NAMESPACE (talos), TALOS_CONTROLLER_DEPLOY (talos-controller),
#   TALOS_INSTALL_ENV (/etc/talos/install.env).
# Compose honours COMPOSE_FILE / COMPOSE_PROJECT_NAME as `docker compose` does.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VAR=TALOS_ADMIN_QUERY_DATABASE_URL
BIN=/app/controller
LOG_LINE="query_paginated connects as its own login"

err() { printf '✗ %s\n' "$*" >&2; }
ok() { printf '✓ %s\n' "$*" >&2; }
usage() {
    sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

mode=""
remove=""
env_file=".env"
while [ $# -gt 0 ]; do
    case "$1" in
        --compose | --k3s) [ -z "$mode" ] || usage; mode="${1#--}" ;;
        --remove) remove=1 ;;
        --env-file) [ $# -ge 2 ] || usage; env_file="$2"; shift ;;
        -h | --help) usage ;;
        *) err "unknown argument: $1"; usage ;;
    esac
    shift
done
[ -n "$mode" ] || usage

# Put VAR=value into a KEY=VALUE file (or take it out when value is empty),
# atomically and readable by its owner only. The value never reaches argv: awk
# reads it from the environment.
set_in_file() { # set_in_file <file> <value|"">
    local file="$1" dir tmp
    dir="$(dirname "$file")"
    tmp="$(umask 077 && mktemp "$dir/.${VAR}.XXXXXX")"
    if [ -f "$file" ]; then
        SETUP_VALUE="$2" awk -v var="$VAR" '
            BEGIN { value = ENVIRON["SETUP_VALUE"]; done = 0 }
            index($0, var "=") == 1 {
                if (!done && value != "") print var "=" value
                done = 1
                next
            }
            { print }
            END { if (!done && value != "") print var "=" value }
        ' "$file" > "$tmp"
    elif [ -n "$2" ]; then
        SETUP_VALUE="$2" awk -v var="$VAR" 'BEGIN { print var "=" ENVIRON["SETUP_VALUE"] }' > "$tmp"
    else
        rm -f "$tmp"
        return 0
    fi
    chmod 600 "$tmp"
    mv -f "$tmp" "$file"
}

# Wait until the controller's log says it uses its own login.
await_log_line() { # await_log_line <command printing recent logs...>
    local i
    for i in $(seq 1 60); do
        if "$@" 2>/dev/null | grep -qF "$LOG_LINE"; then
            ok "the controller says: $LOG_LINE"
            return 0
        fi
        sleep 2
    done
    err "the controller has not logged \"$LOG_LINE\" after 2 minutes; check its log for an error about $VAR"
    return 1
}

# The URL lives in this variable only; it is never echoed, and is cleared on exit.
url=""
trap 'url=""' EXIT

case "$mode" in
    compose)
        compose() { docker compose "$@"; }
        if [ -n "$remove" ]; then
            set_in_file "$env_file" ""
            compose up -d controller >&2
            compose exec -T controller "$BIN" admin-query-login disable >&2
            ok "query_paginated runs on the controller's own connection again; $VAR removed from $env_file"
            exit 0
        fi
        # Provision first: if it fails, nothing has been changed.
        if ! url="$(compose exec -T controller "$BIN" admin-query-login provision)"; then
            err "provisioning failed (its reason is above); $env_file and the controller are unchanged"
            exit 1
        fi
        case "$url" in
            postgres://* | postgresql://*) ;;
            *) err "the controller did not return a database URL; nothing changed"; exit 1 ;;
        esac
        set_in_file "$env_file" "$url"
        url=""
        ok "$VAR written to $env_file (mode 600)"
        since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        compose up -d controller >&2
        await_log_line compose logs --since "$since" controller
        ;;
    k3s)
        if command -v k3s >/dev/null 2>&1 && [ -f /etc/rancher/k3s/k3s.yaml ]; then
            kube() { k3s kubectl "$@"; }
        elif command -v kubectl >/dev/null 2>&1; then
            kube() { kubectl "$@"; }
        else
            err "no kubectl found; run this on the k3s host"
            exit 1
        fi
        ns="${TALOS_NAMESPACE:-talos}"
        deploy="${TALOS_CONTROLLER_DEPLOY:-talos-controller}"
        install_env="${TALOS_INSTALL_ENV:-/etc/talos/install.env}"
        if [ -n "$remove" ]; then
            # An empty value: the controller reads it as unset.
            printf '%s=\n' "$VAR" | "$HERE/patch-bootstrap-secret.sh"
            [ ! -f "$install_env" ] || set_in_file "$install_env" ""
            kube -n "$ns" exec "deploy/$deploy" -- "$BIN" admin-query-login disable >&2
            ok "query_paginated runs on the controller's own connection again"
            exit 0
        fi
        if ! url="$(kube -n "$ns" exec "deploy/$deploy" -- "$BIN" admin-query-login provision)"; then
            err "provisioning failed (its reason is above); the Secret and the controller are unchanged"
            exit 1
        fi
        case "$url" in
            postgres://* | postgresql://*) ;;
            *) err "the controller did not return a database URL; nothing changed"; exit 1 ;;
        esac
        # The helper reads the value from stdin (`KEY=-`), so it never reaches
        # argv, and restarts the controller.
        printf '%s\n' "$url" | "$HERE/patch-bootstrap-secret.sh" "$VAR=-"
        if [ -f "$install_env" ]; then
            set_in_file "$install_env" "$url"
            ok "$VAR written to $install_env (mode 600)"
        fi
        url=""
        await_log_line kube -n "$ns" logs "deploy/$deploy" --since=5m
        ;;
esac
