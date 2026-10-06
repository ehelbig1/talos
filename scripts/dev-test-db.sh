#!/usr/bin/env bash
# `make test-db` — a local Postgres for the controller's database tests.
#
# The controller's DB tests (`mod common;`) clone a MIGRATED TEMPLATE database
# per test and need `DATABASE_URL` to name it. `make test-integration` builds
# one, runs every suite and tears it down — right for a full run, far too slow
# for "run this one test binary again". Until this script the alternative was
# a container set up by hand from notes: start it, read its password, rebuild
# the template whenever migrations moved, export the URL.
#
#   scripts/dev-test-db.sh up            start the container; build or update the template
#   scripts/dev-test-db.sh run <cmd…>    `up`, then run <cmd…> with DATABASE_URL set
#   scripts/dev-test-db.sh status        what exists, read-only
#   scripts/dev-test-db.sh rebuild       drop the template and every test clone, build again
#   scripts/dev-test-db.sh stop          stop the container (the template is kept)
#
#   scripts/dev-test-db.sh run cargo test -p controller --test owner_added_grants_tests
#
# WHAT THIS NEVER TOUCHES: the stack's own Postgres. Every statement goes
# through `docker exec` into ONE container, named below, which this script
# creates; a name that is the stack's container is refused. Tests that clone a
# template into the operator's live database are DDL on the only database
# there is.
#
# The password is generated when the container is created, lives in the
# container's own environment, and is written to an env file readable by the
# owner only. It is never printed.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

NAME="${TALOS_DEV_TEST_DB_CONTAINER:-talos-ctl-scratch-pg}"
PORT="${TALOS_DEV_TEST_DB_PORT:-15433}"
TEMPLATE="talos_ctl"
ENV_FILE="${TALOS_DEV_TEST_DB_ENV:-$HOME/.talos/test-db.env}"
PG_USER="talos"

say()  { printf '%s\n' "$*" >&2; }
fail() { say "✗ $*"; exit 1; }

case "$NAME" in
    talos-postgres|talos-postgres-*|*_postgres_1|*-postgres-1)
        fail "refusing to use '$NAME': that is the stack's own database, not a scratch one" ;;
esac
[ "$PORT" != 5432 ] || fail "refusing port 5432: that is the stack's own database"

command -v docker >/dev/null 2>&1 || fail "docker is not installed"

# The image, from the ONE place that pins it: the integration runner. A
# second pinned digest here would drift from it.
image() {
    local img
    img="$(grep -o 'pgvector/pgvector:pg17@sha256:[0-9a-f]\{64\}' scripts/test-integration.sh | head -1)"
    [ -n "$img" ] || fail "could not read the pgvector image from scripts/test-integration.sh"
    printf '%s\n' "$img"
}

# `docker inspect` of a container that does not exist prints an empty line
# AND fails, so "print it, or else print absent" yields two lines.
state() {
    local s
    s="$(docker inspect -f '{{.State.Status}}' "$NAME" 2>/dev/null)" || s=""
    printf '%s\n' "${s:-absent}"
}

password() {
    docker inspect "$NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' \
        | awk -F= '$1 == "POSTGRES_PASSWORD" { print substr($0, index($0, "=") + 1) }'
}

psql_in() { # $1 = database; the rest = psql arguments
    local db="$1"; shift
    docker exec -i "$NAME" psql -q -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$PG_USER" -d "$db" "$@"
}

scalar() { psql_in "$1" -At -c "$2"; }

url() { printf 'postgres://%s:%s@127.0.0.1:%s/%s' "$PG_USER" "$(password)" "$PORT" "$TEMPLATE"; }

wait_ready() {
    local _
    # Over TCP, not the socket: a fresh container answers on its socket from a
    # TEMPORARY server before the real one is up.
    for _ in $(seq 1 60); do
        if docker exec "$NAME" pg_isready -h 127.0.0.1 -p 5432 -U "$PG_USER" >/dev/null 2>&1 \
            && docker exec "$NAME" psql -h 127.0.0.1 -U "$PG_USER" -d postgres -c 'SELECT 1' >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    fail "Postgres in '$NAME' never became ready"
}

start_container() {
    case "$(state)" in
        running) ;;
        absent)
            say "▶ creating scratch Postgres '$NAME' on 127.0.0.1:$PORT"
            local pw
            pw="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
            # `pg_stat_statements` must be preloaded at postmaster start, as in
            # docker-compose.yml and the integration runner: without it one
            # migration no-ops and the tests that read it see `not_installed`.
            docker run -d --name "$NAME" \
                -e "POSTGRES_USER=$PG_USER" -e "POSTGRES_PASSWORD=$pw" -e POSTGRES_DB=postgres \
                -p "127.0.0.1:${PORT}:5432" "$(image)" \
                -c shared_preload_libraries=pg_stat_statements \
                -c authentication_timeout=5s >/dev/null
            ;;
        *)
            say "▶ starting scratch Postgres '$NAME'"
            docker start "$NAME" >/dev/null
            ;;
    esac
    wait_ready
}

template_exists() {
    [ "$(scalar postgres "SELECT count(*) FROM pg_database WHERE datname = '$TEMPLATE'")" = 1 ]
}

drop_clones() {
    local db
    for db in $(scalar postgres "SELECT datname FROM pg_database WHERE datname ~ '^test_[0-9a-f]{32}$'"); do
        psql_in postgres -c "DROP DATABASE IF EXISTS \"$db\" WITH (FORCE)" >/dev/null
    done
}

build_template() {
    command -v sqlx >/dev/null 2>&1 || fail "sqlx-cli is not installed (cargo install sqlx-cli)"
    say "▶ building template '$TEMPLATE' from the schema baseline + the migrations after it"
    psql_in postgres -c "DROP DATABASE IF EXISTS \"$TEMPLATE\" WITH (FORCE)" >/dev/null
    psql_in postgres -c "CREATE DATABASE \"$TEMPLATE\"" >/dev/null
    psql_in "$TEMPLATE" < migrations/.baseline/schema.sql >/dev/null
    psql_in "$TEMPLATE" < migrations/.baseline/seed_sqlx_migrations.sql >/dev/null
    DATABASE_URL="$(url)" sqlx migrate run --source migrations >/dev/null
}

# A template is usable when every migration of THIS checkout is applied, none
# it does not have is, and no test wrote into it. The last matters: a test
# that ran against the template itself leaves an encryption key behind, and
# every clone then fails to unwrap it.
template_problem() {
    local applied files keys
    applied="$(scalar "$TEMPLATE" "SELECT version FROM _sqlx_migrations WHERE success ORDER BY version" 2>/dev/null)" \
        || { echo "its migration table cannot be read"; return 0; }
    files="$(find migrations -maxdepth 1 -name '*.sql' -exec basename {} \; | sed -E 's/^([0-9]+)_.*/\1/' | sort -n)"
    if [ -n "$(comm -13 <(printf '%s\n' "$files" | sed 's/^0*//' | sort) <(printf '%s\n' "$applied" | sort))" ]; then
        echo "it holds a migration this checkout does not have"; return 0
    fi
    keys="$(scalar "$TEMPLATE" "SELECT count(*) FROM encryption_keys" 2>/dev/null || echo unknown)"
    if [ "$keys" != 0 ]; then
        echo "a test wrote into it ($keys encryption key row(s))"; return 0
    fi
    if [ -n "$(comm -23 <(printf '%s\n' "$files" | sed 's/^0*//' | sort) <(printf '%s\n' "$applied" | sort))" ]; then
        echo behind; return 0
    fi
    echo ""
}

write_env() {
    mkdir -p "$(dirname "$ENV_FILE")"
    ( umask 077; printf 'export DATABASE_URL=%q\n' "$(url)" > "$ENV_FILE" )
    chmod 600 "$ENV_FILE"
}

cmd_up() {
    start_container
    if ! template_exists; then
        build_template
    else
        local problem
        problem="$(template_problem)"
        case "$problem" in
            "") ;;
            behind)
                command -v sqlx >/dev/null 2>&1 || fail "sqlx-cli is not installed (cargo install sqlx-cli)"
                say "▶ template is behind this checkout; applying the new migrations"
                DATABASE_URL="$(url)" sqlx migrate run --source migrations >/dev/null \
                    || { say "  that failed; rebuilding"; build_template; }
                ;;
            *)
                say "▶ template is not usable: $problem"
                build_template
                ;;
        esac
    fi
    write_env
    say "✓ test database ready: template '$TEMPLATE' in '$NAME' ($(scalar "$TEMPLATE" "SELECT count(*) FROM _sqlx_migrations WHERE success") migrations)"
    say "  environment file: $ENV_FILE"
}

cmd_status() {
    local s
    s="$(state)"
    say "container  $NAME: $s"
    [ "$s" = running ] || { say "template   unknown (container is not running)"; return 0; }
    if template_exists; then
        local problem
        problem="$(template_problem)"
        say "template   $TEMPLATE: $(scalar "$TEMPLATE" "SELECT count(*) FROM _sqlx_migrations WHERE success") migrations applied${problem:+ — $problem}"
    else
        say "template   $TEMPLATE: absent"
    fi
    say "clones     $(scalar postgres "SELECT count(*) FROM pg_database WHERE datname ~ '^test_[0-9a-f]{32}$'") left by tests that did not finish"
    say "env file   $([ -f "$ENV_FILE" ] && echo "$ENV_FILE" || echo "absent ($ENV_FILE)")"
}

case "${1:-up}" in
    up)      cmd_up ;;
    status)  cmd_status ;;
    rebuild) start_container; drop_clones; build_template; write_env; say "✓ rebuilt" ;;
    stop)
        [ "$(state)" = running ] && docker stop "$NAME" >/dev/null
        say "✓ stopped (the template is kept; '$0 up' starts it again)" ;;
    run)
        shift
        [ "$#" -gt 0 ] || fail "run needs a command, e.g. run cargo test -p controller --test <name>"
        cmd_up
        DATABASE_URL="$(url)" exec "$@" ;;
    *) fail "unknown command '$1' (up | run <cmd…> | status | rebuild | stop)" ;;
esac
