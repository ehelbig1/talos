# shellcheck shell=bash
# The backup drill's result as a Talos ops alert.
#
# Why this exists (2026-10-05): scripts/drills/backup-restore.sh ran weekly
# under launchd and failed every week from 2026-09-14, and nobody was told.
# Its result reached exactly one place, a Prometheus textfile metric, and the
# alert built on that metric goes to an Alertmanager that delivers nowhere.
# A Talos ops alert is a channel the operator already reads (and a workflow
# can forward it to a phone), so the drill now raises one on failure and
# resolves it on success, through the MCP tool `report_ops_alert`.
#
# BEST EFFORT, BY CONSTRUCTION. The report runs AFTER the metric is written
# and can change neither the metric nor the drill's exit status: every
# command below is guarded, the function always returns 0, and a failed
# report is one WARN line naming the HTTP status — never a response body,
# never the key.
#
# Sourced by scripts/drills/backup-restore.sh; tested by
# scripts/tests/drill-ops-alert-test.sh (fake `curl` on PATH, runs anywhere).
#
# Configuration (environment):
#   TALOS_DRILL_REPORT_KEY_FILE  a file holding an MCP agent token. Set →
#                                POST ${TALOS_URL}/mcp with
#                                `Authorization: Bearer <token>`, the header
#                                passed to curl from a 0600 temp file so the
#                                token is never on a command line `ps` shows.
#                                Unset → POST ${TALOS_URL}/mcp/local, the
#                                unauthenticated dev-only endpoint (disabled
#                                in production).
#   TALOS_URL                    controller base URL (default
#                                http://localhost:8000).
#   TALOS_DRILL_REPORT           `off` disables the report entirely.
#   TALOS_DRILL_REPORT_TIMEOUT_SECS  curl's whole-request bound (default 10).

# drill_step_label <step-token> — the human name of a drill step, from a
# CLOSED table: the alert title carries this, never a free-form log line
# (those name host paths).
drill_step_label() {
    case "$1" in
        0)  echo "pre-flight" ;;
        0b) echo "KEK from escrow" ;;
        1)  echo "select the backup artifacts" ;;
        2)  echo "build the verifiers" ;;
        3)  echo "start scratch postgres" ;;
        4)  echo "restore postgres" ;;
        5)  echo "restore vault" ;;
        6)  echo "restore neo4j" ;;
        7)  echo "verify the restored stack" ;;
        8)  echo "finish" ;;
        *)  echo "unknown step" ;;
    esac
}

# drill_json_string <text> — <text> as a JSON string literal. Newlines and
# tabs become spaces and other control bytes are dropped, so the escaping
# below only has to handle `\` and `"`. sed rather than ${var//} because
# backslashes in a parameter-expansion replacement differ across bash
# versions (macOS ships 3.2).
drill_json_string() {
    local s
    s="$(printf '%s' "$1" | tr '\n\r\t' '   ' | LC_ALL=C tr -d '\000-\037' \
        | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"
    printf '"%s"' "$s"
}

_drill_report_warn() {
    if declare -F warn >/dev/null 2>&1; then
        warn "$*"
    else
        printf '⚠ %s\n' "$*" >&2
    fi
}

_drill_report_ok() {
    if declare -F ok >/dev/null 2>&1; then
        ok "$*"
    else
        printf '✓ %s\n' "$*"
    fi
}

# drill_report_ops_alert <success|failure> <source-mode> <step-token> <reason> <drill-id>
#
# success → resolve `backup-drill|<source-mode>`; failure → raise it, titled
# with the step that failed, severity_hint high. Always returns 0.
drill_report_ops_alert() {
    local status="$1" source_mode="$2" step="$3" reason="$4" drill_id="$5"
    if [[ "${TALOS_DRILL_REPORT:-on}" == "off" ]]; then
        return 0
    fi
    local base="${TALOS_URL:-http://localhost:8000}"
    base="${base%/}"
    local dedup="backup-drill|$source_mode"

    local args
    if [[ "$status" == "success" ]]; then
        args="{\"source\":\"backup-drill\",\"dedup_key\":$(drill_json_string "$dedup"),\"status_event\":\"resolved\"}"
    else
        local label title first_reason
        label="$(drill_step_label "$step")"
        title="Backup restore drill failed (source $source_mode) at step $step/8: $label"
        # The first line only: a die message's continuation lines are advice.
        first_reason="$(printf '%s\n' "$reason" | head -1)"
        args="{\"source\":\"backup-drill\",\"dedup_key\":$(drill_json_string "$dedup")"
        args="$args,\"title\":$(drill_json_string "$title"),\"severity_hint\":\"high\""
        args="$args,\"resource\":$(drill_json_string "backup copy: $source_mode")"
        args="$args,\"external_id\":$(drill_json_string "$drill_id")"
        args="$args,\"raw\":{\"drill_id\":$(drill_json_string "$drill_id")"
        args="$args,\"source\":$(drill_json_string "$source_mode")"
        args="$args,\"step\":$(drill_json_string "$step/8 $label")"
        args="$args,\"reason\":$(drill_json_string "$first_reason")}}"
    fi
    local body="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"report_ops_alert\",\"arguments\":$args}}"

    local url endpoint hdr=""
    if [[ -n "${TALOS_DRILL_REPORT_KEY_FILE:-}" ]]; then
        endpoint="/mcp"
        url="$base/mcp"
        local key=""
        if [[ -r "$TALOS_DRILL_REPORT_KEY_FILE" ]]; then
            # Trim the ends only: an interior space is a malformed token,
            # refused below, not two halves to glue together.
            key="$(head -1 "$TALOS_DRILL_REPORT_KEY_FILE" 2>/dev/null | tr -d '\r' \
                | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' || true)"
        fi
        # A token is one header-safe word. Anything else (empty, unreadable,
        # a stray newline-joined second value) would be a broken or injected
        # header; refuse it rather than send it.
        if [[ -z "$key" || ! "$key" =~ ^[A-Za-z0-9._~+/=-]+$ ]]; then
            _drill_report_warn "ops-alert report NOT sent: TALOS_DRILL_REPORT_KEY_FILE is unreadable or holds no usable token"
            return 0
        fi
        hdr="$(mktemp "${TMPDIR:-/tmp}/talos-drill-report.XXXXXX" 2>/dev/null || true)"
        if [[ -z "$hdr" ]]; then
            _drill_report_warn "ops-alert report NOT sent: could not create a private header file"
            return 0
        fi
        chmod 600 "$hdr" 2>/dev/null || true
        # printf is a builtin: the token never appears in a process's argv.
        printf 'Authorization: Bearer %s\n' "$key" > "$hdr" 2>/dev/null || true
        key=""
    else
        endpoint="/mcp/local"
        url="$base/mcp/local"
    fi

    local resp code rc
    resp="$(mktemp "${TMPDIR:-/tmp}/talos-drill-reply.XXXXXX" 2>/dev/null || true)"
    if [[ -z "$resp" ]]; then
        [[ -n "$hdr" ]] && rm -f "$hdr"
        _drill_report_warn "ops-alert report NOT sent: could not create a temp file"
        return 0
    fi
    local -a hdr_args=()
    [[ -n "$hdr" ]] && hdr_args=(-H "@$hdr")
    # `${arr[@]+…}`: bash 3.2 calls an empty array unbound under `set -u`.
    code="$(printf '%s' "$body" | curl -sS -m "${TALOS_DRILL_REPORT_TIMEOUT_SECS:-10}" \
        -X POST -H 'Content-Type: application/json' ${hdr_args[@]+"${hdr_args[@]}"} \
        --data-binary @- -o "$resp" -w '%{http_code}' "$url" 2>/dev/null)" && rc=0 || rc=$?
    [[ -n "$hdr" ]] && rm -f "$hdr"
    [[ "$code" =~ ^[0-9]{3}$ ]] || code="000"

    if [[ "$code" != 2?? ]]; then
        if (( rc != 0 )); then
            _drill_report_warn "ops-alert report NOT delivered to $endpoint (HTTP $code, curl exit $rc)"
        else
            _drill_report_warn "ops-alert report NOT delivered to $endpoint (HTTP $code)"
        fi
    elif grep -q '"error":{' "$resp" 2>/dev/null || grep -q '"isError":true' "$resp" 2>/dev/null; then
        _drill_report_warn "ops-alert report REFUSED by $endpoint (HTTP $code, tool error)"
    else
        # A word from a CLOSED set, read out of the reply — never the reply.
        local outcome
        outcome="$(grep -oE 'result\\?"[[:space:]]*:[[:space:]]*\\?"(created|bumped|reopened|resolved|no_active_alert)' "$resp" 2>/dev/null \
            | head -1 | grep -oE '(created|bumped|reopened|resolved|no_active_alert)$' || true)"
        _drill_report_ok "ops alert reported to $endpoint: ${outcome:-accepted} (backup-drill|$source_mode)"
    fi
    rm -f "$resp"
    return 0
}
