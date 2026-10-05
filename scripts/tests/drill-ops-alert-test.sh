#!/usr/bin/env bash
# Tests for scripts/lib/drill-ops-alert.sh and its use by
# scripts/drills/backup-restore.sh.
#
# The drill reports its result as a Talos ops alert through the MCP tool
# `report_ops_alert`, after the textfile metric, and the report must never
# change the drill's metric or exit status. A fake `curl` on PATH records
# each call (argv, body, header files, URL) and answers from the
# environment: delivered, endpoint down, HTTP 500, or a tool error. Two
# halves:
#   1. the reporter alone: success → resolve; failure → raise naming the
#      step; key file → /mcp with the header from a file and the key in no
#      argv; every failure mode → one WARN line, no body, return 0.
#   2. the REAL drill, made to fail at its first pre-flight check by a fake
#      `docker` whose daemon is "down": it raises the alert naming the step,
#      and with the report endpoint down it still exits 1 with the same
#      failure metric.
# No daemon, controller or network is touched, so this runs anywhere (CI:
# quality.yml `audit` job).
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
        echo "✗ drill-ops-alert test stopped before its last check (status $st)" >&2
        exit 1
    fi
    exit "$st"
}
trap on_exit EXIT

mkdir -p "$T/bin" "$T/home" "$T/textfile" "$T/tmp"

# ── The fakes ───────────────────────────────────────────────────────────
cat > "$T/bin/curl" <<'SHIM'
#!/usr/bin/env bash
printf 'curl %s\n' "$*" >> "$SHIM_LOG"
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -H)
      case "$2" in
        @*) f="${2#@}"
            printf '%s\n' "$f" >> "$SHIM_HDRFILES"
            printf 'mode:%s\n' "$(ls -l "$f" | cut -c1-10)" >> "$SHIM_HDRFILES"
            cat "$f" >> "$SHIM_HEADERS" ;;
        *)  printf '%s\n' "$2" >> "$SHIM_HEADERS" ;;
      esac
      shift 2 ;;
    -m|-X|-w|--data-binary) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
cat > "$SHIM_BODY"
printf '%s\n' "$url" >> "$SHIM_URLS"
case "${SHIM_CURL:-ok}" in
  down)      printf '000'; exit 7 ;;
  http500)   printf 'BODY-MUST-NOT-BE-LOGGED' > "$out"; printf '500' ;;
  toolerror) printf '{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":"BODY-MUST-NOT-BE-LOGGED"}]}}' > "$out"; printf '200' ;;
  ok)        printf '{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\\"result\\":\\"%s\\",\\"alert_id\\":\\"BODY-MUST-NOT-BE-LOGGED\\"}"}]}}' "${SHIM_RESULT:-created}" > "$out"; printf '200' ;;
esac
SHIM

# The drill's first pre-flight check is `docker info`; a daemon that is down
# fails it, so the real drill dies at step 0 without staging anything.
cat > "$T/bin/docker" <<'SHIM'
#!/usr/bin/env bash
printf 'docker %s\n' "$*" >> "$SHIM_LOG"
exit 1
SHIM
chmod +x "$T/bin/curl" "$T/bin/docker"

export SHIM_LOG="$T/shim.log" SHIM_BODY="$T/body.json" SHIM_HEADERS="$T/headers" \
       SHIM_HDRFILES="$T/hdrfiles" SHIM_URLS="$T/urls" TMPDIR="$T/tmp"
reset() { rm -f "$SHIM_LOG" "$SHIM_BODY" "$SHIM_HEADERS" "$SHIM_HDRFILES" "$SHIM_URLS"; touch "$SHIM_LOG" "$SHIM_HEADERS" "$SHIM_HDRFILES" "$SHIM_URLS"; }
json_get() { # json_get <file> <python expression over `d`>
    python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print($2)" "$1" 2>/dev/null || echo "<invalid json>"
}

# The reporter alone, in a subshell with the caller's strict options, as the
# drill runs it. Prints the reporter's output and its status.
report() { # report <env assignments…> -- <args…>
    local -a envs=()
    while [ "$1" != "--" ]; do envs+=("$1"); shift; done
    shift
    # shellcheck disable=SC2016  # expanded by the inner shell, on purpose
    env ${envs[@]+"${envs[@]}"} PATH="$T/bin:/usr/bin:/bin" bash -euo pipefail -c '
        source "$1"; shift
        drill_report_ops_alert "$@"; echo "status=$?"' _ "$REPO/scripts/lib/drill-ops-alert.sh" "$@" 2>&1
}

echo "── the reporter"

reset
out="$(SHIM_RESULT=resolved report -- success artifact 8 "" drill-20261005T030000Z)"
check "success: returns 0"                      yes "$(has "$out" "status=0")"
check "success: POSTs to /mcp/local"            "http://localhost:8000/mcp/local" "$(cat "$SHIM_URLS")"
check "success: tools/call report_ops_alert"    "tools/call report_ops_alert" "$(json_get "$SHIM_BODY" "d['method']+' '+d['params']['name']")"
check "success: resolves the drill's key"       "backup-drill|artifact resolved" "$(json_get "$SHIM_BODY" "d['params']['arguments']['dedup_key']+' '+d['params']['arguments']['status_event']")"
check "success: no title on a resolve"          False "$(json_get "$SHIM_BODY" "'title' in d['params']['arguments']")"
check "success: no Authorization without a key" no "$(has "$(cat "$SHIM_HEADERS")" "Authorization")"
check "success: says what happened"             yes "$(has "$out" "ops alert reported to /mcp/local: resolved")"
check "success: never prints the reply"         no "$(has "$out" "BODY-MUST-NOT-BE-LOGGED")"

reset
out="$(SHIM_RESULT=created report -- failure b2 4 'pg_restore failed: "quoted" \back\slash
second line of advice' drill-20261005T030000Z)"
args_py="d['params']['arguments']"
check "failure: returns 0"                      yes "$(has "$out" "status=0")"
check "failure: raises the drill's key"         "backup-drill|b2" "$(json_get "$SHIM_BODY" "${args_py}['dedup_key']")"
check "failure: title names the failed step"    "Backup restore drill failed (source b2) at step 4/8: restore postgres" "$(json_get "$SHIM_BODY" "${args_py}['title']")"
check "failure: severity_hint high"             high "$(json_get "$SHIM_BODY" "${args_py}['severity_hint']")"
check "failure: no status_event"                False "$(json_get "$SHIM_BODY" "'status_event' in $args_py")"
check "failure: reason escaped, first line only" 'pg_restore failed: "quoted" \back\slash' "$(json_get "$SHIM_BODY" "${args_py}['raw']['reason']")"
check "failure: step in raw"                    "4/8 restore postgres" "$(json_get "$SHIM_BODY" "${args_py}['raw']['step']")"
check "failure: says what happened"             yes "$(has "$out" "reported to /mcp/local: created")"

reset
printf 'tok_example_0123456789abcdef\n' > "$T/key"
chmod 600 "$T/key"
out="$(report TALOS_DRILL_REPORT_KEY_FILE="$T/key" TALOS_URL="https://talos.example.test/" -- failure artifact 0b "no escrow" drill-x)"
check "key file: POSTs to /mcp"                 "https://talos.example.test/mcp" "$(cat "$SHIM_URLS")"
check "key file: Bearer header delivered"       yes "$(has "$(cat "$SHIM_HEADERS")" "Authorization: Bearer tok_example_0123456789abcdef")"
check "key file: header came from a file"       yes "$(has "$(cat "$SHIM_HDRFILES")" "$T/tmp/talos-drill-report.")"
check "key file: that file was private"         yes "$(has "$(cat "$SHIM_HDRFILES")" "mode:-rw-------")"
check "key file: the key is in no argv"         no "$(has "$(cat "$SHIM_LOG")" "tok_example_0123456789abcdef")"
check "key file: the header file is removed"    "" "$(ls "$T/tmp")"
check "key file: title names step 0b"           "Backup restore drill failed (source artifact) at step 0b/8: KEK from escrow" "$(json_get "$SHIM_BODY" "${args_py}['title']")"
check "key file: never prints the key"          no "$(has "$out" "tok_example")"

reset
printf 'two words\n' > "$T/badkey"
out="$(report TALOS_DRILL_REPORT_KEY_FILE="$T/badkey" -- failure artifact 3 "x" drill-x)"
check "unusable key: not sent"                  "" "$(cat "$SHIM_URLS")"
check "unusable key: one WARN"                  1 "$(printf '%s\n' "$out" | grep -c 'NOT sent')"
check "unusable key: returns 0"                 yes "$(has "$out" "status=0")"
reset
out="$(report TALOS_DRILL_REPORT_KEY_FILE="$T/missing" -- failure artifact 3 "x" drill-x)"
check "missing key file: not sent"              "" "$(cat "$SHIM_URLS")"

for mode in down http500 toolerror; do
    reset
    out="$(SHIM_CURL=$mode report -- failure artifact 5 "vault unseal failed" drill-x)"
    case "$mode" in
        down)      want="NOT delivered to /mcp/local (HTTP 000, curl exit 7)" ;;
        http500)   want="NOT delivered to /mcp/local (HTTP 500)" ;;
        toolerror) want="REFUSED by /mcp/local (HTTP 200, tool error)" ;;
    esac
    check "$mode: one WARN line naming the status" 1 "$(printf '%s\n' "$out" | grep -cF "$want")"
    check "$mode: no reply body printed"           no "$(has "$out" "BODY-MUST-NOT-BE-LOGGED")"
    check "$mode: returns 0"                       yes "$(has "$out" "status=0")"
    check "$mode: no temp file left"               "" "$(ls "$T/tmp")"
done

reset
out="$(report TALOS_DRILL_REPORT=off -- failure artifact 1 "x" drill-x)"
check "TALOS_DRILL_REPORT=off: no call"         "" "$(cat "$SHIM_URLS")"

echo "── the drill"

# run_drill <curl mode> — the real drill, failing at `docker info`.
run_drill() {
    reset
    rm -f "$T/textfile"/*.prom
    local st=0
    DRILL_OUT="$(env -i HOME="$T/home" TMPDIR="$T/tmp" PATH="$T/bin:/usr/bin:/bin" \
        SHIM_LOG="$SHIM_LOG" SHIM_BODY="$SHIM_BODY" SHIM_HEADERS="$SHIM_HEADERS" \
        SHIM_HDRFILES="$SHIM_HDRFILES" SHIM_URLS="$SHIM_URLS" SHIM_CURL="$1" \
        TALOS_DRILL_TEXTFILE_DIR="$T/textfile" \
        bash "$REPO/scripts/drills/backup-restore.sh" --source artifact 2>&1)" || st=$?
    DRILL_STATUS=$st
    DRILL_METRIC="$(grep '^talos_backup_drill_last_status' "$T/textfile/talos_backup_drill.prom" 2>/dev/null || true)"
}

run_drill ok
check "drill fails: exit 1"                     1 "$DRILL_STATUS"
check "drill fails: failure metric written"     'talos_backup_drill_last_status{source="artifact"} 0' "$DRILL_METRIC"
check "drill fails: one report call"            1 "$(grep -c . "$SHIM_URLS")"
check "drill fails: raises backup-drill|artifact" "backup-drill|artifact" "$(json_get "$SHIM_BODY" "${args_py}['dedup_key']")"
check "drill fails: title names the step"       "Backup restore drill failed (source artifact) at step 0/8: pre-flight" "$(json_get "$SHIM_BODY" "${args_py}['title']")"
check "drill fails: reason is the die message"  "docker daemon not reachable" "$(json_get "$SHIM_BODY" "${args_py}['raw']['reason']")"
check "drill fails: metric before report"       yes "$(printf '%s\n' "$DRILL_OUT" | awk '/emitted metric/{m=NR} /ops alert reported/{r=NR} END{print (m && r && m<r) ? "yes" : "no"}')"
st_ok=$DRILL_STATUS; metric_ok=$DRILL_METRIC

run_drill down
check "report endpoint down: exit status unchanged" "$st_ok" "$DRILL_STATUS"
check "report endpoint down: metric unchanged"  "$metric_ok" "$DRILL_METRIC"
check "report endpoint down: one WARN line"     1 "$(printf '%s\n' "$DRILL_OUT" | grep -c 'NOT delivered to /mcp/local (HTTP 000')"

run_drill http500
check "report HTTP 500: exit status unchanged"  "$st_ok" "$DRILL_STATUS"
check "report HTTP 500: metric unchanged"       "$metric_ok" "$DRILL_METRIC"

completed=1
if [ "$fails" -gt 0 ]; then
    echo "✗ $fails check(s) failed"
    exit 1
fi
echo "✓ drill-ops-alert: all checks passed"
