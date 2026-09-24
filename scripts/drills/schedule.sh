#!/usr/bin/env bash
#
# Schedule the backup→restore drill so its answer stays current.
#
# WHY A SCHEDULER AND NOT A COMPOSE SIDECAR. The drill creates and destroys
# containers, so a containerised version of it needs the docker socket — which
# is root on the host. Mounting /var/run/docker.sock into a long-lived,
# restart:unless-stopped sidecar to gain a weekly cron tick is a bad trade, so
# the drill stays a host-side job and this installs a host-side timer.
#
# CADENCE. Weekly. TalosBackupRestoreDrillFailed fires when the last green run
# is 14 days old, so a weekly cadence tolerates exactly ONE missed run — enough
# that one skipped week (a closed laptop, a stack that was down) does not page,
# few enough that the alert still means something. The margin on that one miss
# is thin: the 14-day threshold falls on the recovery run's own scheduled slot,
# and only the alert's `for: 1h` covers the gap, so a run launchd defers by more
# than an hour (a laptop woken late) pages regardless. Do NOT stretch
# this to fortnightly: a cadence equal to the alert window guarantees the
# alert fires on ordinary jitter, and an alert that fires on healthy operation
# is the failure mode this whole arc exists to remove.
#
# LAUNCHD SPECIFICS. StartCalendarInterval fires missed jobs once the machine
# wakes, which is what makes this workable on a laptop — the same wake-aware
# property the backup sidecars get from their hourly-tick loop.
#
# On Linux use the systemd timer in README.md instead; this script is macOS
# only and says so rather than pretending to be portable.
#
# Usage:
#   scripts/drills/schedule.sh install     # render + install + load
#   scripts/drills/schedule.sh render      # print the plist install would write
#   scripts/drills/schedule.sh uninstall
#   scripts/drills/schedule.sh status
#
set -euo pipefail

LABEL="com.talos.backup-drill"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_DIR="$HOME/.talos/logs"
LOG="$LOG_DIR/backup-drill.log"

# The commands the scheduled drill runs before it can do anything else: it
# `cargo build`s its verifiers and drives the scratch stack with `docker`. Their
# directories go on the job's PATH as THIS shell resolves them (see
# scripts/lib/launchd-path.sh for the 2026-09-14 failure that motivated it).
# The escrow command's own tools (`op`, `security`) are the operator's to
# resolve; if one is missing the run fails loudly at step 0b, not silently.
# shellcheck source=../lib/launchd-path.sh
source "$REPO_ROOT/scripts/lib/launchd-path.sh"
# shellcheck source=../lib/offhost-env.sh
source "$REPO_ROOT/scripts/lib/offhost-env.sh"
# Sunday 03:00 local. Sunday because a failure then leaves a full working week
# to fix it before the 14-day threshold.
WEEKDAY=0
HOUR=3
MINUTE=0

# WHICH COPY THE UNATTENDED RUN RESTORES, stated rather than defaulted.
# Until 2026-08-26 ProgramArguments passed NO arguments, so every scheduled
# run silently took backup-restore.sh's `artifact` default — the dump on the
# very disk the backups insure against — and the metric it published could not
# say so. The value is now written into the plist explicitly: `launchctl` and
# `plutil -p` show what is actually being certified, and `status` below reads
# it back out of the installed plist rather than assuming.
#
# `artifact` remains the DEFAULT because it is the only mode that runs with no
# operator secrets. `TALOS_DRILL_SCHEDULE_SOURCE=b2 make drill-schedule` is
# the upgrade path once the off-host chain and its age passphrase are wired:
# that is the strictly harder question, and scheduling it is what turns
# "the off-host copy is uncertified" into a continuously answered one.
DRILL_SOURCE="${TALOS_DRILL_SCHEDULE_SOURCE:-artifact}"
case "$DRILL_SOURCE" in
    artifact|b2|live) ;;
    *) printf 'TALOS_DRILL_SCHEDULE_SOURCE must be artifact, b2 or live, got %s\n' \
        "$DRILL_SOURCE" >&2; exit 1 ;;
esac

# The tool list is DERIVED from the source, not fixed, because `b2` runs one
# command the other two never do. `--source b2` fetches through the `aws` CLI
# (talos-offhost-backup/src/aws.rs: B2 is addressed as S3, and credentials
# reach `aws` through the ENVIRONMENT so they are structurally absent from
# argv). A scheduled b2 drill whose PATH cannot resolve `aws` fails exactly
# the way the 2026-09-14 defect failed `cargo` — at `env: aws: No such file
# or directory`, weekly, with `status` still reporting "✓ scheduled".
# Listing it unconditionally would be the other error: it would refuse to
# schedule an `artifact` drill on a host that has no reason to own `aws`.
SCHEDULED_TOOLS=(cargo docker)
[[ "$DRILL_SOURCE" == "b2" ]] && SCHEDULED_TOOLS+=(aws)

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }

[[ "$(uname -s)" == "Darwin" ]] || {
    red "This installs a launchd agent and only works on macOS."
    yellow "On Linux use the systemd timer in scripts/drills/README.md § Scheduling."
    exit 1
}

# XML-escape a value destined for plist element content. Only `&` and `<`
# are structurally significant there; `"` (which `op read "op://…"` contains)
# is not, but is escaped anyway so the rendered plist survives being pasted
# into an attribute by someone editing it later.
xml_escape() {
    printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

# Escrow passthrough. Since 2026-08-13 the drill REFUSES to source the KEK
# from the live stack, so an unattended run needs an escrow source in its own
# environment — launchd gives it neither your shell's env nor a TTY for the
# interactive prompt.
#
# What is propagated is the COMMAND or the PATH, never the key. A plist is
# `chmod 600` but it is still a plaintext file on the same disk as the
# ciphertext, which is the arrangement the escrow rule exists to prevent; a
# `TALOS_DRILL_ESCROW_KEY` variable is therefore deliberately not supported.
#
# The command must run NON-INTERACTIVELY at 03:00 on a Sunday. `op read` with
# a service-account token qualifies; `op read` that pops a Touch ID prompt does
# not.
#
# What happens to a prompting helper, stated as the mechanism rather than as a
# vague reassurance: the drill runs it under a WATCHDOG bounded by
# TALOS_DRILL_ESCROW_TIMEOUT_SECS (default 120), kills the whole process tree
# when it expires, and fails the run with a message naming the knob. This text
# used to say it would "hang until the drill's own step ordering gives up",
# which was simply false — `grep -n timeout scripts/drills/*.sh` found nothing,
# nothing bounded the command, and under launchd a prompt no one can answer
# waits forever. That matters more than a hung run: launchd will not start the
# next weekly job while this one is still alive, so the drill stops running
# altogether and the only signal is the 14-day staleness alert.
render_escrow_env() {
    if [[ -n "${TALOS_DRILL_ESCROW_KEY_CMD:-}" ]]; then
        printf '    <key>TALOS_DRILL_ESCROW_KEY_CMD</key><string>%s</string>\n' \
            "$(xml_escape "$TALOS_DRILL_ESCROW_KEY_CMD")"
    fi
    if [[ -n "${TALOS_DRILL_ESCROW_KEY_FILE:-}" ]]; then
        printf '    <key>TALOS_DRILL_ESCROW_KEY_FILE</key><string>%s</string>\n' \
            "$(xml_escape "$TALOS_DRILL_ESCROW_KEY_FILE")"
    fi
    if [[ -n "${TALOS_DRILL_KEK_PROVIDER:-}" ]]; then
        printf '    <key>TALOS_DRILL_KEK_PROVIDER</key><string>%s</string>\n' \
            "$(xml_escape "$TALOS_DRILL_KEK_PROVIDER")"
    fi
    # Propagated for the same reason as the escrow source itself: an operator
    # who raised the timeout because their helper is genuinely slow would
    # otherwise silently get the 120 s default in the unattended run — the one
    # place the value actually matters.
    if [[ -n "${TALOS_DRILL_ESCROW_TIMEOUT_SECS:-}" ]]; then
        printf '    <key>TALOS_DRILL_ESCROW_TIMEOUT_SECS</key><string>%s</string>\n' \
            "$(xml_escape "$TALOS_DRILL_ESCROW_TIMEOUT_SECS")"
    fi

    # ── The off-host job's environment. ───────────────────────────────
    #
    # `--source b2` is the only mode that talks to the bucket, and until
    # 2026-09-24 this function carried nothing for it: a
    # TALOS_DRILL_SCHEDULE_SOURCE=b2 install rendered a plist with no age
    # passphrase, no bucket, no endpoint and no region, so the job died
    # weekly at backup-restore.sh's "no age passphrase source configured"
    # and the leg that answers "does anything survive losing this disk" had
    # never run once. The header above already called b2 "the upgrade path
    # once the off-host chain and its age passphrase are wired" — this is
    # the wiring.
    #
    # The list has ONE home (scripts/lib/offhost-env.sh), shared with
    # scripts/offhost-backup/schedule.sh: both address the same bucket with
    # the same credentials, and that file is also where the rule lives that
    # AWS_SECRET_ACCESS_KEY is never propagated.
    #
    # Emitted whenever the variables are set, not gated on DRILL_SOURCE: the
    # escrow block above is unconditional for the same reason, and silently
    # dropping a value the operator did set is worse than carrying one the
    # run will ignore.
    render_offhost_plist_env
}

# Refuse a pair where BOTH the command and the file form are set.
#
# backup-restore.sh dies on exactly this for both pairs, and its reason is
# that resolving by precedence "would silently ignore one of them — and the
# one that loses is the FILE, the branch that carries the containment
# checks". Catching it HERE costs the operator one line at install; catching
# it at 03:00 on a Sunday costs a week. This is the one place a refusal beats
# the warn-and-install treatment the MISSING case gets: a missing secret is
# an operator act still to come, a contradictory pair is already wrong.
assert_pair_exclusive() { # <label> <cmd-value> <file-value> <cmd-name> <file-name>
    if [[ -n "$2" && -n "$3" ]]; then
        red "✗ refusing to schedule: both $4 and $5 are set."
        red "  Set exactly one. The drill refuses this pair too, so a plist carrying"
        red "  both renders a job that dies every week at step 0b ($1)."
        exit 1
    fi
}

render_plist() {
    cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$REPO_ROOT/scripts/drills/backup-restore.sh</string>
    <string>--source</string>
    <string>$DRILL_SOURCE</string>
  </array>
  <key>WorkingDirectory</key><string>$REPO_ROOT</string>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Weekday</key><integer>$WEEKDAY</integer>
    <key>Hour</key><integer>$HOUR</integer>
    <key>Minute</key><integer>$MINUTE</integer>
  </dict>
  <key>StandardOutPath</key><string>$LOG</string>
  <key>StandardErrorPath</key><string>$LOG</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>$(xml_escape "$SCHEDULED_PATH")</string>
$(render_escrow_env)  </dict>
  <key>RunAtLoad</key><false/>
</dict>
</plist>
EOF
}

# Check the INSTALLED plist's PATH against the tools the job runs. Before
# 2026-09-14 `status` printed "✓ scheduled" for a plist whose job could not
# find `cargo`; existence of the file is not a working schedule.
report_scheduled_path() {
    local plist_path missing
    plist_path="$(/usr/bin/plutil -extract EnvironmentVariables.PATH raw -o - "$PLIST" 2>/dev/null || true)"
    if [[ -z "$plist_path" ]]; then
        red "  ✗ the installed plist sets no readable PATH — re-run '$1'"
        return
    fi
    missing="$(launchd_path_missing "$plist_path" "${SCHEDULED_TOOLS[@]}" | tr '\n' ' ')"
    if [[ -n "$missing" ]]; then
        red "  ✗ the scheduled job cannot find: ${missing% } — every run fails before it starts."
        red "    Re-run '$1' from a shell where they resolve."
    else
        green "  scheduled job's PATH resolves ${SCHEDULED_TOOLS[*]}"
    fi
}

# Resolve the job's PATH or refuse. Shared by `install` and `render`.
resolve_scheduled_path() {
    assert_pair_exclusive "KEK escrow" \
        "${TALOS_DRILL_ESCROW_KEY_CMD:-}" "${TALOS_DRILL_ESCROW_KEY_FILE:-}" \
        TALOS_DRILL_ESCROW_KEY_CMD TALOS_DRILL_ESCROW_KEY_FILE
    assert_pair_exclusive "off-host age passphrase" \
        "${TALOS_OFFHOST_AGE_PASSPHRASE_CMD:-}" "${TALOS_OFFHOST_AGE_PASSPHRASE_FILE:-}" \
        TALOS_OFFHOST_AGE_PASSPHRASE_CMD TALOS_OFFHOST_AGE_PASSPHRASE_FILE
    if ! SCHEDULED_PATH="$(launchd_path_for "${SCHEDULED_TOOLS[@]}")"; then
        red "✗ refusing to schedule: the drill runs ${SCHEDULED_TOOLS[*]}, and at least one"
        red "  is not on this shell's PATH (named above). A LaunchAgent that cannot find"
        red "  its first command fails every week and says so only in the log."
        exit 1
    fi
}

case "${1:-status}" in
render)
    # The plist `install` would write, on stdout — nothing is installed or
    # loaded. Used by scripts/tests/launchd-path-test.sh and for inspection.
    resolve_scheduled_path
    render_plist
    ;;
install)
    resolve_scheduled_path
    mkdir -p "$HOME/Library/LaunchAgents" "$LOG_DIR"
    render_plist > "$PLIST"
    chmod 600 "$PLIST"
    launchctl unload "$PLIST" >/dev/null 2>&1 || true
    launchctl load "$PLIST"
    green "✓ installed $PLIST"
    green "  weekly: Sunday $(printf '%02d:%02d' "$HOUR" "$MINUTE") local, logging to $LOG"
    green "  job PATH (from where this shell finds ${SCHEDULED_TOOLS[*]}): $SCHEDULED_PATH"
    if [[ -n "${TALOS_DRILL_ESCROW_KEY_CMD:-}${TALOS_DRILL_ESCROW_KEY_FILE:-}" ]]; then
        green "  escrow source propagated into the plist (command/path only, never the key)."
        yellow "  Verify it runs NON-INTERACTIVELY. A Touch ID prompt at 03:00 has nobody to"
        yellow "  answer it: the drill's watchdog kills it after"
        yellow "  \${TALOS_DRILL_ESCROW_TIMEOUT_SECS:-120}s and the run fails."
    else
        red   "  ⚠ NO ESCROW SOURCE — this scheduled drill WILL FAIL every week."
        yellow "    The drill no longer reads the KEK from the live controller (that was the"
        yellow "    defect: it made the drill pass only while the host it insures was alive)."
        yellow "    launchd gives it no TTY, so the interactive prompt is unavailable too."
        yellow "    Re-run with the escrow source in your environment so it is propagated:"
        yellow "      TALOS_DRILL_ESCROW_KEY_CMD='op read \"op://Private/Talos KEK/password\"' \\"
        yellow "        make drill-schedule"
        yellow "    Leaving it as-is means TalosBackupRestoreDrillFailed fires permanently."
        yellow "    That is TRUE — you currently cannot prove recoverability unattended — but a"
        yellow "    permanently-red alert trains you to ignore red. Fix it or unschedule."
    fi
    # The b2 leg needs a SECOND secret, and it is worth saying separately:
    # a green `artifact` drill and a wired escrow key tell an operator
    # nothing about whether this one can run.
    if [[ "$DRILL_SOURCE" == "b2" ]]; then
        if [[ -n "${TALOS_OFFHOST_AGE_PASSPHRASE_CMD:-}${TALOS_OFFHOST_AGE_PASSPHRASE_FILE:-}" ]]; then
            green "  off-host age passphrase propagated (command/path only, never the passphrase)."
        else
            red   "  ⚠ NO OFF-HOST AGE PASSPHRASE — this b2 drill WILL FAIL every week."
            yellow "    --source b2 opens age-encrypted archives; without the passphrase it dies"
            yellow "    at '[1/8] fetching backup artifacts' and certifies nothing. Supply ONE of:"
            yellow "      TALOS_OFFHOST_AGE_PASSPHRASE_CMD='op read \"op://Private/Talos age backup/password\"' \\"
            yellow "        make drill-schedule"
            yellow "      TALOS_OFFHOST_AGE_PASSPHRASE_FILE=/Volumes/escrow/talos-age.pass make drill-schedule"
        fi
        yellow "  AWS credentials are NOT in the plist, by design: a plist carries a command or"
        yellow "  a path, never a key. The scheduled run reads them the way \`aws\` already does"
        yellow "  (~/.aws/credentials), so confirm that file is readable by your login session."
    fi
    ;;
uninstall)
    if [[ -f "$PLIST" ]]; then
        launchctl unload "$PLIST" >/dev/null 2>&1 || true
        rm -f "$PLIST"
        green "✓ removed $PLIST"
    else
        yellow "not installed ($PLIST absent)"
    fi
    ;;
status)
    if [[ -f "$PLIST" ]]; then
        green "✓ scheduled: $PLIST"
        launchctl list | grep -F "$LABEL" || yellow "  (plist present but not loaded — run 'make drill-schedule')"
        report_scheduled_path "make drill-schedule"
    else
        yellow "not scheduled. Install with: make drill-schedule"
    fi
    # The metric file is the authority on when the drill last actually
    # succeeded — the same file Prometheus scrapes, so this cannot disagree
    # with the alert.
    #
    # ONE LINE PER COPY, and the parse reads BOTH formats. The old pattern
    # here was `/^talos_backup_drill_last_success_timestamp_seconds /` — an
    # anchored, label-free prefix with a trailing space, which stops matching
    # the instant the producer writes `…_seconds{source="artifact"} 123`. It
    # would not have errored; it would have printed "no successful drill
    # recorded yet" in red on a host that had one. The legacy unlabelled line
    # is attributed to `artifact` for the same reason emit_metric adopts it
    # there: the LaunchAgent has never passed `--source`.
    if [[ -f "$PLIST" ]]; then
        # `sed -nE`, not `sed -n`: BSD sed's BASIC regex has no `\|`
        # alternation, so the obvious `\(artifact\|b2\|live\)` matches
        # NOTHING on macOS — the platform this script refuses to run on
        # anything but. It printed "the installed plist passes no --source"
        # for a plist that passed one, which is this PR's own subject
        # (a report that cannot see what it describes) committed inside the
        # PR that fixes it. Caught by rendering a plist and reading it back.
        installed_src=$(sed -nE 's/.*<string>(artifact|b2|live)<\/string>.*/\1/p' "$PLIST" | head -1)
        if [[ -n "$installed_src" ]]; then
            green "  scheduled run restores the ${installed_src} copy (--source $installed_src)"
        else
            yellow "  the installed plist passes no --source, so its runs take the"
            yellow "  'artifact' default and certify only the LOCAL dump. Re-run"
            yellow "  'make drill-schedule' to record the source explicitly."
        fi
    fi
    tf="${TALOS_DRILL_TEXTFILE_DIR:-${TALOS_TEXTFILE_DIR:-$HOME/.talos/metrics/textfile_collector}}/talos_backup_drill.prom"
    if [[ -f "$tf" ]]; then
        proven=""
        while IFS='|' read -r src ts; do
            [[ -z "$src" || -z "$ts" || "$ts" == "0" ]] && continue
            proven="$proven $src"
            green "  last SUCCESSFUL drill of the $src copy: $(date -r "$ts" '+%F %T %Z')"
        done < <(awk '
            /^talos_backup_drill_last_success_timestamp_seconds\{source="[a-z0-9]+"\} / {
                s = $1; sub(/.*source="/, "", s); sub(/".*/, "", s); print s "|" $2; next }
            /^talos_backup_drill_last_success_timestamp_seconds [0-9]/ { print "artifact|" $2 }
        ' "$tf")
        [[ -z "$proven" ]] && red "  no successful drill recorded yet"
        # NAME THE COPY THAT HAS NEVER BEEN PROVEN. A green artifact drill is
        # the easy question — it restores a file from the disk whose loss the
        # backups insure against. The absence of a b2 line IS the finding, and
        # an absence is invisible unless something says it out loud.
        case "$proven" in
            *b2*) ;;
            *)  yellow "  the OFF-HOST copy has never been restored on this host."
                yellow "    Nothing here certifies that losing this disk is survivable."
                yellow "    'make drill ARGS=\"--source b2\"' answers that; it needs the"
                yellow "    escrowed age passphrase and the bucket config, see"
                yellow "    docs/offhost-backup.md." ;;
        esac
    else
        red "  no drill metric at $tf — the drill has never emitted one"
    fi
    ;;
*)
    red "usage: $0 {install|uninstall|status}"; exit 1 ;;
esac
