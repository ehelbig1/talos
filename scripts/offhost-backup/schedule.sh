#!/usr/bin/env bash
#
# Schedule the off-host backup upload (Tier 2).
#
# WHY A SCHEDULER AND NOT A COMPOSE SIDECAR. The push carries a credential
# that belongs to the host operator and an `age` passphrase whose loss is as
# total as losing the KEK. Handing both to a long-lived container that also
# holds a live Postgres password is a worse trade than a host-side timer —
# and the sidecar image has neither `age` nor `aws` in it anyway.
#
# CADENCE. DAILY, and deliberately NOT weekly like the drill. The backup
# sidecar takes a dump every 24 h; an upload that ran weekly would mean up to
# six days of dumps existing only on the disk they insure, which is most of
# the exposure this change exists to remove. 03:30 local, half an hour after
# the drill's Sunday slot so the two never contend for the same laptop wake.
#
# LAUNCHD SPECIFICS. StartCalendarInterval fires missed jobs once the machine
# wakes, which is what makes this workable on a laptop — the same wake-aware
# property the backup sidecars get from their hourly-tick loop.
#
# WHAT A SCHEDULED RUN CANNOT DO. It cannot answer a Touch ID prompt. If
# TALOS_OFFHOST_AGE_PASSPHRASE_CMD is interactive, the watchdog kills it after
# TALOS_OFFHOST_ESCROW_TIMEOUT_SECS (default 120) and the run fails — visibly,
# via talos_offhost_backup_failures_total{reason="config"}, not silently.
#
# On Linux use a systemd timer running scripts/offhost-backup/upload.sh; this
# script is macOS only and says so rather than pretending to be portable.
#
# Usage:
#   scripts/offhost-backup/schedule.sh install
#   scripts/offhost-backup/schedule.sh uninstall
#   scripts/offhost-backup/schedule.sh status

set -euo pipefail

LABEL="com.talos.offhost-backup"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
LOG_DIR="$HOME/.talos/logs"
LOG="$LOG_DIR/offhost-backup.log"
HOUR=3
MINUTE=30

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }

[[ "$(uname -s)" == "Darwin" ]] || {
    red "This installs a launchd agent and only works on macOS."
    yellow "On Linux run scripts/offhost-backup/upload.sh from a systemd timer."
    exit 1
}

xml_escape() {
    printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

# What is propagated into the plist, and what is NOT.
#
# PROPAGATED: the bucket/endpoint/region, the AWS key **ID**, the passphrase
# COMMAND or PATH, and the timeout.
#
# NEVER PROPAGATED: AWS_SECRET_ACCESS_KEY and the passphrase itself. A plist
# is chmod 600 but it is still a plaintext file on the same disk as the
# ciphertext — precisely the arrangement the containment rules exist to
# prevent. The secret must reach the job some other way; the supported shape
# is a `~/.aws/credentials` profile (chmod 600, outside the repo and outside
# $BACKUP_DIR) or a wrapper that exports it. This is stated here rather than
# quietly worked around, because a scheduler that "helpfully" copied the
# secret in would undo the whole containment argument.
render_env() {
    local v
    for v in TALOS_OFFHOST_B2_BUCKET TALOS_OFFHOST_B2_ENDPOINT TALOS_OFFHOST_B2_REGION \
             TALOS_OFFHOST_AGE_PASSPHRASE_CMD TALOS_OFFHOST_AGE_PASSPHRASE_FILE \
             TALOS_OFFHOST_ESCROW_TIMEOUT_SECS TALOS_BACKUP_DIR TALOS_TEXTFILE_DIR \
             AWS_ACCESS_KEY_ID AWS_PROFILE AWS_SHARED_CREDENTIALS_FILE; do
        if [[ -n "${!v:-}" ]]; then
            printf '    <key>%s</key><string>%s</string>\n' "$v" "$(xml_escape "${!v}")"
        fi
    done
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
    <string>$REPO_ROOT/scripts/offhost-backup/upload.sh</string>
  </array>
  <key>WorkingDirectory</key><string>$REPO_ROOT</string>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key><integer>$HOUR</integer>
    <key>Minute</key><integer>$MINUTE</integer>
  </dict>
  <key>StandardOutPath</key><string>$LOG</string>
  <key>StandardErrorPath</key><string>$LOG</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
$(render_env)  </dict>
  <key>RunAtLoad</key><false/>
</dict>
</plist>
EOF
}

case "${1:-status}" in
install)
    mkdir -p "$HOME/Library/LaunchAgents" "$LOG_DIR"
    render_plist > "$PLIST"
    chmod 600 "$PLIST"
    launchctl unload "$PLIST" >/dev/null 2>&1 || true
    launchctl load "$PLIST"
    green "✓ installed $PLIST"
    green "  daily: $(printf '%02d:%02d' "$HOUR" "$MINUTE") local, logging to $LOG"
    yellow "  NOTE: launchd runs this without your interactive shell. 'cargo' and 'aws'"
    yellow "  must be on the plist's PATH."
    if [[ -z "${TALOS_OFFHOST_B2_BUCKET:-}" ]]; then
        red   "  ⚠ NO BUCKET CONFIGURED — every run will fail with reason=\"config\"."
        yellow "    Nothing goes off-host until docs/offhost-backup.md § Operator setup is done."
    fi
    if [[ -z "${TALOS_OFFHOST_AGE_PASSPHRASE_CMD:-}${TALOS_OFFHOST_AGE_PASSPHRASE_FILE:-}" ]]; then
        red   "  ⚠ NO age PASSPHRASE SOURCE — every run will fail with reason=\"config\"."
        yellow "    Uploading the dump unencrypted is NOT offered at any flag: it carries"
        yellow "    plaintext workflow names, module source and graph_json alongside the"
        yellow "    encrypted columns, so an unencrypted push publishes all of it."
    fi
    if [[ -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
        yellow "  NOTE: AWS_SECRET_ACCESS_KEY is set in this shell and was deliberately NOT"
        yellow "  written into the plist. Put it in a chmod-600 ~/.aws/credentials profile"
        yellow "  (outside the repo and outside \$BACKUP_DIR) and set AWS_PROFILE."
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
        launchctl list | grep -F "$LABEL" || yellow "  (plist present but not loaded — run 'make offhost-schedule')"
    else
        yellow "not scheduled. Install with: make offhost-schedule"
    fi
    # The metric file is the authority — the same file Prometheus scrapes, so
    # this cannot disagree with the alert.
    tf="${TALOS_OFFHOST_TEXTFILE_DIR:-${TALOS_TEXTFILE_DIR:-$HOME/.talos/metrics/textfile_collector}}/talos_offhost_backup.prom"
    if [[ -f "$tf" ]]; then
        while read -r kind ts; do
            if [[ -n "$ts" && "$ts" != "0" ]]; then
                green "  last SUCCESSFUL $kind upload: $(date -r "$ts" '+%F %T %Z')"
            else
                red "  no successful $kind upload recorded yet"
            fi
        done < <(awk -F'[="]' '/^talos_offhost_backup_last_success_timestamp_seconds\{/{print $3, $NF}' "$tf" \
                 | sed 's/} / /')
        fails=$(awk '/^talos_offhost_backup_failures_total\{/{s+=$NF} END{print s+0}' "$tf")
        if [[ "$fails" != "0" ]]; then
            red "  $fails cumulative upload failure(s) — see $LOG"
        fi
    else
        red "  no metric at $tf — the uploader has never run"
        yellow "  NOTE: while that file is ABSENT, TalosOffhostBackupStale cannot fire"
        yellow "  (it is gated on talos_offhost_backup_enabled == 1, which only exists"
        yellow "  once the uploader has run at least once). The guard for 'never ran at"
        yellow "  all' is the restore drill's --source b2 leg, not this alert."
    fi
    ;;
*)
    red "usage: $0 {install|uninstall|status}"; exit 1 ;;
esac
