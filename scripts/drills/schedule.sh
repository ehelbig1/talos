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
#   scripts/drills/schedule.sh uninstall
#   scripts/drills/schedule.sh status
#
set -euo pipefail

LABEL="com.talos.backup-drill"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_DIR="$HOME/.talos/logs"
LOG="$LOG_DIR/backup-drill.log"
# Sunday 03:00 local. Sunday because a failure then leaves a full working week
# to fix it before the 14-day threshold.
WEEKDAY=0
HOUR=3
MINUTE=0

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }

[[ "$(uname -s)" == "Darwin" ]] || {
    red "This installs a launchd agent and only works on macOS."
    yellow "On Linux use the systemd timer in scripts/drills/README.md § Scheduling."
    exit 1
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
    <key>PATH</key><string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
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
    green "  weekly: Sunday $(printf '%02d:%02d' "$HOUR" "$MINUTE") local, logging to $LOG"
    yellow "  NOTE: launchd runs this without your interactive shell. If 'docker'"
    yellow "  or 'cargo' live somewhere unusual, add them to the plist's PATH."
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
    else
        yellow "not scheduled. Install with: make drill-schedule"
    fi
    # The metric file is the authority on when the drill last actually
    # succeeded — the same file Prometheus scrapes, so this cannot disagree
    # with the alert.
    tf="${TALOS_DRILL_TEXTFILE_DIR:-${TALOS_TEXTFILE_DIR:-$HOME/.talos/metrics/textfile_collector}}/talos_backup_drill.prom"
    if [[ -f "$tf" ]]; then
        ts=$(awk '/^talos_backup_drill_last_success_timestamp_seconds /{print $2}' "$tf" | head -1)
        if [[ -n "$ts" && "$ts" != "0" ]]; then
            green "  last SUCCESSFUL drill: $(date -r "$ts" '+%F %T %Z')"
        else
            red "  no successful drill recorded yet"
        fi
    else
        red "  no drill metric at $tf — the drill has never emitted one"
    fi
    ;;
*)
    red "usage: $0 {install|uninstall|status}"; exit 1 ;;
esac
