#!/usr/bin/env bash
# The ONE list of environment variables a LaunchAgent may carry for an
# off-host (Backblaze B2 / S3) job, and the one statement of what it may not.
#
# Sourced by BOTH schedulers: scripts/offhost-backup/schedule.sh (which
# UPLOADS) and scripts/drills/schedule.sh (which, under `--source b2`,
# DOWNLOADS and restores). They address the same bucket with the same
# credentials, so two lists would be two answers to one question — and the
# 2026-09-24 defect was exactly that shape one level down: the drill's
# scheduler propagated no off-host variables at all, so a `b2` schedule
# rendered a job that died weekly at "no age passphrase source configured"
# and the leg that answers "does anything survive losing this disk" had
# never run once.
#
# # What is NOT here, and why it never will be
#
# AWS_SECRET_ACCESS_KEY. A plist is a world-readable file in the operator's
# home directory; a job that carried the bucket secret there would put the
# key next to the path of the ciphertext it opens — precisely the
# arrangement the containment rules exist to prevent. The secret must reach
# the job another way: an `~/.aws/credentials` profile (chmod 600, outside
# any checkout and outside $BACKUP_DIR) or a wrapper that exports it, which
# is why AWS_PROFILE and AWS_SHARED_CREDENTIALS_FILE ARE here — they select
# a credential without being one.
#
# AWS_ACCESS_KEY_ID is here deliberately: talos-offhost-backup/src/aws.rs
# states the asymmetry it relies on — "the key id may be logged; the secret
# may not" — so the id is configuration and the secret is not.
#
# The age passphrase follows the same rule as the KEK escrow: the COMMAND or
# the PATH, never the passphrase. There is deliberately no
# TALOS_OFFHOST_AGE_PASSPHRASE variable for the same reason there is no
# TALOS_DRILL_ESCROW_KEY one.

# Names only — every value is read from the CALLER's environment, so nothing
# here can hold a secret even transiently.
OFFHOST_PLIST_ENV_VARS=(
    TALOS_OFFHOST_B2_BUCKET
    TALOS_OFFHOST_B2_ENDPOINT
    TALOS_OFFHOST_B2_REGION
    TALOS_OFFHOST_AGE_PASSPHRASE_CMD
    TALOS_OFFHOST_AGE_PASSPHRASE_FILE
    TALOS_OFFHOST_ESCROW_TIMEOUT_SECS
    TALOS_BACKUP_DIR
    TALOS_TEXTFILE_DIR
    AWS_ACCESS_KEY_ID
    AWS_PROFILE
    AWS_SHARED_CREDENTIALS_FILE
)

# Emit the `<key>…</key><string>…</string>` lines for every variable above
# that is SET AND NON-EMPTY in this shell. Requires the caller to provide
# `xml_escape` (both schedulers already do).
render_offhost_plist_env() {
    local v
    for v in "${OFFHOST_PLIST_ENV_VARS[@]}"; do
        if [[ -n "${!v:-}" ]]; then
            printf '    <key>%s</key><string>%s</string>\n' "$v" "$(xml_escape "${!v}")"
        fi
    done
}
