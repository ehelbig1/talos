#!/usr/bin/env bash
#
# Push the newest local backup artifacts off this host, encrypted (Tier 2).
#
# WHAT THIS SOLVES. Tier 1 (2026-08-13) escrowed the master KEK, so the
# restore drill's claim became "these artifacts + the escrowed KEK ⇒ readable
# data". The half that stayed open is WHERE THE ARTIFACTS LIVE: one laptop
# SSD, replicated nowhere. `tmutil destinationinfo` answers "No destinations
# configured". Losing that disk loses 22,360 module payloads, 7,122 workflow
# outputs and — the only genuinely irreplaceable slice — 1,544 ml_examples
# plus 384 ml_disagreements, a month of human labelling. Code re-clones;
# labels do not.
#
# WHY THIS IS A SEPARATE HOST-SIDE JOB AND NOT PART OF THE BACKUP SIDECAR.
# Two reasons, both deliberate:
#
#   1. THE UPLOAD MUST NEVER FAIL THE DUMP. A dump taken while the network is
#      down is still worth having. Running the push in a different process on
#      a different schedule makes that structural rather than a promise: the
#      `postgres-backup` sidecar has no code path that can reach this.
#   2. The sidecar image (pgvector) has no `age` and no `aws`, and the
#      credential belongs to the host operator, not to a container that also
#      holds a live Postgres password.
#
# AND THAT IS EXACTLY WHY IT NEEDS A COUNTER. Decoupling makes a persistent
# failure INVISIBLE — nothing goes red, the dump keeps succeeding, and the
# off-host copy quietly stops. So every run writes
# talos_offhost_backup_{uploads,failures}_total and
# talos_offhost_backup_last_success_timestamp_seconds into the node_exporter
# textfile directory, and TalosOffhostBackupUploadFailing /
# TalosOffhostBackupStale fire on them. A silently-failing upload is worse
# than no upload, because it manufactures confidence in the one thing you
# would reach for after losing the disk.
#
# Usage:
#   scripts/offhost-backup/upload.sh                # newest of each kind
#   scripts/offhost-backup/upload.sh --backfill     # one-time: whole history
#   scripts/offhost-backup/upload.sh plan --offline # what would be sent
#   scripts/offhost-backup/upload.sh probe-append-only
#
# See docs/offhost-backup.md for the operator prerequisites (bucket,
# application key, lifecycle rule, age passphrase escrow).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"

red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*" >&2; }

# ── Checkout roots for the passphrase containment check ───────────────
#
# The `age` passphrase is a SECOND fatal secret: lose it and every archive in
# the bucket is unreadable forever, exactly as if the KEK had been lost. So it
# gets #639's containment — it must not resolve inside a checkout or inside
# $BACKUP_DIR, symlinks resolved first.
#
# BOTH roots, not one. `${BASH_SOURCE[0]}/../..` resolves to the WORKTREE
# root, whose subtree does NOT contain the main clone — running the worktree
# copy therefore ACCEPTED a key file sitting in the main checkout, which in
# this repo's layout is a PARENT of the worktree. `git rev-parse
# --git-common-dir` names the shared `.git`, whose parent is the main working
# tree.
roots="$REPO_ROOT"
common="$(cd "$SCRIPT_DIR" && git rev-parse --git-common-dir 2>/dev/null || true)"
if [[ -n "$common" ]]; then
    main_root="$( (cd "$SCRIPT_DIR" && cd "$common/.." && pwd -P) 2>/dev/null || true)"
    [[ -n "$main_root" && "$main_root" != "$REPO_ROOT" ]] && roots="$roots:$main_root"
fi
export TALOS_OFFHOST_CHECKOUT_ROOTS="$roots"

# ── Resolve the binary ────────────────────────────────────────────────
#
# Built, not `cargo run`: `cargo run` with DATABASE_URL exported changes the
# sqlx macro fingerprint and rebuilds a large part of the workspace, which is
# how the restore drill spent 17 minutes compiling in step 6 (2026-08-03).
# `env -u DATABASE_URL` for the same reason.
BIN="${TALOS_OFFHOST_BIN:-}"
if [[ -z "$BIN" ]]; then
    cd "$REPO_ROOT"
    if ! env -u DATABASE_URL cargo build --quiet -p talos-offhost-backup \
            --bin talos-offhost-backup; then
        red "✗ could not build talos-offhost-backup"
        yellow "  → the off-host copy does NOT advance while this is broken, and the"
        yellow "    staleness alert (TalosOffhostBackupStale) is what will notice."
        exit 1
    fi
    TARGET_DIR="$(env -u DATABASE_URL cargo metadata --no-deps --format-version 1 \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
    BIN="$TARGET_DIR/debug/talos-offhost-backup"
fi
[[ -x "$BIN" ]] || { red "✗ binary not executable: $BIN"; exit 1; }

# ── Dispatch ──────────────────────────────────────────────────────────
# Bare flags (`--backfill`) mean `upload`; an explicit subcommand is passed
# straight through. Deliberately NOT a silent default of "do nothing useful":
# a scheduled run with no arguments must actually upload.
if [[ $# -eq 0 ]]; then
    set -- upload
elif [[ "$1" == --* ]]; then
    set -- upload "$@"
fi

exec "$BIN" "$@"
