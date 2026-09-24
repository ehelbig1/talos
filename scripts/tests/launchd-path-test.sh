#!/usr/bin/env bash
# Tests for scripts/lib/launchd-path.sh and the two LaunchAgent schedulers that
# use it (scripts/drills/schedule.sh, scripts/offhost-backup/schedule.sh).
#
# The defect (2026-09-14): both schedulers hardcoded a PATH without
# ~/.cargo/bin — rustup's default — so the first scheduled drill failed at
# `env: cargo: No such file or directory`, and `status` still said
# "✓ scheduled". The helper half is pure bash and runs everywhere (CI:
# quality.yml `audit` job). The scheduler half renders real plists and needs
# macOS `plutil`; on Linux it SKIPS LOUDLY and the helper half still runs.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
# shellcheck source=../lib/launchd-path.sh
source "$REPO/scripts/lib/launchd-path.sh"
# shellcheck source=../lib/offhost-env.sh
source "$REPO/scripts/lib/offhost-env.sh"

fails=0
check() { # check <label> <expected> <actual>
    if [ "$2" = "$3" ]; then printf '  ok   %s\n' "$1"; else printf '  FAIL %s\n       expected: %s\n       actual:   %s\n' "$1" "$2" "$3"; fails=$((fails+1)); fi
}
contains() { case ":$1:" in *":$2:"*) echo yes ;; *) echo no ;; esac; }

T="$(mktemp -d)"
# A run that stops early must FAIL. On macOS's bash 3.2 an abort inside an
# `if` condition (e.g. `set -u` over an empty array) exits the shell with
# status 0 and skips every later check — measured: a mutation that made the
# helper accept missing tools printed three FAILs and exited 0. `completed`
# is set on the last line, so anything short of it is a failure.
completed=""
on_exit() {
    local st=$?
    rm -rf "$T"
    if [[ -z "$completed" ]]; then
        echo "✗ launchd PATH test stopped before its last check (status $st)" >&2
        exit 1
    fi
    exit "$st"
}
trap on_exit EXIT
mkdir -p "$T/rustup/bin" "$T/docker/bin" "$T/aws/bin" "$T/home"
for tool in "rustup/bin/cargo" "docker/bin/docker" "aws/bin/aws"; do
    printf '#!/bin/sh\nexit 0\n' > "$T/$tool"
    chmod +x "$T/$tool"
done
# A shell that finds the tools where a real laptop does: cargo somewhere the
# old hardcoded PATH never listed.
TOOL_PATH="$T/rustup/bin:$T/docker/bin:$T/aws/bin:/usr/bin:/bin"

echo "▶ launchd_path_for"
got="$(PATH="$TOOL_PATH" launchd_path_for cargo docker)"
check "cargo's directory is on the job PATH"   yes "$(contains "$got" "$T/rustup/bin")"
check "docker's directory is on the job PATH"  yes "$(contains "$got" "$T/docker/bin")"
check "resolved dirs come first, in order" "$T/rustup/bin:$T/docker/bin" "$(printf '%s' "$got" | cut -d: -f1-2)"
check "base PATH is kept"                      yes "$(contains "$got" /usr/local/bin)"
check "no directory appears twice"             "" "$(printf '%s' "$got" | tr ':' '\n' | sort | uniq -d)"
check "a tool in a base dir adds no duplicate" 1 "$(PATH="/usr/bin:/bin" launchd_path_for sh | tr ':' '\n' | grep -cx /bin)"
check "every requested tool resolves on the result" "" "$(launchd_path_missing "$got" cargo docker)"
if out="$(PATH="$TOOL_PATH" launchd_path_for cargo definitely-not-a-tool 2>"$T/err")"; then
    check "a missing tool is refused" refused "accepted: $out"
else
    check "a missing tool is refused" refused refused
fi
check "the refusal names the missing tool" yes "$(grep -q definitely-not-a-tool "$T/err" && echo yes || echo no)"
check "the refusal prints no PATH" "" "${out:-}"
check "no tools still yields the base PATH" "$LAUNCHD_BASE_PATH" "$(launchd_path_for)"
f() { :; }
if PATH="$TOOL_PATH" launchd_path_for f >/dev/null 2>&1; then check "a shell function is not a tool" refused accepted; else check "a shell function is not a tool" refused refused; fi

echo "▶ launchd_path_missing — the 2026-09-14 plist, reproduced"
# A tool name no system directory can hold, so the result does not depend on
# where THIS host installed its real cargo.
printf '#!/bin/sh\nexit 0\n' > "$T/rustup/bin/talos-launchd-probe-tool"
chmod +x "$T/rustup/bin/talos-launchd-probe-tool"
check "the old hardcoded PATH cannot find a tool in a rustup-style dir" talos-launchd-probe-tool \
    "$(launchd_path_missing "$LAUNCHD_BASE_PATH" talos-launchd-probe-tool)"
check "a PATH with that dir finds it" "" "$(launchd_path_missing "$T/rustup/bin:$LAUNCHD_BASE_PATH" talos-launchd-probe-tool)"

if [[ "$(uname -s)" != "Darwin" ]] || ! command -v plutil >/dev/null 2>&1; then
    echo "⊘ SKIPPED scheduler render/status checks — they need macOS plutil (the schedulers are macOS-only)"
else
    for s in drills/schedule.sh:cargo:docker offhost-backup/schedule.sh:cargo:aws; do
        script="${s%%:*}"; rest="${s#*:}"; t1="${rest%%:*}"; t2="${rest#*:}"
        echo "▶ scripts/$script"
        plist="$(HOME="$T/home" PATH="$TOOL_PATH:/usr/sbin:/sbin" bash "$REPO/scripts/$script" render 2>/dev/null)"
        check "render emits a valid plist" OK "$(printf '%s' "$plist" | plutil -lint - | sed 's/^<stdin>: //')"
        ppath="$(printf '%s' "$plist" | plutil -extract EnvironmentVariables.PATH raw -o - -)"
        check "rendered PATH resolves $t1 and $t2" "" "$(launchd_path_missing "$ppath" "$t1" "$t2")"
        if HOME="$T/home" PATH="$T/docker/bin:/usr/bin:/bin:/usr/sbin:/sbin" bash "$REPO/scripts/$script" render >/dev/null 2>&1 \
            && [ -z "$(PATH="/usr/bin:/bin:/usr/sbin:/sbin" type -P "$t1" || true)" ]; then
            check "render refuses when $t1 is not resolvable" refused accepted
        else
            check "render refuses when $t1 is not resolvable" refused refused
        fi
        # status on a plist whose PATH cannot find the job's tools must say
        # broken. `/nonexistent` stands in for the old hardcoded PATH so the
        # result does not depend on where this host keeps its real cargo.
        label="$(printf '%s' "$plist" | plutil -extract Label raw -o - -)"
        mkdir -p "$T/home/Library/LaunchAgents"
        printf '%s' "$plist" | sed "s#<key>PATH</key><string>[^<]*</string>#<key>PATH</key><string>/nonexistent:/also-nonexistent</string>#" \
            > "$T/home/Library/LaunchAgents/$label.plist"
        st="$(HOME="$T/home" PATH="$TOOL_PATH:/usr/sbin:/sbin" bash "$REPO/scripts/$script" status 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g')"
        check "status reports an unresolving PATH as broken" yes "$(printf '%s' "$st" | grep -q "cannot find: $t1 $t2" && echo yes || echo no)"
        printf '%s' "$plist" > "$T/home/Library/LaunchAgents/$label.plist"
        st="$(HOME="$T/home" PATH="$TOOL_PATH:/usr/sbin:/sbin" bash "$REPO/scripts/$script" status 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g')"
        check "status reports a rendered PATH as resolving" yes "$(printf '%s' "$st" | grep -q "PATH resolves $t1" && echo yes || echo no)"
        rm -f "$T/home/Library/LaunchAgents/$label.plist"
    done

    # ── The off-host (b2) drill schedule. ──────────────────────────────
    #
    # Until 2026-09-24 a `TALOS_DRILL_SCHEDULE_SOURCE=b2` install rendered a
    # plist carrying no age passphrase, so the job died weekly at
    # backup-restore.sh's "no age passphrase source configured" and the leg
    # that answers "does anything survive losing this disk" had never run.
    echo "▶ scripts/drills/schedule.sh --source b2"
    DRILL="$REPO/scripts/drills/schedule.sh"
    # cargo + docker resolvable, aws deliberately NOT — the discriminating PATH.
    NO_AWS="$T/rustup/bin:$T/docker/bin:/usr/bin:/bin:/usr/sbin:/sbin"

    b2plist="$(HOME="$T/home" PATH="$TOOL_PATH:/usr/sbin:/sbin" \
        TALOS_DRILL_SCHEDULE_SOURCE=b2 \
        TALOS_OFFHOST_AGE_PASSPHRASE_CMD='op read "op://Private/age/password"' \
        bash "$DRILL" render 2>/dev/null)"
    check "b2 plist is valid" OK "$(printf '%s' "$b2plist" | plutil -lint - | sed 's/^<stdin>: //')"
    check "b2 propagates the age passphrase COMMAND" 'op read "op://Private/age/password"' \
        "$(printf '%s' "$b2plist" | plutil -extract EnvironmentVariables.TALOS_OFFHOST_AGE_PASSPHRASE_CMD raw -o - - 2>/dev/null)"
    check "b2 plist runs --source b2" b2 \
        "$(printf '%s' "$b2plist" | plutil -extract ProgramArguments.3 raw -o - - 2>/dev/null)"

    b2file="$(HOME="$T/home" PATH="$TOOL_PATH:/usr/sbin:/sbin" \
        TALOS_DRILL_SCHEDULE_SOURCE=b2 TALOS_OFFHOST_AGE_PASSPHRASE_FILE=/Volumes/escrow/age.pass \
        bash "$DRILL" render 2>/dev/null)"
    check "b2 propagates the age passphrase FILE" /Volumes/escrow/age.pass \
        "$(printf '%s' "$b2file" | plutil -extract EnvironmentVariables.TALOS_OFFHOST_AGE_PASSPHRASE_FILE raw -o - - 2>/dev/null)"

    # The tool list is DERIVED: b2 needs `aws`, the other modes must not be
    # refused for lacking it. Both halves, or the derivation is unproven.
    if HOME="$T/home" PATH="$NO_AWS" bash "$DRILL" render >/dev/null 2>&1; then
        check "artifact schedules without aws" accepted accepted
    else
        check "artifact schedules without aws" accepted refused
    fi
    if HOME="$T/home" PATH="$NO_AWS" TALOS_DRILL_SCHEDULE_SOURCE=b2 \
        TALOS_OFFHOST_AGE_PASSPHRASE_CMD=x bash "$DRILL" render >/dev/null 2>&1; then
        check "b2 refuses when aws is unresolvable" refused accepted
    else
        check "b2 refuses when aws is unresolvable" refused refused
    fi

    # A contradictory pair is refused at INSTALL rather than at 03:00 on a
    # Sunday. Both pairs: adding the check to one and not its twin is the
    # asymmetry this codebase keeps paying for.
    for pair in \
        "off-host:TALOS_OFFHOST_AGE_PASSPHRASE_CMD:TALOS_OFFHOST_AGE_PASSPHRASE_FILE" \
        "escrow:TALOS_DRILL_ESCROW_KEY_CMD:TALOS_DRILL_ESCROW_KEY_FILE"; do
        lbl="${pair%%:*}"; rest="${pair#*:}"; cvar="${rest%%:*}"; fvar="${rest#*:}"
        if HOME="$T/home" PATH="$TOOL_PATH:/usr/sbin:/sbin" \
            env "$cvar=a" "$fvar=/tmp/b" bash "$DRILL" render >/dev/null 2>&1; then
            check "$lbl pair: both forms set is refused" refused accepted
        else
            check "$lbl pair: both forms set is refused" refused refused
        fi
    done

    # The destination config the b2 leg needs. Without these the fix would
    # only move the weekly failure from "no age passphrase" to "no bucket".
    destplist="$(HOME="$T/home" PATH="$TOOL_PATH:/usr/sbin:/sbin" \
        TALOS_DRILL_SCHEDULE_SOURCE=b2 TALOS_OFFHOST_AGE_PASSPHRASE_CMD=x \
        TALOS_OFFHOST_B2_BUCKET=bkt TALOS_OFFHOST_B2_ENDPOINT=https://ep \
        TALOS_OFFHOST_B2_REGION=us-west-004 \
        bash "$DRILL" render 2>/dev/null)"
    for kv in TALOS_OFFHOST_B2_BUCKET:bkt TALOS_OFFHOST_B2_ENDPOINT:https://ep \
              TALOS_OFFHOST_B2_REGION:us-west-004; do
        k="${kv%%:*}"; want="${kv#*:}"
        check "b2 propagates $k" "$want" \
            "$(printf '%s' "$destplist" | plutil -extract "EnvironmentVariables.$k" raw -o - - 2>/dev/null)"
    done

    # A plist carries a command, a path or a credential SELECTOR — never the
    # key itself. talos-offhost-backup/src/aws.rs relies on exactly this
    # asymmetry: "the key id may be logged; the secret may not".
    credplist="$(HOME="$T/home" PATH="$TOOL_PATH:/usr/sbin:/sbin" \
        TALOS_DRILL_SCHEDULE_SOURCE=b2 TALOS_OFFHOST_AGE_PASSPHRASE_CMD=x \
        AWS_SECRET_ACCESS_KEY=sekrit-must-not-be-propagated \
        AWS_ACCESS_KEY_ID=keyid-is-configuration \
        bash "$DRILL" render 2>/dev/null)"
    check "the bucket SECRET never reaches the plist" no \
        "$(printf '%s' "$credplist" | grep -qE 'sekrit-must-not-be-propagated|AWS_SECRET_ACCESS_KEY' && echo yes || echo no)"
    check "the key id (not a secret) is carried" keyid-is-configuration \
        "$(printf '%s' "$credplist" | plutil -extract EnvironmentVariables.AWS_ACCESS_KEY_ID raw -o - - 2>/dev/null)"

    # ONE list, two schedulers. They address the same bucket with the same
    # credentials, so a variable either scheduler carries and the other drops
    # is a drift that only shows up as a weekly failure in one of them.
    # The probe sets every variable EXCEPT the passphrase FILE, because
    # setting it alongside _CMD is the contradictory pair both schedulers now
    # refuse — a probe that trips the guard under test proves nothing. The
    # FILE half is covered by "b2 propagates the age passphrase FILE" above.
    envall=""
    for v in "${OFFHOST_PLIST_ENV_VARS[@]}"; do
        [[ "$v" == TALOS_OFFHOST_AGE_PASSPHRASE_FILE ]] && continue
        envall="$envall $v=probe-$v"
    done
    # shellcheck disable=SC2086 # deliberate word-splitting: NAME=VALUE pairs
    dplist="$(HOME="$T/home" PATH="$TOOL_PATH:/usr/sbin:/sbin" TALOS_DRILL_SCHEDULE_SOURCE=b2 \
        env $envall bash "$DRILL" render 2>/dev/null || true)"
    # shellcheck disable=SC2086
    oplist="$(HOME="$T/home" PATH="$TOOL_PATH:/usr/sbin:/sbin" \
        env $envall bash "$REPO/scripts/offhost-backup/schedule.sh" render 2>/dev/null || true)"
    check "the parity probe rendered both plists" "yes yes" \
        "$([ -n "$dplist" ] && printf yes || printf no) $([ -n "$oplist" ] && printf yes || printf no)"
    for v in "${OFFHOST_PLIST_ENV_VARS[@]}"; do
        [[ "$v" == TALOS_OFFHOST_AGE_PASSPHRASE_FILE ]] && continue
        check "both schedulers carry $v" "yes yes" \
            "$(printf '%s' "$dplist" | grep -q "<key>$v</key>" && printf yes || printf no) $(printf '%s' "$oplist" | grep -q "<key>$v</key>" && printf yes || printf no)"
    done
fi

completed=1
if [[ $fails -gt 0 ]]; then echo "✗ $fails check(s) failed"; exit 1; fi
echo "✓ all launchd PATH checks passed"
