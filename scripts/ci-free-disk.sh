#!/usr/bin/env bash
# Free a hosted CI runner's disk only when it is short, and without waiting.
#
# The Rust jobs used to delete six toolchains the runner image ships and this
# repository never uses, in the foreground, before doing anything else.
# Measured over six passing runs of quality.yml that took a median of 1.5–2.1
# minutes in each of the four jobs that set the run's wall time, and in one
# run 1m57s in one job and 6m12s in another — time in which the job compiled
# nothing.
#
# Measured 2026-10-05 (run 37388069851, `df` first and last in each job): the
# runner starts with 86 GB free of 145 GB and a test job adds about 25 GB. So
# on these runners nothing needs deleting, and this does nothing unless less
# than MIN_FREE_GB is free. The step stays as a guard for a smaller runner
# (GitHub promises far less disk than it currently gives).
#
# When it does free space, it renames each directory out of the way (instant:
# a rename inside one directory) and deletes the renamed copies in the
# background. A later step sees exactly what it saw when the deletion was in
# the foreground — the paths are gone — so nothing can race it: a step that
# recreates one (setup-node rebuilds the tool cache) writes a new directory,
# not the one being removed.
#
# Each job that runs this ends with a `df -h /` step, so its log keeps saying
# what the job needed.
#
# For the test, which runs this on made-up directories:
# TALOS_CI_FREE_DISK_PATHS (colon-separated) replaces the list,
# TALOS_CI_FREE_DISK_SUDO="" drops sudo, TALOS_CI_FREE_DISK_WAIT=1 deletes in
# the foreground, and TALOS_CI_FREE_DISK_AVAIL_GB replaces the reading of free
# space. TALOS_CI_FREE_DISK_MIN_GB (default 40) is the threshold.
set -euo pipefail

MIN_FREE_GB="${TALOS_CI_FREE_DISK_MIN_GB:-40}"
[[ "$MIN_FREE_GB" =~ ^[0-9]+$ ]] || { echo "TALOS_CI_FREE_DISK_MIN_GB must be a whole number, got '$MIN_FREE_GB'" >&2; exit 1; }
# Free space on / in whole GB. Unreadable reads as 0: free the disk.
avail_gb="${TALOS_CI_FREE_DISK_AVAIL_GB:-$(df -Pk / 2>/dev/null | awk 'NR==2 { printf "%d", $4 / 1048576 }')}"
[[ "$avail_gb" =~ ^[0-9]+$ ]] || avail_gb=0
df -h / || true
if (( avail_gb >= MIN_FREE_GB )); then
    echo "${avail_gb} GB free (threshold ${MIN_FREE_GB} GB): nothing deleted"
    exit 0
fi
echo "${avail_gb} GB free is under ${MIN_FREE_GB} GB: freeing the unused toolchains"

SUDO="${TALOS_CI_FREE_DISK_SUDO-sudo}"
if [[ -n "${TALOS_CI_FREE_DISK_PATHS:-}" ]]; then
    IFS=':' read -r -a paths <<< "$TALOS_CI_FREE_DISK_PATHS"
else
    # A path inside another comes first, so both renames find their source.
    paths=(
        /usr/share/dotnet
        /usr/local/lib/android
        /opt/ghc
        /opt/hostedtoolcache/CodeQL
        /usr/local/share/boost
        "${AGENT_TOOLSDIRECTORY:-}"
    )
fi

doomed=()
for d in "${paths[@]}"; do
    d="${d%/}"
    [[ -n "$d" && "$d" == /* && -e "$d" ]] || continue
    # Beside the original, so the rename never crosses a filesystem.
    $SUDO mv "$d" "$d.ci-doomed-$$"
    doomed+=("$d.ci-doomed-$$")
    echo "queued for deletion: $d"
done

if [[ ${#doomed[@]} -eq 0 ]]; then
    echo "nothing to free"
elif [[ "${TALOS_CI_FREE_DISK_WAIT:-}" == "1" ]]; then
    $SUDO rm -rf "${doomed[@]}"
else
    # Output closed: a step does not end while a child holds its pipe.
    $SUDO nohup rm -rf "${doomed[@]}" >/dev/null 2>&1 &
    disown
    echo "deleting ${#doomed[@]} director(ies) in the background"
fi
