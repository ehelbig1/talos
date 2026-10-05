#!/usr/bin/env bash
# Free a hosted CI runner's disk WITHOUT waiting for it.
#
# The Rust jobs remove toolchains the runner image ships and this repository
# never uses. Until 2026-10-05 each job deleted them in the foreground before
# doing anything else. Measured over six passing runs of quality.yml that step
# took a median of 1.5–2.1 minutes in each of the four jobs that set the run's
# wall time, and in one run 1m57s in one job and 6m12s in another — time in
# which the job compiled nothing.
#
# The space is not needed until late in a build, so this renames each
# directory out of the way (instant: a rename inside one directory) and
# deletes the renamed copies in the background. A later step sees exactly what
# it saw before — the paths are gone — so nothing can race the deletion: a
# step that recreates one (setup-node rebuilds the tool cache) writes a new
# directory, not the one being removed.
#
# Each job that runs this ends with a `df -h /` step, so its log holds what
# the job needed — the evidence for whether deleting is necessary at all.
#
# TALOS_CI_FREE_DISK_PATHS (colon-separated) replaces the list, TALOS_CI_FREE_DISK_SUDO=""
# drops sudo, and TALOS_CI_FREE_DISK_WAIT=1 deletes in the foreground — all
# three for the test, which runs this on made-up directories.
set -euo pipefail

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
df -h / || true
