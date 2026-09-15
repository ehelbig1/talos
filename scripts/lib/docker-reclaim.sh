#!/usr/bin/env bash
# Docker disk-reclaim commands — ONE home for the flag spelling `make up`'s
# disk preflight prints and `make clean` runs.
#
# Why (2026-09-15): `make up` refused to start at 95% Docker disk and printed
# `docker builder prune -f --keep-storage 20GB` first. On this machine
# (Docker 29.7.2, buildx 0.36.1, BuildKit 0.32.2) it printed a deprecation
# warning and reclaimed 0 B against 57.9 GB of build cache; the same prune with
# `-a` and `--reserved-space 20GB` then reclaimed the cache down to 21 GB.
# A controlled small-scale experiment did NOT reproduce the 0 B: a threshold
# flag below the private cache size pruned down to it with or without `-a`,
# and `--keep-storage` behaved exactly like `--reserved-space`. So this helper
# does not claim the old spelling never works. It uses the spelling that was
# proven at real scale here, keeps `--keep-storage` only for a Docker whose
# `builder prune` does not know `--reserved-space`, and gives the preflight a
# way to show what is actually reclaimable, so an operator can see whether a
# command did anything.
#
# Measured on the same machine and worth knowing: while an image exists, its
# layers are not reclaimable build cache (`docker buildx du` counted 152 B
# private with the image present), so `docker image prune` goes FIRST.
#
# Sourceable (`docker_prune_reserve_flag`) and executable:
#   bash scripts/lib/docker-reclaim.sh reserve-flag

# The `builder prune` flag that keeps a cache floor. `--reserved-space` where
# the client knows it; `--keep-storage` otherwise (older buildx). A client that
# cannot even print help gets the older spelling, which every Docker with
# BuildKit accepts.
docker_prune_reserve_flag() {
    if docker builder prune --help 2>/dev/null | grep -q -- '--reserved-space'; then
        printf '%s\n' '--reserved-space'
    else
        printf '%s\n' '--keep-storage'
    fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        reserve-flag) docker_prune_reserve_flag ;;
        *)
            echo "usage: $0 reserve-flag" >&2
            exit 2
            ;;
    esac
fi
