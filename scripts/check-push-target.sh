#!/usr/bin/env bash
# Refuse a push that adds commits to a branch whose pull request has merged.
#
# Measured 2026-10-06: of the last 60 merged pull requests, two had commits
# pushed to their branch AFTER the merge (#1111, #1112) — the same day, by a
# session that was still improving a change the operator had already merged.
# Nothing said so: git accepts the push, no workflow runs for it, and the
# commit never reaches main. One of the two was then reported as measured,
# from the earlier commit's run.
#
# Reads git's pre-push lines on stdin
# (`<local ref> <local sha> <remote ref> <remote sha>`), and for each branch
# asks GitHub for its pull requests. The push is refused when
#
#   * a MERGED pull request has this head branch, and
#   * the commit that merged is an ancestor of the one being pushed (so this
#     is that work continued, not a branch name used again from main), and
#   * the push adds something (the two commits differ), and
#   * no OPEN pull request has the branch.
#
# What it cannot find out is never a refusal: without `gh`, offline, or with
# an answer it cannot read, it says so on stderr and lets the push through.
#
#   TALOS_PUSH_TO_MERGED=1 git push    push anyway
set -uo pipefail

[ "${TALOS_PUSH_TO_MERGED:-0}" = "1" ] && exit 0

zero="0000000000000000000000000000000000000000"
refused=0
while read -r _local_ref local_sha remote_ref _remote_sha; do
    [ -n "${local_sha:-}" ] || continue
    [ "$local_sha" = "$zero" ] && continue          # deleting a branch
    case "${remote_ref:-}" in refs/heads/*) ;; *) continue ;; esac
    branch="${remote_ref#refs/heads/}"
    case "$branch" in main|master) continue ;; esac

    if ! command -v gh >/dev/null 2>&1; then
        echo "pre-push: gh is not installed — did not check whether '$branch' has a merged pull request." >&2
        continue
    fi
    if ! prs="$(gh pr list --head "$branch" --state all --limit 30 \
                  --json number,state,headRefOid --jq '.[] | "\(.state) \(.number) \(.headRefOid)"' 2>/dev/null)"; then
        echo "pre-push: could not ask GitHub about '$branch' — did not check whether its pull request has merged." >&2
        continue
    fi

    open=""; merged_number=""; merged_head=""
    while read -r state number head; do
        [ -n "${state:-}" ] || continue
        case "$state" in
            OPEN) open="$number" ;;
            MERGED)
                [ "$head" != "$local_sha" ] || continue
                if git merge-base --is-ancestor "$head" "$local_sha" 2>/dev/null; then
                    merged_number="$number"; merged_head="$head"
                fi
                ;;
        esac
    done <<< "$prs"

    if [ -n "$merged_number" ] && [ -z "$open" ]; then
        added="$(git rev-list --count "${merged_head}..${local_sha}" 2>/dev/null || echo '?')"
        {
            echo
            echo "✗ pre-push: pull request #${merged_number} for '$branch' has already MERGED (at ${merged_head:0:8})."
            echo "  This push adds $added commit(s) on top of it. They would not reach main, and no"
            echo "  workflow would run for them."
            echo "  Put the follow-up on a new branch from main and open a new pull request:"
            echo "      git fetch origin && git switch -c <new-branch> origin/main && git cherry-pick ${merged_head:0:8}..${local_sha:0:8}"
            echo "  To push to this branch anyway: TALOS_PUSH_TO_MERGED=1 git push"
        } >&2
        refused=1
    fi
done
exit "$refused"
