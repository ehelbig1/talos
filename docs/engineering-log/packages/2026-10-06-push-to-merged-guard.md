# A push to a merged pull request's branch is refused (2026-10-06)

## Measured

Of the last 60 merged pull requests, two had commits pushed to their branch
after the merge: #1111 and #1112, both on 2026-10-06, by a session still
improving a change the operator had already merged. In both cases git
accepted the push, no workflow ran for the new commit, and it never reached
main; the session also rewrote each merged pull request's description to
cover the commit, and reported the earlier commit's run as the new one's
measurement. Each cost a follow-up pull request and a corrected description.

The repository does not delete a branch when its pull request merges
(`delete_branch_on_merge` is off; 13 of those 60 branches still exist), so
the stale branch is there to be pushed to.

## Changed

`scripts/check-push-target.sh`, run by `.githooks/pre-push` before the lint
gates (one question to GitHub; the gates take over a minute) and before
`SKIP_LINT`. It refuses a push when a MERGED pull request has the branch as
its head, the commit that merged is an ancestor of the one being pushed, the
push adds something, and no OPEN pull request has the branch. The message
names the pull request, counts the commits that would be lost, and gives the
command that moves them to a new branch from main.

Replayed on the real case — #1112's branch and the commit pushed after it
merged — it refuses. A branch name used again from other history, a branch
with an open pull request, a closed unmerged one and a push to main all go
through (`scripts/tests/check-push-target-test.sh`, in the supply-chain job).

## Decided

* **What it cannot find out is not a refusal.** Without `gh`, offline, or
  with an unreadable answer it says the check was not made and lets the push
  through: a hook that blocks every push when GitHub is slow gets bypassed
  with `--no-verify`, which skips the lint gates too.
* **`TALOS_PUSH_TO_MERGED=1`** is the stated way through; `--no-verify`
  also skips it, with everything else.

## Not done

* **Turning on "delete head branches" for the repository.** It is the
  operator's setting, and it would not prevent this: a push to a deleted
  branch recreates it just as silently. The guard covers that case (the
  merged commit is still an ancestor).
* **A guard on editing a merged pull request's description.** That is a `gh`
  call, not a push; no hook sees it.
