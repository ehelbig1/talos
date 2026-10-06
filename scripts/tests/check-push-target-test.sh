#!/usr/bin/env bash
# Tests for scripts/check-push-target.sh: a throwaway git repository and a
# fake `gh` on PATH that answers with whatever the case sets. No network.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="$HERE/../check-push-target.sh"

fails=0
T="$(mktemp -d)"
completed=""
on_exit() {
    local st=$?
    rm -rf "$T"
    if [[ -z "$completed" ]]; then
        echo "✗ check-push-target test stopped before its last check (status $st)" >&2
        exit 1
    fi
    exit "$st"
}
trap on_exit EXIT

mkdir -p "$T/bin" "$T/repo"
cat > "$T/bin/gh" <<'SHIM'
#!/usr/bin/env bash
# `gh pr list … --jq …` answers "STATE NUMBER HEAD" lines.
[ "${FAKE_GH_FAIL:-0}" = "1" ] && exit 1
printf '%s' "${FAKE_GH_OUT:-}"
SHIM
chmod +x "$T/bin/gh"

g() { git -C "$T/repo" -c user.name=test -c user.email=test@example.test -c commit.gpgsign=false "$@"; }
g init -q -b main
g commit -q --allow-empty -m "the commit that merged"
MERGED="$(g rev-parse HEAD)"
g commit -q --allow-empty -m "a follow-up on top of it"
FOLLOW="$(g rev-parse HEAD)"
g checkout -q --orphan other
g commit -q --allow-empty -m "unrelated history"
OTHER="$(g rev-parse HEAD)"
ZERO=0000000000000000000000000000000000000000

# run <expected exit> <label> <pre-push line> [VAR=value …] — sets OUT.
run() {
    local want="$1" label="$2" line="$3"; shift 3
    set +e
    OUT="$(cd "$T/repo" && printf '%s\n' "$line" | env PATH="$T/bin:$PATH" "$@" bash "$GUARD" 2>&1)"
    local got=$?
    set -e
    if [ "$got" = "$want" ]; then printf '  ok   %s\n' "$label"; else printf '  FAIL %s (exit %s, want %s)\n       %s\n' "$label" "$got" "$want" "$OUT"; fails=$((fails+1)); fi
}
has() { if grep -qF -- "$2" <<< "$OUT"; then printf '  ok   %s\n' "$1"; else printf '  FAIL %s\n       missing: %s\n' "$1" "$2"; fails=$((fails+1)); fi; }

LINE="refs/heads/feature $FOLLOW refs/heads/feature $MERGED"

echo "a follow-up pushed to a merged pull request's branch is refused"
run 1 "refused" "$LINE" FAKE_GH_OUT="MERGED 41 $MERGED"
has "names the pull request"            "pull request #41 for 'feature' has already MERGED"
has "counts what would be lost"         "adds 1 commit(s)"
has "says what to do"                   "git switch -c <new-branch> origin/main"
run 1 "refused when the branch was deleted after the merge" "refs/heads/feature $FOLLOW refs/heads/feature $ZERO" FAKE_GH_OUT="MERGED 41 $MERGED"

echo "what is not that mistake goes through"
run 0 "the merged commit itself (nothing added)" "refs/heads/feature $MERGED refs/heads/feature $MERGED" FAKE_GH_OUT="MERGED 41 $MERGED"
run 0 "the branch name used again from other history" "refs/heads/feature $OTHER refs/heads/feature $ZERO" FAKE_GH_OUT="MERGED 41 $MERGED"
run 0 "an open pull request also has the branch" "$LINE" FAKE_GH_OUT="MERGED 41 $MERGED"$'\n'"OPEN 42 $FOLLOW"
run 0 "only an open pull request" "$LINE" FAKE_GH_OUT="OPEN 42 $MERGED"
run 0 "a closed, unmerged pull request" "$LINE" FAKE_GH_OUT="CLOSED 40 $MERGED"
run 0 "no pull request at all" "$LINE" FAKE_GH_OUT=""
run 0 "a push to main is not this guard's business" "refs/heads/main $FOLLOW refs/heads/main $MERGED" FAKE_GH_OUT="MERGED 41 $MERGED"
run 0 "deleting a branch" "(delete) $ZERO refs/heads/feature $MERGED" FAKE_GH_OUT="MERGED 41 $MERGED"
run 0 "a tag" "refs/tags/v1 $FOLLOW refs/tags/v1 $ZERO" FAKE_GH_OUT="MERGED 41 $MERGED"

echo "what cannot be found out is said, and is not a refusal"
run 0 "GitHub does not answer" "$LINE" FAKE_GH_FAIL=1
has "says the check was not made" "did not check whether its pull request has merged"

echo "the stated way through"
run 0 "TALOS_PUSH_TO_MERGED=1" "$LINE" FAKE_GH_OUT="MERGED 41 $MERGED" TALOS_PUSH_TO_MERGED=1

completed=1
if [ "$fails" -gt 0 ]; then
    echo "✗ $fails check(s) failed"
    exit 1
fi
echo "✓ check-push-target: all checks passed"
