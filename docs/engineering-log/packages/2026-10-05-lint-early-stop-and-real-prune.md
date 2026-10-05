# The lint says when it stops early, and its shared exclude list prunes (2026-10-05)

Two findings from the check 70/52/64 speed-up (#1098), left unchanged there
so that change stayed provably equivalent.

## 1. A check could end the whole lint, silently

Check 64 built its lists with `ALL64="$(…; …)"`. A command substitution takes
the LAST command's status, so under `set -e` a test-target classifier that
refused the tree ended the script at that line. Reproduced with a planted
test file reading `TALOS_TEST_DATABASE_URL` with no marker: `main`'s lint
printed check 64's refusal and stopped — no check 65 to 97, no summary line.

- Check 64 now asks the classifier for each category on its own, records a
  failure, and skips only the leg that needs the lists (a runner naming a
  target by hand), saying so. With the same plant the lint now runs to its
  summary.
- The script has ONE exit trap (it also removes the temp files the two old
  traps removed). If the script ends before its last line it prints which
  check it stopped in and that the rest did not run. Tested by planting
  `false` in check 30 of a copy: "the lint STOPPED inside check 30 (exit
  status 1); the checks after it did not run".

## 2. The shared exclude list walked what it excluded

`TREE_PRUNE_FIND` was `-not -path '*/.claude/*' -not -path '*/.git/*'`: a
filter, so `find` walked every file under those directories and dropped them
afterwards. Measured from the main checkout (23 agent worktrees, 326,101
files under `.claude/`): about 8 s per walk filtered against about 1 s
pruned, same files. Ten walks use the list.

- `TREE_PRUNE_FIND=( \( -name .claude -o -name .git \) -prune -o )`. Every
  walk is now `find . "${TREE_PRUNE_FIND[@]}" [site prunes] <tests> -print0`:
  the list first, an explicit action last (without one, find prints the
  pruned directories).
- The same walks dropped `target/` the same filter-only way where they
  excluded it; those are prunes too (`-name target` where the old pattern
  was `*/target/*`, `-path ./target` where it was `./target/*`).
- Check 75 enforces the new shape for every `find`: the list straight after
  the root and an explicit action. Mutation-checked: moving the list after a
  site prune, and dropping `-print` from check 63's walk, are each reported.

## Equivalence

Each of the eight distinct statement shapes was run old against new in this
worktree and in the main checkout: identical file lists every time (1,193 /
1,271 / 996 / 1,270 / 995 files in the main checkout). The whole lint's
verdict lines are identical between `main`'s script and this one on the same
tree. From the main checkout the ten walks go from roughly 80 s to roughly
10 s in all.

## Not done

- 23 worktrees sit under the main checkout's `.claude/` (326,101 files).
  Cleaning them up is the operator's call, not a lint change.
