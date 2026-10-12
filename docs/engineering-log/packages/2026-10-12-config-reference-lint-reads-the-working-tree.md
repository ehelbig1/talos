# 2026-10-12 — the configuration-reference lint reads the working tree

**Why.** Check 89 (`scripts/lint-config-reference-components.py`) holds each
row of `docs/configuration-reference.md` against the crates that read the
variable. Writing a new integration crate, its environment read was reported
as read by "nothing", and the row documenting it as naming a crate that
"does not read it", until the crate was `git add`ed. Nothing in the message
said the cause was staging.

**Observed.** With one reader file made untracked on an otherwise clean
tree, main's script: `API_KEY_BCRYPT_COST Component names talos-api-keys but
that crate does not read it (readers: nothing)`, 1 finding. The same tree
with the file tracked: 0 findings.

**Cause.** The source set came from `git ls-files '*.rs'` (tracked files).
The linked-crate sets come from `cargo tree`, which reads the working tree.
The two halves of one check looked at different trees.

**Decided.**
- **Read the working tree**: tracked files, and files git does not track yet
  and does not ignore (`git ls-files --others --exclude-standard`). Ignored
  files (build output, scratch directories) stay out.
- **And say so.** The summary line names each untracked file read (five at
  most, then a count) and ends "`git add` them, CI sees only what is
  committed". `lint-structural.sh` prints that line on a pass, so it is seen.
  With no untracked file the line is byte-for-byte what it was.
- Both, not one: the prompt offered "say so, or read the working tree".
  Saying so alone leaves a correct tree failing; reading alone makes a local
  pass that CI then fails if the file is never added.
- Under CI the checkout has no untracked files, so the set is unchanged.

**Tests.** `--self-test` (found by `make test-scripts`): in a throwaway
repository, a tracked file and a not-yet-added file are both read, an ignored
file and an untracked test file are not, only the not-yet-added one is named,
and it stops being named once added; the note's wording at 0, 1 and 8 files.
Mutation: with the untracked listing dropped, the self-test fails.

**Not verified, stated.** The other checks that list files with
`git ls-files` were not surveyed for the same disagreement.
