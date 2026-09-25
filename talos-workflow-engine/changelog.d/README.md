# Changelog fragments

New `talos-workflow-engine` changelog entries go here, one file per change,
instead of into the `## [Unreleased]` section of `../CHANGELOG.md`. Parallel
PRs that each edited that section conflicted at the same lines; separate files
cannot.

    talos-workflow-engine/changelog.d/<slug>.<category>.md

- `<slug>` — anything unique: the branch name or the PR number.
- `<category>` — `added`, `changed`, `deprecated`, `removed`, `fixed`,
  `security`, `performance` or `tooling`.
- The body is the entry in Markdown. If it does not start with `- ` it becomes
  one bullet.

Example — `talos-workflow-engine/changelog.d/edge-routing.fixed.md`:

    Edge conditions now apply after every node kind, not only after a
    worker-dispatched module.

At release time, fold the fragments into `[Unreleased]` and delete them:

    python3 scripts/changelog-fragments.py preview  talos-workflow-engine
    python3 scripts/changelog-fragments.py assemble talos-workflow-engine

CI (`quality.yml`, lint job) runs `python3 scripts/changelog-fragments.py check`,
which rejects a misnamed, mis-categorised or empty fragment.
