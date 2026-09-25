# Package records

One file per package of work, named `<YYYY-MM-DD>-<slug>.md`. This replaced the
per-package bullet in `CLAUDE.md` on 2026-09-25: that file had become the one
nearly every change edited (57 of the 58 commits before the change), so
parallel PRs conflicted there, and every session paid at start-up for a record
it only needed when working in that area. A new file conflicts with nothing,
and `grep -ril <subsystem> docs/engineering-log/` finds it.

## What goes in a record

The content a package bullet carried — the part that stops the next session
redoing work already done:

- **Decided** — what was chosen, and the one-line reason.
- **Deliberately NOT done** — each option declined, and why.
- **Measured** — populations and numbers (before/after, precision of a lint
  candidate), with the query or command that produced them when it is short.
- **Latent vs live** — whether the defect could fire on the reference fleet.
- **Stated limits** — what the change does not cover.
- **One home** — the function, crate or constant that now owns the rule.

Keep the discovery story out, or short. A record is read when someone is about
to work in the same area; it is not read at session start.

## What does NOT go here

A RULE every future session must follow goes in `CLAUDE.md`, in the section
that owns it, in a sentence or two — and the package record says it did so.
If you cannot tell whether something is a rule or a story, it is a rule.

## Mutation testing

Expected only where a passing mutation would be a vulnerability: tenancy,
crypto, authentication/authorization, the write ceiling, egress controls. For
those, record each mutation and whether it was caught. Elsewhere, a test that
fails on the pre-fix tree is enough; do not list mutations.
