# Dependabot version updates, in a shape that can be kept up with (2026-10-06)

Follows `2026-10-06-dependabot-security-only.md` by a few hours; the operator
asked whether version bumps should be on as well.

## What happened when Dependabot was switched on

Turning on alerts woke Dependabot, which acted on the OLD config still on
main before the security-only one merged. In about ten minutes it opened
**25 pull requests** — 16 for Docker images, compose services and GitHub
Actions, the rest for cargo — each starting a `quality.yml` run; 25 runs
were queued at once and the config change that would stop them waited behind
them. 21 version-bump pull requests were closed by hand with a note, and
their runs cancelled.

That also answers why no Dependabot pull request had ever existed: its
features were off for the repository, and the one run on 2026-09-16 produced
nothing that could be opened.

Among the 25: Node 22 → 26, `registry` 2 → 3, `ollama` 0.5 → 0.35,
`redis` 0.27 → 1.7, `ed25519-dalek` 2 → 3 — and the Rust image 1.96 → 1.98,
which would have moved the image past the toolchain `quality.yml` pins.

The same hour, it did the thing it was switched on for: a critical advisory
in `shell-quote` (GHSA-pqg4-j6r4-53mv) reached the advisory database, main's
audit gate failed on it, and Dependabot's fix (#1138, three lockfile lines)
was already open.

## The case for version updates

The week's hardest advisory fix (2026-10-06, `@graphql-tools/utils`) needed
an npm `overrides` entry because the dependency was a MAJOR version behind
its patched release. Small regular bumps keep a security fix small.

## Decided

Version updates are on, shaped by what the 25 showed:

* **Only where CI exercises the result**: cargo, npm (`/frontend`), GitHub
  Actions. Not Docker images or compose services: `quality.yml` runs
  neither, and a compose bump lands on a running stack.
* **Minor and patch only, ONE grouped pull request per ecosystem**, at most
  one open at a time. Majors are ignored (`ignore … semver-major`, which
  does not affect security updates) and done by hand; the runbook's
  quarterly list says how to find them.
* **Nothing younger than 7 days** (`cooldown`).
* Monday 09:00 Pacific.

So at most three pull requests a week, each through the normal gate.

## Not yet seen

A grouped version-update pull request from this config: the first is due
the Monday after it merges. Whether the cargo group is small enough to
review in one sitting is the thing to look at then; if it is not, split it
by the old file's domains (async runtime, serde, crypto, …).
