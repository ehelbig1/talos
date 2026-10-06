# Dependabot does one thing, and it is switched on (2026-10-06)

## Measured

* `.github/dependabot.yml` (191 lines) asked for weekly, grouped
  version-update pull requests for cargo, four Docker images,
  docker-compose and GitHub Actions.
* Dependabot has run once: seven jobs on 2026-09-16, none since (three
  Mondays). The cargo job's log lists **56 pull requests "created"**.
  **No Dependabot pull request exists**: no pull request in the repository
  has a `dependabot/` head branch or a bot author, and the 20 opened on
  2026-09-16/17 are numbered consecutively (#867–#886), all the operator's.
* Dependabot alerts and security updates were both disabled.
* The frontend was not listed. Of the four dependency-advisory failures in
  150 runs of `quality.yml` (2026-10-01..06), three were `npm audit`.
* Nothing found that would block it: no rulesets; main's protection requires
  one status check and restricts no one. WHY no pull request appeared is not
  known — GitHub shows that on the repository's Dependabot page, which the
  API used here cannot read.

So the file, and §2.7 of `docs/security/operational-runbook.md`, described
automation that did not exist.

## Decided by the operator

* **Alerts and security updates: on.** Done through the repository settings
  API the same day (`vulnerability-alerts`, `automated-security-fixes`;
  both read back as enabled).
* **Weekly version bumps: removed.** One run proposed 56 for cargo alone.

## Changed

* `.github/dependabot.yml`: two entries, cargo (`/`) and npm (`/frontend`),
  each with `open-pull-requests-limit: 0` — version updates off, security
  updates on. No `labels:` (the two the old file named do not exist in the
  repository). Docker images and GitHub Actions are not listed: both are
  pinned by digest or commit and bumped by hand.
* `docs/ci.md` "A new advisory": step 0 is to look for Dependabot's pull
  request.
* `docs/security/operational-runbook.md` §2.7 and its quarterly checklist
  say what runs.

## Not yet seen

A Dependabot security pull request. Right after the switch the alerts list
was empty (GitHub's scan had not run); the one advisory open on main —
`braces`, no patched release — cannot produce one. The first advisory with
a patched release is the first test.

## Limits

A security update moves a dependency to its patched release. It cannot write
an `overrides` entry when the patched release is outside what a dependent
asks for (the `@graphql-tools/utils` case of 2026-10-06), and the CI gates
remain what blocks.
