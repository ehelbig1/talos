# Catalog template: the newest run of a GitHub Actions workflow (2026-10-05)

## Why

Every commit on `main` now gets a full `quality.yml` run, but a red run
reaches no one unless they look (`make confirm-deploy`, or GitHub's mail).
The owner asked for it on the phone, through Talos's own alerts.

## What

`module-templates/github-workflow-run` (http-node, `api.github.com`, GET):
reads the newest FINISHED run of one workflow on one branch and reports
`state` = failing / passing / other / none with the run's facts. With `ALERT`
(default) it also emits `__ops_alert__`: a failing run raises or bumps ONE
rolling alert per repo/workflow/branch (`source` github-actions, severity hint
from `SEVERITY`, default high); a passing run resolves it with
`status_event: "resolved"`; other leaves it.

It does not notify. Telling a person once per run needs memory of what was
told, which an http-node must not hold (the delivery pattern: compose with
memory, send with network). The owner's workflow puts a compose node and a
`notify-*` adapter after it.

## Decisions

- **Its own workflow, not the existing critical-alert email notifier.** That
  notifier selects critical alerts FIRST SEEN in the last 45 minutes, so a
  rolling alert that resolves and fails again is never sent a second time —
  exactly the red/green/red pattern CI produces.
- **Severity hint `high` by default**, so a CI failure shows in the ops digest
  without also triggering the critical-alert email.
- **Unauthenticated by default.** The repository is public; 60 requests an
  hour per address, against one request per poll. `AUTH_HEADER` takes a
  `vault://` reference for a private repository.
- **A non-2xx answer fails the node** with the status only. The platform's
  self-monitoring then raises its own alert for the watcher.
- **Inputs that reach the URL are validated** (owner/name, workflow file name,
  branch percent-encoded, `..` refused) before any request; a link off
  `github.com` is dropped from the output.

## Measured

- Fixture: a made-up reply with the shape and size of a real one (11.8 KB):
  every value replaced, a scan for the owner's identifiers finds none.
- `make check-catalog-fuel TEMPLATE=github-workflow-run`: 424,819 fuel of a
  1,000,000 limit (42.5%).
- 11 template tests (`cargo test -p talos-catalog-tests -- github_workflow_run`);
  `cargo clippy -p talos-catalog-tests --all-targets -D warnings` clean.

## Not done here

The owner's workflow (reader → compose that remembers the last reported run →
`notify-home-assistant`) is in the private workflows repository and is wired
on the platform once this template can be installed.

## Corrected the same day: GitHub chose the wrong run (v1.1.0)

The first live run reported a run from 2026-09-26 as the newest finished run
on `main`, whose newest finished run was minutes old. Measured with the same
unauthenticated query: `status=completed&per_page=1` returned run #1639 and
`total_count` 568 three times in a row; the same query with `per_page` 2, 3,
5 or 10 returned run #1860 first and `total_count` 701. GitHub's
documentation does not describe the difference.

So the template no longer asks GitHub to filter or to choose: it reads the
ten newest runs on the branch, unfiltered, and picks the newest FINISHED one
itself (by creation time, then run number). A new test lists an old failure
first, the newest run still in progress and the newest finished run in the
middle. If all ten are still running the state is `none` and nothing changes.

Fuel, re-measured on a made-up ten-run recording (120 KB): 2,406,860, which
is 20 fuel per byte for parsing whole run objects. The manifest now declares
`fuel_per_byte: 20`; the declared limit is 6,500,000 and the run uses 37.0%.

What the wrong reading did before it was caught: the workflow's send node was
in dry run, so nothing was sent. It raised the rolling alert for the old
failure and stored that run as reported. The next run on a fixed reader reads
`main` passing, which resolves the alert by itself and stores "passing"; that
run's "green again" notification goes to the same dry-run send.
