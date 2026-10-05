# One command for "is main what is running?"

2026-10-04

After a merge and `git pull && make up`, whether the running stack was the
merged commit was answered by hand each time, and by inference: the
controller container had started after the merge time. A start time says when
a container started, not what it was built from.

## Where the commit already was

No Rust changed. The controller already reports the commit it was built from:

- `get_platform_info.build_version` — `<package version>+<7-char sha>[-dirty]`,
  composed in `talos-mcp-handlers/src/platform.rs` (`handle_get_platform_info`)
  from the `GIT_SHA` / `GIT_DIRTY` constants `talos-mcp-handlers/build.rs`
  stamps at compile time. A `TALOS_VERSION` environment override replaces the
  whole string.
- `session_start.server_version` — the same composition, no override
  (`talos-mcp-handlers/src/advanced.rs`). Not used by the script: that handler
  also starts background repair tasks, so it is not a read.
- The same reply's `fleet.workers[]` carries the build each registered worker
  reported.

`GET /health` returns `{"status": …}` only and carries no commit. It was left
alone: the commit is readable without it.

## Decided

`scripts/confirm-deploy.sh`, run by `make confirm-deploy`. Eight checks, one
line each, `PASS` / `FAIL` / `UNKNOWN`; exit 1 if any failed, exit 0 otherwise,
and the summary line says that `UNKNOWN` alone does not fail.

- **Expected commit** from `git ls-remote origin refs/heads/main`. No fetch;
  the checkout is not changed.
- **Controller commit**: the 7 characters after `+` compared as a prefix of the
  40. Different is `FAIL` naming both.
- **A `-dirty` build of the right commit is `UNKNOWN`, not `PASS`.** The image
  was built with uncommitted changes, so it is not provably that commit. It is
  not `FAIL` either: nothing shows it is a different one.
- **Worker commit** was not in the request and was added because the reply
  already carries it. It reads registered rows only. A worker known only by a
  pinned key reports no build, and with no registered row the check is
  `UNKNOWN`.
- **Migrations** compare the local checkout's files against
  `_sqlx_migrations`. The version is the digits before the first `_`: 37 of the
  362 files are named `001_…`, not with a 14-digit timestamp. The line states
  the checkout's commit and whether it is `origin/main`.
- **Log**: a line counts when its level is `ERROR` (second field of the default
  format) or it is a panic line. Matching the word anywhere would count an
  `INFO` line that quotes it.
- `/health` passes on 200 with status `ok`. A 200 with `degraded` fails.

## Read-only, and how that is held

Everything the script sends is listed in its header. The Postgres read runs
with `default_transaction_read_only=on`, so the server refuses a write even if
the statement were changed. `scripts/tests/confirm-deploy-test.sh` puts fake
`git`, `docker` and `curl` on `PATH`, logs every call across all its scenarios,
and fails on a call outside the list.

Calling `get_platform_info` and `tools/list` makes the controller write one
`INFO` log line per call, as for any caller.

Printed log lines have colour codes removed, are cut to 160 characters, and
have bearer values, common key prefixes and `password=`-style values masked.
The masking is by pattern; it is a second line behind the rule that the
controller does not log secrets, not a guarantee.

## Measured

Against the development stack on 2026-10-04: 8 `PASS`, exit 0. Controller and
one registered worker row at `326ae6f`, equal to `origin/main`; 362 of 362
migrations applied, newest `20261004160000`; 0 `ERROR` lines; 361 tools.

With the controller URL pointed at a closed port and two container names that
do not exist: 2 `PASS`, 3 `FAIL`, 3 `UNKNOWN`, exit 1.

The test: 64 assertions, all passing under macOS bash 3.2.57. It runs the
script as `bash -e` and as `bash -u -o pipefail`, on a healthy and on a failing
stack.

## Stated limits

- The migrations check says nothing about a migration that exists on
  `origin/main` and not in the checkout the command runs in.
- A production build does not serve `/mcp/local`. Against one, both commit
  checks are `UNKNOWN` and the `tools/list` check fails. `make smoke` is the
  command for a deployed cluster.
- The worker's build is what it reported at registration. It is not signed.
- `WARN` lines are not counted. The worker's log is not read.
- A JSON log format would report 0 `ERROR` lines whatever the log held.
- Seven characters are compared, because that is what the build carries.

## Not verified

- No live run produced a `FAIL` or `UNKNOWN` on the commit, migration or log
  checks. Those arms were driven by the test's fakes only.
- The test's read-only assertion was not shown to fail on a script that makes
  another call.
- Nothing was run on Linux or under bash 4 or 5.
- The test is not run by any CI job.

## Left out of this change

Three edits belong to this package and are not in it. They were not made
when it was written, and are listed so nobody reads their absence as done:

* `confirm-deploy` is not in the Makefile's `.PHONY` list. The target works
  without it (no file of that name exists).
* No operator document describes the command. The fitting place is
  `docs/deployment.md`, under "Docker Compose Deployment".
* `scripts/tests/confirm-deploy-test.sh` runs in no CI job. Until a step
  runs it, a change to the script is checked only when someone runs the
  test by hand.

Seen and untouched: `docs/deployment.md` shows a `/health` body with
`version` and `checks` fields; the live endpoint returns `{"status":"ok"}`.

## Added the same day: the GitHub API when git cannot ask

First real use: the SSH agent was locked, `git ls-remote` failed, and the two
commit checks came back UNKNOWN. That was the right answer for a check that
could not be made, and it still left the question to be answered by hand.

When `git ls-remote` fails and `origin` is a github.com repository, the
script now asks `https://api.github.com/repos/<owner>/<repo>/commits/main`
for the commit, unauthenticated, and says on the `origin/main` line that it
did. A private repository answers 404, which is not a commit, so the checks
stay UNKNOWN as before. An origin that is not exactly `owner/repo` on
github.com is not sent anywhere. The test covers: the API answers, names
another commit, answers without a commit, is unreachable, a non-GitHub
origin (the API is never asked), a malformed origin, and that the API is not
consulted when git answers.

## The three edits left out, added 2026-10-05

`confirm-deploy` is in `.PHONY`; `docs/deployment.md` has a "Confirming a
deploy" section; and `quality.yml`'s lint job runs
`scripts/tests/confirm-deploy-test.sh`, so a change to the script is now
checked on every pull request.

Writing the document section found the neighbouring one wrong, and it is
corrected in the same change: "Unified Health Check" showed a `/health` body
with `version` and a `checks` object, and described `/health` as the detailed
view. Measured on the live controller: `/health` answers `{"status":"ok"}`
and nothing else; the per-subsystem view is `/ready`.

