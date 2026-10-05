# A local test database that sets itself up

2026-10-04

## The gap

The controller's DB tests clone a migrated template database per test. There
were two ways to get one. `make test-integration` builds it, runs every
suite and tears it down — about 15 minutes, right for a full run. For "run
this one binary again" there was a container set up by hand from notes: start
it, read its password out of `docker inspect`, rebuild the template by hand
whenever migrations moved, export the URL. In one working day that cost:

* the hand-written environment file vanished with a temp directory and every
  DB test failed at connect until it was rewritten;
* a new migration had to be applied to the template by hand before its tests
  could run;
* every brief to a parallel agent repeated the same eight lines of setup.

## What was added

`scripts/dev-test-db.sh` (`up`, `run <cmd…>`, `status`, `rebuild`, `stop`),
`make test-db` and `make test-db-stop`.

## Decisions

**It decides for itself whether the template is usable.** Usable means:
every migration of this checkout applied, none it does not have, and no test
wrote into it. Behind → apply the new ones. Anything else → rebuild from the
schema baseline plus the tail, the same recipe `scripts/test-integration.sh`
uses.

**One pinned image.** The script reads the pgvector image from
`scripts/test-integration.sh` instead of pinning a second digest.

**It cannot reach the stack's database.** Every statement goes through
`docker exec` into one named container that the script creates; a name or
port that is the stack's is refused.

**The password is never printed.** Generated at creation, read back from the
container's own environment, written to an env file with mode 600. `run`
passes it to the command's environment without a file at all.

**Not a CI job.** CI already has `test-integration`. This is the inner loop.

## Verified

By hand, on scratch containers only:

| Path | Result |
|---|---|
| existing container, template current | ready, 362 migrations |
| `run` a real test binary | 5 passed |
| template behind (newest migration row removed) | reported, applied, 362 |
| template holds a migration the checkout lacks (a made-up row) | reported, rebuilt, 362 |
| no container (another name and port) | created on 127.0.0.1, template built, test passed, stopped |
| name `talos-postgres`; port 5432; `run` with no command; unknown command | each refused |

The first version reported an absent container as something else and tried
to start it: `docker inspect` of a missing container prints an empty line
AND fails, so "print it, or print absent" printed two lines. Found by the
fresh-container run above and fixed.

## Not verified

* The "a test wrote into it" rebuild: not exercised (it needs a row in
  `encryption_keys`).
* Linux and bash 4/5: run on macOS bash 3.2 only.
* There is no automated test of this script.
