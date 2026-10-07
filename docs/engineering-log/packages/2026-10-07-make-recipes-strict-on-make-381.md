# Makefile recipes are strict on every make, including macOS's 3.81

2026-10-07. The root `Makefile` asked for `bash -eu -o pipefail` through
`.SHELLFLAGS`. That variable arrived in GNU Make 3.82; the `/usr/bin/make`
macOS ships is 3.81 and ignores it without a word. On a Mac no recipe had
`-e`, `-u` or `pipefail`. CI (Ubuntu, make 4.x) was never affected.

## Decided

**The flags are on `SHELL`: `SHELL := /bin/bash -eu -o pipefail`, and
`.SHELLFLAGS` is gone.** Every make splits `SHELL` into words before it
appends `-c`, so one line covers every recipe and every `$(shell …)`, on both
versions, including recipes not written yet. Measured with a stand-in shell
that prints its arguments: make 4.4.1 runs
`<-eu><-o><pipefail><-c><recipe line>` with the old header and with the new
one — the same argv, so nothing changes under 4.x from this line.

**One home:** that `SHELL` line and the comment above it.
**Guard:** `scripts/tests/make-strict-shell-test.sh` (found by
`make test-scripts`).

## The audit

A recipe line is one shell. A line holding a single command needs none of the
flags; these are the lines that hold more.

Relied on a flag, so were wrong under 3.81:

| Target | Flag | What 3.81 did |
|---|---|---|
| `clippy` | `pipefail`, `-e` | `cargo clippy … \| tee`: status was `tee`'s. Exit 0 when clippy failed to compile. |
| `up` (build block) | `-e` | A failed `docker compose build` was followed by "NOTHING REBUILT — every layer was cached", then `docker compose up -d` started the old images and the target reported a healthy stack. |
| `test-clean` | `-e` | `docker ps` failing printed "✓ no leaked test-harness containers"; `docker rm` failing printed "✓ removed". |
| `ps` | `pipefail` | `psql … \| awk \|\| printf '(database unreachable)'`: the fallback never printed. |

Were wrong WITH the flags — the line handles the failure itself, and strict
mode stopped it first. Latent under 4.x, and each would have reached the Mac
the moment 3.81 became strict, so each is changed here:

| Target | Line | Under the flags, before | Change |
|---|---|---|---|
| `up` | `dirty="$(git status --porcelain \| head -5)"` and the listing below it | Outside a git checkout: exit 128 and no message. On a listing longer than the pipe buffer: SIGPIPE, 141. | `\|\| true` |
| `up` | `url="$(curl -sf …4040/api/tunnels \| grep -o … \| head -1 \| cut …)"` | A tunnel not up after 2 s failed `make up` instead of printing "tunnel starting". | `\|\| true` inside the `$(…)` |
| `observability-reload` | `code="$(curl … -w '%{http_code}' …)"`, and the Alertmanager twin | curl exit 7 stopped the line before the `case`: the "no response … is the stack up?" diagnosis never printed. | `\|\| true` inside the `$(…)` |
| `sqlx-prepare`, `sqlx-check` | `[ -n "$DATABASE_URL" ] \|\| { … }` | bash's "unbound variable" replaced the recipe's own message. | `${DATABASE_URL:-}` |

Read and needing nothing: `help`, `lint` (every line a single command or an
explicit `\|\| { …; exit 1; }`), `lint-frontend*`, `check-frontend-codegen`,
`test-unit`, `test`, `test-integration`, `coverage-html`, `release`, `nuke`,
`_wait-healthy`, `audit`'s migration loop (it opens with `set +e` and exits by
hand), `up`'s tunnel-start and observability `if` blocks, and the two
`$(shell …)` at the top of the file (no pipeline, no unset variable). Every
other recipe is one command per line.

## Measured

`scripts/tests/make-strict-shell-test.sh [MAKEFILE]`, 23 checks per make:

| | make 3.81 (`/usr/bin/make`, macOS) | make 4.4.1 (controller image) |
|---|---|---|
| Makefile on `main` | 12 fail | 5 fail |
| this branch | 0 fail | 0 fail |

The 12 are the first table plus the probes; the 5 are the second table. CI
(`ubuntu-latest`, make 4.x) runs the same test in the supply-chain job.

## The test

Probe recipes are added to the real Makefile through `include`, so they run
under its `SHELL`: the options are on, a failing pipeline / a failing command
/ an unset variable stops the recipe, the same through `$(MAKE)` and
`$(shell …)`, and a healthy pipeline still passes (so it cannot pass because
make is broken). Then the Makefile's own `clippy`, `test-clean`, `ps`, `up`,
`observability-reload`, `sqlx-check` and `sqlx-prepare` are run against stub
`cargo` / `docker` / `curl` / `sqlx` / `sleep` programs; `up` runs in a temp
folder on a copy of the Makefile. It tests the make on `PATH`, `/usr/bin/make`
and `gmake`, each once.

## Deliberately NOT done

- **`set -euo pipefail;` at the head of each multi-command recipe.** Same
  effect, but one more site for every recipe written later, and the guard
  would have had to parse recipes to find a missing one.
- **`${PIPESTATUS[0]}` after `tee` in `clippy`.** Fixes one recipe of four,
  and the clippy command line must stay byte-identical with structural check 7.
- **Refusing to run on make older than 3.82.** The operator deploys with
  `make up` on stock macOS make.
- **`BASH_ENV`.** It would put `set -eu` into every bash script a recipe runs.
- **A line in `CLAUDE.md`.** The rule for writing a recipe is in the comment
  above `SHELL`, where a recipe is written, and the test enforces the rest.

## Found, not changed

`make audit`'s secret scan is `if grep -rEn … dirs 2>/dev/null | grep -v
'secret-scan-allow'; then fail`. Under `pipefail` with GNU grep (CI), a scanned
directory that does not exist makes the first grep exit 2 even when it printed
a match, the pipeline is then non-zero, and the `if` reads that as "nothing
found". Measured in the controller image: a secret-shaped line in
`controller/src` with `sdks` absent is NOT detected. macOS's BSD grep exits 0
there, so this is CI's make-4.x behaviour, not a 3.81 one. Latent: all four
directories exist. It is its own change.

## Stated limits

- `make SHELL=/bin/bash <target>` on the command line overrides the line, as
  it overrides any makefile variable.
- A script a recipe runs sets its own options; nothing here reaches it.
- `make up` was run on stubs, not against a real stack; `make clippy` was run
  with a stub `cargo`, not over the workspace.
- There is no other makefile in the repository.
