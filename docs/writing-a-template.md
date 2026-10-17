# Writing a catalog template

A catalog template is a module every user of every deployment can install:
it lives in `module-templates/<slug>/`, is tested in CI, and is published as a
signed artifact. Writing one takes three commands, and the tools hold it to
the platform's security rules for you: you are not asked to remember them.

```bash
make new-template SLUG=acme-invoice-reader ROLE=reader HOST=api.acme.example
make record-template TEMPLATE=acme-invoice-reader
make template TEMPLATE=acme-invoice-reader
```

## 1. What kind of block is it?

Every template is ONE of five roles (`docs/building-blocks.md`). Pick the one
its single job is:

| ROLE | Its one job | What it may reach |
|---|---|---|
| `reader` | read one service, change nothing there | one host, GET only |
| `decider` | compute over its input: classify, pick, summarise | nothing |
| `keeper` | be the only writer of one memory key | its own memory key |
| `composer` | render one surface (a notification, an email) | nothing |
| `sender` | make one change at one service | one host, POST only |

Something that reads AND sends is two templates. That split is the security
design: a module that reads private data cannot also send it anywhere.

## 2. Start it

```bash
make new-template SLUG=<slug> ROLE=<role> [HOST=<api host>]
```

`SLUG` is lower-case words joined by hyphens. A reader or sender names the
one API host it talks to (`api.acme.example`: no scheme, no path, no `*`).

This copies the role's skeleton (`talos-catalog-tests/skeletons/`), which is a
working template that already passes every gate. It already does what its
role must:

* a **reader** is GET-only and bounded (pages, items), says when it stopped
  short, keeps the kind of a failed request in its error so a timeout is
  retried and a refusal is not, and names the host and status of a refusal,
  never the body;
* a **decider** and a **composer** reach no network; a composer says when
  its input was stale or a source failed;
* a **keeper** is idempotent, bounded, and treats an unreadable store as an
  error, never as an empty store to write over;
* a **sender** has `DRY_RUN` on by default and sends nothing until it is
  turned off, and makes one request per run; a sender of a message to a
  person (`notify-*`, `send-*`) returns the delivery verdict
  (`docs/building-blocks.md`, "Sender"), which the engine records.

## 3. Write it

Replace the parts marked `TODO(author)` in `template.rs`, and say in
`talos.json` what it does: `description`, `config_schema`,
`setup_instructions`.

* **Config** is a struct named `…Config` with one
  `#[serde(rename = "KEY")]` field per setting, each with a doc comment. Every
  key it reads is declared in `config_schema` with a description, and every
  declared key is read.
* **Upstream data** is parsed into typed structs with only the fields you
  use: an unread field costs no fuel.
* **Secrets** never reach the module. A token is a config value
  `"Bearer vault://<path>"` that the platform puts into the request header;
  the installer grants exactly that path.
* **Hosts**: `allowed_hosts` is exactly the hosts your source addresses. A
  URL kept as data and never fetched (a link for a person) says so on its
  line: `// host-not-requested: <why>`.
* **Tests** are a `#[cfg(test)] mod tests` in `template.rs`, run natively
  against `talos_module_testkit::host` (set HTTP answers, memory, secrets,
  the clock). A test runs this module; a reader's test may also run the
  check that reads its output.
* **Data** in tests and fixtures is made up: an address at `example.com`,
  a Google project named `example-…`. The repository is public, and CI
  refuses anything that looks real.
* No `env!()`, `include_str!()`, `#[path]` or `unsafe`, anywhere: the
  platform compiles the source itself and refuses them.

## 4. Record its run

```bash
make record-template TEMPLATE=<slug>
```

One test ends with
`talos_module_testkit::recorded_run::keep("<slug>", &envelope())`. Recording
writes `fixtures/` from what that test served: the requests and answers, and
the config and input it ran with. After that, an ordinary `cargo test` fails
if the module or the test changes what is served, so the recording cannot
drift. Read the diff before you commit it.

A keeper has no recorded run (the rehearsal has no memory to read).

## 5. Check it

```bash
make template TEMPLATE=<slug>
```

Runs, fastest first, everything CI runs on a template, and stops at the first
failure with what to change:

1. **no identifiers**;
2. **its tests and every catalog gate**: the compile lint, its role against
   its grants, hosts used = hosts granted, config read = config declared,
   failure kinds kept, and, for a security check, its planted faults;
3. **it compiles for the sandbox**, with only the crates it declares;
4. **its recorded run fits its fuel**.

The first time, step 4 prints a `recommended_fuel` to paste into
`talos.json`, sized for the recording. Raise `expected_items` or
`bytes_per_item` to the largest payload the module should handle (its own
caps on pages and items are the guide).

## 6. Hand it in

Open a pull request. CI runs the same gates. After the merge,
`gh workflow run template-publish.yml --ref main` publishes it, signed.

Moving a module you already wrote and proved elsewhere into the catalog is
promotion instead (`docs/module-promotion.md`); the checks are the same.

## What the gates are, and where

| Gate | Where |
|---|---|
| no identifiers in the catalog | `scripts/promote-module.py --scan` (in `make check-catalog`) |
| the platform's compile lint | `talos-catalog-tests/tests/source_lints.rs` |
| one role, and the grants it allows | `talos-catalog-tests/tests/block_roles.rs` |
| hosts used = hosts granted | `talos-catalog-tests/tests/hosts_match_source.rs` |
| config read = config declared | `talos-catalog-tests/tests/config_schema_matches_source.rs` |
| the time comes from the host clock | `talos-catalog-tests/tests/clock_from_host.rs` |
| a failed request keeps its kind | `talos-catalog-tests/tests/http_failure_kind.rs` |
| a secret grant the catalog reads | `talos-catalog-tests/tests/manifest_keys.rs` |
| every rule finds its planted fault | `talos-catalog-tests/tests/planted_faults.rs` |
| the recorded run fits its fuel | `talos-catalog-tests/tests/fuel_fixtures.rs` (`make check-catalog-fuel`) |
| it compiles for the sandbox | `scripts/check-catalog.sh` (`make check-catalog`) |

Each gate also runs over the skeletons, so a new template never starts from
one that fails. The hosts, config and clock rules and the compile lint are
functions of `talos-module-source`; the files above hold the catalog's
population and its `PREDATING` lists, and an authoring lane runs the same
functions over its own modules.

A template takes the time from the host (`datetime::now_unix()`), never from
`chrono::Utc::now()`, `chrono::Local::now()` or `std::time::SystemTime::now()`:
a test sets the host clock with `talos_module_testkit::host::clock::set_unix`,
and a date the process reads for itself cannot be pinned, so a test built on a
fixture's due date passes until the calendar passes it.
