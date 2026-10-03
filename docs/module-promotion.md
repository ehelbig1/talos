# Promoting a module to the catalog

A module has two homes.

* **Your own modules** are written, compiled and run on your platform. Nothing
  else needs to know about them.
* **Catalog templates** live in `module-templates/` in this repository. They
  are tested in CI, published to the registry as signed artifacts, and shared
  by every user of every deployment that syncs that registry.

Promotion is how a module moves from the first home to the second. It is for
a module that has proven itself where it was written and is general enough
that someone else could use it.

## What a promoted module brings with it

| From the authoring lane | Becomes |
|---|---|
| `module.rs` | `template.rs`, with the module macro on `fn run` (the platform adds that macro when it compiles your source; a template is compiled as written) |
| `tests.rs` | a `#[cfg(test)]` module inside `template.rs`, run in CI by `talos-catalog-tests` |
| `module.json` grants and dependencies | `talos.json` |
| `fixtures/` (the recorded run it was rehearsed against) | `fixtures/`, checked in CI |

What does **not** come along: the module's id and its fuel limit on your
platform, and any secret grant that names your own connection.

## Steps

1. **Promote.**

   ```bash
   scripts/promote-module.py ../my-workflows/modules/calendar-week-fetch \
       --description "One calendar's events for the days ahead, reduced to planner fields." \
       --secret 'oauth/google_calendar/*'
   ```

   The script refuses, and writes nothing, when:

   * `module.json` grants a secret path that names one user's connection and
     you did not give a pattern with `--secret`;
   * anything it would copy — source, tests, any fixture — contains a UUID or
     an e-mail address outside the reserved example domains. This repository
     is public. Replace real values with made-up ones where the module is
     kept, then promote again;
   * the module states no capability world, or has no `fn run(`;
   * the template directory already exists (`--force` replaces the files the
     script writes).

   It is a filter over shapes, not a guarantee. Read what it wrote.

2. **Fill in the manifest.** Open `module-templates/<slug>/talos.json` and
   write the `config_schema` (every config key the module reads, with a
   description) and a `description` that says what the module returns and what
   it costs.

3. **Measure, then declare the fuel limit.**

   ```bash
   make check-catalog-fuel TEMPLATE=<slug>
   ```

   This builds the template through the same compile path the platform uses,
   runs it once in the worker runtime against `fixtures/http.json` (nothing is
   sent), and prints the fuel it used. On the first run it fails, because the
   manifest declares no limit yet, and the failure states the figure:

   ```
   calendar-week-fetch: has a recorded run but declares no recommended_fuel in
   talos.json. This run used 5173771 fuel over 26356 bytes of recorded response …
   ```

   Declare a `recommended_fuel` in `talos.json` whose computed limit leaves
   the recorded run at or under 80% (see `docs/fuel-budget-sizing.md` for the
   fields). Size it for the largest response the module should handle, not
   only the one you recorded, and say in `fixtures/README.md` what the
   recording represents. Run the command again until it passes.

4. **Run the template's tests and the compile check.**

   ```bash
   make test-templates
   make check-catalog
   ```

   If the module declares a crate in `dependencies`, add it to
   `talos-catalog-tests/Cargo.toml` (the build says so if it is missing).

5. **Open a pull request.** CI runs the three checks above on every change
   under `module-templates/`.

6. **Publish.** After the merge:

   ```bash
   gh workflow run template-publish.yml --ref main
   ```

   The workflow refuses to publish unless `quality.yml` is green for that
   exact commit, then builds every template with the controller image, pushes
   each as an OCI artifact and signs it. A deployment that syncs the registry
   picks the template up on its next sync; the shared row's fuel limit is the
   one the manifest declares.

## The fixtures directory

| File | What it is |
|---|---|
| `http.json` | The recorded responses, in request order: `[{method?, url_contains?, status?, headers?, body?}]`. The same shape `test_module`'s `http_fixtures` takes. |
| `config.json` | The node config for the run (optional). |
| `input.json` | The upstream output for the run (optional). |
| `grants.json` | `{"allowed_hosts": [...]}` — hosts the rehearsal may address, for a template whose manifest grants none because the installer supplies them (optional). Used by the check only. |
| `README.md` | What the recording represents: how many items, how large. |

## What the fuel check proves, and what it does not

It proves that the recorded run completes under the declared limit with
headroom, on the build the platform would produce today. It does not prove the
limit is enough for a larger response than the one recorded, and the figure is
not stable across compiler versions, so nothing asserts an exact number.

A template without `fixtures/http.json` is not checked at all. That is right
for a module that makes no requests and costs the same every time; for a
module that reads a response, record one.
