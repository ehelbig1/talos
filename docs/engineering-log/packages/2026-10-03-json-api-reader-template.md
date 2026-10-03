# A config-driven JSON reader template

2026-10-03

> Superseded the same day by
> [`2026-10-03-json-api-reader-measured.md`](2026-10-03-json-api-reader-measured.md):
> the parsing described below was measured, found to build a tree in the
> common case, and replaced. The decisions about grants, credentials and
> bounds stand.

## Why

Most read integrations written this month are the same three steps: one
request with a credential, find the list in the response, keep a few fields
of each entry. Each was a new module (source, compile, grants, tests). The
catalog's `http-request` returns the whole response and grants every host
and every verb, so it does not replace them.

## What it is

`module-templates/json-api-reader`: one request (GET, or POST with a JSON
body), then a streaming pass that walks to the list named by `ROWS_AT` and
keeps the `FIELDS` of each entry. Output `{rows, count, total, truncated, top,
status}`.

## Decisions

* **Streaming projection, not a parsed tree.** Three `DeserializeSeed`s walk
  the response; everything not named is skipped with `IgnoredAny` and never
  allocated. A whole-input `serde_json::Value` parse measured about 430 fuel
  per byte on 2026-10-01; skipping is the point of this module. It also makes
  "a field you did not ask for cannot appear in the output" a property of the
  parser rather than of a filter (tested).
* **Installs able to reach nothing.** `allowed_hosts: []` and no secrets. The
  installer grants one API's host and its secret paths. `http-request` ships
  `["*"]`; a reader that carries a credential should not, because the
  credential's destination would then be whatever the config says. One
  installed copy per API keeps a credential bound to its host.
* **Reads only.** GET and POST; any other verb is refused in config, and the
  manifest declares only those two.
* **The module never holds a credential.** Header values and strings inside
  `BODY` may be `vault://` references; the host replaces them at the socket.
  A test asserts the request leaves the module with the references intact.
* **An error response's body is not echoed.** The failure names the host and
  the status. An error body can repeat what was sent.
* **Bounded.** `MAX_ROWS` 1..1000 (default 100); entries past it are counted
  (`total`, `truncated`), not kept. At most 32 fields, paths at most 8 deep.
* **One request, no paging.** `TOP` carries a cursor out for the workflow to
  use. Paging inside the module would make its fuel and time unbounded by
  config.
* **Absent is null.** Every row has every field.
* **`TOP` needs `ROWS_AT`**, and two fields may not share an output name;
  both are refused before any request, as is every other config that cannot
  mean what it says.

## Stated limits

* **`recommended_fuel` is an estimate, not a measurement** (20 fuel per byte,
  100 entries of 4 KB). Measure it with a rehearsal
  (`test_module` + `http_fixtures` + `fuel_profile`) once the template is
  installed, and correct the manifest.
* A pick that names a whole nested value builds that value; picking
  `"owner"` from entries with large `owner` objects costs what they cost.
* When `TOP` and `ROWS_AT` share their first key, that subtree is built once
  to serve both.
* No array indices in paths; no filtering of rows.

## Tests

Nine, run natively by `talos-catalog-tests` against the kit: projection
(renames, nesting, absent fields, a value and a field inside it), the row
limit, a top-level list and a single object, the request as sent (references
intact, one request), failures (status only, network), a response without the
list, config refusals with nothing sent, and skipped content that looks like
structure. `make check-catalog` compiles it against the real bindings.
