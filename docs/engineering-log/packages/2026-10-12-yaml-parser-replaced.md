# 2026-10-12 — workflow YAML is parsed by `serde-saphyr`, not `serde_yaml`

**Why.** `make audit` went red on an unchanged dependency: RUSTSEC-2024-0449,
`unsafe-libyaml` is unmaintained (main's run at 00:51Z on 14337a7 passed; the
next pull request's failed). `unsafe-libyaml` is a machine translation of
libyaml's C into unsafe Rust, its repository is archived, and it was linked
through `serde_yaml` 0.9.34 (itself deprecated) by `talos-yaml-workflows`.

**Decided: replace it, not except it.** The other "unmaintained" exceptions in
`deny.toml` are crates whose code runs on trusted input or at build time. This
one parses text a user sends (`import_yaml_workflow`, up to 1 MiB): a memory
bug in it would be reachable by any authenticated user, and upstream has said
none will be fixed. Two production calls used it (`parse_yaml`, `to_yaml`), so
the replacement is small. `serde-saphyr` 1.3 parses in safe Rust and budgets
what a document may expand to.

**Two options are set, and each is a compatibility decision** (`parse_options`):
- **`strict_booleans: true`.** The new parser's default reads `yes` / `no` /
  `on` / `off` as booleans. `serde_yaml` read them as strings and WROTE such
  strings unquoted, so with the default a config value `"yes"` in a file an
  earlier release exported would have come back as `true`. Found by the
  old-format test, not by reading documentation.
- **`with_snippet: false`.** The default error quotes the document around the
  fault. The document is a user's workflow, config values included, and the
  error is returned to the caller and logged.

**Stated difference, not fixed.** With strict booleans only the exact literals
`true` and `false` are booleans. `serde_yaml` also accepted `True` and `TRUE`
(and `False`, `FALSE`). A hand-written file using those now gets a string in a
config value and a parse error in a boolean field. Files this platform
exported are unaffected: it always wrote lower case.

**Not changed.** The 1 MiB cap in `parse_yaml` is still checked before the
parser runs and does not rely on the parser's own budget. Duplicate keys are
an error, as before.

**Tests** (`talos-yaml-workflows`): a document in the old export format imports
to the same values and JSON types (quoted look-alikes stay strings, unquoted
`yes` / `off` stay strings, a `|` block keeps its text, `null` is null), and
re-exports to something that imports to the same thing; 36 strings that look
like other types survive a round trip; a parse error does not quote the
document; a 2,000-node document under the cap is read. The 68 tests in
`talos-workflow-types` and the handler crate's 788 pass unchanged.

**Checked.** `cargo tree -i unsafe-libyaml` and `-i serde_yaml` match nothing.
`make audit`: advisories, bans, licenses and sources ok. Six crates enter the
lock file (`serde-saphyr`, `granit-parser`, `annotate-snippets`, `arraydeque`,
`encoding_rs_io`, `nohash-hasher`).
