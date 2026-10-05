# confirm-deploy says whether a commit gap needs a deploy (2026-10-05)

## Why

With pull requests merging by themselves, `main` moves without a deploy, and
`make confirm-deploy` reported every such gap as a FAIL — including gaps of
documentation and CI commits that change nothing in a container.

## Measured before writing the rule

- Both images `COPY . .`, so every tracked file is in the build context. What
  reaches a running container: the binaries; `migrations/`, `wit/`,
  `talos_sdk_macros/`, `module-templates/`, `workflow-templates/` (copied
  into the controller image); and the compose mounts (`scripts/dev-backup`,
  `deploy/`, `docker/`, `observability/`, `module-templates/`,
  `frontend/src`, `frontend/public`). `make up` also runs
  `scripts/preflight-disk.sh` and `scripts/verify-observability.sh`.
- **Six documents under `docs/` are compiled into binaries** with
  `include_str!` (`docs/workflow-engine/graph-json-schema.md`,
  `docs/THREAT_MODEL.md`, …). Found by resolving all 391 include macros in
  main's tree (180 resolved to files; the 10 unresolved are comments, test
  strings and `build.rs` format strings). So "it is documentation" is not a
  rule.
- An include climbs out of its crate, so it names the file after a slash
  (`"../../docs/x.md"`). Searching Rust source for `/docs/x.md` finds all six;
  searching for the bare path also matched prose such as "see CLAUDE.md" in
  string literals (5 such lines for `CLAUDE.md`).

## The rule

A changed file has no effect only when it is under `docs/`, `.github/`,
`.githooks/`, `scripts/tests/` or a crate's `tests/`, is a lint or CI script
(`scripts/lint-*`, `check-*`, `ci-*`, `ci_*`, `confirm-deploy.sh`,
`dev-test-db.sh`) or is a `.md` file; is outside every copied or mounted
directory; and is named by no Rust source as an include would name it, and by
no `build.rs`, Dockerfile or compose file outside a comment. Anything else, a
running commit that is not an ancestor of `main`, or a gap it cannot read
(objects not local — it never fetches), is a FAIL.

## Checked on real merges

| Merge | Changed | Verdict |
|---|---|---|
| #1092 | `docs/ci.md`, a record | none |
| #1090 | `CLAUDE.md`, archive files, the log checker | none |
| #1094 | a lint script, a record | none |
| #1089 | a controller test, a record | none |
| #1088 | a script and the `Makefile` | deploy (`Makefile`) |
| #1084 | Rust sources | deploy |
| #1082 | a catalog template | deploy |

The live gap on 2026-10-05 (running `784ae28`, main ten commits ahead) reads
"deploy" because of a `.PHONY` line in the `Makefile` and a comment in
`scripts/publish-images.sh` — the rule's stated bias towards "deploy".

## Tests

18 new assertions in `scripts/tests/confirm-deploy-test.sh`; the fake `git`
answers each of the three searches separately so every rule is tested alone.
Four mutations — dropping the Rust-include rule, the build.rs comment rule,
the copied/mounted-directory rule, or the leading slash — each fail it.

## Not done

- A `Makefile` change always counts, though most targets are not `make up`.
- The worker line excuses a worker that is behind only when its own gap is
  "none"; a mixed fleet reports the first wrong row's gap.
