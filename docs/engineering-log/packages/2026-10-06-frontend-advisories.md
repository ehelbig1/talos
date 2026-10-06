# Three frontend advisories the gate began reporting on 2026-10-06

The blocking `npm audit` step (frontend job) failed on a PR that touches no
frontend file: the advisory service started reporting three advisories since
the last full run. Because every push to main runs the frontend job, the next
merge would have turned main red.

| Advisory | Package | Was | Now | How |
|---|---|---|---|---|
| GHSA-68fv-2mgg-jv7q | `source-map-js` | 1.2.1 | 1.2.2 | in-range update |
| GHSA-6fw5-9hq8-w87g | `@graphql-tools/executor-legacy-ws` | 1.1.25 | 1.1.37 | in-range update |
| GHSA-7mx3-vvmw-hjmv | `@graphql-tools/utils` | 11.1.0 | 12.0.3 | `overrides` |

`@graphql-tools/utils` is patched only from 12.0.1, and the newest
`@graphql-codegen/cli` (7.4.4) and `plugin-helpers` (7.4.1) ask for
`^11.2.0`, so no plain update reaches it. The gate's rule is an exception
only when no patched release exists; one does, so it is forced with an
`overrides` entry (the sixth; same mechanism as the other five).

**Why the major bump is safe here.** The package is reached only through
`@graphql-codegen/*`, a development tool. With the override installed
(`npm ci`), `npm run codegen` — offline, from the checked-in schema — writes
`src/generated` byte-identical to what is committed, which is the same
comparison CI makes. Lint, 408 tests and the build pass.

Still covered by its reviewed exception (expires 2026-11-03): `braces`
GHSA-vfj7-8cjw-p6xm, for which no patched release exists.

**Remove the override** when `@graphql-codegen/cli` and `plugin-helpers`
declare `@graphql-tools/utils` `^12`.

`npm audit fix --package-lock-only` was tried first and not used: it rewrote
1,618 lockfile lines to clear the same two in-range advisories; the narrow
`npm update source-map-js @graphql-tools/executor-legacy-ws` plus the override
change 43.
