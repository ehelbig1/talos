# 2026-09-29 — undici 7.29.0 → 7.30.0 (GHSA-3wwx-pv8p-q78v)

**Why.** A moderate advisory was published against `undici` `>=7.28.0 <7.29.1`:
denial of service via an unhandled error in WebSocket `permessage-deflate`
decompression. The frontend job's `npm audit` gate (moderate and above, backlog
kept at zero on `main`) failed on every PR that runs that job. It surfaced on
#982, which changed no frontend code; that PR runs the job because it edits
`quality.yml`.

**Exposure: none in production.** `undici` enters only through `jsdom` 28.1.0,
the vitest DOM environment, a dev dependency. It is not bundled into the
frontend and not used by any server.

**Decided.** A lockfile-only bump. `jsdom` declares `undici: ^7.21.0`, and
`npm update undici` resolved 7.30.0, the newest in range and what a fresh
install resolves. No `package.json` change and no other package moved.

**Proof.**
- `npm audit`: 0 at every severity.
- `npm run lint` and prettier: clean.
- vitest: 76 files, 403 passed (1 pre-existing skip).
