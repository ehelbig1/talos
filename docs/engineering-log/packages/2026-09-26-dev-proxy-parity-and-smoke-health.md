# 2026-09-26 — the smoke test certified /health from the SPA fallback

**Why.** In the live verification of #960, `make smoke BASE_URL=http://localhost:3002`
reported `✓ /health → 200` and `✗ /mcp → 404`. The 200 was the dev server's
`index.html` (`Content-Type: text/html`): the check read only the status code,
so a proxy with no `/health` route passed. That is the "nginx routes it to the
SPA" case the script says it exists to catch.

**Measured.**
- Production nginx (`frontend/nginx.conf`, mirrored by the chart ConfigMap)
  sends 11 locations to the controller. The Vite dev server proxied 5
  (`/graphql`, `/api`, `/auth/oauth`, `/auth/csrf`, `/ws`) and answered the
  other six (`/health`, `/mcp`, `/webhooks/`, `/approvals/`,
  `/approval-actions/`, `/corrections/`) with `index.html` and a 200.
- The SPA had its own client route at `/health` (the Health page). nginx's
  prefix `location /health` sends that path to the controller, so in
  production a reload or bookmark of the page renders `{"status":"ok"}`. It
  worked in dev only because of the gap above. It is the only SPA route under a
  controller location.
- Not a live defect for emailed links: approval and correction links are built
  from `TALOS_PUBLIC_BASE_URL`, else the ngrok tunnel, else `FRONTEND_URL`.
  This fleet's tunnel forwards to `controller:8000`, bypassing both proxies.
- Both dev ports are published on loopback only (`127.0.0.1:3002`,
  `127.0.0.1:8000`), so proxying the six routes through the dev server exposes
  nothing new.

**Decided.**
- `scripts/smoke.sh` `/health` passes only on a 200 whose body carries the
  controller's `"status"` key. The handler builds every response with it. A
  200 of HTML fails with "answered by the SPA fallback".
- `frontend/vite.config.ts` proxies all 11 controller locations through one
  `controllerProxy()` helper; the four identical copied literals are gone, and
  `/ws` keeps its own entry.
- The SPA Health page moves to `/system-health`, which avoids the `/health`
  prefix that nginx's prefix match would also capture.
- `frontend/src/lib/devProxyParity.test.ts` pins the parity, reading the real
  `nginx.conf` and the real Vite config object: every nginx controller location
  is proxied, nothing else is, and no `App.tsx` route sits under one. A floor
  on the parsed location count keeps a parser that stops matching from passing
  vacuously. It runs in the node environment, because importing the Vite
  config loads esbuild, which refuses jsdom's `TextEncoder`.

**Proof.** The parity test fails on `origin/main`'s `vite.config.ts` and
`App.tsx` (six missing routes, one shadowed route) and passes after. Smoke,
read-only against the live stack:

| Target | Result |
|---|---|
| running dev frontend `:3002` (old config) | `/health` now fails "answered by the SPA fallback"; `/mcp` 404 |
| controller `:8000` | 5/5 pass |
| local Vite from this branch, `API_PROXY_TARGET=:8000` | 5/5 pass (`/health` JSON, `/mcp` 401); `/system-health` serves the SPA |

Full vitest 401/401 pass (1 skipped), `make lint-frontend` and `tsc --noEmit`
clean.

## The same class on `/ws` (found while verifying this package)

`smoke.sh` passed `/ws` on a `101`. The controller refuses a disallowed `Origin`
AFTER the upgrade, with an immediate close, which browsers report as
"WebSocket connection failed". CLAUDE.md records that failure for a handler that
passed no Origin. Found live: my smoke runs against `:8000` and `:3099`
(origins not in `ALLOWED_ORIGIN`) printed `✓ /ws → 101` while
`talos_ws_handshakes_total{outcome="origin_not_allowed"}` went 0 → 2.

`scripts/lib/ws_probe.py` (stdlib, the same dependency as leg 7's crawl)
completes the upgrade with `Origin: <base URL>`, sends graphql-ws
`connection_init` without a session, and reads the first frame:
`connection_error` means the origin was accepted and authentication was reached
(`auth-required`); a close with no text means it was refused (`closed`). This is
deterministic, not a timing bet, because the server answers `connection_init`
at once. Live: `:3002` gives `auth-required` and `:8000` gives `closed`, and the
server's counters moved by exactly one `no_token` and one `origin_not_allowed`.

**Deliberately NOT done.**
- Reformatting `vite.config.ts` with Prettier: it was not Prettier-clean
  before, and it sits outside the `src/**` lint scope.
- A client-side redirect from `/health`: nginx (and now Vite) answer that path
  before the SPA loads, so the redirect could never run.

**Stated limits.**
- The running dev frontend picks up the new proxy only after its image is
  rebuilt (`vite.config.ts` is not bind-mounted).
- A bookmark of the old `/health` page now shows the controller's JSON in dev
  too, which is what production already did.
