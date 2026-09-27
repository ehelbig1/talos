// @vitest-environment node
/**
 * The dev server (Vite) must send to the controller exactly the paths that
 * production nginx does, and no SPA route may sit under one of them.
 *
 * Measured 2026-09-26: Vite proxied 5 of nginx's 11 controller locations. The
 * other six (/health, /mcp, /webhooks/, /approvals/, /approval-actions/,
 * /corrections/) were answered by the dev server with index.html and a 200, so
 * `scripts/smoke.sh` reported /health healthy without reaching the controller.
 * In the other direction, the SPA's own /health page could not be reloaded in
 * production, because nginx's `location /health` sends that path to the
 * controller.
 *
 * Runs in the node environment: importing the Vite config loads esbuild, which
 * refuses jsdom's `TextEncoder`.
 */
import { readFileSync } from "node:fs";
import viteConfig from "../../vite.config";

const read = (relative: string) =>
  readFileSync(new URL(relative, import.meta.url), "utf8");

/** `location` paths whose block proxies to the controller upstream. */
function nginxControllerLocations(conf: string): string[] {
  const paths: string[] = [];
  let current: string | null = null;
  for (const raw of conf.split("\n")) {
    const line = raw.trim();
    if (line.startsWith("#")) continue;
    const location = /^location\s+(?:=\s+)?(\/\S*)\s*\{/.exec(line);
    if (location) current = location[1];
    if (current && line.startsWith("proxy_pass http://talos_controller")) {
      paths.push(current);
      current = null;
    }
  }
  return paths;
}

const withoutTrailingSlash = (p: string) =>
  p.length > 1 ? p.replace(/\/$/, "") : p;

const nginx = nginxControllerLocations(read("../../nginx.conf"));
const proxy = Object.keys(
  (viteConfig as { server?: { proxy?: Record<string, unknown> } }).server
    ?.proxy ?? {},
);

describe("dev proxy parity with production nginx", () => {
  it("reads a plausible number of controller locations", () => {
    // A parser that stops matching must fail, not pass vacuously.
    expect(nginx.length).toBeGreaterThanOrEqual(10);
    expect(nginx).toContain("/graphql");
  });

  it("proxies every path nginx sends to the controller", () => {
    const proxied = new Set(proxy.map(withoutTrailingSlash));
    const missing = nginx.filter((p) => !proxied.has(withoutTrailingSlash(p)));
    expect(missing).toEqual([]);
  });

  it("proxies nothing nginx serves from the SPA", () => {
    const routed = new Set(nginx.map(withoutTrailingSlash));
    const extra = proxy.filter((p) => !routed.has(withoutTrailingSlash(p)));
    expect(extra).toEqual([]);
  });

  it("puts no SPA route under a controller location", () => {
    const routes = [...read("../App.tsx").matchAll(/path="([^"]+)"/g)].map(
      (m) => m[1],
    );
    expect(routes.length).toBeGreaterThan(5);
    const shadowed = routes.filter((route) =>
      nginx.some(
        (location) =>
          route === withoutTrailingSlash(location) ||
          route.startsWith(location),
      ),
    );
    expect(shadowed).toEqual([]);
  });
});
