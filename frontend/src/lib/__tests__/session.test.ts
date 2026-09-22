/**
 * The session home's guarantees, driven through the PRODUCTION entry points
 * (`graphqlRequest`, `authedFetch`, `refreshAccessToken`) rather than the
 * home alone — on the tree before this module each surface had its own
 * in-flight promise (or none), so the cross-surface cases below fail there
 * by construction: three concurrent surfaces produced two or three
 * `RefreshToken` mutations, not one.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { graphqlRequest } from "../graphqlClient";
import { authedFetch } from "../authedFetch";
import { refreshAccessToken } from "../auth";
import { isAuthErrorMessage, refreshSession, seedCsrfCookie } from "../session";

type Init = RequestInit | undefined;

function bodyOf(init: Init): { query?: string } {
  return typeof init?.body === "string" ? JSON.parse(init.body) : {};
}

const refreshOk = JSON.stringify({
  data: {
    refreshToken: {
      user: {
        id: "u1",
        email: "u@example.com",
        twoFactorEnabled: false,
        isTwoFactorVerified: false,
      },
    },
  },
});

/** A fetch stub: the first call on each surface is an auth failure, the
 *  refresh is SLOW (so concurrent callers overlap), the retry succeeds. */
function installFetch(opts: { refreshFails?: boolean } = {}) {
  let refreshCalls = 0;
  let csrfGets = 0;
  const seenRetry = new Set<string>();
  vi.mocked(fetch).mockImplementation(async (url, init) => {
    const u = String(url);
    if (init?.method === "GET" && u.endsWith("/auth/csrf")) {
      csrfGets++;
      await new Promise((r) => setTimeout(r, 20));
      vi.stubGlobal("document", { cookie: "talos_csrf_token=seeded" });
      return { ok: true, status: 200, text: async () => "" } as Response;
    }
    const q = bodyOf(init).query ?? "";
    if (q.includes("mutation RefreshToken")) {
      refreshCalls++;
      await new Promise((r) => setTimeout(r, 40));
      return {
        ok: true,
        status: 200,
        text: async () =>
          opts.refreshFails
            ? JSON.stringify({
                errors: [{ message: "No refresh token found in cookies" }],
              })
            : refreshOk,
      } as Response;
    }
    if (u.endsWith("/graphql")) {
      // GraphQL: first call per query text fails with an auth error.
      if (!seenRetry.has(q)) {
        seenRetry.add(q);
        return {
          ok: true,
          status: 200,
          text: async () =>
            JSON.stringify({ errors: [{ message: "Not authenticated" }] }),
        } as Response;
      }
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ data: { ping: true } }),
      } as Response;
    }
    // REST: first call is a 401, the retry a 200.
    if (!seenRetry.has(u)) {
      seenRetry.add(u);
      return {
        ok: false,
        status: 401,
        text: async () => "Not authenticated",
      } as Response;
    }
    return { ok: true, status: 200, text: async () => "{}" } as Response;
  });
  return { refreshCalls: () => refreshCalls, csrfGets: () => csrfGets };
}

describe("session: one refresh home for every surface", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
    vi.stubGlobal("document", { cookie: "talos_csrf_token=t" });
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("a GraphQL auth error, a REST 401 and the timer refresh CONCURRENTLY share one mutation", async () => {
    const m = installFetch();
    await Promise.all([
      graphqlRequest("{ ping }"),
      authedFetch("/api/rest-thing"),
      refreshAccessToken(),
    ]);
    expect(m.refreshCalls()).toBe(1);
  });

  it("a refresh that has settled does not shadow the next one", async () => {
    const m = installFetch();
    const first = await refreshSession();
    expect(first.refreshed).toBe(true);
    const second = await refreshSession();
    expect(second.refreshed).toBe(true);
    expect(m.refreshCalls()).toBe(2);
  });

  it("a failed refresh is reported once to every concurrent caller and then forgotten", async () => {
    const m = installFetch({ refreshFails: true });
    const [a, b] = await Promise.all([refreshSession(), refreshSession()]);
    expect(a.refreshed).toBe(false);
    expect(b.refreshed).toBe(false);
    expect(m.refreshCalls()).toBe(1);
    await refreshSession();
    expect(m.refreshCalls()).toBe(2);
    // The timer's wrapper turns the boolean into a throw the hook already catches.
    await expect(refreshAccessToken()).rejects.toThrow(
      "Session refresh failed",
    );
  });

  it("the timer receives the refreshed user, not a bare boolean", async () => {
    installFetch();
    const out = await refreshAccessToken();
    expect(out.user.id).toBe("u1");
    expect(out.user.email).toBe("u@example.com");
  });

  it("the CSRF seed is shared across the GraphQL and REST wrappers", async () => {
    vi.stubGlobal("document", { cookie: "" });
    const m = installFetch();
    await Promise.all([graphqlRequest("{ a }"), authedFetch("/api/b")]);
    expect(m.csrfGets()).toBe(1);
    // Direct callers share it too.
    vi.stubGlobal("document", { cookie: "" });
    await Promise.all([seedCsrfCookie(), seedCsrfCookie()]);
    expect(m.csrfGets()).toBe(2);
  });

  it("the auth-error vocabulary has exactly the three backend phrasings", () => {
    expect(isAuthErrorMessage("Authentication required")).toBe(true);
    expect(isAuthErrorMessage("Not authenticated")).toBe(true);
    expect(isAuthErrorMessage("Token has expired")).toBe(true);
    expect(isAuthErrorMessage("Workflow not found")).toBe(false);
    expect(isAuthErrorMessage(undefined)).toBe(false);
    expect(isAuthErrorMessage({ message: "Not authenticated" })).toBe(false);
  });
});
