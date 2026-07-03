import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { graphqlRequest } from "../graphqlClient";

describe("graphqlRequest Concurrency", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
    vi.stubGlobal("document", {
      cookie: "talos_csrf_token=test-token",
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should deduplicate concurrent CSRF seeding requests", async () => {
    // Clear cookie to trigger seeding
    vi.stubGlobal("document", { cookie: "" });

    vi.mocked(fetch).mockImplementation(async (url, init) => {
      if (init?.method === "GET") {
        // Simulate slow seed request
        await new Promise((resolve) => setTimeout(resolve, 50));
        vi.stubGlobal("document", { cookie: "talos_csrf_token=new-token" });
        return { ok: true, text: () => Promise.resolve("") } as any;
      }
      return {
        ok: true,
        text: () => Promise.resolve(JSON.stringify({ data: { test: true } })),
      } as any;
    });

    // Fire multiple requests simultaneously
    const p1 = graphqlRequest("{ test }");
    const p2 = graphqlRequest("{ test }");

    await Promise.all([p1, p2]);

    // Should have 1 GET (seed) and 2 POSTs (queries)
    const getCalls = vi
      .mocked(fetch)
      .mock.calls.filter((c) => c[1]?.method === "GET");
    expect(getCalls.length).toBe(1);
  });

  it("should deduplicate concurrent token refresh attempts (thundering herd)", async () => {
    let refreshCalls = 0;

    vi.mocked(fetch).mockImplementation(async (url, init) => {
      const body = typeof init?.body === "string" ? JSON.parse(init.body) : {};

      if (body.query?.includes("mutation RefreshToken")) {
        refreshCalls++;
        await new Promise((resolve) => setTimeout(resolve, 50));
        return {
          ok: true,
          text: () =>
            Promise.resolve(
              JSON.stringify({ data: { refreshToken: { user: { id: "1" } } } }),
            ),
        } as any;
      }

      // Return auth error for first attempt of both queries
      return {
        ok: true,
        text: () =>
          Promise.resolve(
            JSON.stringify({
              errors: [{ message: "Authentication expired" }],
            }),
          ),
      } as any;
    });

    const p1 = graphqlRequest("{ query1 }");
    const p2 = graphqlRequest("{ query2 }");

    // After refresh starts, mock success for the retries
    setTimeout(() => {
      vi.mocked(fetch).mockImplementation(async (_url, _init) => {
        return {
          ok: true,
          text: () =>
            Promise.resolve(JSON.stringify({ data: { success: true } })),
        } as any;
      });
    }, 20);

    await Promise.all([p1, p2]);

    expect(refreshCalls).toBe(1);
  });
});
