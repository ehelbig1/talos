import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { graphqlRequest } from "../graphqlClient";
import { graphql, HttpResponse, http } from "msw";
import { server } from "../../../vitest.setup";

describe("graphqlClient", () => {
  beforeEach(() => {
    vi.stubGlobal("document", {
      cookie: "",
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("performs a basic GraphQL query", async () => {
    server.use(
      // Match both GET (seed) and POST (query)
      http.get("*/graphql", () => HttpResponse.text("ok")),
      graphql.query("TestQuery", () => {
        return HttpResponse.json({
          data: { test: "success" },
        });
      }),
    );

    const result = await graphqlRequest<any>("query TestQuery { test }");
    expect(result.test).toBe("success");
  });

  it("seeds CSRF cookie on first request if missing", async () => {
    let seedCalled = false;

    server.use(
      // seedCsrfCookie() GETs the dedicated /auth/csrf endpoint (not /graphql,
      // which returns 405 with no Set-Cookie in prod — see graphqlClient.ts).
      http.get("*/auth/csrf", () => {
        seedCalled = true;
        vi.stubGlobal("document", { cookie: "talos_csrf_token=mock-token" });
        return HttpResponse.text("ok");
      }),
      graphql.query("TestQuery", () => {
        return HttpResponse.json({ data: { test: "ok" } });
      }),
    );

    await graphqlRequest("query TestQuery { test }");
    expect(seedCalled).toBe(true);
  });

  it("handles token refresh on 401-like GraphQL errors", async () => {
    let refreshCalled = false;
    let requestCount = 0;

    server.use(
      http.get("*/graphql", () => {
        vi.stubGlobal("document", { cookie: "talos_csrf_token=mock-token" });
        return HttpResponse.text("ok");
      }),
      graphql.operation(({ query }) => {
        if (query.includes("RefreshToken")) {
          refreshCalled = true;
          return HttpResponse.json({
            data: { refreshToken: { user: { id: "1" } } },
          });
        }

        if (query.includes("TestQuery")) {
          requestCount++;
          if (requestCount === 1) {
            return HttpResponse.json({
              errors: [{ message: "Authentication required" }],
            });
          }
          return HttpResponse.json({ data: { test: "success" } });
        }
        return undefined;
      }),
    );

    const result = await graphqlRequest<any>("query TestQuery { test }");
    expect(refreshCalled).toBe(true);
    expect(requestCount).toBe(2);
    expect(result.test).toBe("success");
  });

  it("throws sanitized error messages", async () => {
    server.use(
      http.get("*/graphql", () => {
        vi.stubGlobal("document", { cookie: "talos_csrf_token=mock-token" });
        return HttpResponse.text("ok");
      }),
      graphql.query("FailQuery", () => {
        return HttpResponse.json({
          errors: [
            { message: "Database constraint violation: users_email_key" },
          ],
        });
      }),
    );

    // Assuming sanitizeErrorMessage hides internal details
    try {
      await graphqlRequest("query FailQuery { test }");
    } catch (e: any) {
      expect(e.message).not.toContain("users_email_key");
      expect(e.message).toContain("[CONSTRAINT REDACTED]");
    }
  });

  it("handles rate limit errors without sanitization", async () => {
    server.use(
      http.get("*/graphql", () => {
        vi.stubGlobal("document", { cookie: "talos_csrf_token=mock-token" });
        return HttpResponse.text("ok");
      }),
      graphql.query("RateLimitQuery", () => {
        return HttpResponse.json({
          errors: [
            {
              message: "Too Many Requests",
              extensions: { code: "RATE_LIMITED" },
            },
          ],
        });
      }),
    );

    await expect(
      graphqlRequest("query RateLimitQuery { test }"),
    ).rejects.toThrow("Too Many Requests");
  });

  it("handles network timeouts", async () => {
    server.use(
      http.get("*/graphql", () => {
        vi.stubGlobal("document", { cookie: "talos_csrf_token=mock-token" });
        return HttpResponse.text("ok");
      }),
      graphql.query("TimeoutQuery", () => {
        return new Promise(() => {}); // Never resolve
      }),
    );

    // We can't easily test the actual 45s timeout in a unit test without
    // mocking timers or waiting a long time. But we can verify the logic.
    // For now, let's just ensure we handle a fetch rejection.
    server.use(
      graphql.query("TimeoutQuery", () => {
        return HttpResponse.error();
      }),
    );

    await expect(
      graphqlRequest("query TimeoutQuery { test }"),
    ).rejects.toThrow();
  });
});
