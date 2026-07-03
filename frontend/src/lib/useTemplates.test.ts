import { renderHook, waitFor } from "../test-utils";
import { useTemplates } from "./useTemplates";
import { describe, it, expect } from "vitest";
import { server } from "../../vitest.setup";
import { http, HttpResponse } from "msw";

describe("useTemplates", () => {
  it("fetches templates on mount", async () => {
    const { result } = renderHook(() => useTemplates());

    expect(result.current.loading).toBe(true);

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.templates.length).toBeGreaterThan(0);
    expect(result.current.templates[0].name).toBe("HTTP Request");
    expect(result.current.error).toBe(null);
  });

  it("handles fetch errors", async () => {
    // Override the default handler to return an error
    server.use(
      http.post("*/graphql", () => {
        return HttpResponse.json(
          { errors: [{ message: "Network Error" }] },
          { status: 200 },
        );
      }),
    );

    const { result } = renderHook(() => useTemplates());

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.error).toBe("Network Error");
    expect(result.current.templates).toEqual([]);
  });

  it("refetches templates when refetch is called", async () => {
    const { result } = renderHook(() => useTemplates());

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    // Mock a change in data for refetch
    server.use(
      http.post("*/graphql", async ({ request }) => {
        const body = (await request.json()) as any;
        // Verify it's the right query
        if (body.query?.includes("nodeTemplates")) {
          return HttpResponse.json({
            data: {
              nodeTemplates: [
                {
                  id: "template-2",
                  name: "New Template",
                  category: "ai",
                  description: "AI test",
                  configSchema: "{}",
                  icon: "box",
                  capabilityDescription: "test",
                  allowedHosts: [],
                },
              ],
            },
          });
        }
        return HttpResponse.json({ data: {} });
      }),
    );

    await result.current.refetch();

    await waitFor(
      () => {
        expect(result.current.templates[0].name).toBe("New Template");
      },
      { timeout: 2000 },
    );
  });
});
