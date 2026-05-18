import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  discoverOpenAPISpec,
  parseOpenAPIEndpoints,
  endpointToNodeConfig,
  generateExampleBody,
} from "../openapi";

describe("OpenAPI Integration", () => {
  describe("discoverOpenAPISpec", () => {
    const baseUrl = "https://api.example.com";

    beforeEach(() => {
      vi.stubGlobal("fetch", vi.fn());
    });

    it("should discover a spec at a common pattern", async () => {
      const mockSpec = {
        openapi: "3.0.0",
        info: { title: "Test API", version: "1.0.0" },
      };

      (vi.mocked(fetch) as any).mockImplementation((url: string) => {
        if (url === "https://api.example.com/openapi.json") {
          return Promise.resolve({
            ok: true,
            headers: new Map([["content-type", "application/json"]]),
            json: () => Promise.resolve(mockSpec),
          } as any);
        }
        return Promise.resolve({ ok: false } as any);
      });

      const spec = await discoverOpenAPISpec(baseUrl);
      expect(spec).toEqual(mockSpec);
    });

    it("should return null if no spec is found", async () => {
      vi.mocked(fetch).mockResolvedValue({ ok: false } as any);
      const spec = await discoverOpenAPISpec(baseUrl);
      expect(spec).toBeNull();
    });

    it("should skip YAML files for now", async () => {
      (vi.mocked(fetch) as any).mockImplementation((url: string) => {
        if (url === "https://api.example.com/openapi.yaml") {
          return Promise.resolve({
            ok: true,
            headers: new Map([["content-type", "application/yaml"]]),
          } as any);
        }
        return Promise.resolve({ ok: false } as any);
      });

      const spec = await discoverOpenAPISpec(baseUrl);
      expect(spec).toBeNull();
    });
  });

  describe("parseOpenAPIEndpoints", () => {
    it("should extract endpoints from a valid spec", () => {
      const spec = {
        openapi: "3.0.0",
        paths: {
          "/users": {
            get: { summary: "List users" },
            post: { summary: "Create user" },
          },
          "/users/{id}": {
            get: { summary: "Get user" },
          },
        },
      };

      const endpoints = parseOpenAPIEndpoints(spec as any);
      expect(endpoints).toHaveLength(3);
      expect(endpoints).toContainEqual(
        expect.objectContaining({ path: "/users", method: "GET" }),
      );
      expect(endpoints).toContainEqual(
        expect.objectContaining({ path: "/users", method: "POST" }),
      );
      expect(endpoints).toContainEqual(
        expect.objectContaining({ path: "/users/{id}", method: "GET" }),
      );
    });
  });

  describe("endpointToNodeConfig", () => {
    it("should convert an endpoint to node configuration", () => {
      const endpoint = {
        path: "/users/{id}",
        method: "GET",
        parameters: [{ name: "id", in: "path" }],
      };
      const baseUrl = "https://api.example.com";

      const config = endpointToNodeConfig(endpoint as any, baseUrl);
      expect(config.METHOD).toBe("GET");
      expect(config.URL).toBe("https://api.example.com/users/{{id}}");
    });

    it("should add Content-Type header if request body exists", () => {
      const endpoint = {
        path: "/users",
        method: "POST",
        requestBody: {
          content: {
            "application/json": {},
          },
        },
      };
      const config = endpointToNodeConfig(
        endpoint as any,
        "https://api.example.com",
      );
      expect(config.HEADERS).toContainEqual({
        key: "Content-Type",
        value: "application/json",
      });
    });

    it("should handle bearer auth", () => {
      const endpoint = {
        path: "/test",
        method: "GET",
        security: [{ bearerAuth: [] }],
      };
      const spec = {
        components: {
          securitySchemes: {
            bearerAuth: { type: "http", scheme: "bearer" },
          },
        },
      };
      const config = endpointToNodeConfig(
        endpoint as any,
        "https://api.example.com",
        spec as any,
      );
      expect(config.HEADERS).toContainEqual({
        key: "Authorization",
        value: "Bearer YOUR_TOKEN_HERE",
      });
    });

    it("should handle apiKey auth", () => {
      const spec = {
        components: {
          securitySchemes: {
            apiKey: { type: "apiKey", name: "X-API-Key", in: "header" },
          },
        },
      };
      const config = endpointToNodeConfig(
        { path: "/test", method: "GET" } as any,
        "https://api.example.com",
        spec as any,
      );
      expect(config.HEADERS).toContainEqual({
        key: "X-API-Key",
        value: "YOUR_API_KEY_HERE",
      });
    });
  });

  describe("generateExampleBody", () => {
    it("should generate an example body from schema", () => {
      const requestBody = {
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                name: { type: "string" },
                age: { type: "integer" },
                active: { type: "boolean" },
              },
            },
          },
        },
      };

      const body = generateExampleBody(requestBody);
      const parsedBody = JSON.parse(body!);
      expect(parsedBody).toEqual({
        name: "example",
        age: 0,
        active: false,
      });
    });

    it("should handle arrays and nested objects", () => {
      const requestBody = {
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                tags: { type: "array", items: { type: "string" } },
                profile: {
                  type: "object",
                  properties: { email: { type: "string", format: "email" } },
                },
              },
            },
          },
        },
      };

      const body = generateExampleBody(requestBody);
      const parsedBody = JSON.parse(body!);
      expect(parsedBody.tags).toEqual(["example"]);
      expect(parsedBody.profile.email).toBe("user@example.com");
    });
  });
});
