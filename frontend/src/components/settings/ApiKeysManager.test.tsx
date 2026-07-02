import React from "react";
import { render, screen, fireEvent, waitFor } from "@/test-utils";
import ApiKeysManager from "./ApiKeysManager";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { server } from "@/../vitest.setup";
import { http, HttpResponse } from "msw";

interface GqlBody {
  query: string;
  variables?: Record<string, unknown>;
}

function sampleKeys() {
  return [
    {
      id: "key-1",
      name: "CI Runner",
      keyPrefix: "tk_live_abc",
      scopes: ["workflows:read"],
      createdAt: new Date("2026-01-01").toISOString(),
      expiresAt: null,
      lastUsedAt: null,
      isActive: true,
      usageCount: 3,
    },
  ];
}

function mockGraphql(
  handlers: Record<string, (vars: Record<string, unknown>) => unknown>,
) {
  server.use(
    http.post("*/graphql", async ({ request }) => {
      const body = (await request.json()) as GqlBody;
      for (const [needle, resolve] of Object.entries(handlers)) {
        if (body.query.includes(needle)) {
          const value = resolve(body.variables ?? {});
          if (value instanceof HttpResponse) return value;
          return HttpResponse.json(value as Record<string, unknown>);
        }
      }
      return HttpResponse.json({ data: {} });
    }),
  );
}

describe("ApiKeysManager", () => {
  beforeEach(() => {
    Object.assign(navigator, {
      clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
  });

  it("renders the list of API keys after loading", async () => {
    mockGraphql({
      apiKeys: () => ({ data: { apiKeys: sampleKeys() } }),
    });

    render(<ApiKeysManager />);

    await waitFor(() => {
      expect(screen.getByText("CI Runner")).toBeInTheDocument();
    });
    expect(screen.getByText(/Permanent/i)).toBeInTheDocument();
  });

  it("renders the empty state when there are no keys", async () => {
    mockGraphql({
      apiKeys: () => ({ data: { apiKeys: [] } }),
    });

    render(<ApiKeysManager />);

    await waitFor(() => {
      expect(screen.getByText("No API keys found")).toBeInTheDocument();
    });
  });

  it("opens the create dialog and gates submit until name + scope set", async () => {
    mockGraphql({
      apiKeys: () => ({ data: { apiKeys: [] } }),
    });

    render(<ApiKeysManager />);
    await waitFor(() =>
      expect(screen.getByText("No API keys found")).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByText("Create New Key"));

    await waitFor(() =>
      expect(
        screen.getByPlaceholderText("e.g. GitHub Actions Runner"),
      ).toBeInTheDocument(),
    );

    const generate = screen.getByText("Generate Key").closest("button")!;
    // No name / no scope yet → submit is disabled.
    expect(generate).toBeDisabled();
  });

  it("creates a key and reveals the secret exactly once", async () => {
    mockGraphql({
      apiKeys: () => ({ data: { apiKeys: [] } }),
      createApiKey: (vars) => ({
        data: {
          createApiKey: {
            id: "key-new",
            name: (vars.input as { name?: string })?.name ?? "New Key",
            key: "tk_live_SECRETVALUE",
            scopes: ["workflows:read"],
            expiresAt: null,
          },
        },
      }),
    });

    render(<ApiKeysManager />);
    await waitFor(() =>
      expect(screen.getByText("No API keys found")).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByText("Create New Key"));
    await waitFor(() =>
      expect(
        screen.getByPlaceholderText("e.g. GitHub Actions Runner"),
      ).toBeInTheDocument(),
    );

    fireEvent.change(
      screen.getByPlaceholderText("e.g. GitHub Actions Runner"),
      { target: { value: "My Key" } },
    );
    // Select a scope so submit becomes enabled.
    fireEvent.click(screen.getByText("Read Workflows"));
    fireEvent.click(screen.getByText("Generate Key"));

    await waitFor(() => {
      expect(screen.getByText("Key Generated")).toBeInTheDocument();
    });
    expect(screen.getByText("tk_live_SECRETVALUE")).toBeInTheDocument();
    expect(screen.getByText("I've Saved It")).toBeInTheDocument();
  });

  it("shows a confirmation gate before revoking a key", async () => {
    mockGraphql({
      apiKeys: () => ({ data: { apiKeys: sampleKeys() } }),
    });

    render(<ApiKeysManager />);
    await waitFor(() =>
      expect(screen.getByText("CI Runner")).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByText("Revoke"));

    await waitFor(() =>
      expect(screen.getByText("Revoke API Key?")).toBeInTheDocument(),
    );
    expect(screen.getByText("Revoke Key")).toBeInTheDocument();
  });

  it("shows a confirmation gate before deleting a key", async () => {
    mockGraphql({
      apiKeys: () => ({ data: { apiKeys: sampleKeys() } }),
    });

    render(<ApiKeysManager />);
    await waitFor(() =>
      expect(screen.getByText("CI Runner")).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByText("Delete"));

    await waitFor(() =>
      expect(screen.getByText("Delete API Key?")).toBeInTheDocument(),
    );
    expect(screen.getByText("Delete Key")).toBeInTheDocument();
  });
});
