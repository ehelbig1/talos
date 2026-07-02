import React from "react";
import { render, screen, fireEvent, waitFor } from "@/test-utils";
import OAuthManager from "./OAuthManager";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { server } from "@/../vitest.setup";
import { http, HttpResponse } from "msw";

interface GqlBody {
  query: string;
  variables?: Record<string, unknown>;
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

// OAuthManager resolves an allowlist of hosts on mount (loadOAuthHosts) that it
// uses to validate the returned authUrl before navigating. Stub it so link
// validation is deterministic in tests.
vi.mock("@/lib/oauthUtils", () => ({
  loadOAuthHosts: vi.fn().mockResolvedValue(undefined),
  validateOAuthUrl: (url: string) => url.startsWith("https://accounts.google"),
}));

describe("OAuthManager", () => {
  beforeEach(() => {
    // jsdom forbids assigning window.location.href; provide a settable stub.
    Object.defineProperty(window, "location", {
      configurable: true,
      writable: true,
      value: { href: "" },
    });
  });

  it("shows the loading state then the providers", async () => {
    mockGraphql({
      ListLinkedAccounts: () => ({ data: { linkedOauthAccounts: [] } }),
    });

    render(<OAuthManager />);
    // Providers are hardcoded and render after the accounts query resolves.
    await waitFor(() => {
      expect(screen.getByText("Google")).toBeInTheDocument();
    });
    expect(screen.getByText("Okta")).toBeInTheDocument();
    expect(screen.getByText("Snyk")).toBeInTheDocument();
  });

  it("renders the empty-link state for an unlinked provider", async () => {
    mockGraphql({
      ListLinkedAccounts: () => ({ data: { linkedOauthAccounts: [] } }),
    });

    render(<OAuthManager />);
    await waitFor(() =>
      expect(
        screen.getByText(/No active credential link for Google/i),
      ).toBeInTheDocument(),
    );
    expect(screen.getAllByText("ESTABLISH_LINK").length).toBeGreaterThan(0);
  });

  it("redirects to the OAuth provider on a valid link URL", async () => {
    mockGraphql({
      ListLinkedAccounts: () => ({ data: { linkedOauthAccounts: [] } }),
      GetOAuthUrl: () => ({
        data: {
          oauthLoginUrl: {
            authUrl: "https://accounts.google.com/o/oauth2/auth?x=1",
          },
        },
      }),
    });

    render(<OAuthManager />);
    await waitFor(() => expect(screen.getByText("Google")).toBeInTheDocument());

    fireEvent.click(screen.getAllByText("ESTABLISH_LINK")[0]);

    await waitFor(() => {
      expect(window.location.href).toBe(
        "https://accounts.google.com/o/oauth2/auth?x=1",
      );
    });
  });

  it("shows a confirmation gate before severing a linked account", async () => {
    mockGraphql({
      ListLinkedAccounts: () => ({
        data: {
          linkedOauthAccounts: [
            {
              id: "acc-1",
              provider: "google",
              email: "user@example.com",
              name: "Test User",
              pictureUrl: null,
              linkedAt: new Date().toISOString(),
              lastLoginAt: null,
            },
          ],
        },
      }),
    });

    render(<OAuthManager />);
    await waitFor(() =>
      expect(screen.getByText("user@example.com")).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByText("Disconnect_Protocol"));

    await waitFor(() =>
      expect(screen.getByText("Sever Protocol Link?")).toBeInTheDocument(),
    );
    expect(screen.getByText("Sever Link")).toBeInTheDocument();
  });
});
