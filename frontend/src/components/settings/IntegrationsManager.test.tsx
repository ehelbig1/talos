import React from "react";
import { render, screen, fireEvent, waitFor } from "@/test-utils";
import { IntegrationsManager } from "./IntegrationsManager";
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

const GCP_PROVIDER = {
  id: "gcp",
  display_name: "Google Cloud",
  description: "List projects and receive Cloud Monitoring alerts",
  icon: "LayoutGrid",
  color: "#4285F4",
  graphql_enum: "GOOGLE_CLOUD",
  oauth_hosts: ["accounts.google.com"],
  configured: true,
  connect_url: "/api/gcp/connect",
};

// IntegrationsManager unconditionally renders GoogleCalendarWatchChannels,
// GmailWatchChannels, and GoogleCloudWatchChannels alongside the provider
// grid. Each fetches its own `/integrations` + `/watch-channels` REST pair
// on mount; a 401 makes them gate off (return null) without pulling their
// own scenarios into this test.
function stubSiblingWatchPanels() {
  const gate = () => HttpResponse.json({}, { status: 401 });
  for (const path of [
    "*/api/gmail/watch-channels",
    "*/api/gmail/integrations",
    "*/api/google-calendar/watch-channels",
    "*/api/google-calendar/integrations",
    "*/api/gcp/watch-channels",
    "*/api/gcp/integrations",
  ]) {
    server.use(http.get(path, gate));
  }
}

// OAuthManager-style stub: the connect flow validates the returned
// authorization_url against a host allowlist loaded on mount. Stub it so
// the redirect assertion below is deterministic and independent of that
// network call.
vi.mock("@/lib/oauthUtils", () => ({
  loadOAuthHosts: vi.fn().mockResolvedValue(undefined),
  validateOAuthUrl: (url: string) => url.startsWith("https://accounts.google"),
}));

describe("IntegrationsManager", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    // jsdom forbids assigning window.location.href; provide a settable stub.
    // href must stay a valid absolute URL — IntegrationsManager's own
    // `authedFetch` helper (unlike graphqlClient's API_URL-prefixed calls)
    // issues page-relative requests (`/api/gcp/connect-write`), and msw's
    // fetch interceptor resolves those against `location.href` as the base;
    // an empty string base throws "Invalid URL" before the mock ever fires.
    Object.defineProperty(window, "location", {
      configurable: true,
      writable: true,
      value: {
        href: "http://localhost/settings",
        search: "",
        pathname: "/settings",
      },
    });

    stubSiblingWatchPanels();
    mockGraphql({
      ListServiceIntegrations: () => ({ data: { serviceIntegrations: [] } }),
    });
    server.use(
      http.get("*/api/integrations/providers", () =>
        HttpResponse.json([GCP_PROVIDER]),
      ),
      http.get("*/api/github/installations", () =>
        HttpResponse.json({ installations: [] }),
      ),
      // graphqlClient's CSRF-seed preflight (best-effort; failure is caught
      // internally) — mocked only to keep test output free of msw's
      // unhandled-request noise.
      http.get("*/auth/csrf", () => new HttpResponse(null, { status: 204 })),
    );
  });

  it("renders a provisioning action for the Google Cloud card with an explanatory tooltip", async () => {
    render(<IntegrationsManager />);

    const provisionBtn = await screen.findByRole("button", {
      name: /Enable provisioning/i,
    });
    expect(provisionBtn).toHaveAttribute(
      "title",
      expect.stringContaining("Pub/Sub and Monitoring only"),
    );
  });

  it("fires GET /api/gcp/connect-write and redirects to the returned authorization_url", async () => {
    let calledConnectWrite = false;
    server.use(
      http.get("*/api/gcp/connect-write", () => {
        calledConnectWrite = true;
        return HttpResponse.json({
          success: true,
          data: {
            authorization_url:
              "https://accounts.google.com/o/oauth2/auth?scope=pubsub+monitoring",
            csrf_token: "csrf-abc",
          },
        });
      }),
      // A regular /connect call should NEVER fire for this button — if it
      // does, the redirect below would still succeed on a read-tier URL,
      // masking a wiring bug where the button hits the wrong endpoint.
      http.get("*/api/gcp/connect", () =>
        HttpResponse.json({
          success: true,
          data: {
            authorization_url: "https://accounts.google.com/wrong-tier",
            csrf_token: "csrf-wrong",
          },
        }),
      ),
    );

    render(<IntegrationsManager />);

    const provisionBtn = await screen.findByRole("button", {
      name: /Enable provisioning/i,
    });
    fireEvent.click(provisionBtn);

    await waitFor(() => {
      expect(window.location.href).toBe(
        "https://accounts.google.com/o/oauth2/auth?scope=pubsub+monitoring",
      );
    });
    expect(calledConnectWrite).toBe(true);
  });
});
