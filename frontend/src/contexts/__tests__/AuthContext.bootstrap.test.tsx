/**
 * The bootstrap probe is gated on the readable session marker (package DW,
 * 2026-09-22): with no `talos_session_present` cookie the provider renders
 * anonymous with ZERO requests — on the pre-fix tree the same load issued
 * `me` and then a doomed `refreshToken`. With the marker it asks `me` as
 * before, so a returning user's expired access token still refreshes.
 */
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider, useAuth } from "../AuthContext";

function Probe() {
  const { isAuthenticated, isLoading } = useAuth();
  return (
    <div>
      <span data-testid="loading">{String(isLoading)}</span>
      <span data-testid="authed">{String(isAuthenticated)}</span>
    </div>
  );
}

type Init = RequestInit | undefined;
function bodyOf(init: Init): { query?: string } {
  return typeof init?.body === "string" ? JSON.parse(init.body) : {};
}

/** jsdom's cookie jar lives on `Document.prototype`; spy on its getter
 *  rather than replacing `document`, which React renders into. */
function withCookies(value: string) {
  vi.spyOn(Document.prototype, "cookie", "get").mockReturnValue(value);
}

describe("AuthContext bootstrap and the session marker", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("with no marker the provider settles anonymous and sends NOTHING", async () => {
    withCookies("talos_csrf_token=t");
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() =>
      expect(screen.getByTestId("loading").textContent).toBe("false"),
    );
    expect(screen.getByTestId("authed").textContent).toBe("false");
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it("with the marker the provider asks `me` (the returning-user path is unchanged)", async () => {
    withCookies("talos_csrf_token=t; talos_session_present=1");
    const seen: string[] = [];
    vi.mocked(fetch).mockImplementation(async (_url, init) => {
      seen.push(bodyOf(init).query ?? "");
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            data: {
              me: {
                id: "u1",
                email: "u@example.com",
                twoFactorEnabled: false,
                isTwoFactorVerified: false,
              },
            },
          }),
      } as Response;
    });
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() =>
      expect(screen.getByTestId("authed").textContent).toBe("true"),
    );
    expect(seen.some((q) => q.includes("query Me"))).toBe(true);
  });

  it("a marker with any value but `1` reads as absent", async () => {
    withCookies("talos_session_present=yes");
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() =>
      expect(screen.getByTestId("loading").textContent).toBe("false"),
    );
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });
});
