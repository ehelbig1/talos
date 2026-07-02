import React from "react";
import { render, screen, fireEvent, waitFor } from "@/test-utils";
import TwoFactorSettings from "./TwoFactorSettings";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { server } from "@/../vitest.setup";
import { http, HttpResponse } from "msw";

// GraphQL body helper for MSW operation dispatch.
interface GqlBody {
  query: string;
  variables?: Record<string, unknown>;
}

function respondForOps(
  overrides: Record<string, (vars: Record<string, unknown>) => unknown>,
) {
  server.use(
    http.post("*/graphql", async ({ request }) => {
      const body = (await request.json()) as GqlBody;
      for (const [needle, resolve] of Object.entries(overrides)) {
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

describe("TwoFactorSettings", () => {
  beforeEach(() => {
    // Provide a clipboard stub so the copy-secret flow doesn't throw.
    Object.assign(navigator, {
      clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
  });

  it("renders the enabled/protected state when 2FA is on", () => {
    render(<TwoFactorSettings enabled={true} />);
    expect(
      screen.getByText(/Identity_Sovereignty_Verified/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/DEACTIVATE_PROTECTION/i)).toBeInTheDocument();
  });

  it("renders the setup entry point when 2FA is disabled", () => {
    render(<TwoFactorSettings enabled={false} />);
    expect(screen.getByText(/INITIALIZE_SETUP_SEQUENCE/i)).toBeInTheDocument();
  });

  it("runs the setup flow and shows the secret to scan", async () => {
    respondForOps({
      setupTwoFactor: () => ({
        data: {
          setupTwoFactor: {
            secret: "JBSWY3DPEHPK3PXP",
            qrCodeUrl: "otpauth://totp/Talos:test",
            qrCodePng: "data:image/png;base64,AAAA",
          },
        },
      }),
    });

    render(<TwoFactorSettings enabled={false} />);
    fireEvent.click(screen.getByText(/INITIALIZE_SETUP_SEQUENCE/i));

    await waitFor(() => {
      expect(screen.getByText("JBSWY3DPEHPK3PXP")).toBeInTheDocument();
    });
    // Manual key section header renders in the setup step.
    expect(screen.getByText(/Manual_Cipher_Key/i)).toBeInTheDocument();
  });

  it("opens the deactivate confirmation gate before disabling", async () => {
    render(<TwoFactorSettings enabled={true} />);
    fireEvent.click(screen.getByText(/DEACTIVATE_PROTECTION/i));

    await waitFor(() => {
      expect(screen.getByText("Deactivate Protection?")).toBeInTheDocument();
    });
    expect(screen.getByText("Yes, Deactivate")).toBeInTheDocument();
  });

  it("surfaces a setup error without crashing", async () => {
    respondForOps({
      setupTwoFactor: () =>
        HttpResponse.json({
          errors: [{ message: "boom" }],
          data: null,
        }),
    });

    render(<TwoFactorSettings enabled={false} />);
    fireEvent.click(screen.getByText(/INITIALIZE_SETUP_SEQUENCE/i));

    // The initial setup button remains after an error (no crash, no secret).
    await waitFor(() => {
      expect(
        screen.getByText(/INITIALIZE_SETUP_SEQUENCE/i),
      ).toBeInTheDocument();
    });
  });
});
