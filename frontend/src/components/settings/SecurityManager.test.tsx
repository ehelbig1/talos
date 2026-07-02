import React from "react";
import { render, screen, fireEvent, waitFor } from "@/test-utils";
import SecurityManager from "./SecurityManager";
import { describe, it, expect } from "vitest";
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

describe("SecurityManager", () => {
  it("renders all rotation controls", () => {
    render(<SecurityManager />);
    expect(screen.getByText("ROTATE_DEK")).toBeInTheDocument();
    expect(screen.getByText("INITIATE_SWEEP")).toBeInTheDocument();
    expect(screen.getByText("COMMIT_ROOT_ROTATION")).toBeInTheDocument();
    expect(screen.getByText("ROTATE_SYMMETRIC")).toBeInTheDocument();
  });

  it("opens the DEK rotation confirmation gate", async () => {
    render(<SecurityManager />);
    fireEvent.click(screen.getByText("ROTATE_DEK"));

    await waitFor(() =>
      expect(
        screen.getByText("Rotate Data Encryption Key?"),
      ).toBeInTheDocument(),
    );
  });

  it("opens the re-encrypt-secrets confirmation gate", async () => {
    render(<SecurityManager />);
    fireEvent.click(screen.getByText("INITIATE_SWEEP"));

    await waitFor(() =>
      expect(screen.getByText("Re-encrypt All Secrets?")).toBeInTheDocument(),
    );
  });

  it("opens the symmetric-key rotation confirmation gate (destructive)", async () => {
    render(<SecurityManager />);
    fireEvent.click(screen.getByText("ROTATE_SYMMETRIC"));

    await waitFor(() =>
      expect(
        screen.getByText("Rotate Secret Encryption Key?"),
      ).toBeInTheDocument(),
    );
  });

  it("runs a DEK rotation through the confirm gate and shows the result", async () => {
    mockGraphql({
      rotateDek: () => ({
        data: {
          rotateDek: { newDekId: "dek-123", message: "DEK rotated" },
        },
      }),
    });

    render(<SecurityManager />);
    fireEvent.click(screen.getByText("ROTATE_DEK"));

    // Confirm inside the dialog (the confirm button reuses the ROTATE_DEK label).
    await waitFor(() =>
      expect(
        screen.getByText("Rotate Data Encryption Key?"),
      ).toBeInTheDocument(),
    );
    const confirmButtons = screen.getAllByText("ROTATE_DEK");
    // The last "ROTATE_DEK" is the dialog's confirm action.
    fireEvent.click(confirmButtons[confirmButtons.length - 1]);

    await waitFor(() => {
      expect(screen.getByText(/dek-123/)).toBeInTheDocument();
    });
  });

  it("keeps the master-key commit gated on a 64-char hex entropy input", () => {
    render(<SecurityManager />);
    const entropyInput = screen.getByPlaceholderText("ENTER_HEX_ENTROPY...");
    fireEvent.change(entropyInput, { target: { value: "abc" } });

    // Too-short entropy surfaces the length error and keeps commit disabled.
    expect(screen.getByText(/INVALID_ENTROPY_LENGTH/i)).toBeInTheDocument();
    const commit = screen.getByText("COMMIT_ROOT_ROTATION").closest("button")!;
    expect(commit).toBeDisabled();
  });
});
